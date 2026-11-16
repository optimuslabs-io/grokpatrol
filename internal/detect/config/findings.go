package config

import (
	"fmt"
	"strings"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// remediationText prints every setting the host needs, because each is required, and
// the recommended extras after them, marked as such.
func remediationText(required []Mitigation) string {
	var b strings.Builder
	b.WriteString("Add to ~/.grok/config.toml (all required):\n")
	writeTOML(&b, required)
	b.WriteString("\n\nRecommended, not required (they cut what else Grok sends):\n")
	writeTOML(&b, Recommended())
	return b.String()
}

// writeTOML groups settings by table, so two [harness] keys print under one header.
func writeTOML(b *strings.Builder, ms []Mitigation) {
	var order []string
	byTable := map[string][]Mitigation{}
	for _, m := range ms {
		if _, ok := byTable[m.Table]; !ok {
			order = append(order, m.Table)
		}
		byTable[m.Table] = append(byTable[m.Table], m)
	}
	for _, t := range order {
		fmt.Fprintf(b, "\n    [%s]", t)
		for _, m := range byTable[t] {
			fmt.Fprintf(b, "\n    %s = %s", m.Key, m.Want)
		}
	}
}

func configFindings(homes []homeState, getenv func(string) string) []model.Finding {
	var out []model.Finding

	for _, h := range homes {
		switch {
		case h.missing:
			out = append(out, model.Finding{
				ID:       "config.absent",
				Detector: "config",
				Severity: model.SevMedium,
				Tags:     []string{model.TagConfig},
				Title:    "No Grok config.toml, so no upload mitigation is set",
				Detail: "Grok is present on this machine but has no config.toml, managed_config.toml or requirements.toml. " +
					"None of " + keyList(h.required) + " is set, so nothing is blocked on the client side.",
				Remediation: remediationText(h.required),
				Evidence:    []model.Evidence{{Path: h.userPath, Note: "file does not exist"}},
			})

		case h.uncertain:
			// Fail closed. Better to tell someone to check by hand than to tell them they
			// are protected when we could not actually confirm it.
			ev := []model.Evidence{{Path: h.userPath, Note: "could not confirm the mitigations"}}
			if h.badPath != h.userPath {
				ev = append(ev, model.Evidence{Path: h.badPath, Note: "this layer could not be confirmed"})
			}
			out = append(out, model.Finding{
				ID:       "config.unparseable",
				Detector: "config",
				Severity: model.SevMedium,
				Tags:     []string{model.TagConfig},
				Title:    "A Grok config file uses constructs this scanner does not model",
				Detail: "grokpatrol could not positively confirm the upload mitigations. It reports EXPOSED rather than " +
					"guess in the reassuring direction. Verify this file by hand.",
				Remediation: remediationText(h.required),
				Evidence:    ev,
			})

		default:
			out = append(out, mitigationFindings(h, getenv)...)
		}

		// Surface every other key under the required tables. The list of what Grok
		// reads there changes between releases, so an unrecognised option is shown
		// rather than silently ignored.
		if others := otherKeys(h); len(others) > 0 {
			out = append(out, model.Finding{
				ID:       "config.other_keys",
				Detector: "config",
				Severity: model.SevInfo,
				Tags:     []string{model.TagConfig},
				Title:    "Other upload-related options are set: " + strings.Join(others, ", "),
				Detail: "These keys sit alongside the known mitigations. grokpatrol does not judge them; they are " +
					"listed so you can check them against xAI's documentation.",
				Evidence: []model.Evidence{{Path: h.userPath}},
			})
		}

		out = append(out, destinationFindings(h)...)
	}
	return out
}

// mitigationFindings evaluates each required setting independently, on the merged
// layers. A host with only some set is PARTIALLY mitigated, which is not mitigated.
//
// Evidence[0] is always the home's config.toml: the report groups config findings by
// that path into one row per home. When the value came from another layer (a
// managed or requirements file), a second evidence row names it.
func mitigationFindings(h homeState, getenv func(string) string) []model.Finding {
	var out []model.Finding
	satisfied := 0

	for _, m := range h.required {
		full := m.Table + "." + m.Key
		val, src, set := h.resolve(full)

		// An environment variable beats every file but a requirements pin. If one
		// that can switch this upload back on is set, the file's value is not the
		// answer, whatever it says.
		if vars := setVars(envOverrides[full], getenv); len(vars) > 0 && !h.pinned(full) {
			out = append(out, model.Finding{
				ID:       "config.env_override",
				Detector: "config",
				Severity: model.SevMedium,
				Tags:     []string{model.TagConfig},
				Title:    fmt.Sprintf("%s is set in the environment, so %s cannot be verified", strings.Join(vars, " and "), full),
				Detail: "Grok gives environment variables precedence over config.toml and managed_config.toml; only a " +
					"requirements.toml pin beats them. grokpatrol does not interpret the value: it cannot see the " +
					"environment Grok itself is launched with, so it treats " + full + " as unconfirmed rather than " +
					"guess in the reassuring direction.",
				Remediation: fmt.Sprintf("Unset %s wherever Grok is launched, or pin %s = %s in requirements.toml.",
					strings.Join(vars, " and "), full, m.Want),
				Evidence: []model.Evidence{
					{Path: h.userPath, Locator: full, Note: "overridden by the environment"},
					{Locator: "env:" + strings.Join(vars, ",env:"), Note: "set in the environment grokpatrol ran in"},
				},
			})
			continue
		}

		switch {
		case set && val == m.Want:
			satisfied++
		case set:
			ev := []model.Evidence{{Path: h.userPath, Locator: full, Note: "set to the wrong value"}}
			if src.path != h.userPath {
				ev = append(ev, model.Evidence{Path: src.path, Locator: full, Note: layerNote(src) + " sets the wrong value"})
			}
			out = append(out, model.Finding{
				ID:       "config.explicitly_disabled",
				Detector: "config",
				Severity: model.SevHigh,
				Tags:     []string{model.TagConfig},
				Title:    fmt.Sprintf("%s is set to the WRONG value under [%s]", m.Key, m.Table),
				Detail: fmt.Sprintf("The mitigation exists in this config but is turned off, so %s is permitted. "+
					"It must be %s = %s.", m.What, m.Key, m.Want),
				Remediation: remediationText(h.required),
				Evidence:    ev,
			})
		default:
			out = append(out, model.Finding{
				ID:          "config.not_mitigated",
				Detector:    "config",
				Severity:    model.SevMedium,
				Tags:        []string{model.TagConfig},
				Title:       fmt.Sprintf("%s = %s is not set under [%s]", m.Key, m.Want, m.Table),
				Detail:      "Without it, " + m.What + " is not blocked on the client side.",
				Remediation: remediationText(h.required),
				Evidence:    []model.Evidence{{Path: h.userPath, Locator: full, Note: "mitigation absent"}},
			})
		}
	}

	if satisfied == len(h.required) {
		ev := []model.Evidence{{Path: h.userPath, Note: "all required mitigations present"}}
		for _, m := range h.required {
			if _, src, _ := h.resolve(m.Table + "." + m.Key); src.path != h.userPath {
				ev = append(ev, model.Evidence{Path: src.path, Locator: m.Table + "." + m.Key, Note: layerNote(src)})
			}
		}
		out = append(out, model.Finding{
			ID:       "config.mitigated",
			Detector: "config",
			Severity: model.SevInfo,
			Tags:     []string{model.TagConfig},
			Title:    fmt.Sprintf("All %d required upload mitigations are set", len(h.required)),
			Detail: "Session trace upload and repository snapshot upload are disabled in this host's Grok config. " +
				"This prevents FUTURE uploads only -- it does nothing about repositories already collected, which " +
				"the exfiltration ledger reports separately.",
			Evidence: ev,
		})
		if missing := missingRecommended(h); len(missing) > 0 {
			out = append(out, model.Finding{
				ID:          "config.recommended_unset",
				Detector:    "config",
				Severity:    model.SevInfo,
				Tags:        []string{model.TagConfig},
				Title:       "Recommended, not required: " + strings.Join(missing, ", "),
				Detail:      "These do not gate the repository or trace uploads, so the host is mitigated without them. They reduce what else Grok sends.",
				Remediation: remediationText(h.required),
				Evidence:    []model.Evidence{{Path: h.userPath, Note: "recommended settings absent"}},
			})
		}
	}
	return out
}

// missingRecommended lists the recommended settings not in force. features.telemetry
// also accepts "off", which is a string, so both spellings count.
func missingRecommended(h homeState) []string {
	var out []string
	for _, m := range Recommended() {
		full := m.Table + "." + m.Key
		if v, _, ok := h.resolve(full); ok && v == m.Want {
			continue
		}
		if v, _, ok := h.resolveString(full); ok && strings.EqualFold(v, "off") {
			continue
		}
		out = append(out, fmt.Sprintf("%s = %s", full, m.Want))
	}
	return out
}

// envFindings notes the variables that bear on uploads without being able to switch
// a required one back on. Names only: a value is never printed.
func envFindings(getenv func(string) string) []model.Finding {
	vars := setVars(envNoted, getenv)
	if len(vars) == 0 {
		return nil
	}
	ev := make([]model.Evidence, 0, len(vars))
	for _, v := range vars {
		ev = append(ev, model.Evidence{Locator: "env:" + v, Note: "set in the environment grokpatrol ran in"})
	}
	return []model.Finding{{
		ID:       "config.env_set",
		Detector: "config",
		Severity: model.SevInfo,
		Tags:     []string{model.TagConfig},
		Title:    "Grok environment variables are set: " + strings.Join(vars, ", "),
		Detail: "The effect of these cannot be verified from files, and grokpatrol sees only its own environment. " +
			"DISABLE_TELEMETRY and DISABLE_ERROR_REPORTING can only turn things off. GROK_CONFIG and GROK_CONFIG_PATH " +
			"are an overlay that Grok confines to models, features, toolset and shell_environment_policy, so they " +
			"cannot reach the required mitigations. None of these changes the verdict.",
		Evidence: ev,
	}}
}

// destinationFindings reports configured trace-upload destinations. Informational:
// a redirected destination changes WHERE traces go, not WHETHER they go, and the
// mitigation findings already answer whether.
func destinationFindings(h homeState) []model.Finding {
	var ev []model.Evidence
	for _, k := range destinationKeys {
		full := "endpoints." + k
		if v, src, ok := h.resolveString(full); ok {
			ev = append(ev, model.Evidence{Path: src.path, Locator: sanitizeTarget(v), Note: full + " (" + layerNote(src) + ")"})
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return []model.Finding{{
		ID:       "config.upload_destination",
		Detector: "config",
		Severity: model.SevInfo,
		Tags:     []string{model.TagConfig},
		Title:    "A custom trace-upload destination is configured",
		Detail: "Session traces are configured to go to this destination instead of xAI's proxy. grokpatrol also " +
			"searches the logs and upload_queue for a configured bucket, since a redirected upload never names xAI's.",
		Evidence: ev,
	}}
}

// envDestinationFindings is destinationFindings for the environment variables that
// redirect trace uploads. The variable is named; its value is sanitised to a location.
func envDestinationFindings(env *engine.Env) []model.Finding {
	var ev []model.Evidence
	for _, e := range destinationEnv {
		if v := strings.TrimSpace(env.LookupEnv(e.name)); v != "" {
			ev = append(ev, model.Evidence{Locator: sanitizeTarget(v), Note: "env:" + e.name + " (set in the environment grokpatrol ran in)"})
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return []model.Finding{{
		ID:       "config.upload_destination",
		Detector: "config",
		Severity: model.SevInfo,
		Tags:     []string{model.TagConfig},
		Title:    "A custom trace-upload destination is set in the environment",
		Detail: "Grok reads these variables over the config files (for a gs:// bucket, GROK_TELEMETRY_GCS_BUCKET " +
			"replaces the bucket even over a requirements pin). grokpatrol also searches the logs and upload_queue " +
			"for a configured bucket, since a redirected upload never names xAI's.",
		Evidence: ev,
	}}
}

func setVars(names []string, getenv func(string) string) []string {
	var out []string
	for _, n := range names {
		if strings.TrimSpace(getenv(n)) != "" {
			out = append(out, n)
		}
	}
	return out
}

func layerNote(l layer) string {
	if l.pin {
		return "requirements pin"
	}
	if strings.HasSuffix(l.path, "managed_config.toml") {
		return "fleet default"
	}
	return "user config"
}

func keyList(ms []Mitigation) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, m.Table+"."+m.Key)
	}
	return strings.Join(parts, ", ")
}

// otherKeys lists keys under the required tables that are not themselves a known
// mitigation, across every layer.
func otherKeys(h homeState) []string {
	known := map[string]bool{}
	for _, m := range Mitigations() {
		known[m.Table+"."+m.Key] = true
	}
	var out []string
	for _, l := range h.layers {
		for _, m := range Mitigations() {
			for _, k := range l.st.keys[m.Table] {
				full := m.Table + "." + k
				if !known[full] {
					out = append(out, full)
					known[full] = true // dedupe across tables and layers
				}
			}
		}
	}
	return out
}
