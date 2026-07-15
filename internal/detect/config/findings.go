package config

import (
	"fmt"
	"strings"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// remediationText prints both settings, because both are required.
func remediationText() string {
	var b strings.Builder
	b.WriteString("Add to ~/.grok/config.toml:\n")
	for _, m := range Mitigations() {
		fmt.Fprintf(&b, "\n    [%s]\n    %s = %s", m.Table, m.Key, m.Want)
	}
	return b.String()
}

func configFindings(states []state) []model.Finding {
	var out []model.Finding

	for _, st := range states {
		switch {
		case st.missing:
			out = append(out, model.Finding{
				ID:       "config.absent",
				Detector: "config",
				Severity: model.SevMedium,
				Tags:     []string{model.TagConfig},
				Title:    "No Grok config.toml, so neither upload mitigation is set",
				Detail: "Grok is present on this machine but has no config file. Neither " + MitigationKey +
					" nor " + TraceKey + " is set, so nothing is blocked on the client side.",
				Remediation: remediationText(),
				Evidence:    []model.Evidence{{Path: st.path, Note: "file does not exist"}},
			})

		case st.uncertain:
			// Fail closed. Better to tell someone to check by hand than to tell them they
			// are protected when we could not actually confirm it.
			out = append(out, model.Finding{
				ID:       "config.unparseable",
				Detector: "config",
				Severity: model.SevMedium,
				Tags:     []string{model.TagConfig},
				Title:    "config.toml uses constructs this scanner does not model",
				Detail: "grokpatrol could not positively confirm the upload mitigations. It reports EXPOSED rather than " +
					"guess in the reassuring direction. Verify this file by hand.",
				Remediation: remediationText(),
				Evidence:    []model.Evidence{{Path: st.path, Note: "could not confirm the mitigations"}},
			})

		default:
			out = append(out, mitigationFindings(st)...)
		}

		// Surface every other key under the two tables that matter. The vendor's own
		// documentation was never available -- the mitigation keys came from public
		// reporting and a screenshot -- so an unrecognized option is shown rather than
		// silently ignored.
		if others := otherKeys(st); len(others) > 0 {
			out = append(out, model.Finding{
				ID:       "config.other_keys",
				Detector: "config",
				Severity: model.SevInfo,
				Tags:     []string{model.TagConfig},
				Title:    "Other upload-related options are set: " + strings.Join(others, ", "),
				Detail: "These keys sit alongside the known mitigations. grokpatrol does not know what they do; they are " +
					"listed so you can check them against xAI's documentation.",
				Evidence: []model.Evidence{{Path: st.path}},
			})
		}
	}
	return out
}

// mitigationFindings evaluates each required setting independently. A host with
// only one of the two set is PARTIALLY mitigated, which is not mitigated: it has
// stopped the repository archives but is still shipping session traces.
func mitigationFindings(st state) []model.Finding {
	var out []model.Finding
	satisfied := 0

	for _, m := range Mitigations() {
		switch {
		case st.Satisfied(m):
			satisfied++
		case st.Present(m):
			out = append(out, model.Finding{
				ID:       "config.explicitly_disabled",
				Detector: "config",
				Severity: model.SevHigh,
				Tags:     []string{model.TagConfig},
				Title:    fmt.Sprintf("%s is set to the WRONG value under [%s]", m.Key, m.Table),
				Detail: fmt.Sprintf("The mitigation exists in this config but is turned off, so %s is permitted. "+
					"It must be %s = %s.", m.What, m.Key, m.Want),
				Remediation: remediationText(),
				Evidence:    []model.Evidence{{Path: st.path, Locator: m.Table + "." + m.Key, Note: "set to the wrong value"}},
			})
		default:
			out = append(out, model.Finding{
				ID:          "config.not_mitigated",
				Detector:    "config",
				Severity:    model.SevMedium,
				Tags:        []string{model.TagConfig},
				Title:       fmt.Sprintf("%s = %s is not set under [%s]", m.Key, m.Want, m.Table),
				Detail:      "Without it, " + m.What + " is not blocked on the client side.",
				Remediation: remediationText(),
				Evidence:    []model.Evidence{{Path: st.path, Locator: m.Table + "." + m.Key, Note: "mitigation absent"}},
			})
		}
	}

	if satisfied == len(Mitigations()) {
		out = append(out, model.Finding{
			ID:       "config.mitigated",
			Detector: "config",
			Severity: model.SevInfo,
			Tags:     []string{model.TagConfig},
			Title:    "Both upload mitigations are set",
			Detail: "Repository archive upload and session trace upload are both disabled in this config. Note that this " +
				"prevents FUTURE uploads only -- it does nothing about repositories already collected, which the " +
				"exfiltration ledger reports separately.",
			Evidence: []model.Evidence{{Path: st.path, Note: "both mitigations present"}},
		})
	}
	return out
}

// otherKeys lists keys under the mitigation tables that are not themselves a
// known mitigation.
func otherKeys(st state) []string {
	known := map[string]bool{}
	for _, m := range Mitigations() {
		known[m.Table+"."+m.Key] = true
	}
	var out []string
	for _, m := range Mitigations() {
		for _, k := range st.keys[m.Table] {
			full := m.Table + "." + k
			if !known[full] {
				out = append(out, full)
				known[full] = true // dedupe across the two tables
			}
		}
	}
	return out
}
