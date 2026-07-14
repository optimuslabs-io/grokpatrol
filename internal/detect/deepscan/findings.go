package deepscan

import (
	"fmt"

	"github.com/optimuslabs/grokpatrol/internal/engine"
	"github.com/optimuslabs/grokpatrol/internal/hostfs"
	"github.com/optimuslabs/grokpatrol/internal/model"
	"github.com/optimuslabs/grokpatrol/internal/scan"
)

func findings(d *engine.Discovered, env *engine.Env) []model.Finding {
	var out []model.Finding

	var installs, mentions []engine.BinaryHit
	for _, b := range d.Binaries {
		if b.IsInstall() {
			installs = append(installs, b)
		} else {
			mentions = append(mentions, b)
		}
	}

	if len(installs) > 0 {
		var ev []model.Evidence
		for _, b := range installs {
			for _, m := range b.Markers {
				ev = append(ev, model.Evidence{
					Path:      b.Path,
					Locator:   fmt.Sprintf("offset:0x%x", m.Offset),
					Note:      "contains marker " + m.Marker,
					SHA256:    b.SHA256,
					SizeBytes: b.SizeBytes,
				})
			}
		}
		out = append(out, model.Finding{
			ID:       "deepscan.binary_marker",
			Detector: "deepscan",
			Severity: model.SevHigh,
			Tags:     []string{model.TagInstall},
			Title:    fmt.Sprintf("%d executables contain the exfiltration bucket name %q", len(installs), scan.MarkerBucket),
			Detail: "The destination bucket for the repository uploads is named inside these programs. That means the " +
				"collector code is on this machine; it does not by itself prove it ran -- the log ledger answers that.",
			Remediation: "Remove the Grok Build CLI. Until then, set " + scan.MarkerFlag + " = true under [harness] in config.toml.",
			Evidence:    ev,
		})
	}

	// Reported, but NOT treated as an install and NOT enough to make a host EXPOSED.
	// Being honest about the difference is what keeps the High findings meaningful.
	if len(mentions) > 0 {
		var ev []model.Evidence
		for _, b := range mentions {
			ev = append(ev, model.Evidence{
				Path: b.Path, SizeBytes: b.SizeBytes, SHA256: b.SHA256,
				Note: fmt.Sprintf("%s file mentioning %d indicator string(s)", b.Kind, len(b.Markers)),
			})
		}
		out = append(out, model.Finding{
			ID:       "deepscan.file_reference",
			Detector: "deepscan",
			Severity: model.SevInfo,
			Tags:     []string{model.TagInstall},
			Title:    fmt.Sprintf("%d small text files mention Grok indicator strings", len(mentions)),
			Detail: "These are not executables and are too small to be a packed CLI, so they are almost certainly notes, " +
				"an IoC list, or another detection tool -- not a Grok install. They are listed for completeness only, " +
				"and they do not affect the verdict.",
			Evidence: ev,
		})
	}

	// A .grok outside the expected home means a second install or a second profile,
	// whose logs and config also need reading. Assuming ~/.grok is the only one is a
	// false negative.
	for _, h := range d.GrokHomes {
		if h == env.GrokHome {
			continue
		}
		// The path goes in the Evidence, never in the Title. Only Evidence.Path is
		// rendered home-relative (report.Display walks the paths, not the prose), so a
		// title that embedded the location would print an absolute path in the middle of
		// an otherwise ~/-relative report.
		out = append(out, model.Finding{
			ID:       "deepscan.stray_grok_home",
			Detector: "deepscan",
			Severity: model.SevMedium,
			Tags:     []string{model.TagInstall},
			Title:    "A second Grok home was found outside the configured one",
			Detail: "Its logs and config were parsed as well. A second grok home usually means a second install " +
				"or a container mount.",
			Evidence: []model.Evidence{{Path: h, Note: "grok home outside " + hostfs.Display(env.GrokHome, env.Home)}},
		})
	}

	return out
}
