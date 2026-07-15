package deepscan

import (
	"fmt"
	"path/filepath"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
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
		// Which of these is the grok that actually runs when the user types `grok`? That
		// is the one on $PATH, and on a host with several copies on disk it is the one the
		// report must surface first. activeEntry is the $PATH location; it is empty when no
		// grok is on $PATH, or when the one that is was not among the discovered installs.
		activeFile, activeEntry := activeInstall(installs, env)
		var ev []model.Evidence
		for _, b := range installs {
			entry := ""
			if activeEntry != "" && b.Path == activeFile {
				entry = activeEntry
			}
			for _, m := range b.Markers {
				ev = append(ev, model.Evidence{
					Path:      b.Path,
					Locator:   fmt.Sprintf("offset:0x%x", m.Offset),
					Note:      "contains marker " + m.Marker,
					SHA256:    b.SHA256,
					SizeBytes: b.SizeBytes,
					PathEntry: entry,
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

// activeInstall returns the discovered install the grok command resolves to on $PATH
// -- the file that runs when the user types `grok` -- and the $PATH entry that points
// at it. It returns empty strings when no grok is on $PATH, or when the one that is was
// not among the discovered installs: a $PATH directory the walk did not cover, or a
// symlink target outside the scanned roots. In that case there is nothing to highlight,
// and the caller must not invent a row for a file it never inspected.
//
// Matching is by RESOLVED path, cleaned on both sides: the $PATH entry is typically a
// symlink and its real target is what deepscan recorded when it walked the file.
func activeInstall(installs []engine.BinaryHit, env *engine.Env) (file, entry string) {
	e, resolved, ok := hostfs.ResolveOnPath(env.PathDirs, scan.GrokCommandNames)
	if !ok {
		return "", ""
	}
	want := filepath.Clean(resolved)
	for _, b := range installs {
		// Either match: resolved == the walked file, or the $PATH entry is itself the
		// discovered file (a real binary on $PATH the walk reached directly).
		if filepath.Clean(b.Path) == want || filepath.Clean(b.Path) == filepath.Clean(e) {
			return b.Path, e
		}
	}
	return "", ""
}
