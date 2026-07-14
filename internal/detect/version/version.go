// Package version determines which Grok version is installed WITHOUT executing it.
//
// The binary is never launched -- not with --version, not with --help, not ever.
// It carries a collector that runs outside the tool-call permission system, so
// running it to ask its version could itself start a session and trigger an
// upload. Every source below is passive: files on disk, and strings inside the
// binary we already read.
package version

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/optimuslabs/grokpatrol/internal/engine"
	"github.com/optimuslabs/grokpatrol/internal/grokver"
	"github.com/optimuslabs/grokpatrol/internal/hostfs"
	"github.com/optimuslabs/grokpatrol/internal/model"
	"github.com/optimuslabs/grokpatrol/internal/scan"
)

type Detector struct{}

func New() *Detector           { return &Detector{} }
func (*Detector) Name() string { return "version" }

// Describe says "without executing it" out loud, because that restraint is the
// non-obvious part: the obvious way to get a version is `grok --version`, and doing
// that would run a collector that lives outside the permission system.
func (*Detector) Describe() string {
	return "inferring the Grok version from install manifests, package metadata and binary strings " +
		"(the grok binary is never executed)"
}

func summarize(vs []model.VersionEvidence) string {
	for _, v := range vs {
		if v.Class == model.VersionConfirmedAffected {
			return v.Version + " -- CONFIRMED AFFECTED"
		}
	}
	for _, v := range vs {
		if v.Class == model.VersionReportedAffected {
			return v.Version + " -- REPORTED AFFECTED"
		}
	}
	if len(vs) > 0 {
		// Never "safe": there is no ground truth for a fixed release, so a version
		// outside the known-affected range is unknown, not clean.
		return engine.Plural(len(vs), "version") + " found, none in the known-affected range (which is not the same as safe)"
	}
	return "no version evidence found"
}

// manifestNames are the passive places an install records its own version.
var manifestNames = []string{"version", "VERSION", ".version", "install.json", "manifest.json", "package.json"}

const maxManifestBytes = 1 << 20

func (d *Detector) Run(ctx context.Context, env *engine.Env) (engine.Result, error) {
	var res engine.Result

	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}

	for _, h := range homes {
		for _, name := range manifestNames {
			if ev := fromManifest(filepath.Join(h, name)); ev != nil {
				res.Versions = append(res.Versions, *ev)
			}
		}
	}

	for _, b := range env.Discovered.Binaries {
		// Homebrew encodes the version in the install path: the path IS the manifest.
		if ev := fromCellarPath(b.Path); ev != nil {
			res.Versions = append(res.Versions, *ev)
		}
		dir := filepath.Dir(b.Path)
		for _, cand := range []string{dir, filepath.Dir(dir)} {
			if ev := fromManifest(filepath.Join(cand, "package.json")); ev != nil {
				res.Versions = append(res.Versions, *ev)
			}
		}
		// Only binaries that already matched a marker are string-mined, so we never
		// read the whole home directory twice.
		res.Versions = append(res.Versions, fromBinaryStrings(ctx, b.Path)...)
	}

	res.Versions = dedupe(res.Versions)
	res.Findings = findings(res.Versions)
	res.Summary = summarize(res.Versions)
	if len(res.Versions) > 0 {
		res.Limitations = append(res.Limitations,
			"Versions above the reported-affected range are classed UNKNOWN, never clean: this tool has no ground "+
				"truth for a fixed release, and the verdict is driven by the artifacts on disk rather than by a version number.")
	}
	return res, nil
}

func fromManifest(path string) *model.VersionEvidence {
	b, err := hostfs.ReadFileCapped(path, maxManifestBytes)
	if err != nil || len(b) == 0 {
		return nil
	}
	base := filepath.Base(path)

	if strings.HasSuffix(base, ".json") {
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return nil
		}
		// A package.json next to the binary is only meaningful if it is grok's own.
		if base == "package.json" {
			if name, _ := m["name"].(string); !isGrokPkg(name) {
				return nil
			}
		}
		v, _ := m["version"].(string)
		if !grokver.Plausible(v) {
			return nil
		}
		return &model.VersionEvidence{
			Version: v, Source: "manifest:" + base, Confidence: "high",
			Class: grokver.Class(v), Path: path,
		}
	}

	v := strings.TrimSpace(string(b))
	if !grokver.Plausible(v) {
		return nil
	}
	return &model.VersionEvidence{
		Version: v, Source: "manifest:" + base, Confidence: "high",
		Class: grokver.Class(v), Path: path,
	}
}

func isGrokPkg(name string) bool {
	n := strings.ToLower(name)
	return n == "grok" || strings.HasSuffix(n, "/grok") || strings.Contains(n, "grok-cli") || strings.Contains(n, "grok-build")
}

var cellarRe = regexp.MustCompile(`(?i)/Cellar/[^/]*grok[^/]*/(\d+\.\d+\.\d+[^/]*)/`)

func fromCellarPath(path string) *model.VersionEvidence {
	m := cellarRe.FindStringSubmatch(filepath.ToSlash(path))
	if m == nil {
		return nil
	}
	return &model.VersionEvidence{
		Version: m[1], Source: "homebrew-path", Confidence: "high",
		Class: grokver.Class(m[1]), Path: path,
	}
}

// contextual patterns are far more reliable than a bare semver, because a packed
// binary contains dozens of unrelated dependency versions.
var contextual = []*regexp.Regexp{
	regexp.MustCompile(`(?i)grok[-_ ]?(?:build|cli)?[/ v]{1,3}(\d+\.\d+\.\d+)`),
	regexp.MustCompile(`(?i)"version"\s*:\s*"(\d+\.\d+\.\d+)"`),
}

// fromBinaryStrings mines printable ASCII runs out of a binary. This is the
// weakest source by far -- every dependency's version string is in there too --
// so it is always labeled low confidence and is never enough on its own to say
// anything reassuring.
func fromBinaryStrings(ctx context.Context, path string) []model.VersionEvidence {
	f, err := hostfs.OpenRead(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	found := map[string]bool{}
	r := bufio.NewReaderSize(f, 256<<10)
	var run []byte

	flush := func() {
		if len(run) >= 6 {
			s := string(run)
			for _, re := range contextual {
				for _, m := range re.FindAllStringSubmatch(s, -1) {
					if grokver.Plausible(m[1]) {
						found[m[1]] = true
					}
				}
			}
		}
		run = run[:0]
	}

	for {
		if ctx.Err() != nil {
			break
		}
		c, err := r.ReadByte()
		if err != nil {
			flush()
			break
		}
		if c >= 0x20 && c < 0x7f {
			if len(run) < 4096 {
				run = append(run, c)
			}
			continue
		}
		flush()
	}

	out := make([]model.VersionEvidence, 0, len(found))
	for v := range found {
		out = append(out, model.VersionEvidence{
			Version: v, Source: "binary-strings", Confidence: "low",
			Class: grokver.Class(v), Path: path,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

func dedupe(in []model.VersionEvidence) []model.VersionEvidence {
	seen := map[string]bool{}
	var out []model.VersionEvidence
	for _, v := range in {
		k := v.Version + "|" + v.Source + "|" + v.Path
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence // high before low
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func findings(vs []model.VersionEvidence) []model.Finding {
	var confirmed, reported []model.VersionEvidence
	for _, v := range vs {
		// Low-confidence binary strings never drive a finding on their own: a semver
		// scraped out of a bundle is as likely to belong to a dependency as to grok.
		if v.Confidence == "low" {
			continue
		}
		switch v.Class {
		case model.VersionConfirmedAffected:
			confirmed = append(confirmed, v)
		case model.VersionReportedAffected:
			reported = append(reported, v)
		}
	}

	var out []model.Finding
	if len(confirmed) > 0 {
		out = append(out, model.Finding{
			ID:       "version.confirmed_affected",
			Detector: "version",
			Severity: model.SevHigh,
			Tags:     []string{model.TagInstall},
			Title:    "Grok " + grokver.ConfirmedAffected + " is installed -- the version publicly reproduced uploading whole repositories",
			Detail: "This is the exact version for which whole-repository upload to " + scan.BucketURL() + " was " +
				"independently reproduced, including full git history and files deleted from the checkout.",
			Remediation: "Remove it, and set " + scan.MarkerFlag + " = true under [harness] until you do.",
			Evidence:    evidenceOf(confirmed),
		})
	}
	if len(reported) > 0 {
		out = append(out, model.Finding{
			ID:       "version.reported_affected",
			Detector: "version",
			Severity: model.SevMedium,
			Tags:     []string{model.TagInstall},
			Title:    fmt.Sprintf("Grok %s is in the range reported to still carry the collector (through %s)", reported[0].Version, grokver.ReportedAffectedMax),
			Detail: "Public reporting states the background collector was still present through " + grokver.ReportedAffectedMax +
				". That is reported, not independently verified by this tool.",
			Evidence: evidenceOf(reported),
		})
	}
	return out
}

func evidenceOf(vs []model.VersionEvidence) []model.Evidence {
	out := make([]model.Evidence, 0, len(vs))
	for _, v := range vs {
		p := v.Path
		if p == "" {
			p = v.Source
		}
		out = append(out, model.Evidence{Path: p, Locator: v.Version, Note: "source: " + v.Source})
	}
	return out
}
