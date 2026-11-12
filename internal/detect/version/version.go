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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/grokver"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
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
	// Skip low confidence, exactly as findings() (a semver scraped from the bundle is
	// as likely a dependency's as grok's) and both report banners do. Without this the
	// stderr progress line would announce "0.2.93 -- CONFIRMED AFFECTED" off a single
	// low-confidence binary string while the finding and the banners correctly stay
	// silent -- the loudest claim in the tool, made on its weakest evidence.
	for _, v := range vs {
		if v.Confidence != "low" && v.Class == model.VersionConfirmedAffected {
			return v.Version + " -- CONFIRMED AFFECTED"
		}
	}
	for _, v := range vs {
		if v.Confidence != "low" && v.Class == model.VersionReportedAffected {
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
// version.json is where Grok 1.x keeps it ({"version", "stable_version", "checked_at"}).
var manifestNames = []string{"version", "VERSION", ".version", "version.json", "install.json", "manifest.json", "package.json"}

// downloadRe matches the self-updater's staged binaries, $GROK_HOME/downloads/
// grok-<version>-<os>-<arch>. The file is named by the updater rather than written by
// the build, and a download may be an old one never cleaned up or a new one not yet
// switched to, so this is medium confidence: it says the version was on this machine,
// not that it is the one that runs.
var downloadRe = regexp.MustCompile(`^grok-(\d+\.\d+\.\d+)-`)

const maxManifestBytes = 1 << 20

func (d *Detector) Run(ctx context.Context, env *engine.Env) (engine.Result, error) {
	var res engine.Result

	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}

	res.Versions = Passive(env)
	for _, b := range env.Discovered.Binaries {
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
	if newer := newerThanObserved(res.Versions); len(newer) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"Grok %s is newer than %s, the latest release grokpatrol was checked against. Its config keys, log event "+
				"names and upload_queue layout may have changed, so a mitigation, an upload event or a staged archive "+
				"in a form this tool does not know could be missed.", newer[0].Version, grokver.LatestObserved))
	}
	return res, nil
}

// Passive is every version source that costs no more than a few small reads: the
// manifests in each grok home, the updater's downloads, Homebrew's install path and a
// package.json beside a discovered binary. It leaves out the binary-string mining
// Run adds, which reads whole executables and is low confidence anyway.
//
// It is exported for the config detector, which runs alongside this one and needs
// to know which Grok generation it is judging: 1.x renamed the documented kill switch.
func Passive(env *engine.Env) []model.VersionEvidence {
	var out []model.VersionEvidence

	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}
	for _, h := range homes {
		for _, name := range manifestNames {
			out = append(out, fromManifest(filepath.Join(h, name))...)
		}
		out = append(out, fromDownloads(filepath.Join(h, "downloads"))...)
	}

	for _, b := range env.Discovered.Binaries {
		// Homebrew encodes the version in the install path: the path IS the manifest.
		if ev := fromCellarPath(b.Path); ev != nil {
			out = append(out, *ev)
		}
		dir := filepath.Dir(b.Path)
		for _, cand := range []string{dir, filepath.Dir(dir)} {
			out = append(out, fromManifest(filepath.Join(cand, "package.json"))...)
		}
	}
	return dedupe(out)
}

// fromDownloads reads versions out of the updater's staged binaries' NAMES. Nothing
// is opened: the directory listing is the evidence.
func fromDownloads(dir string) []model.VersionEvidence {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []model.VersionEvidence
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := downloadRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		out = append(out, model.VersionEvidence{
			Version: m[1], Source: "download:" + e.Name(), Confidence: "medium",
			Class: grokver.Class(m[1]), Path: filepath.Join(dir, e.Name()),
		})
	}
	return out
}

// newerThanObserved returns the evidence for versions above grokver.LatestObserved,
// newest first. Low confidence is skipped, as everywhere else: a semver scraped from
// a bundle is as likely a dependency's as grok's.
func newerThanObserved(vs []model.VersionEvidence) []model.VersionEvidence {
	var out []model.VersionEvidence
	for _, v := range vs {
		if v.Confidence != "low" && grokver.NewerThanObserved(v.Version) {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return grokver.Compare(out[i].Version, out[j].Version) > 0 })
	return out
}

// fromManifest returns the version a manifest records, or nothing.
//
// Grok 1.x's version.json carries two: "version", the installed build (high
// confidence), and "stable_version", the newest release the updater saw on its stable
// channel when it last checked. The second is NOT what is installed -- it is what the
// next update will install -- so it is kept, for the version inventory, at low
// confidence, which keeps it out of every finding and banner.
func fromManifest(path string) []model.VersionEvidence {
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
		var out []model.VersionEvidence
		v, _ := m["version"].(string)
		if grokver.Plausible(v) {
			out = append(out, model.VersionEvidence{
				Version: v, Source: "manifest:" + base, Confidence: "high",
				Class: grokver.Class(v), Path: path,
			})
		}
		if base == "version.json" {
			if sv, _ := m["stable_version"].(string); grokver.Plausible(sv) && sv != v {
				out = append(out, model.VersionEvidence{
					Version: sv, Source: "manifest:" + base + " (stable_version, not installed)", Confidence: "low",
					Class: grokver.Class(sv), Path: path,
				})
			}
		}
		return out
	}

	v := strings.TrimSpace(string(b))
	if !grokver.Plausible(v) {
		return nil
	}
	return []model.VersionEvidence{{
		Version: v, Source: "manifest:" + base, Confidence: "high",
		Class: grokver.Class(v), Path: path,
	}}
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
		if ci, cj := confidenceRank(out[i].Confidence), confidenceRank(out[j].Confidence); ci != cj {
			return ci > cj // high, then medium, then low
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func confidenceRank(c string) int {
	switch c {
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
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
			Remediation: "Remove it, and until you do set " + scan.MarkerFlag + " = true under [harness] and trace_upload = false under [telemetry].",
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
	if newer := newerThanObserved(vs); len(newer) > 0 {
		out = append(out, model.Finding{
			ID:       "version.newer_than_known",
			Detector: "version",
			// SevInfo and untagged: a newer build is not evidence of anything. It is a
			// statement about this tool's own coverage, and it must not move the verdict
			// in either direction.
			Severity: model.SevInfo,
			Title: fmt.Sprintf("Grok %s is newer than %s, the latest release grokpatrol was checked against",
				newer[0].Version, grokver.LatestObserved),
			Detail: "Grok's config keys, log event names and upload_queue layout were checked against " +
				grokver.LatestObserved + ". A newer build may have renamed any of them, and a mitigation or an upload " +
				"artifact in a form this tool does not know would not be recognised. Check for a newer grokpatrol.",
			Evidence: evidenceOf(newer),
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
