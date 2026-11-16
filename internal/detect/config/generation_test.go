package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// host is a fake machine: a grok home and an /etc/grok, both under a temp dir.
type host struct {
	home, etc string
	env       map[string]string
}

func newHost(t *testing.T) *host {
	t.Helper()
	root := t.TempDir()
	h := &host{home: filepath.Join(root, ".grok"), etc: filepath.Join(root, "etc", "grok"), env: map[string]string{}}
	for _, d := range []string{h.home, h.etc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := systemDir
	systemDir = h.etc
	t.Cleanup(func() { systemDir = old })
	return h
}

func (h *host) write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// version records the installed Grok version the way 1.x does.
func (h *host) version(t *testing.T, v string) {
	h.write(t, h.home, "version.json", `{"version":"`+v+`","stable_version":"`+v+`"}`)
}

func (h *host) envp() *engine.Env {
	return &engine.Env{Home: filepath.Dir(h.home), GrokHome: h.home, Getenv: envOf(h.env)}
}

func (h *host) run(t *testing.T) engine.Result {
	t.Helper()
	res, err := New().Run(context.Background(), h.envp())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ids(res engine.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.ID)
	}
	return out
}

func notSetKeys(res engine.Result) []string {
	var out []string
	for _, f := range res.Findings {
		if f.ID == "config.not_mitigated" {
			out = append(out, f.Evidence[0].Locator)
		}
	}
	return out
}

// THE regression this change exists for. Grok 1.x documents only
// disable_workspace_teleport; a 1.x host whose config sets only the 0.2.x key has not
// set the switch its own documentation names, and must never read MITIGATED.
func TestModernHostWithOnlyLegacyKeyIsNotMitigated(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", legacyConfig)

	res := h.run(t)
	if hasID(res.Findings, "config.mitigated") {
		t.Fatal("a Grok 1.x host with only " + MitigationKey + " set was reported MITIGATED")
	}
	if got := notSetKeys(res); len(got) != 1 || got[0] != MitigationTable+"."+TeleportKey {
		t.Errorf("not-set keys = %v, want only the 1.x kill switch", got)
	}
}

// The 1.0.77 binary still carries the 0.2.x key beside a .tar.gz upload path, so a
// 1.x host needs both switches. The documented one alone is not enough.
func TestModernHostNeedsBothKillSwitches(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", modernConfig)

	res := h.run(t)
	if hasID(res.Findings, "config.mitigated") {
		t.Fatal("a 1.x host without " + MitigationKey + " was reported MITIGATED")
	}
	if got := notSetKeys(res); len(got) != 1 || got[0] != MitigationTable+"."+MitigationKey {
		t.Errorf("not-set keys = %v, want only the 0.2.x kill switch", got)
	}
	if hasID(res.Findings, "config.unparseable") {
		t.Error("[[marketplace.sources]] made a stock 1.x config unparseable")
	}
}

func TestModernHostWithBothSwitchesIsMitigated(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", bothConfig)

	res := h.run(t)
	if !hasID(res.Findings, "config.mitigated") {
		t.Fatalf("a 1.x host with every required setting was not MITIGATED: %v", ids(res))
	}
}

// A host known to run only 0.2.x keeps the original two-setting mitigation: that
// build does not know the 1.x key, so demanding it would be noise.
func TestLegacyHostKeepsTheLegacyMitigation(t *testing.T) {
	h := newHost(t)
	h.version(t, "0.2.93")
	h.write(t, h.home, "config.toml", legacyConfig)

	res := h.run(t)
	if !hasID(res.Findings, "config.mitigated") {
		t.Fatalf("a 0.2.93 host with the 0.2.x mitigation was not MITIGATED: %v", ids(res))
	}
}

// The 1.x key does nothing on 0.2.x, so a 0.2.x host with only it is exposed.
func TestLegacyHostWithOnlyModernKeyIsNotMitigated(t *testing.T) {
	h := newHost(t)
	h.version(t, "0.2.93")
	h.write(t, h.home, "config.toml", "[telemetry]\ntrace_upload = false\n[harness]\ndisable_workspace_teleport = true\n")

	if res := h.run(t); hasID(res.Findings, "config.mitigated") {
		t.Fatal("a 0.2.x host with only the 1.x key was reported MITIGATED")
	}
}

// No version evidence is not "probably old": the full set is required.
func TestUnknownVersionRequiresTheFullSet(t *testing.T) {
	h := newHost(t)
	h.write(t, h.home, "config.toml", legacyConfig)

	res := h.run(t)
	if hasID(res.Findings, "config.mitigated") {
		t.Fatal("a host of unknown version with only the 0.2.x settings was reported MITIGATED")
	}
}

// A leftover 1.x download beside a 0.2.x manifest means 1.x has been on the machine.
func TestAnyModernVersionRequiresTheFullSet(t *testing.T) {
	h := newHost(t)
	h.version(t, "0.2.93")
	if err := os.MkdirAll(filepath.Join(h.home, "downloads"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.write(t, filepath.Join(h.home, "downloads"), "grok-1.0.77-macos-aarch64", "x")
	h.write(t, h.home, "config.toml", legacyConfig)

	if res := h.run(t); hasID(res.Findings, "config.mitigated") {
		t.Fatal("a host with a 1.x download was judged against the 0.2.x set alone")
	}
}

func TestLegacyOnly(t *testing.T) {
	ev := func(v, conf string) model.VersionEvidence { return model.VersionEvidence{Version: v, Confidence: conf} }
	cases := []struct {
		name string
		vs   []model.VersionEvidence
		want bool
	}{
		{"no evidence", nil, false},
		{"analysed 0.2.x", []model.VersionEvidence{ev("0.2.93", "high")}, true},
		{"0.2.x above the analysed range", []model.VersionEvidence{ev("0.2.111", "medium")}, false},
		{"1.x", []model.VersionEvidence{ev("1.0.77", "high")}, false},
		{"mixed", []model.VersionEvidence{ev("0.2.93", "high"), ev("1.0.77", "medium")}, false},
		{"low confidence ignored", []model.VersionEvidence{ev("0.2.93", "high"), ev("1.0.77", "low")}, true},
		{"only low confidence", []model.VersionEvidence{ev("0.2.93", "low")}, false},
	}
	for _, c := range cases {
		if got := legacyOnly(c.vs); got != c.want {
			t.Errorf("%s: legacyOnly = %v, want %v", c.name, got, c.want)
		}
	}
}

// requirements.toml pins beat config.toml: a pinned mitigation holds even when the
// user's file turns it off.
func TestRequirementsPinBeatsUserConfig(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", strings.Replace(bothConfig, "trace_upload = false", "trace_upload = true", 1))
	h.write(t, h.etc, "requirements.toml", "[telemetry]\ntrace_upload = false\n")

	res := h.run(t)
	if !hasID(res.Findings, "config.mitigated") {
		t.Fatalf("a requirements pin did not win over config.toml: %v", ids(res))
	}
}

// ...and the dangerous direction: a pin that turns a mitigation OFF wins too.
func TestRequirementsPinCanBreakTheMitigation(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", bothConfig)
	h.write(t, h.home, "requirements.toml", "[harness]\ndisable_workspace_teleport = false\n")

	res := h.run(t)
	if hasID(res.Findings, "config.mitigated") {
		t.Fatal("a requirements pin turning the kill switch off was ignored")
	}
	if !hasID(res.Findings, "config.explicitly_disabled") {
		t.Errorf("want config.explicitly_disabled, got %v", ids(res))
	}
}

// managed_config.toml is a fleet DEFAULT: the user's own file overrides it.
func TestUserConfigBeatsManagedDefault(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.etc, "managed_config.toml", bothConfig)
	h.write(t, h.home, "config.toml", "[telemetry]\ntrace_upload = true\n")

	res := h.run(t)
	if hasID(res.Findings, "config.mitigated") {
		t.Fatal("a fleet default beat the user's own config.toml")
	}
	if !hasID(res.Findings, "config.explicitly_disabled") {
		t.Errorf("want config.explicitly_disabled, got %v", ids(res))
	}
}

// With no config.toml at all, a fleet default still counts: the host is not "absent".
func TestManagedDefaultAloneCounts(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "managed_config.toml", bothConfig)

	res := h.run(t)
	if hasID(res.Findings, "config.absent") || !hasID(res.Findings, "config.mitigated") {
		t.Fatalf("managed_config.toml was not read: %v", ids(res))
	}
}

func TestUnparseableLayerFailsClosed(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", bothConfig)
	h.write(t, h.etc, "requirements.toml", "[harness]\ndisable_workspace_teleport = \"\"\"\n")

	res := h.run(t)
	if hasID(res.Findings, "config.mitigated") || !hasID(res.Findings, "config.unparseable") {
		t.Fatalf("an unreadable requirements.toml did not fail closed: %v", ids(res))
	}
}

// An environment variable beats every file but a pin. grokpatrol cannot see the
// environment Grok is launched with, so the mitigation is unverifiable.
func TestTraceUploadEnvMakesMitigationUnverifiable(t *testing.T) {
	for _, name := range []string{"GROK_TELEMETRY_TRACE_UPLOAD", "GROK_TELEMETRY_ENABLED"} {
		h := newHost(t)
		h.version(t, "1.0.77")
		h.write(t, h.home, "config.toml", bothConfig)
		h.env[name] = "0" // even a value that looks reassuring is not interpreted

		res := h.run(t)
		if hasID(res.Findings, "config.mitigated") {
			t.Errorf("%s set: still reported MITIGATED", name)
		}
		if !hasID(res.Findings, "config.env_override") {
			t.Errorf("%s set: want config.env_override, got %v", name, ids(res))
		}
		for _, f := range res.Findings {
			for _, e := range f.Evidence {
				if strings.Contains(e.Locator+e.Note+f.Title+f.Detail, "=0") {
					t.Errorf("an environment value leaked into the report: %+v", f)
				}
			}
		}
	}
}

func TestPinnedTraceUploadIgnoresEnv(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", bothConfig)
	h.write(t, h.home, "requirements.toml", "[telemetry]\ntrace_upload = false\n")
	h.env["GROK_TELEMETRY_TRACE_UPLOAD"] = "1"

	if res := h.run(t); !hasID(res.Findings, "config.mitigated") {
		t.Fatalf("a requirements pin should hold against the environment: %v", ids(res))
	}
}

// Variables that can only turn things off, or the overlay that cannot reach the
// required settings, are reported without changing the verdict.
func TestNotedEnvDoesNotChangeTheVerdict(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", bothConfig)
	h.env["DISABLE_TELEMETRY"] = "1"
	h.env["GROK_CONFIG"] = `{"features":{"telemetry":true}}`

	res := h.run(t)
	if !hasID(res.Findings, "config.mitigated") || !hasID(res.Findings, "config.env_set") {
		t.Fatalf("want mitigated plus config.env_set, got %v", ids(res))
	}
	for _, f := range res.Findings {
		if f.ID == "config.env_set" && f.Severity != model.SevInfo {
			t.Errorf("config.env_set severity = %v, want info", f.Severity)
		}
	}
}

func TestUploadDestinationsAreReported(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", bothConfig+
		"\n[endpoints]\ntrace_upload_bucket = \"gs://acme-traces/team-a\"\n"+
		"trace_upload_url = \"https://user:pw@proxy.example.invalid/up?token=abc\"\n")
	h.env["GROK_TELEMETRY_GCS_BUCKET"] = "acme-override"

	res := h.run(t)
	var file, env *model.Finding
	for i, f := range res.Findings {
		if f.ID == "config.upload_destination" {
			if f.Evidence[0].Path == "" {
				env = &res.Findings[i]
			} else {
				file = &res.Findings[i]
			}
		}
	}
	if file == nil || env == nil {
		t.Fatalf("want a file and an env upload_destination finding, got %v", ids(res))
	}
	var locs []string
	for _, e := range file.Evidence {
		locs = append(locs, e.Locator)
	}
	joined := strings.Join(locs, " ")
	if !strings.Contains(joined, "gs://acme-traces/team-a") || !strings.Contains(joined, "https://proxy.example.invalid/up") {
		t.Errorf("destinations = %v", locs)
	}
	if strings.Contains(joined, "pw") || strings.Contains(joined, "token") {
		t.Errorf("a credential in a destination URL reached the report: %v", locs)
	}

	got := UploadBuckets(h.envp())
	want := []string{"gs://acme-override/", "gs://acme-traces/"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("UploadBuckets = %v, want %v", got, want)
	}
}

func TestBucketMarker(t *testing.T) {
	cases := map[string]string{
		"gs://acme-traces/team-a": "gs://acme-traces/",
		"s3://acme/":              "s3://acme/",
		"S3://acme":               "s3://acme/",
		"https://example.invalid": "",
		"gs://":                   "",
	}
	for in, want := range cases {
		if got := bucketMarker(in); got != want {
			t.Errorf("bucketMarker(%q) = %q, want %q", in, got, want)
		}
	}
}

// Recommended settings are advice. Missing them never costs a host its MITIGATED.
func TestRecommendedSettingsAreAdviceOnly(t *testing.T) {
	h := newHost(t)
	h.version(t, "1.0.77")
	h.write(t, h.home, "config.toml", bothConfig)

	res := h.run(t)
	if !hasID(res.Findings, "config.mitigated") || !hasID(res.Findings, "config.recommended_unset") {
		t.Fatalf("want mitigated plus recommended_unset, got %v", ids(res))
	}

	h.write(t, h.home, "config.toml", bothConfig+"\n[features]\ntelemetry = \"off\"\n[diagnostics]\nerror_reporting = false\n")
	res = h.run(t)
	if !hasID(res.Findings, "config.mitigated") || hasID(res.Findings, "config.recommended_unset") {
		t.Fatalf("telemetry = \"off\" should satisfy the recommendation without unsettling the parse: %v", ids(res))
	}
}

func TestRemediationMarksRecommendedAsOptional(t *testing.T) {
	txt := remediationText(requiredFor(false))
	req, rec, _ := strings.Cut(txt, "Recommended, not required")
	for _, m := range Mitigations() {
		if !strings.Contains(req, m.Key+" = "+m.Want) {
			t.Errorf("required section is missing %s", m.Key)
		}
	}
	for _, m := range Recommended() {
		if !strings.Contains(rec, m.Key+" = "+m.Want) || strings.Contains(req, "["+m.Table+"]") {
			t.Errorf("%s.%s should appear only under the recommended section", m.Table, m.Key)
		}
	}
}

func TestParserTablesAndPatches(t *testing.T) {
	cases := []struct {
		name          string
		src           string
		wantUncertain bool
	}{
		{"array of tables elsewhere is fine", "[[marketplace.sources]]\nname = \"x\"\n", false},
		{"experiment patching telemetry", "[[experiments]]\nid = \"a\"\n[experiments.telemetry]\ntrace_upload = true\n", true},
		{"experiment dotted key", "[[experiments]]\ntelemetry.trace_upload = true\n", true},
		{"experiment inline table", "[[experiments]]\nharness = { disable_workspace_teleport = false }\n", true},
		{"campaign patching harness", "[[campaigns.harness]]\nx = 1\n", true},
		{"experiment patching cli", "[[experiments]]\nid = \"a\"\n[experiments.cli]\nchannel = \"alpha\"\n", false},
		{"inline required table", "harness = { disable_codebase_upload = true }\n", true},
		{"recommended key as string", "[features]\ntelemetry = \"off\"\n", false},
	}
	for _, c := range cases {
		if got := parse(c.src).uncertain; got != c.wantUncertain {
			t.Errorf("%s: uncertain = %v, want %v", c.name, got, c.wantUncertain)
		}
	}

	// Keys inside an array element never count as the real table's.
	st := parse("[[telemetry_sinks]]\ntrace_upload = false\n")
	if st.Satisfied(mitigation(t, TraceKey)) {
		t.Error("a key inside [[telemetry_sinks]] was read as [telemetry]")
	}
}
