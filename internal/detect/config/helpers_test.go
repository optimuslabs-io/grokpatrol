package config

import (
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// The two config shapes the tool must judge, as each generation's users write them.
const (
	// legacyConfig is the 0.2.x mitigation as publicly reported.
	legacyConfig = "[telemetry]\ntrace_upload = false\n\n[harness]\ndisable_codebase_upload = true\n"
	// modernConfig is the 1.x mitigation as Grok 1.x documents it, in a stock-looking
	// file: [[marketplace.sources]] entries are what Grok 1.x writes by itself.
	modernConfig = "[cli]\nauto_update = true\n\n[harness]\ndisable_workspace_teleport = true\n\n" +
		"[telemetry]\ntrace_upload = false\n\n[features]\ntelemetry = false\n\n" +
		"[[marketplace.sources]]\nname = \"official\"\nurl = \"https://example.invalid/m.json\"\n\n" +
		"[[marketplace.sources]]\nname = \"team\"\nurl = \"https://example.invalid/t.json\"\n"
	// bothConfig sets both kill switches, as grokpatrol advises for 1.x.
	bothConfig = "[telemetry]\ntrace_upload = false\n\n[harness]\ndisable_workspace_teleport = true\n" +
		"disable_codebase_upload = true\n"
)

func noEnv(string) string { return "" }

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// homeOf builds a single-layer home from one config.toml body.
func homeOf(src string, legacy bool) homeState {
	st := parse(src)
	st.path = "/h/.grok/config.toml"
	return homeState{
		userPath:  st.path,
		layers:    []layer{{path: st.path, st: st}},
		required:  requiredFor(legacy),
		uncertain: st.uncertain,
	}
}

func mitigation(t *testing.T, key string) Mitigation {
	t.Helper()
	for _, m := range Mitigations() {
		if m.Key == key {
			return m
		}
	}
	t.Fatalf("no mitigation %q", key)
	return Mitigation{}
}

func hasID(fs []model.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}
