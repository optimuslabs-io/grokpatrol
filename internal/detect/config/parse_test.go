package config

import "testing"

// The scanner must confirm a mitigation ONLY when it positively parsed the key, in
// the right table, with the exact expected literal. Everything else fails closed.
//
// The dangerous direction is a FALSE MITIGATED -- telling a user they are protected
// because a `true` happened to appear in a comment or inside a string. Each
// "tricky" case below is an input a naive grep would get wrong in exactly that way.
func TestParseFailsClosed(t *testing.T) {
	harness := Mitigations()[0] // disable_codebase_upload = true
	trace := Mitigations()[1]   // trace_upload = false

	cases := []struct {
		name          string
		src           string
		wantHarness   bool
		wantTrace     bool
		wantUncertain bool
	}{
		{
			// The canonical config, exactly as documented in the screenshot.
			name:        "both mitigations set",
			src:         "[telemetry]\ntrace_upload = false\n\n[harness]\ndisable_codebase_upload = true\n",
			wantHarness: true, wantTrace: true,
		},
		{
			// The trap this detector exists to catch: everyone set the flag the headlines
			// named, and kept shipping session traces.
			name:        "only the famous flag set",
			src:         "[harness]\ndisable_codebase_upload = true\n",
			wantHarness: true, wantTrace: false,
		},
		{
			name:        "dotted top-level form",
			src:         "harness.disable_codebase_upload = true\ntelemetry.trace_upload = false\n",
			wantHarness: true, wantTrace: true,
		},
		{
			name:        "spacing and a trailing comment",
			src:         "[harness]\n  disable_codebase_upload=true   # belt and braces\n",
			wantHarness: true,
		},
		{
			name: "commented out",
			src:  "[harness]\n# disable_codebase_upload = true\n",
		},
		{
			// trace_upload's safe value is false, so `true` here means NOT mitigated.
			name: "trace_upload set to true is not a mitigation",
			src:  "[telemetry]\ntrace_upload = true\n",
		},
		{
			name: "right key, wrong table",
			src:  "[telemetry]\ndisable_codebase_upload = true\n",
		},
		{
			// The classic false-mitigated trap: the setting appears verbatim inside a
			// multi-line string. A line-based grep declares the host safe.
			name: "mitigation inside a multi-line string",
			src: "[harness]\nnotes = \"\"\"\nExample config:\n  disable_codebase_upload = true\n\"\"\"\n" +
				"model = \"grok-code-fast\"\n",
		},
		{
			name:          "string value rather than a boolean",
			src:           "[harness]\ndisable_codebase_upload = \"true\"\n",
			wantUncertain: true,
		},
		{
			name:          "array value",
			src:           "[harness]\ndisable_codebase_upload = [true]\n",
			wantUncertain: true,
		},
		{
			name:          "unterminated multi-line string",
			src:           "[harness]\nnotes = \"\"\"\ndisable_codebase_upload = true\n",
			wantUncertain: true,
		},
		{name: "empty file", src: ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := parse(c.src)
			if got := st.Satisfied(harness); got != c.wantHarness {
				t.Errorf("%s satisfied = %v, want %v -- a false MITIGATED tells a compromised user they are safe",
					harness.Key, got, c.wantHarness)
			}
			if got := st.Satisfied(trace); got != c.wantTrace {
				t.Errorf("%s satisfied = %v, want %v", trace.Key, got, c.wantTrace)
			}
			if c.wantUncertain && !st.uncertain {
				t.Error("uncertain = false, want true: the scanner should admit it could not confirm this construct")
			}
		})
	}
}

// Both mitigations are required, so a config with only one produces a finding for
// the other -- and never reports the host as mitigated.
func TestPartialMitigationIsNotMitigated(t *testing.T) {
	st := parse("[harness]\ndisable_codebase_upload = true\n")
	fs := mitigationFindings(st)

	for _, f := range fs {
		if f.ID == "config.mitigated" {
			t.Fatal("a host with only one of the two mitigations was reported as MITIGATED; " +
				"it is still uploading session traces")
		}
	}
	found := false
	for _, f := range fs {
		if f.ID == "config.not_mitigated" {
			found = true
		}
	}
	if !found {
		t.Error("no finding was raised for the missing trace_upload mitigation")
	}
}

func TestFullyMitigated(t *testing.T) {
	st := parse("[telemetry]\ntrace_upload = false\n\n[harness]\ndisable_codebase_upload = true\n")
	var mitigated bool
	for _, f := range mitigationFindings(st) {
		if f.ID == "config.mitigated" {
			mitigated = true
		}
		if f.ID == "config.not_mitigated" || f.ID == "config.explicitly_disabled" {
			t.Errorf("unexpected finding on a fully mitigated config: %s", f.ID)
		}
	}
	if !mitigated {
		t.Error("a config with both mitigations set was not reported as mitigated")
	}
}

// Unrecognized options under the mitigation tables are surfaced: the key list came
// from a screenshot, not from vendor docs, so there may be others.
func TestOtherKeysAreSurfaced(t *testing.T) {
	st := parse("[harness]\ndisable_codebase_upload = true\nsome_new_upload_flag = true\n[telemetry]\ntrace_upload = false\n")
	got := otherKeys(st)
	if len(got) != 1 || got[0] != "harness.some_new_upload_flag" {
		t.Errorf("otherKeys = %v, want the one unrecognized key", got)
	}
}

func TestStripCommentRespectsStrings(t *testing.T) {
	if got := stripComment(`shell = "#!/bin/sh"  # a real comment`); got != `shell = "#!/bin/sh"  ` {
		t.Errorf("stripComment truncated inside a string: %q", got)
	}
}
