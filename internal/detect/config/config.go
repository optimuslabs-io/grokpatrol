// Package config checks whether the upload mitigations are actually set.
//
// There are TWO of them, not one:
//
//	[telemetry]
//	trace_upload = false
//
//	[harness]
//	disable_codebase_upload = true
//
// Both are required. A host with only disable_codebase_upload set has stopped the
// whole-repository archive upload but is still sending session traces, so this
// detector evaluates each independently and treats "partially mitigated" as
// EXPOSED. Checking only the flag the headlines mentioned would tell such a host
// it was safe.
//
// The parser is a hand-rolled TOML line scanner rather than a library: pulling a
// five-thousand-line third-party parser into a tool whose entire trust story is
// "zero dependencies, read the source" -- to read two booleans -- is a bad trade.
//
// It FAILS CLOSED. A naive scanner's failure mode is a false MITIGATED: it sees
// `true` in a comment or inside a multi-line string and declares the host safe.
// That is the one output this tool must never produce, so a key counts only when
// it is positively parsed, in the right table, with the exact expected literal.
package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/optimuslabs/grokpatrol/internal/engine"
	"github.com/optimuslabs/grokpatrol/internal/hostfs"
	"github.com/optimuslabs/grokpatrol/internal/model"
	"github.com/optimuslabs/grokpatrol/internal/scan"
)

// Mitigation is one config setting that must hold for uploads to be blocked.
type Mitigation struct {
	Table string
	Key   string
	Want  string // the exact literal required: "true" or "false"
	What  string // what it stops, in plain language
}

// MitigationKey is sourced from scan rather than written as a literal here:
// grokpatrol searches binaries for this exact string, so a plain copy of it would
// sit in grokpatrol's own .rodata and the tool would detect itself as a Grok
// install. See internal/scan/markers.go -- this is not hypothetical, it happened.
var MitigationKey = scan.MarkerFlag

const (
	MitigationTable = "harness"
	TraceTable      = "telemetry"
	TraceKey        = "trace_upload"
	maxConfigBytes  = 1 << 20
)

// Mitigations returns the full set. Both must hold for a host to be mitigated.
func Mitigations() []Mitigation {
	return []Mitigation{
		{Table: MitigationTable, Key: MitigationKey, Want: "true", What: "whole-repository archive upload"},
		{Table: TraceTable, Key: TraceKey, Want: "false", What: "session trace upload"},
	}
}

type Detector struct{}

func New() *Detector           { return &Detector{} }
func (*Detector) Name() string { return "config" }

// Describe names BOTH mitigations, on purpose. Public reporting fixated on one
// flag, and a host with only that one set is still uploading session traces. The
// progress line is where a reader learns there are two things to check -- which is
// the whole point of the detector.
func (*Detector) Describe() string {
	keys := make([]string, 0, 2)
	for _, m := range Mitigations() {
		keys = append(keys, m.Table+"."+m.Key)
	}
	return "checking config.toml for BOTH upload mitigations: " + strings.Join(keys, " and ")
}

// summarize reports mitigation state. "Partially mitigated" is named as such and
// never rounded up to mitigated: a host with one of the two set has stopped the
// repository archives and is still shipping session traces.
func summarize(states []state) string {
	for _, st := range states {
		switch {
		case st.missing:
			return "no config.toml: NEITHER mitigation is set"
		case st.uncertain:
			return "config.toml could not be confirmed -- treated as unmitigated"
		}
		set := 0
		for _, m := range Mitigations() {
			if st.Satisfied(m) {
				set++
			}
		}
		switch {
		case set == len(Mitigations()):
			return "both mitigations set"
		case set == 0:
			return "NEITHER mitigation set: uploads are not blocked"
		default:
			return fmt.Sprintf("only %d of %d mitigations set -- partially mitigated is NOT mitigated", set, len(Mitigations()))
		}
	}
	return "no config.toml found"
}

func (d *Detector) Run(_ context.Context, env *engine.Env) (engine.Result, error) {
	var res engine.Result

	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}

	// Only a real install counts. A text file that merely mentions the bucket name --
	// notes, an IoC list, another scanner -- must not make a clean host report EXPOSED.
	grokPresent := len(env.Discovered.Installs()) > 0 || len(env.Discovered.UploadQueues) > 0
	for _, h := range homes {
		if _, err := os.Stat(h); err == nil {
			grokPresent = true
		}
	}

	var states []state
	for _, h := range homes {
		p := filepath.Join(h, "config.toml")
		b, err := hostfs.ReadFileCapped(p, maxConfigBytes)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				states = append(states, state{path: p, missing: true})
				continue
			}
			res.Errors = append(res.Errors, model.ScanError{
				Detector: "config", Kind: "permission", Path: p, Message: err.Error(), Material: true,
			})
			states = append(states, state{path: p, uncertain: true})
			continue
		}
		st := parse(string(b))
		st.path = p
		states = append(states, st)
	}

	// auth.json: existence is noted, and the file is never opened. There is no code
	// path in grokpatrol that reads it.
	for _, h := range homes {
		auth := filepath.Join(h, "auth.json")
		if fi, err := os.Lstat(auth); err == nil {
			res.Findings = append(res.Findings, model.Finding{
				ID:       "config.auth_present",
				Detector: "config",
				Severity: model.SevInfo,
				Tags:     []string{model.TagConfig},
				Title:    "A cached xAI credential is present",
				Detail:   "grokpatrol did not read this file. It only checked that it exists.",
				Remediation: "If you are decommissioning Grok, revoke this token in the xAI console -- deleting the " +
					"file locally does not revoke it.",
				Evidence: []model.Evidence{{Path: auth, SizeBytes: fi.Size(), Note: "not read"}},
			})
		}
	}

	if !grokPresent {
		res.Summary = "no grok install, so no config to check"
		return res, nil // no grok on this host: the absence of its config is not a finding
	}

	res.Findings = append(res.Findings, configFindings(states)...)
	res.Summary = summarize(states)
	res.Limitations = append(res.Limitations,
		"The Grok config keys were recovered from public reporting and a screenshot, not from vendor documentation. "+
			"Other upload-related options may exist; every key found under ["+MitigationTable+"] and ["+TraceTable+"] is "+
			"listed in the report, so an unrecognized one is visible rather than silently ignored.")
	return res, nil
}
