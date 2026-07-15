package engine

import (
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// grokFound is the gate behind Report.GrokPresent, which in turn decides whether the
// report may state grok's absence outright. Two failure modes matter: saying grok is
// absent when a mitigated install is sitting right there (a false negative, the exact
// failure this tool exists to prevent), and saying grok is present on a genuinely clean
// host (which would suppress the plain "no grok" wording the field report asked for).
func TestGrokFound(t *testing.T) {
	cases := []struct {
		name string
		rep  *model.Report
		env  *Env
		want bool
	}{
		{
			// The clean host from the field report: deepscan appended the configured home to
			// GrokHomes but nothing real was found. GrokHomes must NOT count as presence, or
			// every clean host reads as "grok present".
			name: "configured home only is absent",
			rep:  &model.Report{},
			env:  &Env{Discovered: Discovered{GrokHomes: []string{"/home/u/.grok"}}},
			want: false,
		},
		{
			// THE FALSE-NEGATIVE GUARD. Grok present but fully mitigated emits a SevInfo
			// config finding and nothing higher; with a material read error elsewhere the
			// verdict is INDETERMINATE. The report must not tell this host grok is absent.
			name: "mitigated install is present",
			rep:  &model.Report{Findings: []model.Finding{{ID: "config.mitigated", Detector: "config"}}},
			env:  &Env{},
			want: true,
		},
		{
			name: "config.absent finding is present",
			rep:  &model.Report{Findings: []model.Finding{{ID: "config.absent", Detector: "config"}}},
			env:  &Env{},
			want: true,
		},
		{
			name: "installed binary is present",
			rep:  &model.Report{},
			env:  &Env{Discovered: Discovered{Binaries: []BinaryHit{{Executable: true}}}},
			want: true,
		},
		{
			// A text file that merely mentions the bucket is not an install (IsInstall gates
			// on executable magic or bundle size), so it must not read as presence.
			name: "non-install binary hit is absent",
			rep:  &model.Report{},
			env:  &Env{Discovered: Discovered{Binaries: []BinaryHit{{SizeBytes: 10}}}},
			want: false,
		},
		{
			name: "upload queue is present",
			rep:  &model.Report{},
			env:  &Env{Discovered: Discovered{UploadQueues: []string{"/home/u/.grok/upload_queue"}}},
			want: true,
		},
		{
			name: "confident version evidence is present",
			rep:  &model.Report{Versions: []model.VersionEvidence{{Version: "0.2.93", Confidence: "high"}}},
			env:  &Env{},
			want: true,
		},
		{
			// A low-confidence semver is one scraped from a marker-carrying text file's
			// string table -- deepscan calls those "not a Grok install" and versionBanner
			// refuses to display them. A noisy-but-clean host (the user's exact environment)
			// whose only signal is one of these must still read as grok-absent.
			name: "low-confidence version alone is absent",
			rep:  &model.Report{Versions: []model.VersionEvidence{{Version: "0.2.93", Confidence: "low"}}},
			env:  &Env{},
			want: false,
		},
		{
			name: "implicated repo is present",
			rep:  &model.Report{Repos: []model.RepoStatus{{RepoPath: "/home/u/proj"}}},
			env:  &Env{},
			want: true,
		},
		{
			name: "empty report is absent",
			rep:  &model.Report{},
			env:  &Env{},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grokFound(tc.rep, tc.env); got != tc.want {
				t.Errorf("grokFound = %v, want %v", got, tc.want)
			}
		})
	}
}
