package engine

import (
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// verdict() is the whole point of the collection-vs-upload distinction, and it is
// unexported, so it needs a white-box test in this package. Without it the rule can
// be reverted from IsUpload() to IsExfil() and the rest of the suite stays green:
// the end-to-end fixture carries a completion event (so it is COMPROMISED under
// either rule), and the detector-level tests assert finding tags, never a composed
// verdict. This is the one test that fails if the bar slips back to collection.
func TestVerdictSeparatesUploadFromCollection(t *testing.T) {
	finding := func(sev model.Severity, tags ...string) model.Finding {
		return model.Finding{Severity: sev, Tags: tags}
	}
	cases := []struct {
		name     string
		findings []model.Finding
		degraded bool
		want     model.Verdict
	}{
		{
			// THE REVERSAL GUARD. A high-severity collection finding (an enqueued or
			// staged archive) is exfil but not upload: it proves exposure, NOT that the
			// bytes left the machine. It must stop at EXPOSED. If this returns COMPROMISED,
			// verdict() has been rewired to promote on IsExfil() again.
			name:     "high exfil without upload is EXPOSED, not COMPROMISED",
			findings: []model.Finding{finding(model.SevHigh, model.TagExfil)},
			want:     model.VerdictExposed,
		},
		{
			name:     "high upload is COMPROMISED",
			findings: []model.Finding{finding(model.SevCritical, model.TagExfil, model.TagUpload)},
			want:     model.VerdictCompromised,
		},
		{
			// An upload tag below SevHigh must not promote: the gate is (SevHigh AND upload),
			// so a stray low-severity upload-tagged finding still only reaches EXPOSED.
			name:     "medium upload does not reach COMPROMISED",
			findings: []model.Finding{finding(model.SevMedium, model.TagUpload)},
			want:     model.VerdictExposed,
		},
		{
			name:     "medium exposure is EXPOSED",
			findings: []model.Finding{finding(model.SevMedium, model.TagConfig)},
			want:     model.VerdictExposed,
		},
		{
			// COMPROMISED outranks a degraded scan: proof of upload is not softened by an
			// unreadable corner of the disk.
			name:     "upload wins over degraded",
			findings: []model.Finding{finding(model.SevHigh, model.TagUpload)},
			degraded: true,
			want:     model.VerdictCompromised,
		},
		{
			name:     "degraded with only low findings is INDETERMINATE",
			findings: []model.Finding{finding(model.SevLow, model.TagInstall)},
			degraded: true,
			want:     model.VerdictIndeterminate,
		},
		{
			name: "nothing material is CLEAN",
			want: model.VerdictClean,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &model.Report{Findings: tc.findings, Degraded: tc.degraded}
			if got := verdict(rep); got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}
