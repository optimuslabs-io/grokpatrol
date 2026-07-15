package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// A degraded scan that found nothing grok-related is the case in the field report
// that motivated this: five "no grok" step lines followed by a verdict that retreated
// to "no indicators were found". The headline must answer, in the same plain words the
// CLEAN verdict uses, the question the step lines already answered -- was grok here?
func TestIndeterminateSaysGrokAbsentPlainly(t *testing.T) {
	rep := &model.Report{
		Verdict:     model.VerdictIndeterminate,
		Degraded:    true,
		GrokPresent: false,
	}
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	if !strings.Contains(out, "No Grok Build artifacts were found on this machine") {
		t.Errorf("INDETERMINATE + grok absent must state grok's absence plainly; got:\n%s", out)
	}
	if strings.Contains(out, "No indicators were found") {
		t.Errorf("the vague old headline must not survive when grok is absent; got:\n%s", out)
	}
}

// INDETERMINATE is ALSO reachable with grok present-but-mitigated plus a material read
// error. Telling that host "no Grok Build artifacts were found" is a false negative --
// the one failure mode this whole tool is built to avoid. The absence wording must be
// gated on grok actually being absent.
func TestIndeterminateDoesNotDenyGrokWhenPresent(t *testing.T) {
	rep := &model.Report{
		Verdict:     model.VerdictIndeterminate,
		Degraded:    true,
		GrokPresent: true,
	}
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	if strings.Contains(out, "No Grok Build artifacts were found") {
		t.Errorf("must not report grok absent on a host where it is present; got:\n%s", out)
	}
	if !strings.Contains(out, "not a clean bill of health") {
		t.Errorf("the degraded caveat must still print; got:\n%s", out)
	}
}
