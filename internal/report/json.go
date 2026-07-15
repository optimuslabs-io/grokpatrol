package report

import (
	"encoding/json"
	"io"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// JSON writes the machine-readable report. Nothing but JSON goes to this writer:
// every diagnostic in the tool is written to stderr, so `grokpatrol --json | jq`
// always works.
func JSON(w io.Writer, rep *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	// Empty slices rather than nulls: a consumer should be able to range over
	// .findings without a nil check.
	if rep.Findings == nil {
		rep.Findings = []model.Finding{}
	}
	if rep.Repos == nil {
		rep.Repos = []model.RepoStatus{}
	}
	if rep.Errors == nil {
		rep.Errors = []model.ScanError{}
	}
	if rep.Versions == nil {
		rep.Versions = []model.VersionEvidence{}
	}
	return enc.Encode(rep)
}
