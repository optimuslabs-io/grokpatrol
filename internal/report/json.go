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
	if rep.Apps == nil {
		rep.Apps = []model.PublishedApp{}
	}
	if rep.Versions == nil {
		rep.Versions = []model.VersionEvidence{}
	}
	return enc.Encode(rep)
}

// appsRecord is the --apps-only record. It is its own type, not a filtered
// Report, so a field added to Report later cannot leak into it: it carries the
// grok.me apps and the caveats about finding them, and nothing about repositories,
// secret locations, versions or the host. It exists for agents (the grokpatrol-apps
// skill), whose context goes to a model provider.
type appsRecord struct {
	Schema      string               `json:"schema"`
	Tool        model.ToolInfo       `json:"tool"`
	Options     model.Options        `json:"options"`
	Verdict     model.Verdict        `json:"verdict"`
	Apps        []model.PublishedApp `json:"published_apps"`
	Errors      []model.ScanError    `json:"errors"`
	Limitations []string             `json:"limitations"`
}

// appDetectors are the detectors whose errors concern apps or public sources.
var appDetectors = map[string]bool{"apps": true, "discover": true, "app-hosts": true}

// AppsJSON writes the --apps-only record.
func AppsJSON(w io.Writer, rep *model.Report) error {
	out := appsRecord{
		Schema: model.SchemaVersion + "+apps", Tool: rep.Tool, Options: rep.Options, Verdict: rep.Verdict,
		Apps: rep.Apps, Errors: []model.ScanError{}, Limitations: []string{},
	}
	if out.Apps == nil {
		out.Apps = []model.PublishedApp{}
	}
	for _, e := range rep.Errors {
		if appDetectors[e.Detector] {
			out.Errors = append(out.Errors, e)
		}
	}
	// Selected by origin (AppLimitations), never by matching text: a limitation from
	// the secrets detector starts with a repository path, which may contain any word.
	out.Limitations = append(out.Limitations, rep.AppLimitations...)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
