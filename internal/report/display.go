package report

import (
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Display renders every host path in the report the way a person should read it:
// home-relative, so ~/work/payments-api rather than /Users/alan/work/payments-api.
// It is applied once, centrally, after every detector has run -- detectors record
// real paths, because that is what they opened.
//
// This walk is all that remains of the old --redact mode, which hashed repository
// paths and session ids so a report could be pasted into a vendor ticket. That
// mode is gone. grokpatrol's report is an incident document about YOUR machine and
// it stays on it; tokenizing the paths bought a sharing story nobody wanted and
// charged the reader the one thing the report exists to tell them -- which file,
// in which repository, to go and rotate. What survives is the display
// normalization, which had been riding along inside the redactor.
//
// Every path-bearing field in the report is listed here. A new one that is not
// added to this walk will print an absolute path in the middle of an otherwise
// home-relative report, which is how you will notice.
func Display(rep *model.Report, home string) {
	p := func(s string) string { return hostfs.Display(s, home) }

	rep.Host.Home = p(rep.Host.Home)
	rep.Host.GrokHome = p(rep.Host.GrokHome)
	for i := range rep.Host.ScannedRoots {
		rep.Host.ScannedRoots[i] = p(rep.Host.ScannedRoots[i])
	}

	for i := range rep.Findings {
		for j := range rep.Findings[i].Evidence {
			e := &rep.Findings[i].Evidence[j]
			e.Path = p(e.Path)
			e.Source = p(e.Source)
			e.PathEntry = p(e.PathEntry)
			// Locator is left verbatim on purpose: it carries gs:// destinations and git
			// blob ids, neither of which is a path on this filesystem.
		}
	}

	for i := range rep.Repos {
		repo := &rep.Repos[i]
		repo.RepoPath = p(repo.RepoPath)
		repo.LogFile = p(repo.LogFile)
		for j := range repo.Archives {
			repo.Archives[j].LogFile = p(repo.Archives[j].LogFile)
		}
		// SecretFiles[].Path is repo-relative already, and stays that way.
	}

	for i := range rep.Versions {
		rep.Versions[i].Path = p(rep.Versions[i].Path)
	}
	for i := range rep.Errors {
		rep.Errors[i].Path = p(rep.Errors[i].Path)
	}
}
