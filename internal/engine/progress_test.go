package engine_test

import (
	"context"
	"strings"
	"testing"
	"time"

	cfgdet "github.com/optimuslabs-io/grokpatrol/internal/detect/config"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/deepscan"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/logs"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/queue"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/secrets"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/version"
	"github.com/optimuslabs-io/grokpatrol/internal/engine"
)

func allDetectors() []engine.Detector {
	return []engine.Detector{
		deepscan.New(), logs.New(), queue.New(), cfgdet.New(), version.New(), secrets.New(),
	}
}

// Every detector must say what it looks for. A verdict is worth exactly as much as
// the list of things that were checked to reach it, and that list should not be
// something a user has to read the source to discover -- so a detector that stays
// silent about its own coverage is a hole in the tool's central claim.
func TestEveryDetectorDescribesWhatItChecks(t *testing.T) {
	for _, d := range allDetectors() {
		desc, ok := d.(engine.Describer)
		if !ok {
			t.Errorf("%s does not implement Describer: the progress monitor cannot say what it checks", d.Name())
			continue
		}
		if strings.TrimSpace(desc.Describe()) == "" {
			t.Errorf("%s describes itself as an empty string", d.Name())
		}
	}
}

// A detector that finds nothing must SAY so. A blank progress line is
// indistinguishable from a detector that panicked, and a crash that produces no
// findings reads exactly like a clean host -- the worst failure this tool can have.
func TestDetectorsSummarizeEvenWhenTheyFindNothing(t *testing.T) {
	env := &engine.Env{
		Home:          t.TempDir(),
		GrokHome:      t.TempDir() + "/.grok",
		ScanRoots:     []string{t.TempDir()},
		ConfineWalk:   true, // skip the host's system-bin dirs; the fixture is self-contained
		Concurrency:   2,
		MaxFileSize:   1 << 20,
		UseGit:        true,
		HistoryScope:  "head",
		MaxGitObjects: 1000,
		GitTimeout:    10 * time.Second,
	}

	for _, d := range allDetectors() {
		res, err := d.Run(context.Background(), env)
		if err != nil {
			t.Fatalf("%s: %v", d.Name(), err)
		}
		if strings.TrimSpace(res.Summary) == "" {
			t.Errorf("%s returned no summary on a clean host: the progress line would be blank, "+
				"which looks exactly like a detector that died", d.Name())
		}
	}
}

// The progress monitor exists partly because the filesystem walk cannot be skipped
// any more. --quick used to skip it, and then reported CLEAN with the same
// confidence as a scan that had actually looked at the disk.
func TestPlural(t *testing.T) {
	cases := map[string]string{
		engine.Plural(1, "archive"):     "1 archive",
		engine.Plural(2, "archive"):     "2 archives",
		engine.Plural(1, "repository"):  "1 repository",
		engine.Plural(3, "repository"):  "3 repositories",
		engine.Plural(0, "secret file"): "0 secret files",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
