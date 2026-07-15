package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// queueHome builds a fake ~/.grok/upload_queue holding n staged archives, each with
// a manifest naming the bucket. Fixtures are generated, never committed: a repo full
// of files carrying a live IoC string trips corporate EDR.
func queueHome(t *testing.T, n int) string {
	t.Helper()
	home := t.TempDir()
	for i := 0; i < n; i++ {
		dir := filepath.Join(home, ".grok", "upload_queue", fmt.Sprintf("turn_%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"before", "after"} {
			if err := os.WriteFile(filepath.Join(dir, phase+"_codebase.tar.gz"), []byte("archive-bytes"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		manifest, _ := json.Marshal(map[string]string{
			"destination": "gs://" + scan.MarkerBucket + "/sess/turn/after_codebase.tar.gz",
		})
		if err := os.WriteFile(filepath.Join(dir, "metadata.json"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func runQueue(t *testing.T, ctx context.Context, home string) engine.Result {
	t.Helper()
	env := &engine.Env{Home: home, GrokHome: filepath.Join(home, ".grok")}
	res, err := New().Run(ctx, env)
	if err != nil {
		t.Fatalf("Run returned a fatal error, which it never should: %v", err)
	}
	return res
}

func queuePresent(t *testing.T, res engine.Result) model.Finding {
	t.Helper()
	for _, f := range res.Findings {
		if f.ID == "queue.present" {
			return f
		}
	}
	t.Fatal("queue.present finding is missing")
	return model.Finding{}
}

// THE DANGEROUS ONE. The timeout that cuts a walk short is likeliest to fire on
// exactly the host whose queue is enormous -- so the case where the tool knows
// least is the case where the queue is probably fullest. Describing that as "present
// but empty ... nothing was ever queued" is the single most reassuring, and most
// wrong, sentence this tool could print.
func TestInterruptedScanNeverReportsAnEmptyQueue(t *testing.T) {
	home := queueHome(t, 50)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the walk takes a single step

	res := runQueue(t, ctx, home)
	f := queuePresent(t, res)

	if strings.Contains(strings.ToLower(f.Title), "empty") {
		t.Errorf("an interrupted scan reported the queue as EMPTY: %q\n"+
			"The queue holds 150 files. Nothing was read. 'Empty' here tells a compromised user they are fine.", f.Title)
	}
	if strings.Contains(f.Detail, "nothing was ever queued") {
		t.Error("detail claims nothing was ever queued, on a scan that read nothing at all")
	}
	if f.Severity < model.SevHigh {
		t.Errorf("severity = %v; an unreadable queue is not a low-severity condition", f.Severity)
	}
	if !strings.Contains(f.Detail, "NOT evidence that it is empty") {
		t.Errorf("detail does not disclaim emptiness:\n%s", f.Detail)
	}
}

// A partial scan must keep what it found. Returning an error and discarding the
// findings would throw away proof already in hand -- and a queue detector that
// produces nothing reads exactly like a clean host.
func TestInterruptedScanKeepsWhatItFoundAndSaysSo(t *testing.T) {
	home := queueHome(t, 200)

	// Cancel once the walk is underway rather than before it starts.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { cancel() }()

	res := runQueue(t, ctx, home)

	if len(res.Findings) == 0 {
		t.Fatal("an interrupted scan produced NO findings; a silent queue detector reads like a clean host")
	}
	// Whatever it managed to read, it must never present a partial count as a total.
	f := queuePresent(t, res)
	if strings.Contains(f.Title, "AT LEAST") || strings.Contains(f.Title, "interrupted") {
		var timeout bool
		for _, e := range res.Errors {
			if e.Kind == "timeout" && e.Material {
				timeout = true
			}
		}
		if !timeout {
			t.Error("the report says the scan was interrupted but records no material timeout error, so the verdict would not degrade")
		}
	}
}

func TestEmptyQueueStillReadsAsEmpty(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".grok", "upload_queue"), 0o755); err != nil {
		t.Fatal(err)
	}

	res := runQueue(t, context.Background(), home)
	f := queuePresent(t, res)

	if !strings.Contains(strings.ToLower(f.Title), "empty") {
		t.Errorf("title = %q, want it to report the queue as empty", f.Title)
	}
	if f.Severity != model.SevMedium {
		t.Errorf("severity = %v, want SevMedium: an empty queue is exposure, not proof", f.Severity)
	}
}

// The hash cap is a cost bound, not an evidence bound. Every archive must still be
// listed by path and size -- skipping a hash may not hide an archive.
func TestHashCapLeavesTheInventoryComplete(t *testing.T) {
	const turns = maxHashedArchives/2 + 20 // 2 archives per turn -> comfortably over the cap
	home := queueHome(t, turns)

	res := runQueue(t, context.Background(), home)

	var archives model.Finding
	for _, f := range res.Findings {
		if f.ID == "queue.codebase_archive" {
			archives = f
		}
	}
	if got, want := len(archives.Evidence), turns*2; got != want {
		t.Errorf("listed %d archives, want all %d: the hash cap must not drop archives from the inventory", got, want)
	}

	hashed := 0
	for _, e := range archives.Evidence {
		if e.SHA256 != "" {
			hashed++
		}
	}
	if hashed > maxHashedArchives {
		t.Errorf("hashed %d archives, want at most %d", hashed, maxHashedArchives)
	}
	if hashed == len(archives.Evidence) {
		t.Fatal("the cap did not engage; this fixture is meant to exceed it")
	}
	var noted bool
	for _, l := range res.Limitations {
		if strings.Contains(l, "not hashed") {
			noted = true
		}
	}
	if !noted {
		t.Error("archives were silently left unhashed with no limitation recorded")
	}
}

// repoRootOf climbs up to 64 levels calling os.Stat at each. A manifest lists every
// file in a repository, so without memoization the same root is rediscovered from
// scratch for every path in every manifest -- millions of syscalls on the host this
// was written for, against the slowest disk in the system.
func TestRepoRootCacheMemoizesHitsAndMisses(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(repo, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}

	c := newRepoRootCache()
	got := c.repoRootOf(filepath.Join(deep, "main.go"))
	if got != repo {
		t.Fatalf("repoRootOf = %q, want %q", got, repo)
	}
	if len(c.roots) == 0 {
		t.Fatal("the climb populated no cache entries; every later path would re-walk it")
	}
	// A sibling file in the same repo must now resolve from cache.
	before := len(c.roots)
	if got := c.repoRootOf(filepath.Join(deep, "other.go")); got != repo {
		t.Errorf("cached lookup = %q, want %q", got, repo)
	}
	if len(c.roots) != before {
		t.Errorf("a second path in the same repo added %d new cache entries; it should have added none",
			len(c.roots)-before)
	}

	// Misses are cached too: "not in a repo" costs the full 64-level climb to learn,
	// and on a queue full of such paths, not caching it is what turns this quadratic.
	outside := filepath.Join(t.TempDir(), "x", "y")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := c.repoRootOf(filepath.Join(outside, "f.txt")); got != "" {
		t.Errorf("repoRootOf outside any repo = %q, want empty", got)
	}
	if _, cached := c.roots[outside]; !cached {
		t.Error("a negative result was not memoized; the expensive climb will repeat for every sibling path")
	}
}
