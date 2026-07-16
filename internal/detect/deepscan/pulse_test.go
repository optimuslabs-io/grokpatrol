package deepscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
)

type pulseLog struct {
	mu       sync.Mutex
	statuses []string
}

func (p *pulseLog) Checking(string, string)               {}
func (p *pulseLog) Checked(string, string, time.Duration) {}
func (p *pulseLog) Done(time.Duration)                    {}
func (p *pulseLog) Pulse(detector, status string) {
	if detector != "deepscan" {
		return
	}
	p.mu.Lock()
	p.statuses = append(p.statuses, status)
	p.mu.Unlock()
}

func TestDeepscanPulsesDuringWalk(t *testing.T) {
	root := t.TempDir()
	// A few nested dirs so the walk has something to count.
	for _, d := range []string{"a/b", "a/c", "d"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := &pulseLog{}
	env := &engine.Env{
		Home:        root,
		GrokHome:    filepath.Join(root, ".grok"),
		ScanRoots:   []string{root},
		ConfineWalk: true,
		Concurrency: 1,
		MaxFileSize: 1 << 20,
		Progress:    log,
	}
	if _, err := New().Run(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.statuses) == 0 {
		t.Fatal("expected at least one Pulse during the walk")
	}
	joined := strings.Join(log.statuses, "\n")
	if !strings.Contains(joined, "dir") {
		t.Errorf("pulse status should count dirs; got:\n%s", joined)
	}
}

func TestTruncatePulsePath(t *testing.T) {
	if got := truncatePulsePath("short", 48); got != "short" {
		t.Errorf("got %q", got)
	}
	long := strings.Repeat("x", 60)
	got := truncatePulsePath(long, 20)
	if !strings.HasPrefix(got, "…") || len([]rune(got)) != 20 {
		t.Errorf("got %q (rune len %d)", got, len([]rune(got)))
	}
}
