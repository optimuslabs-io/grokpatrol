package apps

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
)

func TestHosts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"url", "https://quiet-moss-lantern-bay.grok.me/", []string{"quiet-moss-lantern-bay.grok.me"}},
		{"uppercase is folded", "HTTPS://Tiny-City.GROK.ME/play", []string{"tiny-city.grok.me"}},
		{"bare host at end of input", "open tiny-city.grok.me", []string{"tiny-city.grok.me"}},
		{"sentence full stop is not a longer name", "see tiny-city.grok.me. next", []string{"tiny-city.grok.me"}},
		{"several, deduplicated, in order", "b.grok.me a.grok.me b.grok.me", []string{"b.grok.me", "a.grok.me"}},
		{"sqlite neighbours", "\x00\x17https://abc.grok.me/\x01\x02", []string{"abc.grok.me"}},
		{"url-encoded scheme is peeled", "https%3A%2F%2Ftiny-city.grok.me%2F", []string{"tiny-city.grok.me"}},
		{"bare domain is not an app", "https://grok.me/", nil},
		{"www is xAI's", "https://www.grok.me/", nil},
		{"deeper name is not an app", "https://a.b.grok.me/", nil},
		{"grok.me inside a longer domain", "https://x.grok.me.evil.example/", nil},
		{"longer tld", "https://x.grok.meow/", nil},
		{"lookalike registrable domain", "https://x.notgrok.me/", nil},
		{"leading hyphen", "https://-bad.grok.me/", nil},
		{"trailing hyphen", "https://bad-.grok.me/", nil},
		{"label over 63 bytes", "https://" + strings.Repeat("a", 64) + ".grok.me/", nil},
		{"label of exactly 63 bytes", "https://" + strings.Repeat("a", 63) + ".grok.me/", []string{strings.Repeat("a", 63) + ".grok.me"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Hosts([]byte(c.in)); !slices.Equal(got, c.want) {
				t.Errorf("Hosts(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// An address that straddles a read boundary must still be found whole, and the
// tail of a host must never be reported on its own.
func TestScanFileAcrossChunkBoundary(t *testing.T) {
	host := "boundary-straddler.grok.me"
	for _, offset := range []int{-20, -8, -1, 0, 1} {
		data := bytes.Repeat([]byte{' '}, chunkSize+offset)
		data = append(data, []byte("https://"+host+"/ trailing")...)
		path := filepath.Join(t.TempDir(), "History")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := scanFile(path, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, []string{host}) {
			t.Errorf("offset %d: got %v, want [%s]", offset, got, host)
		}
	}
}

func TestScanFileHonoursSizeCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(path, append(bytes.Repeat([]byte{' '}, 4096), "late.grok.me"...), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := scanFile(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("read past the cap: %v", got)
	}
}

func TestRunFindsAppsInEverySource(t *testing.T) {
	home := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Library/Application Support/Google/Chrome/Default/History", "SQLite format 3\x00https://from-chrome.grok.me/")
	write("Library/Application Support/Google/Chrome/Profile 1/History-wal", "https://from-wal.grok.me/")
	// A -wal with no main database is not a History file of ours.
	write("Library/Application Support/Google/Chrome/Profile 1/History", "nothing here")
	write(".mozilla/firefox/abc.default/places.sqlite", "https://from-firefox.grok.me/")
	write(".zsh_history", ": 1:0;open https://from-shell.grok.me\n: 2:0;open https://from-chrome.grok.me\n")
	write(".grok/sessions/%2Fwork/0001/events.jsonl", `{"tool":"bash","out":"published at https://from-grok.grok.me"}`)
	write("Documents/notes.txt", "https://not-a-source.grok.me/") // not a place we look

	env := &engine.Env{Home: home, GrokHome: filepath.Join(home, ".grok"), MaxFileSize: 1 << 20}
	res, err := New().Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, a := range res.Apps {
		hosts = append(hosts, a.Host)
	}
	want := []string{"from-chrome.grok.me", "from-firefox.grok.me", "from-grok.grok.me", "from-shell.grok.me", "from-wal.grok.me"}
	if !slices.Equal(hosts, want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}
	for _, a := range res.Apps {
		if a.Host == "from-chrome.grok.me" && len(a.Seen) != 2 {
			t.Errorf("from-chrome should cite Chrome and shell history, got %+v", a.Seen)
		}
		if a.Exposure != "" {
			t.Errorf("offline detector set an exposure: %+v", a)
		}
	}
	if len(res.AppLimitations) == 0 {
		t.Error("the not-necessarily-yours caveat is missing from the app caveats")
	}
}

// A browser history this tool cannot read is reported, but never degrades the
// verdict: nothing in it could hide a sign that repositories were taken.
func TestUnreadableSourceIsReportedNotMaterial(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits do not stop this user")
	}
	home := t.TempDir()
	p := filepath.Join(home, ".zsh_history")
	if err := os.WriteFile(p, []byte("x.grok.me"), 0o000); err != nil {
		t.Fatal(err)
	}
	res, _ := New().Run(context.Background(), &engine.Env{Home: home, GrokHome: filepath.Join(home, ".grok")})
	if len(res.Errors) != 1 || res.Errors[0].Material || res.Errors[0].Kind != "permission" {
		t.Fatalf("errors = %+v, want one immaterial permission error", res.Errors)
	}
	if strings.Contains(res.Errors[0].Message, home) {
		t.Errorf("message repeats the absolute path: %q", res.Errors[0].Message)
	}
}
