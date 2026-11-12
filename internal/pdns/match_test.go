package pdns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func TestKeywordOf(t *testing.T) {
	for in, want := range map[string]string{
		"acme.com": "acme", "ACME.com.": "acme", "eu.acme.com": "acme", "acme.co.uk": "acme",
		"gmail.com": "", "users.noreply.github.com": "", "localhost": "", "-bad.com": "",
	} {
		if got := KeywordOf(in); got != want {
			t.Errorf("KeywordOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeywords(t *testing.T) {
	keep, dropped := Keywords([]string{"acme.com"}, []string{"me@acme.com", "x@gmail.com", "y@ab.io"}, []string{"Payments", "ai", "a b"})
	if !slices.Equal(keep, []string{"acme", "payments"}) {
		t.Errorf("keep = %v", keep)
	}
	if !slices.Equal(dropped, []string{"ab", "ai", "a b"}) {
		t.Errorf("dropped = %v", dropped)
	}
}

func TestGitEmails(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[user]\n\tname = A\n\temail = \"a@acme.com\"\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".config", "git"), 0o755)
	os.WriteFile(filepath.Join(home, ".config", "git", "config"), []byte("[user]\nemail=b@corp.io\n"), 0o644)
	if got := GitEmails(home); !slices.Equal(got, []string{"a@acme.com", "b@corp.io"}) {
		t.Errorf("GitEmails = %v", got)
	}
}

type fakeSource struct {
	name    string
	recs    []Record
	limited bool
	err     error
	gotKW   []string
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Names(_ context.Context, kw []string) ([]Record, bool, error) {
	f.gotKW = kw
	return f.recs, f.limited, f.err
}

type fakeCNAMEs map[string][]Record

func (f fakeCNAMEs) OrgRecords(_ context.Context, d string) ([]Record, error) { return f[d], nil }

func at(day int) time.Time { return time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC) }

func TestEnrichMergesSourcesAndAppliesRules(t *testing.T) {
	rep := &model.Report{Apps: []model.PublishedApp{
		{Host: "seen-here.grok.me", Source: model.AppSourceLocal, Seen: []model.Evidence{{Path: "/h/.zsh_history"}}},
		{Host: "acme-dash.grok.me", Source: model.AppSourceLocal, Seen: []model.Evidence{{Path: "/h/History"}}},
	}}
	crt := &fakeSource{name: "crt.sh", recs: []Record{
		{Name: "seen-here.grok.me", Source: "crt.sh", First: at(3), Last: at(3)},
		{Name: "acme-sales-map.grok.me", Source: "crt.sh", First: at(2), Last: at(2)},
		{Name: "acme-dash.grok.me", Source: "crt.sh", First: at(1), Last: at(1)},
		{Name: "quiet-moss-lantern-bay.grok.me", Source: "crt.sh"},
		{Name: "www.grok.me", Source: "crt.sh"},
		{Name: "deep.acme-x.grok.me", Source: "crt.sh"},
	}}
	scan := &fakeSource{name: "urlscan", recs: []Record{
		{Name: "seen-here.grok.me", Source: "urlscan", First: at(9), Last: at(9)},
		{Name: "acme-sales-map.grok.me", Source: "urlscan", First: at(6), Last: at(6)},
	}}
	grok := &fakeSource{name: "grok-search", recs: []Record{
		{Name: "random-four-word-name.grok.me", Source: "grok-search"}, // no keyword, but searched for by keyword
		{Name: "x.com", Source: "grok-search"},                         // a cited X post, not an app
	}}
	cn := fakeCNAMEs{"acme.com": {
		{Name: "apps.acme.com", RRType: "CNAME", Target: "acme-portal.grok.me", Source: "otx", Last: at(8)},
		{Name: "mail.acme.com", RRType: "CNAME", Target: "ghs.google.com", Source: "otx"},
		{Name: "evil.example", RRType: "CNAME", Target: "x.grok.me", Source: "otx"},
		{Name: "spoof.acme.com", RRType: "CNAME", Target: "grok.me.evil.example", Source: "otx"},
	}}
	res := Enrich(context.Background(), []Source{crt, scan, grok}, cn, rep, []string{"acme"}, []string{"acme.com"})
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %+v", res.Errors)
	}
	if !slices.Equal(grok.gotKW, []string{"acme"}) {
		t.Errorf("keywords not passed to the search source: %v", grok.gotKW)
	}

	got := map[string]model.PublishedApp{}
	var hosts []string
	for _, a := range rep.Apps {
		got[a.Host] = a
		hosts = append(hosts, a.Host)
	}
	slices.Sort(hosts)
	want := []string{"acme-dash.grok.me", "acme-sales-map.grok.me", "apps.acme.com", "random-four-word-name.grok.me", "seen-here.grok.me"}
	if !slices.Equal(hosts, want) || res.Added != 3 {
		t.Fatalf("hosts = %v (added %d), want %v", hosts, res.Added, want)
	}

	// Rule 1: dated across sources, attributed, still local, no keyword claim.
	a := got["seen-here.grok.me"]
	if a.Source != model.AppSourceLocal || !a.FirstSeen.Equal(at(3)) || !a.LastSeen.Equal(at(9)) ||
		!slices.Equal(a.Sources, []string{"crt.sh", "urlscan"}) || a.MatchedBy != "" {
		t.Errorf("seen-here: %+v", a)
	}
	// Rule 2 on a local name: matched, not duplicated.
	if a := got["acme-dash.grok.me"]; a.Source != model.AppSourceLocal || !strings.Contains(a.MatchedBy, `"acme"`) || len(a.Seen) != 1 {
		t.Errorf("acme-dash: %+v", a)
	}
	if a := got["acme-sales-map.grok.me"]; a.Source != model.AppSourcePassiveDNS || !slices.Equal(a.Sources, []string{"crt.sh", "urlscan"}) || !a.LastSeen.Equal(at(6)) {
		t.Errorf("acme-sales-map: %+v", a)
	}
	if a := got["random-four-word-name.grok.me"]; a.Source != model.AppSourceWebSearch || !strings.Contains(a.MatchedBy, "Grok") {
		t.Errorf("grok-search hit: %+v", a)
	}
	// Rule 3.
	if a := got["apps.acme.com"]; a.PointsTo != "acme-portal.grok.me" || !slices.Equal(a.Sources, []string{"otx"}) {
		t.Errorf("apps.acme.com: %+v", a)
	}
}

func TestEnrichReportsFailuresAndCaps(t *testing.T) {
	rep := &model.Report{}
	bad := &fakeSource{name: "crt.sh", err: errors.New("HTTP 502")}
	capped := &fakeSource{name: "urlscan", limited: true, recs: []Record{{Name: "acme.grok.me", Source: "urlscan"}}}
	res := Enrich(context.Background(), []Source{bad, capped}, nil, rep, []string{"acme"}, nil)
	if len(res.Errors) != 1 || res.Errors[0].Material || !strings.Contains(res.Errors[0].Message, "crt.sh") {
		t.Errorf("errors = %+v, want one immaterial crt.sh error", res.Errors)
	}
	if len(res.Limitations) != 1 || !strings.Contains(res.Limitations[0], "urlscan") {
		t.Errorf("limitations = %v", res.Limitations)
	}
	if len(rep.Apps) != 1 {
		t.Errorf("the working source's match was lost: %+v", rep.Apps)
	}
}

func TestAddHosts(t *testing.T) {
	rep := &model.Report{Apps: []model.PublishedApp{{Host: "known.grok.me", Source: model.AppSourceLocal}}}
	added, rejected := AddHosts(rep, []string{
		"# from Parallel",
		"https://acme-dash.grok.me/page",
		"acme-dash.grok.me", // duplicate
		"https://known.grok.me/",
		"https://apps.acme.com/",          // custom domain under --org-domain
		"https://evil.example/",           // not grok, not org
		"https://x.grok.me.evil.example/", // lookalike
		"https://a.b.grok.me/",            // not one label
		"https://notacme.com/",            // suffix without a dot
		"",
	}, []string{"acme.com"})
	if added != 2 || rejected != 4 {
		t.Errorf("added %d rejected %d, want 2 and 4", added, rejected)
	}
	byHost := map[string]model.PublishedApp{}
	for _, a := range rep.Apps {
		byHost[a.Host] = a
	}
	if a := byHost["known.grok.me"]; a.Source != model.AppSourceLocal || !slices.Equal(a.Sources, []string{"web-search"}) {
		t.Errorf("known: %+v", a)
	}
	if a := byHost["apps.acme.com"]; a.PointsTo != "" {
		t.Errorf("a custom domain from search must not be checkable: %+v", a)
	}
}

func TestEnrichMergesCNAMEIntoExistingSearchCustomDomain(t *testing.T) {
	rep := &model.Report{}
	if added, rejected := AddHosts(rep, []string{"https://apps.acme.com/"}, []string{"acme.com"}); added != 1 || rejected != 0 {
		t.Fatalf("AddHosts added=%d rejected=%d", added, rejected)
	}
	cnames := fakeCNAMEs{"acme.com": {{
		Name: "apps.acme.com", RRType: "CNAME", Target: "acme-app.grok.me",
		Source: "otx", First: at(2), Last: at(8),
	}}}
	res := Enrich(context.Background(), nil, cnames, rep, nil, []string{"acme.com"})
	if res.Added != 0 || len(rep.Apps) != 1 {
		t.Fatalf("CNAME duplicate added an app: result=%+v apps=%+v", res, rep.Apps)
	}
	a := rep.Apps[0]
	if a.PointsTo != "acme-app.grok.me" || !strings.Contains(a.MatchedBy, "CNAME to acme-app.grok.me") ||
		!slices.Equal(a.Sources, []string{"otx", "web-search"}) ||
		a.FirstSeen == nil || !a.FirstSeen.Equal(at(2)) || a.LastSeen == nil || !a.LastSeen.Equal(at(8)) {
		t.Errorf("existing search app did not receive CNAME evidence: %+v", a)
	}
}
