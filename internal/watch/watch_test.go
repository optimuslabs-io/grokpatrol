package watch

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

var t0 = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func local(host string) model.PublishedApp {
	return model.PublishedApp{Host: host, Source: model.AppSourceLocal, Seen: []model.Evidence{{Path: "~/h", Note: "Chrome history"}}}
}

func checkedAs(a model.PublishedApp, e model.Exposure) model.PublishedApp {
	a.Exposure, a.ExposureNote = e, "note"
	return a
}

func ptr(t time.Time) *time.Time { return &t }

// round trips entries through a record, as the next run would read them.
func roundTrip(t *testing.T, entries []Entry) map[string]Entry {
	t.Helper()
	b, err := json.Marshal(Record{Schema: Schema, Apps: entries})
	if err != nil {
		t.Fatal(err)
	}
	prev, dropped, err := Load(b)
	if err != nil || dropped != 0 {
		t.Fatalf("Load: %v (dropped %d)", err, dropped)
	}
	return prev
}

func TestFirstRunGivesOneSummaryNotOneAlertPerApp(t *testing.T) {
	found := []model.PublishedApp{
		checkedAs(local("alpha-one.grok.me"), model.ExposurePublic),
		checkedAs(local("beta-two.grok.me"), model.ExposureRestricted),
	}
	checked := map[string]bool{"alpha-one.grok.me": true, "beta-two.grok.me": true}
	entries, alerts := Build(t0, found, checked, nil, true)
	if len(alerts) != 1 || alerts[0].Kind != AlertSummary {
		t.Fatalf("alerts = %+v, want one summary", alerts)
	}
	if want := "Watching 2 apps. 1 opens without sign-in: alpha-one.grok.me."; alerts[0].Message != want {
		t.Errorf("summary = %q, want %q", alerts[0].Message, want)
	}
	if entries[0].PublicSince == nil || entries[1].PublicSince != nil {
		t.Errorf("public_since not recorded as expected: %+v", entries)
	}
}

func TestAlertsOnlyWhenAnAppNewlyOpens(t *testing.T) {
	host := "gamma-three.grok.me"
	checked := map[string]bool{host: true}

	entries, _ := Build(t0, []model.PublishedApp{checkedAs(local(host), model.ExposureRestricted)}, checked, nil, true)
	prev := roundTrip(t, entries)

	// Restricted -> public: one alert.
	entries, alerts := Build(t0.Add(15*time.Minute), []model.PublishedApp{checkedAs(local(host), model.ExposurePublic)}, checked, prev, false)
	if len(alerts) != 1 || alerts[0].Kind != AlertPublic || alerts[0].Host != host {
		t.Fatalf("alerts = %+v, want one public alert for %s", alerts, host)
	}
	if !strings.Contains(alerts[0].Message, "Only you or Invited users") || strings.Contains(alerts[0].Message, "someone else's") {
		t.Errorf("message = %q", alerts[0].Message)
	}
	prev = roundTrip(t, entries)

	// Still public: no repeat.
	entries, alerts = Build(t0.Add(30*time.Minute), []model.PublishedApp{checkedAs(local(host), model.ExposurePublic)}, checked, prev, false)
	if len(alerts) != 0 {
		t.Fatalf("repeat alerts = %+v", alerts)
	}
	prev = roundTrip(t, entries)

	// A failed request neither clears the state nor re-alerts afterwards.
	entries, alerts = Build(t0.Add(45*time.Minute), []model.PublishedApp{checkedAs(local(host), model.ExposureUnknown)}, checked, prev, false)
	if len(alerts) != 0 || entries[0].Exposure != model.ExposurePublic || entries[0].PublicSince == nil {
		t.Fatalf("unknown changed state: alerts %+v entry %+v", alerts, entries[0])
	}
	if !entries[0].CheckedAt.Equal(t0.Add(30 * time.Minute)) {
		t.Errorf("checked_at moved on a failed request: %v", entries[0].CheckedAt)
	}
	prev = roundTrip(t, entries)
	_, alerts = Build(t0.Add(time.Hour), []model.PublishedApp{checkedAs(local(host), model.ExposurePublic)}, checked, prev, false)
	if len(alerts) != 0 {
		t.Fatalf("alert after an unknown blip: %+v", alerts)
	}

	// Made private, then public again: alerts again.
	entries, _ = Build(t0.Add(2*time.Hour), []model.PublishedApp{checkedAs(local(host), model.ExposureRestricted)}, checked, prev, false)
	prev = roundTrip(t, entries)
	_, alerts = Build(t0.Add(3*time.Hour), []model.PublishedApp{checkedAs(local(host), model.ExposurePublic)}, checked, prev, false)
	if len(alerts) != 1 {
		t.Fatalf("no alert when it reopened: %+v", alerts)
	}
}

func TestNewAppAfterFirstRunAlertsAndKeywordMatchSaysItMayNotBeYours(t *testing.T) {
	prev := roundTrip(t, nil)
	a := model.PublishedApp{Host: "acmepay-portal.grok.me", Source: model.AppSourcePassiveDNS, MatchedBy: "org keyword acmepay"}
	_, alerts := Build(t0, []model.PublishedApp{checkedAs(a, model.ExposurePublic)}, map[string]bool{a.Host: true}, prev, false)
	if len(alerts) != 1 || !strings.Contains(alerts[0].Message, "may be someone else's") {
		t.Fatalf("alerts = %+v", alerts)
	}
}

func TestUncheckedAppsKeepTheirState(t *testing.T) {
	host := "delta-four.grok.me"
	entries, _ := Build(t0, []model.PublishedApp{checkedAs(local(host), model.ExposurePublic)}, map[string]bool{host: true}, nil, true)
	prev := roundTrip(t, entries)
	entries, alerts := Build(t0.Add(time.Minute), []model.PublishedApp{local(host)}, map[string]bool{}, prev, false)
	if len(alerts) != 0 || entries[0].Exposure != model.ExposurePublic || entries[0].PublicSince == nil {
		t.Fatalf("unchecked app lost its state: %+v", entries[0])
	}
}

func TestSecretAlertOnlyForNewServerRules(t *testing.T) {
	host := "eps-five.grok.me"
	checked := map[string]bool{host: true}
	withSecrets := func(s ...model.AppSecret) model.PublishedApp {
		a := checkedAs(local(host), model.ExposurePublic)
		a.Secrets, a.SecretScan = s, "scanned the home page and 1 of 1 same-host scripts"
		return a
	}
	browser := model.AppSecret{Rule: "gcp-api-key", Kind: model.SecretBrowser, Asset: "/assets/a.js"}
	server := model.AppSecret{Rule: "openai-api-key", Kind: model.SecretServer, Asset: "/assets/a.js"}

	entries, _ := Build(t0, []model.PublishedApp{withSecrets(browser)}, checked, nil, true)
	prev := roundTrip(t, entries)
	entries, alerts := Build(t0.Add(time.Hour), []model.PublishedApp{withSecrets(browser, server)}, checked, prev, false)
	if len(alerts) != 1 || alerts[0].Kind != AlertSecret || !strings.Contains(alerts[0].Message, "openai-api-key") {
		t.Fatalf("alerts = %+v, want one secret alert naming openai-api-key", alerts)
	}
	if strings.Contains(alerts[0].Message, "gcp-api-key") {
		t.Errorf("browser key reported as a server secret: %q", alerts[0].Message)
	}
	prev = roundTrip(t, entries)
	_, alerts = Build(t0.Add(2*time.Hour), []model.PublishedApp{withSecrets(browser, server)}, checked, prev, false)
	if len(alerts) != 0 {
		t.Fatalf("repeat secret alert: %+v", alerts)
	}
}

func TestDueTiers(t *testing.T) {
	prev := map[string]Entry{
		"new-app.grok.me":  {WatchingSince: t0.Add(-2 * time.Hour), CheckedAt: ptr(t0.Add(-1 * time.Minute))},
		"week-app.grok.me": {WatchingSince: t0.Add(-3 * 24 * time.Hour), CheckedAt: ptr(t0.Add(-30 * time.Minute))},
		"week-due.grok.me": {WatchingSince: t0.Add(-3 * 24 * time.Hour), CheckedAt: ptr(t0.Add(-61 * time.Minute))},
		"old-app.grok.me":  {WatchingSince: t0.Add(-30 * 24 * time.Hour), CheckedAt: ptr(t0.Add(-23 * time.Hour))},
		"old-due.grok.me":  {WatchingSince: t0.Add(-30 * 24 * time.Hour), CheckedAt: ptr(t0.Add(-25 * time.Hour))},
		"never-ok.grok.me": {WatchingSince: t0.Add(-30 * 24 * time.Hour)},
	}
	for host, want := range map[string]bool{
		"new-app.grok.me": true, "week-app.grok.me": false, "week-due.grok.me": true,
		"old-app.grok.me": false, "old-due.grok.me": true, "never-ok.grok.me": true, "brand-new.grok.me": true,
	} {
		if got := Due(host, prev, t0); got != want {
			t.Errorf("Due(%s) = %v, want %v", host, got, want)
		}
	}
}

func TestScanDueOnFirstPublicThenDaily(t *testing.T) {
	prev := map[string]Entry{
		"private.grok.me":      {},
		"public-fresh.grok.me": {PublicSince: ptr(t0), SecretsCheckedAt: ptr(t0.Add(-time.Hour))},
		"public-stale.grok.me": {PublicSince: ptr(t0), SecretsCheckedAt: ptr(t0.Add(-25 * time.Hour))},
	}
	for host, want := range map[string]bool{
		"private.grok.me": true, "public-fresh.grok.me": false, "public-stale.grok.me": true, "unseen.grok.me": true,
	} {
		if got := ScanDue(host, prev, t0); got != want {
			t.Errorf("ScanDue(%s) = %v, want %v", host, got, want)
		}
	}
}

func TestCarryKeepsAppsThisRunDidNotFind(t *testing.T) {
	prev := map[string]Entry{
		"kept-local.grok.me": {Host: "kept-local.grok.me", Source: model.AppSourceLocal, OnThisMachine: true},
		"kept-dns.grok.me":   {Host: "kept-dns.grok.me", Source: model.AppSourcePassiveDNS},
		"found-now.grok.me":  {Host: "found-now.grok.me", Source: model.AppSourceLocal, OnThisMachine: true},
	}
	rep := &model.Report{Apps: []model.PublishedApp{local("found-now.grok.me")}}
	Carry(rep, prev)
	if len(rep.Apps) != 3 {
		t.Fatalf("apps = %+v", rep.Apps)
	}
	for _, a := range rep.Apps {
		switch a.Host {
		case "kept-local.grok.me":
			if len(a.Seen) != 1 || a.Seen[0].Path != "" {
				t.Errorf("local app carried without a path-free sighting: %+v", a.Seen)
			}
		case "kept-dns.grok.me":
			if len(a.Seen) != 0 {
				t.Errorf("public-source app gained a sighting: %+v", a.Seen)
			}
		}
	}
}

func TestLoadRejectsWhatCouldBecomeADestinationOrAlertText(t *testing.T) {
	raw := `{"schema":"` + Schema + `","apps":[
	  {"host":"ok-app.grok.me","source":"local","watching_since":"2026-11-01T00:00:00Z","exposure":"public",
	   "exposure_note":"line one\nline two",
	   "secrets":[{"rule":"openai-api-key","kind":"server","asset":"/a.js"},
	              {"rule":"x; rm -rf /","kind":"server","asset":"/a.js"},
	              {"rule":"aws","kind":"server","asset":"https://evil.example/a.js"}]},
	  {"host":"evil.example.com","source":"local","watching_since":"2026-11-01T00:00:00Z"},
	  {"host":"a.b.grok.me","source":"local","watching_since":"2026-11-01T00:00:00Z"},
	  {"host":"custom.acme.com","points_to":"evil.example.com","source":"passive_dns","watching_since":"2026-11-01T00:00:00Z"},
	  {"host":"no-time.grok.me","source":"local"},
	  {"host":"bad-exposure.grok.me","source":"local","watching_since":"2026-11-01T00:00:00Z","exposure":"fine"}
	]}`
	prev, dropped, err := Load([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 5 || len(prev) != 1 {
		t.Fatalf("kept %d, dropped %d; want 1 kept, 5 dropped: %+v", len(prev), dropped, prev)
	}
	e := prev["ok-app.grok.me"]
	if e.ExposureNote != "" {
		t.Errorf("multi-line note kept: %q", e.ExposureNote)
	}
	if len(e.Secrets) != 1 || e.Secrets[0].Rule != "openai-api-key" {
		t.Errorf("secrets = %+v, want only the valid one", e.Secrets)
	}
}

func TestLoadRefusesOtherFiles(t *testing.T) {
	if _, _, err := Load([]byte(`{"schema":"grokpatrol/1","apps":[]}`)); !errors.Is(err, ErrSchema) {
		t.Errorf("a report was accepted as a watch record: %v", err)
	}
	if _, _, err := Load([]byte(`not json`)); err == nil {
		t.Error("garbage parsed")
	}
}

func TestCapKeepsAppsOnThisMachine(t *testing.T) {
	var entries []Entry
	for i := range maxApps + 10 {
		entries = append(entries, Entry{Host: "x" + strings.Repeat("a", i%50) + ".grok.me", WatchingSince: t0.Add(time.Duration(i) * time.Second)})
	}
	entries[0].OnThisMachine = true
	kept, capped := Cap(entries)
	if !capped || len(kept) != maxApps {
		t.Fatalf("capped=%v len=%d", capped, len(kept))
	}
	found := false
	for _, e := range kept {
		if e.OnThisMachine {
			found = true
		}
	}
	if !found {
		t.Error("the app seen on this machine was dropped")
	}
}
