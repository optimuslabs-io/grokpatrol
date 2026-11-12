//go:build online

package exposure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func TestScanPublicFetchesOnlySameHostScriptsAndRecordsNoValues(t *testing.T) {
	var mu sync.Mutex
	requested := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.Host+r.URL.Path] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><script type="module" src="/assets/index.js"></script>` +
				`<script src="https://cdn.evil.example/x.js"></script><h1>dashboard</h1></html>`))
		case "/assets/index.js":
			w.Write([]byte(`const k="` + plantedPAT + `";const f="` + plantedFirebase + `";`))
		default:
			w.Write([]byte(`const k="` + plantedPAT + `";`))
		}
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewrite{target: target, next: http.DefaultTransport}}
	cfg := Config{UserAgent: "grokpatrol-test", ScanSecrets: true}

	mine := model.PublishedApp{Host: "mine.grok.me", Seen: []model.Evidence{{Path: "~/x", Note: "browser history"}}}
	lead := model.PublishedApp{Host: "lead.grok.me", Source: model.AppSourcePassiveDNS, MatchedBy: "keyword"}
	var budget atomic.Int64
	checkOne(context.Background(), client, &mine, cfg, &budget)
	checkOne(context.Background(), client, &lead, cfg, &budget)

	if requested["cdn.evil.example/x.js"] {
		t.Error("fetched a script from another host")
	}
	if !requested["mine.grok.me/assets/index.js"] {
		t.Error("did not fetch the same-host script")
	}
	if len(mine.Secrets) != 2 || mine.Secrets[0].Kind != model.SecretServer || mine.Secrets[0].Rule != "github-pat" ||
		mine.Secrets[1].Rule != "gcp-api-key" {
		t.Errorf("mine.Secrets = %+v", mine.Secrets)
	}
	if !strings.HasPrefix(mine.SecretScan, "scanned the home page and 1 of 1") {
		t.Errorf("mine.SecretScan = %q", mine.SecretScan)
	}

	if requested["lead.grok.me/assets/index.js"] || len(lead.Secrets) != 0 || !strings.Contains(lead.SecretScan, "--scan-keyword-matches") {
		t.Errorf("a keyword lead was scanned: %+v", lead)
	}
	cfg.ScanKeywordMatches = true
	lead.Secrets, lead.SecretScan = nil, ""
	checkOne(context.Background(), client, &lead, cfg, &budget)
	if len(lead.Secrets) == 0 {
		t.Error("--scan-keyword-matches did not scan the lead")
	}

	out, _ := json.Marshal([]model.PublishedApp{mine, lead})
	for _, v := range []string{plantedPAT, plantedFirebase, "dashboard"} {
		if strings.Contains(string(out), v) {
			t.Errorf("the record carries page content %q", v)
		}
	}
}

func TestScanPublicStopsAtTheRunBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<script src="/a.js"></script><h1>dashboard</h1>`))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewrite{target: target, next: http.DefaultTransport}}
	app := model.PublishedApp{Host: "mine.grok.me", Seen: []model.Evidence{{Path: "~/x"}}}
	var budget atomic.Int64
	budget.Store(maxScanBytes)
	checkOne(context.Background(), client, &app, Config{ScanSecrets: true}, &budget)
	if !strings.Contains(app.SecretScan, "0 of 1") || !strings.Contains(app.SecretScan, "per-run limit") {
		t.Errorf("SecretScan = %q", app.SecretScan)
	}
}
