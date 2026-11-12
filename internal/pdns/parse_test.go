package pdns

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// Fixtures are trimmed from real responses captured on 11 Nov 2026.

func TestParseCrtSh(t *testing.T) {
	in := `[{"issuer_name":"C=US, O=Google Trust Services, CN=WR1","common_name":"artifacts.grok.me",
"name_value":"artifacts.grok.me","not_before":"2026-08-23T14:21:47","not_after":"2026-11-21T15:21:44"},
{"name_value":"Tiny-City.grok.me\nwww.tiny-city.grok.me","not_before":"2026-02-01T00:00:00"}]`
	recs, err := ParseCrtSh(strings.NewReader(in))
	if err != nil || len(recs) != 3 {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
	if recs[1].Name != "tiny-city.grok.me" || recs[1].Source != "crt.sh" || !recs[1].First.Equal(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("rec = %+v", recs[1])
	}
	if _, err := ParseCrtSh(strings.NewReader("<html>busy</html>")); err == nil {
		t.Error("crt.sh error page accepted")
	}
}

func TestParseURLScan(t *testing.T) {
	in := `{"total":176,"has_more":true,"results":[
{"task":{"domain":"metric-roll-converter.grok.me","time":"2026-11-11T22:01:49.602Z"},
 "page":{"domain":"metric-roll-converter.grok.me","title":"Calculator"},"sort":[1794434509602,"01a1cca1"]}]}`
	recs, next, err := ParseURLScan(strings.NewReader(in))
	if err != nil || len(recs) != 2 || recs[0].Name != "metric-roll-converter.grok.me" {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
	if next != "1794434509602,01a1cca1" {
		t.Errorf("next = %q", next)
	}
	if _, next, _ := ParseURLScan(strings.NewReader(`{"has_more":false,"results":[]}`)); next != "" {
		t.Errorf("no more pages, got next %q", next)
	}
}

func TestParseOTX(t *testing.T) {
	in := `{"passive_dns":[
{"hostname":"apps.acme.com","address":"Acme-Portal.grok.me.","record_type":"CNAME","first":"2026-09-01T10:00:00","last":"2026-11-01T10:00:00"},
{"hostname":"x.grok.me","address":"104.16.88.25","record_type":"A","first":"2026-09-02T00:00:00","last":"2026-09-03T00:00:00"}],"count":2}`
	recs, err := ParseOTX(strings.NewReader(in))
	if err != nil || len(recs) != 2 {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
	if recs[0].RRType != "CNAME" || recs[0].Target != "acme-portal.grok.me" || recs[0].Last.IsZero() {
		t.Errorf("cname = %+v", recs[0])
	}
	if recs[1].Target != "" {
		t.Errorf("A record got a target: %+v", recs[1])
	}
}

// Only cited URLs count. A hostname the model wrote in its answer is ignored.
func TestParseXAICitations(t *testing.T) {
	in := `{"citations":["https://acme-dash.grok.me/"],"output":[{"type":"message","content":[{"type":"output_text",
"text":"I found acme-dash.grok.me and invented-name.grok.me",
"annotations":[{"type":"url_citation","url":"https://x.com/someone/status/1"},{"type":"url_citation","url":"https://acme-ops.grok.me/x"}]}]}]}`
	urls, err := ParseXAICitations(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(urls, []string{"https://acme-dash.grok.me/", "https://x.com/someone/status/1", "https://acme-ops.grok.me/x"}) {
		t.Errorf("urls = %v", urls)
	}
	for _, u := range urls {
		if strings.Contains(u, "invented-name") {
			t.Error("a name from the model's prose was used")
		}
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://Tiny.grok.me/play?x=1": "tiny.grok.me",
		"tiny.grok.me":                  "tiny.grok.me",
		"  http://tiny.grok.me.  ":      "tiny.grok.me",
		"https://user@tiny.grok.me/":    "",
		"https://tiny.grok.me:8443/":    "",
		"":                              "",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
