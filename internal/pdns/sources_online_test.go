//go:build online

package pdns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const plantedKey = "KEY-7f3a-never-print"

// server records every request so tests can assert where keys went.
type server struct {
	mu    sync.Mutex
	urls  []string
	heads []http.Header
	body  []string
}

func (s *server) start(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.urls, s.heads, s.body = append(s.urls, r.URL.String()), append(s.heads, r.Header.Clone()), append(s.body, string(b))
		s.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (s *server) keyInURL() bool {
	for _, u := range s.urls {
		if strings.Contains(u, plantedKey) {
			return true
		}
	}
	return false
}

func TestURLScanPagesAndKeyHeader(t *testing.T) {
	var s server
	srv := s.start(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("search_after") == "" {
			io.WriteString(w, `{"has_more":true,"results":[{"task":{"domain":"a.grok.me"},"sort":[1,"x"]}]}`)
			return
		}
		io.WriteString(w, `{"has_more":false,"results":[{"task":{"domain":"b.grok.me"},"sort":[2,"y"]}]}`)
	})
	urlscanURL = srv.URL + "/"
	c := NewURLScan(plantedKey)
	recs, limited, err := c.Names(context.Background(), nil)
	if err != nil || limited || len(recs) != 2 {
		t.Fatalf("recs=%v limited=%v err=%v", recs, limited, err)
	}
	if s.heads[0].Get("API-Key") != plantedKey || s.keyInURL() {
		t.Error("urlscan key must be sent as a header and never in the URL")
	}
	if !strings.Contains(s.urls[0], "size=1000") || !strings.Contains(s.urls[1], "search_after=1%2Cx") {
		t.Errorf("urls = %v", s.urls)
	}
}

func TestOTXKeyNeverInURLOrError(t *testing.T) {
	var s server
	srv := s.start(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	otxURL = srv.URL + "/"
	_, _, err := NewOTX(plantedKey).Names(context.Background(), nil)
	if err == nil || strings.Contains(err.Error(), plantedKey) || s.keyInURL() {
		t.Fatalf("err = %v; a 403 must be an error that never contains the key", err)
	}
	if s.heads[0].Get("X-OTX-API-KEY") != plantedKey {
		t.Error("OTX key not sent in its header")
	}
}

func TestCrtShQuery(t *testing.T) {
	var s server
	srv := s.start(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"name_value":"a.grok.me","not_before":"2026-08-01T00:00:00"}]`)
	})
	crtshURL = srv.URL + "/"
	recs, _, err := NewCrtSh().Names(context.Background(), nil)
	if err != nil || len(recs) != 1 {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
	if !strings.Contains(s.urls[0], "q=%25.grok.me") || !strings.Contains(s.urls[0], "output=json") {
		t.Errorf("url = %s", s.urls[0])
	}
}

func TestGrokSearchRequestAndCitationsOnly(t *testing.T) {
	var s server
	srv := s.start(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"citations":["https://acme-dash.grok.me/"],"output":[{"content":[{"text":"also made-up.grok.me","annotations":[]}]}]}`)
	})
	xaiURL = srv.URL
	recs, _, err := NewGrokSearch(plantedKey, "grok-test").Names(context.Background(), []string{"acme"})
	if err != nil || len(recs) != 1 || recs[0].Name != "acme-dash.grok.me" {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
	if s.heads[0].Get("Authorization") != "Bearer "+plantedKey || s.keyInURL() || strings.Contains(s.body[0], plantedKey) {
		t.Error("xAI key must be sent only as a bearer header")
	}
	var req struct {
		Model string `json:"model"`
		Tools []struct {
			Type           string   `json:"type"`
			AllowedDomains []string `json:"allowed_domains"`
		} `json:"tools"`
	}
	json.Unmarshal([]byte(s.body[0]), &req)
	if req.Model != "grok-test" || len(req.Tools) != 2 || req.Tools[0].Type != "web_search" ||
		len(req.Tools[0].AllowedDomains) != 1 || req.Tools[0].AllowedDomains[0] != "grok.me" || req.Tools[1].Type != "x_search" {
		t.Errorf("request = %s", s.body[0])
	}
	if _, _, err := NewGrokSearch(plantedKey, "m").Names(context.Background(), nil); err == nil {
		t.Error("search without keywords should refuse")
	}
}

func TestCrtShRetriesTransientFailures(t *testing.T) {
	saved := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { retryDelays = saved })

	var n int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		attempt := n
		mu.Unlock()
		switch attempt {
		case 1:
			w.WriteHeader(http.StatusBadGateway)
		case 2:
			w.WriteHeader(http.StatusNotFound)
		default:
			io.WriteString(w, `[{"name_value":"a.grok.me","not_before":"2026-08-01T00:00:00"}]`)
		}
	}))
	defer srv.Close()
	crtshURL = srv.URL + "/"
	recs, _, err := NewCrtSh().Names(context.Background(), nil)
	if err != nil || len(recs) != 1 || n != 3 {
		t.Fatalf("recs=%v err=%v attempts=%d, want success on the third attempt", recs, err, n)
	}

	// Always failing: three attempts, then an error that says so.
	n = 0
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv2.Close()
	crtshURL = srv2.URL + "/"
	if _, _, err := NewCrtSh().Names(context.Background(), nil); err == nil || n != 3 || !strings.Contains(err.Error(), "3 times") {
		t.Errorf("err=%v attempts=%d", err, n)
	}

	// A key problem is not retried.
	n = 0
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv3.Close()
	crtshURL = srv3.URL + "/"
	if _, _, err := NewCrtSh().Names(context.Background(), nil); err == nil || n != 1 {
		t.Errorf("403 retried: err=%v attempts=%d", err, n)
	}
}
