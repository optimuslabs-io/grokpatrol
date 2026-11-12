//go:build online

package exposure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// rewrite sends every request to the test server while keeping the original Host,
// so checkOne runs unchanged against a server we control.
type rewrite struct {
	target *url.URL
	next   http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host = r.target.Scheme, r.target.Host
	return r.next.RoundTrip(out)
}

func TestCheckOneSendsNoCredentialsAndClassifies(t *testing.T) {
	var sawCookie, sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			sawCookie.Store(true)
		}
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		switch r.Host {
		case "open.grok.me":
			w.Write([]byte("<h1>dashboard</h1>"))
		case "locked.grok.me":
			w.WriteHeader(http.StatusUnauthorized)
		case "elsewhere.grok.me":
			http.Redirect(w, r, "https://accounts.example/login", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewrite{target: target, next: http.DefaultTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	want := map[string]model.Exposure{
		"open.grok.me":      model.ExposurePublic,
		"locked.grok.me":    model.ExposureRestricted,
		"elsewhere.grok.me": model.ExposureUnknown,
		"gone.grok.me":      model.ExposureNotFound,
	}
	for host, exp := range want {
		app := model.PublishedApp{Host: host}
		checkOne(context.Background(), client, &app, Config{UserAgent: "grokpatrol-test"}, new(atomic.Int64))
		if app.Exposure != exp {
			t.Errorf("%s: got %q (%s), want %q", host, app.Exposure, app.ExposureNote, exp)
		}
	}
	if sawCookie.Load() || sawAuth.Load() {
		t.Error("the check sent a cookie or an Authorization header")
	}
}

// The one place a file-derived string becomes a network destination refuses
// anything that is not a single label under grok.me, without making a request.
func TestCheckOneRefusesNonGrokHosts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewrite{target: target, next: http.DefaultTransport}}

	for _, host := range []string{"example.com", "a.b.grok.me", "grok.me", "x.grok.me/../evil", "x.grok.me@evil.example"} {
		app := model.PublishedApp{Host: host}
		checkOne(context.Background(), client, &app, Config{UserAgent: "grokpatrol-test"}, new(atomic.Int64))
		if app.Exposure != model.ExposureUnknown {
			t.Errorf("%q: got %q, want unknown", host, app.Exposure)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("made %d requests to refused hosts", hits.Load())
	}
}

func TestAllowedCustomDomains(t *testing.T) {
	orgs := []string{"acme.com"}
	for _, c := range []struct {
		app  model.PublishedApp
		want bool
	}{
		{model.PublishedApp{Host: "tiny.grok.me"}, true},
		{model.PublishedApp{Host: "apps.acme.com", PointsTo: "x.grok.me"}, true},
		{model.PublishedApp{Host: "acme.com", PointsTo: "x.grok.me"}, true},
		{model.PublishedApp{Host: "apps.acme.com"}, false},                       // no grok CNAME behind it
		{model.PublishedApp{Host: "evil.example", PointsTo: "x.grok.me"}, false}, // not under an org domain
		{model.PublishedApp{Host: "notacme.com", PointsTo: "x.grok.me"}, false},  // suffix without a dot
	} {
		if got := allowed(&c.app, orgs); got != c.want {
			t.Errorf("allowed(%+v) = %v, want %v", c.app, got, c.want)
		}
	}
}
