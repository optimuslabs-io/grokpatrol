//go:build online

package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Every key travels only in a request header, never in a URL, so no error message
// (Go's include the URL) and no report field can carry one.

// Endpoints are variables so tests can point them at a local server.
var (
	crtshURL   = "https://crt.sh/"
	urlscanURL = "https://urlscan.io/api/v1/search/"
	otxURL     = "https://otx.alienvault.com/api/v1/indicators/domain/"
	xaiURL     = "https://api.x.ai/v1/responses"
)

func client(timeout time.Duration) *http.Client { return &http.Client{Timeout: timeout} }

// fetch runs one request and returns the body of a 200, or an error that names
// the status but never a header value.
func fetch(ctx context.Context, c *http.Client, method, u string, body []byte, headers map[string]string, who string) (io.ReadCloser, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "grokpatrol (+https://github.com/optimuslabs-io/grokpatrol)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request failed: %w", who, err)
	}
	if resp.StatusCode == http.StatusOK {
		return resp.Body, nil
	}
	resp.Body.Close()
	return nil, statusError{who: who, code: resp.StatusCode}
}

// statusError is a non-200 reply. Its message names the status, never a header.
type statusError struct {
	who  string
	code int
}

func (e statusError) Error() string {
	switch e.code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("%s rejected the request (HTTP %d); check its API key", e.who, e.code)
	case http.StatusTooManyRequests:
		return fmt.Sprintf("%s rate limit reached (HTTP 429); re-run later or set its free API key", e.who)
	default:
		return fmt.Sprintf("%s returned HTTP %d", e.who, e.code)
	}
}

// retryDelays are the waits between attempts for a flaky source. A variable so
// tests can shorten them.
var retryDelays = []time.Duration{5 * time.Second, 15 * time.Second}

// transient reports whether an error is worth another attempt: a network failure,
// an unreadable body, or a 404/429/5xx. A 401/403 is a key problem and is not.
func transient(err error) bool {
	var se statusError
	if errors.As(err, &se) {
		return se.code == http.StatusNotFound || se.code == http.StatusTooManyRequests || se.code >= 500
	}
	return true
}

// retry runs fn up to len(retryDelays)+1 times, waiting between attempts and
// stopping early on success, a non-transient error, or a cancelled context.
func retry[T any](ctx context.Context, fn func() (T, error)) (T, int, error) {
	var (
		v   T
		err error
	)
	for attempt := 0; ; attempt++ {
		if v, err = fn(); err == nil || !transient(err) || attempt == len(retryDelays) {
			return v, attempt + 1, err
		}
		select {
		case <-ctx.Done():
			return v, attempt + 1, err
		case <-time.After(retryDelays[attempt]):
		}
	}
}

// CrtSh lists grok.me names from certificate transparency. No key.
type CrtSh struct{ HTTP *http.Client }

func NewCrtSh() *CrtSh      { return &CrtSh{HTTP: client(3 * time.Minute)} }
func (*CrtSh) Name() string { return "crt.sh" }

// crt.sh is often overloaded: in testing one request in four came back 502 or 404
// for a query that succeeded seconds later. A 404 from it is therefore read as
// "try again", never as "no names", and the request is retried.
func (c *CrtSh) Names(ctx context.Context, _ []string) ([]Record, bool, error) {
	recs, attempts, err := retry(ctx, func() ([]Record, error) {
		body, err := fetch(ctx, c.HTTP, http.MethodGet, crtshURL+"?q=%25.grok.me&output=json", nil, nil, "crt.sh")
		if err != nil {
			return nil, err
		}
		defer body.Close()
		return ParseCrtSh(body)
	})
	if err != nil && attempts > 1 {
		return nil, false, fmt.Errorf("crt.sh failed %d times (it is often overloaded; re-run later): %w", attempts, err)
	}
	return recs, false, err
}

// URLScan lists grok.me pages someone submitted to urlscan.io. The key is optional
// and only raises the page size.
type URLScan struct {
	Key      string
	HTTP     *http.Client
	MaxPages int
}

func NewURLScan(key string) *URLScan {
	return &URLScan{Key: key, HTTP: client(time.Minute), MaxPages: 10}
}
func (*URLScan) Name() string { return "urlscan" }
func (c *URLScan) Names(ctx context.Context, _ []string) ([]Record, bool, error) {
	size, headers := "100", map[string]string{}
	if c.Key != "" {
		size, headers["API-Key"] = "1000", c.Key
	}
	var all []Record
	after := ""
	for page := 0; page < c.MaxPages; page++ {
		q := url.Values{"q": {"page.domain:grok.me"}, "size": {size}}
		if after != "" {
			q.Set("search_after", after)
		}
		body, err := fetch(ctx, c.HTTP, http.MethodGet, urlscanURL+"?"+q.Encode(), nil, headers, "urlscan")
		if err != nil {
			if len(all) > 0 {
				return all, true, nil // keep what earlier pages gave; say it is partial
			}
			return nil, false, err
		}
		recs, next, err := ParseURLScan(body)
		body.Close()
		if err != nil {
			return nil, false, err
		}
		all = append(all, recs...)
		if next == "" {
			return all, false, nil
		}
		after = next
	}
	return all, true, nil
}

// OTX is AlienVault OTX passive DNS. It needs a free key; keyless requests are
// rate-limited to the point of uselessness, so the caller skips it without one.
type OTX struct {
	Key  string
	HTTP *http.Client
}

func NewOTX(key string) *OTX { return &OTX{Key: key, HTTP: client(2 * time.Minute)} }
func (*OTX) Name() string    { return "otx" }

func (c *OTX) records(ctx context.Context, domain string) ([]Record, error) {
	body, err := fetch(ctx, c.HTTP, http.MethodGet, otxURL+url.PathEscape(domain)+"/passive_dns", nil,
		map[string]string{"X-OTX-API-KEY": c.Key}, "OTX")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return ParseOTX(body)
}

func (c *OTX) Names(ctx context.Context, _ []string) ([]Record, bool, error) {
	recs, err := c.records(ctx, "grok.me")
	return recs, false, err
}

func (c *OTX) OrgRecords(ctx context.Context, domain string) ([]Record, error) {
	return c.records(ctx, domain)
}

// GrokSearch asks the xAI API, with its server-side web_search (restricted to
// grok.me) and x_search tools, for grok.me apps tied to the org keywords. Only URLs
// the tools cited are used. Billed to the caller's xAI API credits.
type GrokSearch struct {
	Key   string
	Model string
	HTTP  *http.Client
}

func NewGrokSearch(key, model string) *GrokSearch {
	return &GrokSearch{Key: key, Model: model, HTTP: client(4 * time.Minute)}
}
func (*GrokSearch) Name() string { return "grok-search" }

func (c *GrokSearch) Names(ctx context.Context, keywords []string) ([]Record, bool, error) {
	if len(keywords) == 0 {
		return nil, false, fmt.Errorf("Grok search needs org keywords (--org-keyword or --org-domain)")
	}
	prompt := "Find published Grok Build apps (web addresses ending in .grok.me) that belong to or mention the " +
		"organisation identified by these keywords: " + strings.Join(keywords, ", ") + ". Search the web and X " +
		"posts. Open every grok.me app page you find so that it is cited. Reply with the list of grok.me URLs only."
	req, _ := json.Marshal(map[string]any{
		"model": c.Model,
		"input": []map[string]string{{"role": "user", "content": prompt}},
		"tools": []map[string]any{
			{"type": "web_search", "allowed_domains": []string{"grok.me"}},
			{"type": "x_search"},
		},
	})
	body, err := fetch(ctx, c.HTTP, http.MethodPost, xaiURL, req,
		map[string]string{"Authorization": "Bearer " + c.Key, "Content-Type": "application/json"}, "xAI")
	if err != nil {
		return nil, false, err
	}
	defer body.Close()
	urls, err := ParseXAICitations(body)
	if err != nil {
		return nil, false, err
	}
	var recs []Record
	for _, u := range urls {
		if h := HostOf(u); h != "" {
			recs = append(recs, Record{Name: h, Source: "grok-search"})
		}
	}
	return recs, false, nil
}
