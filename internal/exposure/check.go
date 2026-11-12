//go:build online

package exposure

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/detect/apps"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/pdns"
)

// Limits on what the check does to somebody else's server: one GET per app, a few at
// a time, a short deadline, and only the start of the page.
const (
	maxBody      = 512 << 10
	perRequest   = 15 * time.Second
	workers      = 4
	maxRedirects = 3
	maxChecks    = 200
	// maxScanBytes caps the scripts --scan-public downloads in one run, across apps.
	maxScanBytes = 32 << 20
)

// Config is what one exposure check run may do.
type Config struct {
	UserAgent string
	// OrgDomains are the domains the user named with --org-domain.
	OrgDomains []string
	// ScanSecrets (--scan-public) fetches each eligible public app's same-host
	// scripts and scans them, with its home page, in memory for secrets.
	ScanSecrets bool
	// ScanKeywordMatches extends ScanSecrets to apps tied to the org only by a
	// keyword or a search result, rather than seen on this host or under an org domain.
	ScanKeywordMatches bool
}

// allowed is the gate between a string from a file or a passive DNS record and a
// network destination: exactly one label under grok.me, or a custom domain (one that
// passive DNS showed pointing into grok.me) under a domain the user named.
func allowed(app *model.PublishedApp, orgDomains []string) bool {
	if h := apps.Hosts([]byte(app.Host)); len(h) == 1 && h[0] == app.Host {
		return true
	}
	if app.PointsTo == "" || !pdns.ValidDomain(app.Host) {
		return false
	}
	for _, d := range orgDomains {
		if app.Host == d || strings.HasSuffix(app.Host, "."+d) {
			return true
		}
	}
	return false
}

// Check fills in Exposure for each app with one unauthenticated GET of its home page.
// No cookies, no credentials, no session: the request is what a stranger's
// private-browsing window would send. Only same-host redirects are followed.
//
// orgDomains are the domains the user named with --org-domain. A custom domain is
// checked only if it sits under one of them: the user chose those destinations, so a
// passive DNS record cannot steer a request anywhere else. At most maxChecks apps are
// requested; the rest are marked unknown, not skipped silently.
//
// With cfg.ScanSecrets, each public app that is eligible (see scanEligible) also has
// its home page and up to MaxScripts same-host scripts scanned in memory; only rule
// ids and asset paths are kept.
func Check(ctx context.Context, list []model.PublishedApp, cfg Config) {
	client := &http.Client{
		Timeout: perRequest,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var budget atomic.Int64
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				checkOne(ctx, client, &list[i], cfg, &budget)
			}
		}()
	}
	for i := range list {
		if i >= maxChecks {
			list[i].Exposure = model.ExposureUnknown
			list[i].ExposureNote = "not checked: over the per-run limit of " + strconv.Itoa(maxChecks) + " apps"
			continue
		}
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func checkOne(ctx context.Context, client *http.Client, app *model.PublishedApp, cfg Config, budget *atomic.Int64) {
	// Defence in depth: the detector already validated the host, but this is the
	// one place a string from a file becomes a network destination. Anything that is
	// not exactly one label under grok.me is refused here, so a bug elsewhere cannot
	// turn this into a request to an arbitrary host.
	if !allowed(app, cfg.OrgDomains) {
		app.Exposure, app.ExposureNote = model.ExposureUnknown, "not checked: not a grok.me app address or a custom domain under --org-domain"
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+app.Host+"/", nil)
	if err != nil {
		app.Exposure, app.ExposureNote = model.ExposureUnknown, "not checked: could not build the request"
		return
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "text/html")

	resp, err := client.Do(req)
	if err != nil {
		note := "request failed (network, DNS or TLS); re-run with a working connection"
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			note = "request timed out; re-run later"
		}
		app.Exposure, app.ExposureNote = model.ExposureUnknown, note
		return
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if readErr != nil {
		app.HTTPStatus = resp.StatusCode
		app.Exposure, app.ExposureNote = model.ExposureUnknown, "could not read the home page response"
		if cfg.ScanSecrets {
			app.SecretScan = "not scanned: could not read the home page response"
		}
		return
	}

	app.HTTPStatus = resp.StatusCode
	app.Exposure, app.ExposureNote = Classify(Response{
		Status:          resp.StatusCode,
		CFMitigated:     resp.Header.Get(HeaderCFMitigated),
		RedirectOffHost: resp.StatusCode >= 300 && resp.StatusCode < 400,
		Body:            body,
	})

	if cfg.ScanSecrets && app.Exposure == model.ExposurePublic {
		if !scanEligible(app, cfg.ScanKeywordMatches) {
			app.SecretScan = "not scanned: tied to the org only by a keyword or a search result (--scan-keyword-matches includes it)"
			return
		}
		scanApp(ctx, client, app, body, cfg.UserAgent, budget)
	}
}

// scanEligible keeps the secret scan to apps with a reason to think they are the
// org's: seen on this host, or a custom domain under an --org-domain (allowed
// admits no other). A keyword or search match is a lead, not ownership, so
// scanning it for secrets needs --scan-keyword-matches.
func scanEligible(app *model.PublishedApp, keywordMatches bool) bool {
	return keywordMatches || len(app.Seen) > 0 || app.PointsTo != ""
}

// scanApp scans the home page already fetched and the same-host scripts it loads.
// Nothing fetched outlives this call.
func scanApp(ctx context.Context, client *http.Client, app *model.PublishedApp, page []byte, userAgent string, budget *atomic.Int64) {
	found, err := ScanAsset("/", page)
	if err != nil {
		app.SecretScan = "not scanned: the secret rules failed to load"
		return
	}
	paths := ScriptPaths(page, app.Host)
	scanned := 0
	var notes []string
	for _, p := range paths {
		if ctx.Err() != nil {
			notes = append(notes, "stopped early")
			break
		}
		reserved := reserveBudget(budget)
		if reserved == 0 {
			notes = append(notes, fmt.Sprintf("stopped at the per-run limit of %d MB", maxScanBytes>>20))
			break
		}
		data, truncated, ok := fetchScript(ctx, client, app.Host, p, userAgent, reserved)
		if int64(len(data)) < reserved {
			budget.Add(int64(len(data)) - reserved)
		}
		if !ok {
			continue
		}
		if truncated {
			if reserved < MaxScriptBytes {
				notes = append(notes, "stopped at the per-run limit of "+strconv.Itoa(maxScanBytes>>20)+" MB")
			} else {
				notes = append(notes, p+" read only to "+strconv.Itoa(MaxScriptBytes>>20)+" MB")
			}
		}
		hits, err := ScanAsset(p, data)
		if err != nil {
			continue
		}
		found = append(found, hits...)
		scanned++
	}
	app.Secrets = dedupeSecrets(found)
	app.SecretScan = fmt.Sprintf("scanned the home page and %d of %d same-host scripts", scanned, len(paths))
	if len(notes) > 0 {
		app.SecretScan += "; " + strings.Join(notes, "; ")
	}
}

func reserveBudget(budget *atomic.Int64) int64 {
	for {
		used := budget.Load()
		if used >= maxScanBytes {
			return 0
		}
		reservation := int64(MaxScriptBytes)
		if remaining := maxScanBytes - used; reservation > remaining {
			reservation = remaining
		}
		if budget.CompareAndSwap(used, used+reservation) {
			return reservation
		}
	}
}

// fetchScript GETs one same-host path with no cookies or credentials. Only a 200
// is scanned. The reserved byte limit bounds the read and a full reservation is
// conservatively reported as truncated.
func fetchScript(ctx context.Context, client *http.Client, host, path, userAgent string, limit int64) (data []byte, truncated, ok bool) {
	if !SafePath(path) {
		return nil, false, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return nil, false, false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, false
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return data, false, false
	}
	return data, int64(len(data)) == limit, true
}

// dedupeSecrets keeps one entry per rule and asset, server secrets first.
func dedupeSecrets(in []model.AppSecret) []model.AppSecret {
	seen := map[model.AppSecret]bool{}
	var out []model.AppSecret
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == model.SecretServer
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Asset < out[j].Asset
	})
	return out
}
