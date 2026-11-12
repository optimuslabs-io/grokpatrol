package pdns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/detect/apps"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Source lists grok.me names. keywords are the org keywords, for a source that
// searches by them (xAI search); a source that lists every name ignores them.
// limited reports that the source stopped at a cap, so its list is incomplete.
type Source interface {
	Name() string
	Names(ctx context.Context, keywords []string) (recs []Record, limited bool, err error)
}

// CNAMESource lists DNS records under an org domain, for finding custom domains
// that point into grok.me. Only OTX provides it.
type CNAMESource interface {
	OrgRecords(ctx context.Context, domain string) ([]Record, error)
}

// minKeyword stops short words ("ai", "app", "dev") from matching half of grok.me.
const minKeyword = 4

// freeMail domains say nothing about an employer, so they never become keywords.
var freeMail = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "outlook.com": true, "hotmail.com": true,
	"live.com": true, "msn.com": true, "icloud.com": true, "me.com": true, "mac.com": true,
	"yahoo.com": true, "proton.me": true, "protonmail.com": true, "pm.me": true, "aol.com": true,
	"gmx.com": true, "gmx.net": true, "fastmail.com": true, "hey.com": true, "zoho.com": true,
	"users.noreply.github.com": true,
}

// twoPartSuffixes are public suffixes with two labels, so acme.co.uk gives "acme".
var twoPartSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "com.au": true, "net.au": true,
	"co.nz": true, "co.jp": true, "co.in": true, "com.br": true, "com.sg": true, "co.za": true,
}

// ValidDomain reports whether d is a plain DNS name with at least two labels.
func ValidDomain(d string) bool {
	if len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// KeywordOf returns the organisation label of a domain: acme.com and acme.co.uk
// both give "acme". Free-mail and invalid domains give "".
func KeywordOf(domain string) string {
	d := norm(domain)
	if !ValidDomain(d) || freeMail[d] {
		return ""
	}
	labels := strings.Split(d, ".")
	n := len(labels)
	if n >= 3 && twoPartSuffixes[labels[n-2]+"."+labels[n-1]] {
		return labels[n-3]
	}
	return labels[n-2]
}

// Keywords builds the deduplicated, sorted keyword list from org domains, git
// emails and explicit keywords. Anything shorter than minKeyword or not a-z0-9-
// is dropped, and dropped keywords are returned so the caller can say so.
func Keywords(orgDomains, emails, extra []string) (keep, dropped []string) {
	seen := map[string]bool{}
	add := func(k string) {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		if len(k) < minKeyword || !ValidDomain(k+".x") {
			dropped = append(dropped, k)
			return
		}
		keep = append(keep, k)
	}
	for _, d := range orgDomains {
		add(KeywordOf(d))
	}
	for _, e := range emails {
		if at := strings.LastIndexByte(e, '@'); at >= 0 {
			add(KeywordOf(e[at+1:]))
		}
	}
	for _, k := range extra {
		add(k)
	}
	sort.Strings(keep)
	return keep, dropped
}

// GitEmails reads user.email from the user's global git config files. These are
// plain config, not credentials; ~/.grok/auth.json is never opened.
func GitEmails(home string) []string {
	var out []string
	for _, p := range []string{filepath.Join(home, ".gitconfig"), filepath.Join(home, ".config", "git", "config")} {
		b, err := hostfs.ReadFileCapped(p, 1<<20)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "email") {
				out = append(out, strings.Trim(strings.TrimSpace(v), `"`))
			}
		}
	}
	return out
}

// under reports whether host is d or a name below it.
func under(host, d string) bool { return host == d || strings.HasSuffix(host, "."+d) }

// grokName returns the canonical grok.me app name for s, or "".
func grokName(s string) string {
	s = norm(s)
	if h := apps.Hosts([]byte(s)); len(h) == 1 && h[0] == s {
		return s
	}
	return ""
}

// sighting is everything the sources said about one name.
type sighting struct {
	first, last time.Time
	sources     []string
}

func (s *sighting) add(r Record) {
	if !r.First.IsZero() && (s.first.IsZero() || r.First.Before(s.first)) {
		s.first = r.First
	}
	if r.Last.After(s.last) {
		s.last = r.Last
	}
	if !slices.Contains(s.sources, r.Source) {
		s.sources = append(s.sources, r.Source)
		sort.Strings(s.sources)
	}
}

// apply merges a sighting into an app: earliest first seen, latest last seen, and
// the union of sources.
func (s *sighting) apply(a *model.PublishedApp) {
	if !s.first.IsZero() && (a.FirstSeen == nil || s.first.Before(*a.FirstSeen)) {
		f := s.first
		a.FirstSeen = &f
	}
	if !s.last.IsZero() && (a.LastSeen == nil || s.last.After(*a.LastSeen)) {
		l := s.last
		a.LastSeen = &l
	}
	for _, src := range s.sources {
		if !slices.Contains(a.Sources, src) {
			a.Sources = append(a.Sources, src)
		}
	}
	sort.Strings(a.Sources)
}

// Result is what Enrich could not do, for the report.
type Result struct {
	Errors      []model.ScanError
	Limitations []string
	Added       int
}

// Enrich queries every source, merges what they return, and applies the rules to
// rep.Apps: apps found on this host are dated and attributed (rule 1), names with
// an org keyword are added (rule 2), and custom domains under an org domain that
// CNAME into grok.me are added (rule 3, needs cnames). It never removes an app or
// changes the Host of one it did not add. A failing source is reported, never fatal.
func Enrich(ctx context.Context, sources []Source, cnames CNAMESource, rep *model.Report, keywords, orgDomains []string) Result {
	var res Result
	fail := func(what string, err error) {
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "discover", Kind: "io", Message: what + ": " + err.Error(), Material: false,
		})
	}
	index := map[string]int{}
	for i, a := range rep.Apps {
		index[a.Host] = i
	}
	add := func(a model.PublishedApp) {
		index[a.Host] = len(rep.Apps)
		rep.Apps = append(rep.Apps, a)
		res.Added++
	}

	seen := map[string]*sighting{}
	for _, src := range sources {
		recs, limited, err := src.Names(ctx, keywords)
		if err != nil {
			fail(src.Name(), err)
			continue
		}
		if limited {
			res.Limitations = append(res.Limitations, src.Name()+" stopped at its result cap, so names from it may be incomplete.")
		}
		for _, r := range recs {
			if h := grokName(r.Name); h != "" {
				if seen[h] == nil {
					seen[h] = &sighting{}
				}
				seen[h].add(r)
			}
		}
	}

	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		s := seen[h]
		if i, ok := index[h]; ok { // rule 1, or a name a search returned again
			s.apply(&rep.Apps[i])
		}
		// Search results were found BY the org keywords, so they count as matched.
		searched := slices.Contains(s.sources, "grok-search")
		label := strings.TrimSuffix(h, ".grok.me")
		for _, k := range keywords {
			if !strings.Contains(label, k) {
				continue
			}
			why := fmt.Sprintf("org keyword %q in the name", k)
			if i, ok := index[h]; ok {
				if rep.Apps[i].MatchedBy == "" {
					rep.Apps[i].MatchedBy = why
				}
			} else {
				a := model.PublishedApp{Host: h, Source: model.AppSourcePassiveDNS, MatchedBy: why}
				s.apply(&a)
				add(a)
			}
			searched = false
			break
		}
		if _, ok := index[h]; !ok && searched {
			a := model.PublishedApp{Host: h, Source: model.AppSourceWebSearch,
				MatchedBy: "returned by Grok web/X search for the org keywords"}
			s.apply(&a)
			add(a)
		}
	}

	if cnames != nil {
		for _, d := range orgDomains {
			recs, err := cnames.OrgRecords(ctx, d)
			if err != nil {
				fail("custom domains under "+d, err)
				continue
			}
			var found []string
			targets, spans := map[string]string{}, map[string]*sighting{}
			for _, r := range recs {
				if r.RRType != "CNAME" || !under(r.Name, d) || !ValidDomain(r.Name) {
					continue
				}
				if r.Target != "grok.me" && !strings.HasSuffix(r.Target, ".grok.me") || !ValidDomain(r.Target) {
					continue
				}
				if _, ok := targets[r.Name]; !ok {
					found = append(found, r.Name)
					spans[r.Name] = &sighting{}
				}
				targets[r.Name] = r.Target
				spans[r.Name].add(r)
			}
			sort.Strings(found)
			for _, h := range found {
				if _, ok := index[h]; ok {
					continue
				}
				a := model.PublishedApp{
					Host: h, Source: model.AppSourcePassiveDNS, PointsTo: targets[h],
					MatchedBy: fmt.Sprintf("custom domain under %s, CNAME to %s", d, targets[h]),
				}
				spans[h].apply(&a)
				add(a)
			}
		}
		if len(orgDomains) > 0 {
			res.Limitations = append(res.Limitations, "Custom domains are found by CNAME in OTX only. A domain pointed at "+
				"Grok's hosting with A records (an apex domain, say) is not matched.")
		}
	}
	return res
}

// AddHosts admits URLs or hostnames returned by an external web search (the Claude
// plugin's Parallel/Perplexity lookups, via --app-hosts). A line is kept only if its
// host is exactly one label under grok.me, or a name under one of orgDomains; the
// rest are counted, never echoed, because they are untrusted input.
func AddHosts(rep *model.Report, lines []string, orgDomains []string) (added, rejected int) {
	index := map[string]int{}
	for i, a := range rep.Apps {
		index[a.Host] = i
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h := HostOf(line)
		g := grokName(h)
		custom := g == "" && ValidDomain(h) && slices.ContainsFunc(orgDomains, func(d string) bool { return under(h, d) })
		if g == "" && !custom {
			rejected++
			continue
		}
		if g != "" {
			h = g
		}
		if i, ok := index[h]; ok {
			if !slices.Contains(rep.Apps[i].Sources, "web-search") {
				rep.Apps[i].Sources = append(rep.Apps[i].Sources, "web-search")
				sort.Strings(rep.Apps[i].Sources)
			}
			continue
		}
		a := model.PublishedApp{Host: h, Source: model.AppSourceWebSearch, Sources: []string{"web-search"},
			MatchedBy: "returned by web search (--app-hosts)"}
		if custom {
			// A custom domain from search has no CNAME evidence behind it. PointsTo stays
			// empty, so the exposure check will not contact it.
			a.MatchedBy = "returned by web search (--app-hosts); custom domain, not checked"
		}
		index[h] = len(rep.Apps)
		rep.Apps = append(rep.Apps, a)
		added++
	}
	return added, rejected
}
