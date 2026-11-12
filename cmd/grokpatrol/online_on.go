//go:build online

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/buildinfo"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/apps"
	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/exposure"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/pdns"
)

// onlineOpts are the flags that exist only in the grokpatrol-online build
// (-tags online); the standard binary has none of them and no network code.
type onlineOpts struct {
	checkExposure      bool
	scanPublic         bool
	scanKeywordMatches bool
	discover           bool
	grokSearch         bool
	grokModel          string
	appHosts           string
	orgKeywords        repeatable
	orgDomains         repeatable
}

var online onlineOpts

// maxAppHostsBytes bounds --app-hosts: it is a list of URLs, not a dataset.
const maxAppHostsBytes = 4 << 20

func registerOnlineFlags() {
	flag.BoolVar(&online.checkExposure, "check-exposure", false,
		"after the scan, make one unauthenticated request to each grok.me app found, to see whether it opens without sign-in (network)")
	flag.BoolVar(&online.scanPublic, "scan-public", false,
		"for each app that opens without sign-in, also fetch up to 8 of its same-host scripts and scan them and the home page in memory for secrets; implies --check-exposure (network)")
	flag.BoolVar(&online.scanKeywordMatches, "scan-keyword-matches", false,
		"with --scan-public, also scan apps tied to the org only by a keyword or a search result, not just apps seen on this machine or under --org-domain")
	flag.BoolVar(&online.discover, "discover", false,
		"list grok.me names from free public sources: crt.sh, urlscan.io ($URLSCAN_API_KEY optional) and AlienVault OTX ($OTX_API_KEY, free) (network)")
	flag.BoolVar(&online.grokSearch, "grok-search", false,
		"ask the xAI API's web and X search for grok.me apps matching the org keywords; needs $XAI_API_KEY and bills its API credits (network)")
	flag.StringVar(&online.grokModel, "grok-model", "grok-4.7", "with --grok-search, the xAI model to use")
	flag.StringVar(&online.appHosts, "app-hosts", "", "file of grok.me URLs or hosts from a web search, one per line (the Claude plugin writes it)")
	flag.Var(&online.orgKeywords, "org-keyword", "report grok.me apps whose name contains this word (repeatable)")
	flag.Var(&online.orgDomains, "org-domain", "your org's domain: its name becomes a keyword, and custom domains under it that point at grok.me are reported (repeatable)")
}

// configureOnline validates the online flags and records them on env. A non-nil
// error is a usage error (exit 1), never a finding.
func configureOnline(env *engine.Env) error {
	if online.scanKeywordMatches && !online.scanPublic {
		return fmt.Errorf("--scan-keyword-matches needs --scan-public")
	}
	env.CheckExposure = online.checkExposure || online.scanPublic
	env.ScanPublic, env.ScanKeywordMatches = online.scanPublic, online.scanKeywordMatches
	if online.grokSearch && os.Getenv("XAI_API_KEY") == "" {
		return fmt.Errorf("--grok-search needs an xAI API key in $XAI_API_KEY (grokpatrol never reads ~/.grok/auth.json)")
	}
	var domains []string
	for _, d := range online.orgDomains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if !pdns.ValidDomain(d) {
			return fmt.Errorf("--org-domain %q is not a domain name", d)
		}
		domains = append(domains, d)
	}
	keywords, dropped := pdns.Keywords(domains, pdns.GitEmails(env.Home), online.orgKeywords)
	if len(dropped) > 0 {
		fmt.Fprintf(os.Stderr, "grokpatrol: ignoring keywords shorter than 4 characters or not a-z0-9-: %s\n", strings.Join(dropped, ", "))
	}
	if online.grokSearch && len(keywords) == 0 {
		return fmt.Errorf("--grok-search needs an org keyword: pass --org-keyword or --org-domain")
	}
	env.Discover, env.GrokSearch, env.AppHosts = online.discover, online.grokSearch, online.appHosts != ""
	env.OrgKeywords, env.OrgDomains = keywords, domains
	return nil
}

// runOnline does the opt-in network work after the offline scan: the public sources
// first (they can add apps), then the exposure check over everything found.
func runOnline(ctx context.Context, env *engine.Env, rep *model.Report, prog engine.Progress) {
	if env.AppHosts {
		addAppHosts(rep, env.OrgDomains, prog)
	}
	if env.Discover || env.GrokSearch {
		var sources []pdns.Source
		var cnames pdns.CNAMESource
		var used []string
		if env.Discover {
			sources = append(sources, pdns.NewCrtSh(), pdns.NewURLScan(os.Getenv("URLSCAN_API_KEY")))
			used = append(used, "crt.sh", "urlscan")
			if k := os.Getenv("OTX_API_KEY"); k != "" {
				otx := pdns.NewOTX(k)
				sources, cnames = append(sources, otx), otx
				used = append(used, "OTX")
			} else {
				rep.AddAppLimitations("AlienVault OTX was skipped: set $OTX_API_KEY (free) for its passive " +
					"DNS names and to find custom domains under --org-domain.")
			}
		}
		if env.GrokSearch {
			sources = append(sources, pdns.NewGrokSearch(os.Getenv("XAI_API_KEY"), online.grokModel))
			used = append(used, "Grok search")
		}
		if prog != nil {
			prog.Checking("discover", fmt.Sprintf("asking %s for grok.me names; matching %s and custom domains under %s (network)",
				strings.Join(used, ", "), orList(env.OrgKeywords, "no keywords"), orList(env.OrgDomains, "no org domain")))
		}
		start := time.Now()
		res := pdns.Enrich(ctx, sources, cnames, rep, env.OrgKeywords, env.OrgDomains)
		rep.Errors = append(rep.Errors, res.Errors...)
		rep.AddAppLimitations(res.Limitations...)
		if prog != nil {
			summary := engine.Plural(res.Added, "app") + " added from public sources"
			if len(res.Errors) > 0 {
				summary += fmt.Sprintf(" (%d sources failed; see the report)", len(res.Errors))
			}
			prog.Checked("discover", summary, time.Since(start))
		}
	}
	if env.CheckExposure && len(rep.Apps) > 0 {
		if prog != nil {
			prog.Checking("exposure", fmt.Sprintf("requesting the home page of %s without signing in (network)",
				engine.Plural(len(rep.Apps), "app")))
		}
		start := time.Now()
		ua := "grokpatrol/" + buildinfo.Version + " (exposure check; +https://github.com/optimuslabs-io/grokpatrol)"
		exposure.Check(ctx, rep.Apps, exposure.Config{
			UserAgent: ua, OrgDomains: env.OrgDomains,
			ScanSecrets: env.ScanPublic, ScanKeywordMatches: env.ScanKeywordMatches,
		})
		if prog != nil {
			open, leaking := 0, 0
			for _, a := range rep.Apps {
				if a.Exposure == model.ExposurePublic {
					open++
				}
				if len(a.Secrets) > 0 {
					leaking++
				}
			}
			summary := fmt.Sprintf("%d of %d open without sign-in", open, len(rep.Apps))
			if env.ScanPublic {
				summary += fmt.Sprintf("; %d serve a key or secret", leaking)
			}
			prog.Checked("exposure", summary, time.Since(start))
		}
	}
}

// addAppHosts reads --app-hosts. Its lines are untrusted (search results), so only
// counts are printed, never the lines themselves.
func addAppHosts(rep *model.Report, orgDomains []string, prog engine.Progress) {
	b, err := hostfs.ReadFileCapped(online.appHosts, maxAppHostsBytes)
	if err != nil {
		rep.Errors = append(rep.Errors, model.ScanError{Detector: "app-hosts", Kind: "io", Path: online.appHosts, Message: apps.ErrText(err)})
		return
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	added, rejected := pdns.AddHosts(rep, lines, orgDomains)
	if prog != nil {
		prog.Checking("app-hosts", "reading grok.me URLs from "+online.appHosts)
		prog.Checked("app-hosts", fmt.Sprintf("%s added, %d lines rejected (not a grok.me app or a domain under --org-domain)",
			engine.Plural(added, "app"), rejected), 0)
	}
}

func orList(v []string, none string) string {
	if len(v) == 0 {
		return none
	}
	return strings.Join(v, ", ")
}
