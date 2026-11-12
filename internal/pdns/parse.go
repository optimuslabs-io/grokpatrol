// Package pdns ties Grok Build app names found in free public sources to this
// user's org.
//
// Certificate transparency (crt.sh), urlscan.io and AlienVault OTX passive DNS list
// thousands of *.grok.me names, almost all of them other people's. This package
// narrows that list with three rules, each named on every app it adds: a name already
// found on this host (dated and attributed), a name containing an org keyword, and a
// custom domain under an org domain whose CNAME points into grok.me. It also takes
// grok.me URLs returned by web search (xAI's search tools, or Parallel/Perplexity via
// the Claude plugin) and admits only the ones that pass the same host checks.
//
// Everything in the untagged files is parsing and matching with no network code, so
// it is built and tested in every build. The HTTP clients are in sources_online.go,
// compiled only with -tags online.
package pdns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// Record is one observation of a name by one source.
type Record struct {
	Name   string // lowercased, no trailing dot
	Source string // "crt.sh", "urlscan", "otx", "grok-search", "web-search"
	RRType string // OTX only: "A", "CNAME", ...
	Target string // OTX CNAME target, lowercased, no trailing dot
	First  time.Time
	Last   time.Time
}

// maxBody bounds every response read: crt.sh answers for grok.me run to a few MB.
const maxBody = 64 << 20

func norm(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

// ParseCrtSh reads crt.sh's JSON output. One certificate can carry several names in
// name_value, separated by newlines; not_before is when the certificate was issued,
// which for a Grok app is close to when it was first published.
func ParseCrtSh(r io.Reader) ([]Record, error) {
	var rows []struct {
		NameValue string `json:"name_value"`
		NotBefore string `json:"not_before"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxBody)).Decode(&rows); err != nil {
		return nil, fmt.Errorf("crt.sh response is not the expected JSON: %w", err)
	}
	var out []Record
	for _, row := range rows {
		t, _ := time.Parse("2006-01-02T15:04:05", row.NotBefore)
		for _, n := range strings.Split(row.NameValue, "\n") {
			out = append(out, Record{Name: norm(n), Source: "crt.sh", First: t, Last: t})
		}
	}
	return out, nil
}

// ParseURLScan reads one page of urlscan.io search results. next is the search_after
// cursor for the following page, empty when there is none.
func ParseURLScan(r io.Reader) (recs []Record, next string, err error) {
	var resp struct {
		HasMore bool `json:"has_more"`
		Results []struct {
			Task struct {
				Domain string `json:"domain"`
				Time   string `json:"time"`
			} `json:"task"`
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
			Sort []any `json:"sort"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxBody)).Decode(&resp); err != nil {
		return nil, "", fmt.Errorf("urlscan response is not the expected JSON: %w", err)
	}
	for _, res := range resp.Results {
		t, _ := time.Parse(time.RFC3339Nano, res.Task.Time)
		for _, d := range []string{res.Task.Domain, res.Page.Domain} {
			if d != "" {
				recs = append(recs, Record{Name: norm(d), Source: "urlscan", First: t, Last: t})
			}
		}
	}
	if resp.HasMore && len(resp.Results) > 0 {
		var parts []string
		for _, v := range resp.Results[len(resp.Results)-1].Sort {
			switch x := v.(type) {
			case float64:
				parts = append(parts, fmt.Sprintf("%.0f", x))
			case string:
				parts = append(parts, x)
			}
		}
		next = strings.Join(parts, ",")
	}
	return recs, next, nil
}

// ParseOTX reads AlienVault OTX's passive_dns indicator response.
func ParseOTX(r io.Reader) ([]Record, error) {
	var resp struct {
		PassiveDNS []struct {
			Hostname   string `json:"hostname"`
			Address    string `json:"address"`
			RecordType string `json:"record_type"`
			First      string `json:"first"`
			Last       string `json:"last"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxBody)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("OTX response is not the expected JSON: %w", err)
	}
	var out []Record
	for _, p := range resp.PassiveDNS {
		rec := Record{Name: norm(p.Hostname), Source: "otx", RRType: strings.ToUpper(p.RecordType)}
		if rec.RRType == "CNAME" {
			rec.Target = norm(p.Address)
		}
		rec.First, _ = time.Parse("2006-01-02T15:04:05", p.First)
		rec.Last, _ = time.Parse("2006-01-02T15:04:05", p.Last)
		out = append(out, rec)
	}
	return out, nil
}

// ParseXAICitations reads an xAI Responses API reply and returns only the URLs the
// search tools cited: the top-level citations list and url_citation annotations.
// The model's own prose is never mined for hostnames, because a model can write a
// plausible name that does not exist.
func ParseXAICitations(r io.Reader) ([]string, error) {
	var resp struct {
		Citations []string `json:"citations"`
		Output    []struct {
			Content []struct {
				Annotations []struct {
					Type string `json:"type"`
					URL  string `json:"url"`
				} `json:"annotations"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxBody)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("xAI response is not the expected JSON: %w", err)
	}
	out := append([]string(nil), resp.Citations...)
	for _, o := range resp.Output {
		for _, c := range o.Content {
			for _, a := range c.Annotations {
				if a.Type == "url_citation" && a.URL != "" {
					out = append(out, a.URL)
				}
			}
		}
	}
	return out, nil
}

// HostOf returns the lowercased host of a URL or bare hostname, or "".
func HostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.Port() != "" {
		return ""
	}
	return norm(u.Hostname())
}
