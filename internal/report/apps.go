package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// maxAppRows caps GROK.ME APPS in the default report; --verbose and --json list all.
const maxAppRows = 10

// apps renders GROK.ME APPS: Grok Build app addresses seen on this host and, when the
// online check ran, whether each one opens for a stranger. It sits apart from the
// verdict on purpose: the verdict answers "were my repositories taken", and an app in
// browser history may be somebody else's.
func apps(w io.Writer, rep *model.Report, s Style) {
	if len(rep.Apps) == 0 {
		return
	}
	list := append([]model.PublishedApp(nil), rep.Apps...)
	sort.SliceStable(list, func(i, j int) bool {
		ri, rj := exposureRank(list[i].Exposure), exposureRank(list[j].Exposure)
		if ri != rj {
			return ri < rj
		}
		return list[i].Host < list[j].Host
	})

	local := 0
	for _, a := range list {
		if len(a.Seen) > 0 {
			local++
		}
	}
	sub := fmt.Sprintf("   (%d seen on this machine -- opened or typed here, not necessarily yours)", local)
	if rep.Options.Discover || rep.Options.GrokSearch || rep.Options.AppHosts {
		sub = fmt.Sprintf("   (%d seen on this machine, %d more from public sources -- not necessarily yours)",
			local, len(list)-local)
	}
	fmt.Fprintln(w, s.c(bold, "GROK.ME APPS")+s.c(dim, sub))

	if rep.Options.CheckExposure {
		open := 0
		for _, a := range list {
			if a.Exposure == model.ExposurePublic {
				open++
			}
		}
		if open > 0 {
			fmt.Fprintf(w, "  %s %s\n", s.c(red+bold, "Open:"),
				wrap(fmt.Sprintf("%d opened with no sign-in. If any is yours, set its access to Only you or Invited "+
					"users in Grok's publish settings, and assume anything it held has been seen.", open), 88, "        "))
		}
	}
	secretBanners(w, list, s)

	rows := [][]string{{s.c(dim, "HOST"), s.c(dim, "EXPOSURE"), s.c(dim, "SEEN IN")}}
	shown := list
	if !s.Verbose && len(shown) > maxAppRows {
		shown = shown[:maxAppRows]
	}
	for _, a := range shown {
		host := a.Host
		if s.Color {
			host = s.c(cyan, host)
		}
		rows = append(rows, []string{host, exposureCell(a.Exposure, s) + secretsCell(a, s), seenIn(a, s.Verbose)})
	}
	writeTable(w, "  ", rows)
	if omitted := len(list) - len(shown); omitted > 0 {
		fmt.Fprintf(w, "  %s\n", s.c(dim, fmt.Sprintf("  +%d more -- --verbose or --json lists every app", omitted)))
	}

	if s.Verbose {
		for _, a := range list {
			fmt.Fprintf(w, "  %s\n", s.c(dim, a.Host+":"))
			if a.MatchedBy != "" {
				fmt.Fprintf(w, "    %s %s\n", s.c(dim, "matched:"), a.MatchedBy)
			}
			if len(a.Sources) > 0 {
				fmt.Fprintf(w, "    %s %s\n", s.c(dim, "sources:"), strings.Join(a.Sources, ", "))
			}
			if a.FirstSeen != nil || a.LastSeen != nil {
				fmt.Fprintf(w, "    %s %s to %s\n", s.c(dim, "seen:"), day(a.FirstSeen), day(a.LastSeen))
			}
			if a.ExposureNote != "" {
				fmt.Fprintf(w, "    %s %s\n", s.c(dim, "exposure:"), wrap(a.ExposureNote, 84, "      "))
			}
			for _, sec := range a.Secrets {
				fmt.Fprintf(w, "    %s %s in %s (%s)\n", s.c(dim, "secret:"), sec.Rule, sec.Asset, secretKindText(sec.Kind))
			}
			if a.SecretScan != "" {
				fmt.Fprintf(w, "    %s %s\n", s.c(dim, "secret scan:"), wrap(a.SecretScan, 80, "      "))
			}
			for _, e := range a.Seen {
				fmt.Fprintf(w, "    %s %s %s\n", s.c(dim, "-"), s.c(cyan, e.Path), s.c(dim, "("+e.Note+")"))
			}
		}
	}
	if !rep.Options.CheckExposure {
		fmt.Fprintf(w, "  %s\n", s.c(dim, wrap("Whether these open without sign-in needs a network request: "+
			"grokpatrol-online --check-exposure makes one unauthenticated request per app.", 88, "  ")))
	}
	fmt.Fprintln(w)
}

// day renders a passive DNS timestamp as a date; times of day are noise here.
func day(t *time.Time) string {
	if t == nil {
		return "?"
	}
	return t.Format("2006-01-02")
}

func exposureRank(e model.Exposure) int {
	switch e {
	case model.ExposurePublic:
		return 0
	case model.ExposureAppSignIn:
		return 1
	case model.ExposureUnknown:
		return 2
	case model.ExposureRestricted:
		return 3
	case model.ExposureNotFound:
		return 4
	}
	return 5 // not checked
}

func exposureCell(e model.Exposure, s Style) string {
	switch e {
	case model.ExposurePublic:
		return s.c(red+bold, "PUBLIC")
	case model.ExposureAppSignIn:
		return s.c(yellow, "APP SIGN-IN")
	case model.ExposureRestricted:
		return s.c(green, "RESTRICTED")
	case model.ExposureNotFound:
		return s.c(dim, "NOT FOUND")
	case model.ExposureUnknown:
		return s.c(yellow, "UNKNOWN")
	}
	return s.c(dim, "not checked")
}

// seenIn names the first place an address was found and counts the rest. An app
// found only in passive DNS shows the rule that tied it to this org instead.
func seenIn(a model.PublishedApp, verbose bool) string {
	seen := a.Seen
	if len(seen) == 0 {
		if a.MatchedBy != "" {
			return a.MatchedBy
		}
		return "public source"
	}
	cell := seen[0].Note
	if len(seen) > 1 && !verbose {
		cell += fmt.Sprintf(" (+%d)", len(seen)-1)
	} else if len(seen) > 1 {
		cell += fmt.Sprintf(" (+%d, below)", len(seen)-1)
	}
	return cell
}

// secretBanners says what to do about keys found in public apps, server secrets
// first. Rule ids only: the report never holds a value.
func secretBanners(w io.Writer, list []model.PublishedApp, s Style) {
	server, browser := map[string]bool{}, map[string]bool{}
	nServer, nBrowser := 0, 0
	for _, a := range list {
		hasServer, hasBrowser := false, false
		for _, sec := range a.Secrets {
			if sec.Kind == model.SecretServer {
				server[sec.Rule], hasServer = true, true
			} else {
				browser[sec.Rule], hasBrowser = true, true
			}
		}
		if hasServer {
			nServer++
		}
		if hasBrowser {
			nBrowser++
		}
	}
	if nServer > 0 {
		fmt.Fprintf(w, "  %s %s\n", s.c(red+bold, "ACTION:"),
			wrap(fmt.Sprintf("Anyone who opens %s gets a server secret (%s). If one is yours, revoke and "+
				"rotate the key now, assume it has been used, and move it into a server-side function or secret store.",
				engine.Plural(nServer, "public app"), strings.Join(sortedKeys(server), ", ")), 86, "          "))
	}
	if nBrowser > 0 {
		fmt.Fprintf(w, "  %s %s\n", s.c(yellow+bold, "Check:"),
			wrap(fmt.Sprintf("Keys made for browsers ship in %s (%s). They are safe only if restricted: check "+
				"each key's allowed sites and APIs with its provider.", engine.Plural(nBrowser, "public app"),
				strings.Join(sortedKeys(browser), ", ")), 86, "         "))
	}
}

func secretsCell(a model.PublishedApp, s Style) string {
	server := 0
	for _, sec := range a.Secrets {
		if sec.Kind == model.SecretServer {
			server++
		}
	}
	switch {
	case server > 0:
		return s.c(red+bold, " + SECRET")
	case len(a.Secrets) > 0:
		return s.c(yellow, " + browser key")
	}
	return ""
}

func secretKindText(k model.SecretKind) string {
	if k == model.SecretServer {
		return "server secret: rotate"
	}
	return "browser key: check its restrictions"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
