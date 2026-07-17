// Content-based secret detection, active only under --full-secrets-search.
//
// The engine is a stdlib-only port of gitleaks' detection flow (keyword
// prefilter -> regex -> entropy gate -> allowlists); the rule table it runs is
// generated from gitleaks' MIT-licensed corpus (see rules_gen.go and
// gitleaks/LICENSE). Two deliberate simplifications, documented fidelity gaps
// against upstream: no base64/hex decode-then-rescan pass, and the Aho-Corasick
// keyword prefilter is a plain substring sweep (identical answers, slower --
// fine at per-repo blob volumes, and blobs are already capped by
// --max-blob-scan-bytes).
//
// THE ONE RULE OF THIS FILE: matched bytes never leave it. Not in a return
// value, not in an error, not in a note or progress string. Until this engine
// existed, a secret's value never entered the process at all; now that it lives
// in transient buffers here, the only thing allowed out is WHICH rule matched
// WHERE. Anything more is a leak the report layer can't take back.
package secrets

//go:generate go run ./gitleaks/gen

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
)

// contentRule and allowList mirror gitleaks' config.Rule / config.Allowlist,
// reduced to the fields the default corpus actually uses. rules_gen.go fills
// them with data; nothing else does.
type contentRule struct {
	ID          string
	Regex       string
	Path        string
	Entropy     float64
	SecretGroup int
	Keywords    []string
	Allow       []allowList
}

type allowList struct {
	// CondAND requires every configured component (regexes, paths, stopwords) to
	// hit before the allowlist applies; the default is any-of.
	CondAND     bool
	RegexTarget string // what Regexes test: "" = the secret, "match", or "line"
	Regexes     []string
	Paths       []string
	Stopwords   []string
}

// ruleSet is the compiled engine. Compilation is deferred until the first scan
// because the default (filename-only) run never needs these ~240 regexes.
type ruleSet struct {
	rules    []compiledRule
	global   compiledAllow
	keywords []string // every distinct lowercased keyword across all rules
	maxKwLen int
}

type compiledRule struct {
	id       string
	re       *regexp.Regexp // nil for the one path-only rule (pkcs12-file)
	pathRE   *regexp.Regexp
	entropy  float64
	group    int
	keywords []string // lowercased; empty means "always run the regex"
	allow    []compiledAllow
}

type compiledAllow struct {
	condAND   bool
	target    string
	res       []*regexp.Regexp
	paths     []*regexp.Regexp
	stopwords []string // lowercased
}

var (
	rulesOnce sync.Once
	rulesSet  *ruleSet
	rulesErr  error
)

// compiledRules compiles the generated table exactly once. An error here is a
// build defect (the compile-all test pins every pattern), but it is still
// returned rather than panicked: a crash must never read as a clean host.
func compiledRules() (*ruleSet, error) {
	rulesOnce.Do(func() { rulesSet, rulesErr = compileRules(contentRules, globalAllow) })
	return rulesSet, rulesErr
}

func compileRules(rules []contentRule, global allowList) (*ruleSet, error) {
	rs := &ruleSet{}
	var err error
	if rs.global, err = compileAllow(global); err != nil {
		return nil, fmt.Errorf("global allowlist: %w", err)
	}

	seenKw := map[string]bool{}
	for _, r := range rules {
		cr := compiledRule{id: r.ID, entropy: r.Entropy, group: r.SecretGroup}
		if r.Regex != "" {
			if cr.re, err = regexp.Compile(r.Regex); err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		if r.Path != "" {
			if cr.pathRE, err = regexp.Compile(r.Path); err != nil {
				return nil, fmt.Errorf("rule %s path: %w", r.ID, err)
			}
		}
		for _, kw := range r.Keywords {
			kw = strings.ToLower(kw)
			cr.keywords = append(cr.keywords, kw)
			if !seenKw[kw] {
				seenKw[kw] = true
				rs.keywords = append(rs.keywords, kw)
				if len(kw) > rs.maxKwLen {
					rs.maxKwLen = len(kw)
				}
			}
		}
		for _, a := range r.Allow {
			ca, aerr := compileAllow(a)
			if aerr != nil {
				return nil, fmt.Errorf("rule %s allowlist: %w", r.ID, aerr)
			}
			cr.allow = append(cr.allow, ca)
		}
		rs.rules = append(rs.rules, cr)
	}
	return rs, nil
}

func compileAllow(a allowList) (compiledAllow, error) {
	ca := compiledAllow{condAND: a.CondAND, target: a.RegexTarget}
	for _, p := range a.Regexes {
		re, err := regexp.Compile(p)
		if err != nil {
			return ca, err
		}
		ca.res = append(ca.res, re)
	}
	for _, p := range a.Paths {
		re, err := regexp.Compile(p)
		if err != nil {
			return ca, err
		}
		ca.paths = append(ca.paths, re)
	}
	for _, s := range a.Stopwords {
		ca.stopwords = append(ca.stopwords, strings.ToLower(s))
	}
	return ca, nil
}

// pathSkipped reports whether the global allowlist excludes this path from
// content scanning entirely (lockfiles, images, vendored trees, ...).
func (rs *ruleSet) pathSkipped(path string) bool {
	for _, re := range rs.global.paths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// scan runs every applicable rule over one file's contents and returns the ids
// of the rules that produced at least one surviving finding. Rule ids and
// nothing else: the matched bytes stay in this stack frame.
func (rs *ruleSet) scan(path string, data []byte) []string {
	text := string(data)
	lower := strings.ToLower(text)

	// Keyword presence for the whole buffer, computed once and shared by every
	// rule that lists the keyword (upstream uses Aho-Corasick for this).
	present := map[string]bool{}
	for _, kw := range rs.keywords {
		if strings.Contains(lower, kw) {
			present[kw] = true
		}
	}

	var ids []string
	for i := range rs.rules {
		r := &rs.rules[i]
		if r.pathRE != nil && !r.pathRE.MatchString(path) {
			continue
		}
		if r.re == nil {
			// Path-only rule: the path itself is the finding.
			if r.pathRE != nil {
				ids = append(ids, r.id)
			}
			continue
		}
		if len(r.keywords) > 0 && !anyPresent(present, r.keywords) {
			continue
		}
		if rs.ruleHits(r, path, text, lower) {
			ids = append(ids, r.id)
		}
	}
	return ids
}

func anyPresent(present map[string]bool, kws []string) bool {
	for _, kw := range kws {
		if present[kw] {
			return true
		}
	}
	return false
}

// ruleHits reports whether the rule produces at least one match that survives
// the entropy gate and every allowlist. It deliberately returns only a bool.
func (rs *ruleSet) ruleHits(r *compiledRule, path, text, lower string) bool {
	for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
		match := text[m[0]:m[1]]
		secret, ok := secretOf(r, text, m)
		if !ok {
			continue
		}
		if r.entropy != 0 && shannonEntropy(secret) <= r.entropy {
			continue
		}
		line := lineAround(text, m[0], m[1])
		if allowed(rs.global, path, secret, match, line) {
			continue
		}
		anyAllowed := false
		for _, a := range r.allow {
			if allowed(a, path, secret, match, line) {
				anyAllowed = true
				break
			}
		}
		if anyAllowed {
			continue
		}
		return true
	}
	return false
}

// secretOf extracts the candidate secret from one match, mirroring gitleaks:
// an explicit SecretGroup wins, else the first non-empty capture group, else
// the whole match.
func secretOf(r *compiledRule, text string, m []int) (string, bool) {
	if r.group > 0 {
		if 2*r.group+1 >= len(m) || m[2*r.group] < 0 {
			return "", false // the group the rule promises does not exist: no finding
		}
		return text[m[2*r.group]:m[2*r.group+1]], true
	}
	for g := 1; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 && m[2*g+1] > m[2*g] {
			return text[m[2*g]:m[2*g+1]], true
		}
	}
	return text[m[0]:m[1]], true
}

// allowed reports whether one allowlist suppresses this match.
//
// OR semantics (the default): any configured component hitting is enough.
// AND semantics: every configured component must hit.
func allowed(a compiledAllow, path, secret, match, line string) bool {
	type comp struct {
		configured bool
		hit        bool
	}
	target := secret
	switch a.target {
	case "match":
		target = match
	case "line":
		target = line
	}

	regexes := comp{configured: len(a.res) > 0}
	for _, re := range a.res {
		if re.MatchString(target) {
			regexes.hit = true
			break
		}
	}
	paths := comp{configured: len(a.paths) > 0}
	for _, re := range a.paths {
		if re.MatchString(path) {
			paths.hit = true
			break
		}
	}
	stops := comp{configured: len(a.stopwords) > 0}
	lowerSecret := strings.ToLower(secret)
	for _, sw := range a.stopwords {
		if strings.Contains(lowerSecret, sw) {
			stops.hit = true
			break
		}
	}

	if a.condAND {
		for _, c := range []comp{regexes, paths, stops} {
			if c.configured && !c.hit {
				return false
			}
		}
		return regexes.configured || paths.configured || stops.configured
	}
	return regexes.hit || paths.hit || stops.hit
}

// lineAround widens a match to the enclosing line, for allowlists with
// regexTarget = "line" (e.g. Dockerfile --mount=type=secret).
func lineAround(text string, start, end int) string {
	ls := strings.LastIndexByte(text[:start], '\n') + 1
	le := strings.IndexByte(text[end:], '\n')
	if le < 0 {
		return text[ls:]
	}
	return text[ls : end+le]
}

// shannonEntropy is gitleaks' entropy gate, reproduced exactly -- including
// the quirk that frequencies are per RUNE while the denominator is the BYTE
// length. Faithfulness beats elegance here: a "better" formula would silently
// re-tune every entropy threshold in the imported corpus.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	inv := 1.0 / float64(len(s))
	var entropy float64
	for _, n := range counts {
		f := float64(n) * inv
		entropy -= f * math.Log2(f)
	}
	return entropy
}
