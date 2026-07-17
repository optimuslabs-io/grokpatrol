// Command gen transcribes the vendored gitleaks rule corpus (gitleaks.toml, MIT
// License, Copyright (c) 2019 Zachary Rice) into a generated Go table,
// rules_gen.go, so the shipped binary carries the rules without carrying a TOML
// parser -- or any dependency at all.
//
// This program is a DEV TOOL. It is a separate main package that grokpatrol
// never imports, so it is never linked into the shipped binary; `make
// verify-deps` (empty go.sum, no net in `go list -deps ./...`) still covers it
// because it is stdlib-only and part of this module.
//
// It parses only the TOML subset the generated gitleaks.toml actually uses --
// single-line basic/literal strings, numbers, string arrays, [allowlist],
// [[rules]] and [[rules.allowlists]] -- and FAILS LOUDLY on anything else. When
// a future gitleaks snapshot introduces new syntax or keys, the refresh must be
// a conscious decision here, not a silent drop of rules.
package main

import (
	"errors"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	inPath  = "gitleaks/gitleaks.toml"
	outPath = "rules_gen.go"
	// Provenance: the tag the vendored gitleaks.toml was taken from. Update both
	// the vendored file and this constant together.
	gitleaksVersion = "v8.30.1"
)

// rule and allowlist mirror the structs declared in the secrets package
// (rules.go). The generator emits composite literals for them.
type allowlist struct {
	condAND     bool
	regexTarget string
	regexes     []string
	paths       []string
	stopwords   []string
}

type rule struct {
	id          string
	regex       string
	path        string
	entropy     float64
	secretGroup int
	keywords    []string
	allow       []allowlist
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	rules, global, err := parse(string(raw))
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return errors.New("parsed zero rules; refusing to write an empty table")
	}
	src, err := emit(rules, global)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, src, 0o644)
}

// parse walks the file line by line. p.line is the cursor so array parsing can
// consume continuation lines.
type parser struct {
	lines []string
	line  int
}

func parse(input string) ([]rule, *allowlist, error) {
	p := &parser{lines: strings.Split(input, "\n")}

	var rules []rule
	var global allowlist

	// What the current `key = value` line belongs to.
	const (
		inTop = iota
		inGlobal
		inRule
		inRuleAllow
	)
	where := inTop

	for ; p.line < len(p.lines); p.line++ {
		line := strings.TrimSpace(p.lines[p.line])
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue

		case line == "[allowlist]":
			where = inGlobal

		case line == "[[rules]]":
			rules = append(rules, rule{})
			where = inRule

		case line == "[[rules.allowlists]]":
			if len(rules) == 0 {
				return nil, nil, p.errf("[[rules.allowlists]] before any [[rules]]")
			}
			r := &rules[len(rules)-1]
			r.allow = append(r.allow, allowlist{})
			where = inRuleAllow

		case strings.HasPrefix(line, "["):
			return nil, nil, p.errf("unsupported section %q", line)

		default:
			key, val, err := p.keyValue(line)
			if err != nil {
				return nil, nil, err
			}
			var target error
			switch where {
			case inTop:
				target = topKey(key)
			case inGlobal:
				target = allowKey(&global, key, val, false)
			case inRule:
				target = ruleKey(&rules[len(rules)-1], key, val)
			case inRuleAllow:
				r := &rules[len(rules)-1]
				target = allowKey(&r.allow[len(r.allow)-1], key, val, true)
			}
			if target != nil {
				return nil, nil, fmt.Errorf("line %d: %w", p.line+1, target)
			}
		}
	}
	return rules, &global, nil
}

func topKey(key string) error {
	switch key {
	case "title", "minVersion":
		return nil // metadata, not detection behavior
	}
	return fmt.Errorf("unknown top-level key %q", key)
}

func ruleKey(r *rule, key string, val value) error {
	switch key {
	case "id":
		return val.str(&r.id)
	case "description":
		var drop string
		return val.str(&drop) // the rule id is the shipped label; prose stays behind
	case "regex":
		return val.str(&r.regex)
	case "path":
		return val.str(&r.path)
	case "entropy":
		return val.num(&r.entropy)
	case "secretGroup":
		var f float64
		if err := val.num(&f); err != nil {
			return err
		}
		r.secretGroup = int(f)
		return nil
	case "keywords":
		return val.strs(&r.keywords)
	}
	return fmt.Errorf("unknown [[rules]] key %q", key)
}

func allowKey(a *allowlist, key string, val value, perRule bool) error {
	switch key {
	case "description":
		var drop string
		return val.str(&drop)
	case "condition":
		var s string
		if err := val.str(&s); err != nil {
			return err
		}
		switch s {
		case "AND":
			a.condAND = true
		case "OR":
		default:
			return fmt.Errorf("unknown allowlist condition %q", s)
		}
		return nil
	case "regexTarget":
		var s string
		if err := val.str(&s); err != nil {
			return err
		}
		if s != "match" && s != "line" {
			return fmt.Errorf("unknown regexTarget %q", s)
		}
		a.regexTarget = s
		return nil
	case "regexes":
		return val.strs(&a.regexes)
	case "paths":
		return val.strs(&a.paths)
	case "stopwords":
		return val.strs(&a.stopwords)
	case "commits":
		// Commit allowlists pin specific upstream repos' histories; meaningless for
		// scanning arbitrary hosts. Not present in the current corpus.
		return fmt.Errorf("commit allowlists are not supported")
	}
	where := "[allowlist]"
	if perRule {
		where = "[[rules.allowlists]]"
	}
	return fmt.Errorf("unknown %s key %q", where, key)
}

// value is one parsed TOML value: exactly one of the fields is set.
type value struct {
	s      *string
	f      *float64
	list   []string
	isList bool
}

func (v value) str(dst *string) error {
	if v.s == nil {
		return errors.New("expected a string value")
	}
	*dst = *v.s
	return nil
}

func (v value) num(dst *float64) error {
	if v.f == nil {
		return errors.New("expected a numeric value")
	}
	*dst = *v.f
	return nil
}

func (v value) strs(dst *[]string) error {
	if !v.isList {
		return errors.New("expected an array value")
	}
	*dst = v.list
	return nil
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("line %d: %s", p.line+1, fmt.Sprintf(format, args...))
}

// keyValue parses `key = value`, consuming continuation lines for arrays.
func (p *parser) keyValue(line string) (string, value, error) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", value{}, p.errf("expected key = value, got %q", line)
	}
	key := strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])

	switch {
	case strings.HasPrefix(rest, "["):
		list, err := p.parseArray(rest[1:])
		if err != nil {
			return "", value{}, err
		}
		return key, value{list: list, isList: true}, nil
	case strings.HasPrefix(rest, `"`) || strings.HasPrefix(rest, "'''"):
		s, tail, err := p.parseString(rest)
		if err != nil {
			return "", value{}, err
		}
		if tail != "" {
			return "", value{}, p.errf("trailing content after string: %q", tail)
		}
		return key, value{s: &s}, nil
	default:
		f, err := strconv.ParseFloat(rest, 64)
		if err != nil {
			return "", value{}, p.errf("unsupported value %q", rest)
		}
		return key, value{f: &f}, nil
	}
}

// parseArray consumes string elements, advancing p.line across continuation
// lines, until the closing bracket.
func (p *parser) parseArray(rest string) ([]string, error) {
	list := []string{}
	for {
		rest = strings.TrimSpace(rest)
		switch {
		case rest == "":
			p.line++
			if p.line >= len(p.lines) {
				return nil, errors.New("unterminated array")
			}
			rest = strings.TrimSpace(p.lines[p.line])
		case strings.HasPrefix(rest, "#"):
			rest = "" // comment-only remainder inside an array
		case strings.HasPrefix(rest, "]"):
			return list, nil
		case strings.HasPrefix(rest, ","):
			rest = rest[1:]
		case strings.HasPrefix(rest, `"`) || strings.HasPrefix(rest, "'''"):
			s, tail, err := p.parseString(rest)
			if err != nil {
				return nil, err
			}
			list = append(list, s)
			rest = tail
		default:
			return nil, p.errf("unsupported array element %q", rest)
		}
	}
}

// parseString parses one single-line TOML string (basic or literal) at the
// start of s, returning the value and whatever follows it on the line.
func (p *parser) parseString(s string) (string, string, error) {
	if strings.HasPrefix(s, "'''") {
		end := strings.Index(s[3:], "'''")
		if end < 0 {
			return "", "", p.errf("multi-line ''' strings are not supported")
		}
		return s[3 : 3+end], strings.TrimSpace(s[3+end+3:]), nil
	}
	// Basic string with the escapes the corpus actually uses.
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		switch c {
		case '"':
			return b.String(), strings.TrimSpace(s[i+1:]), nil
		case '\\':
			if i+1 >= len(s) {
				return "", "", p.errf("dangling backslash in basic string")
			}
			i++
			switch s[i] {
			case '"', '\\':
				b.WriteByte(s[i])
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				return "", "", p.errf("unsupported escape \\%c", s[i])
			}
		default:
			b.WriteByte(c)
		}
		i++
	}
	return "", "", p.errf("unterminated basic string")
}

// emit renders rules_gen.go.
func emit(rules []rule, global *allowlist) ([]byte, error) {
	// Deterministic output: the corpus is already ordered, but sort defensively so
	// a re-run never produces diff noise.
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].id < rules[j].id })

	var b strings.Builder
	b.WriteString(`// Code generated by internal/detect/secrets/gitleaks/gen. DO NOT EDIT.
//
// Detection rules transcribed from gitleaks ` + gitleaksVersion + ` config/gitleaks.toml
// (https://github.com/gitleaks/gitleaks), used under the MIT License:
//
//	Copyright (c) 2019 Zachary Rice
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
// The full license text ships with the vendored corpus in
// internal/detect/secrets/gitleaks/LICENSE.
package secrets

// gitleaksRulesVersion records which gitleaks tag the rule table came from, so
// the report can cite provenance without shipping the TOML.
const gitleaksRulesVersion = "` + gitleaksVersion + `"

`)

	b.WriteString("// globalAllow is gitleaks' global allowlist: paths that are never scanned\n")
	b.WriteString("// and candidate values that are never findings, whatever rule matched them.\n")
	b.WriteString("var globalAllow = allowList{\n")
	writeAllowFields(&b, *global)
	b.WriteString("}\n\n")

	b.WriteString("var contentRules = []contentRule{\n")
	for _, r := range rules {
		if r.id == "" || (r.regex == "" && r.path == "") {
			return nil, fmt.Errorf("rule %+v has no id or no pattern", r)
		}
		fmt.Fprintf(&b, "\t{\n\t\tID: %s,\n", strconv.Quote(r.id))
		if r.regex != "" {
			fmt.Fprintf(&b, "\t\tRegex: %s,\n", strconv.Quote(r.regex))
		}
		if r.path != "" {
			fmt.Fprintf(&b, "\t\tPath: %s,\n", strconv.Quote(r.path))
		}
		if r.entropy != 0 {
			fmt.Fprintf(&b, "\t\tEntropy: %s,\n", strconv.FormatFloat(r.entropy, 'g', -1, 64))
		}
		if r.secretGroup != 0 {
			fmt.Fprintf(&b, "\t\tSecretGroup: %d,\n", r.secretGroup)
		}
		if len(r.keywords) > 0 {
			fmt.Fprintf(&b, "\t\tKeywords: %s,\n", quoteSlice(r.keywords))
		}
		if len(r.allow) > 0 {
			b.WriteString("\t\tAllow: []allowList{\n")
			for _, a := range r.allow {
				b.WriteString("\t\t\t{\n")
				writeAllowFields(&b, a)
				b.WriteString("\t\t\t},\n")
			}
			b.WriteString("\t\t},\n")
		}
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n")

	return format.Source([]byte(b.String()))
}

func writeAllowFields(b *strings.Builder, a allowlist) {
	if a.condAND {
		b.WriteString("CondAND: true,\n")
	}
	if a.regexTarget != "" {
		fmt.Fprintf(b, "RegexTarget: %s,\n", strconv.Quote(a.regexTarget))
	}
	if len(a.regexes) > 0 {
		fmt.Fprintf(b, "Regexes: %s,\n", quoteSlice(a.regexes))
	}
	if len(a.paths) > 0 {
		fmt.Fprintf(b, "Paths: %s,\n", quoteSlice(a.paths))
	}
	if len(a.stopwords) > 0 {
		fmt.Fprintf(b, "Stopwords: %s,\n", quoteSlice(a.stopwords))
	}
}

func quoteSlice(ss []string) string {
	var b strings.Builder
	b.WriteString("[]string{")
	for i, s := range ss {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(s))
	}
	b.WriteString("}")
	return b.String()
}
