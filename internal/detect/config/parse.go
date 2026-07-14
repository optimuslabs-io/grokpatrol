package config

import (
	"sort"
	"strings"
)

// state is what one config.toml told us.
type state struct {
	path string
	// values maps "table.key" to the raw literal on the right-hand side, lowercased.
	// Only positively-parsed simple assignments land here.
	values map[string]string
	// keys maps a table name to the keys seen under it, so unrecognized upload
	// options can be surfaced rather than silently ignored.
	keys map[string][]string
	// uncertain means the file used a construct this scanner does not model. It is
	// treated as EXPOSED: being unsure is a safe answer, being confidently wrong in
	// the reassuring direction is not.
	uncertain bool
	missing   bool
}

// Satisfied reports whether a mitigation is positively confirmed.
func (s state) Satisfied(m Mitigation) bool {
	return s.values[m.Table+"."+m.Key] == m.Want
}

// Present reports whether the key exists at all (whatever its value).
func (s state) Present(m Mitigation) bool {
	_, ok := s.values[m.Table+"."+m.Key]
	return ok
}

// parse is a deliberately small TOML subset scanner: table headers, key = value
// pairs, comments outside strings, and enough awareness of multi-line strings not
// to be fooled by one.
func parse(src string) state {
	st := state{values: map[string]string{}, keys: map[string][]string{}}

	table := ""
	inMultiline := false
	mlDelim := ""

	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, "\r")

		// A multi-line string can contain anything -- including a line that reads
		// exactly like `disable_codebase_upload = true`, sitting inside a docstring or a
		// commented-out example. Tracking them is what stops such a line from producing
		// a false MITIGATED.
		if inMultiline {
			if strings.Contains(line, mlDelim) {
				inMultiline = false
			}
			continue
		}

		trimmed := strings.TrimSpace(stripComment(line))
		if trimmed == "" {
			continue
		}

		if d := openingMultiline(trimmed); d != "" && !closesOnSameLine(trimmed, d) {
			inMultiline, mlDelim = true, d
			continue
		}

		if strings.HasPrefix(trimmed, "[") {
			if strings.HasPrefix(trimmed, "[[") {
				st.uncertain = true // array of tables: not modeled
				continue
			}
			end := strings.Index(trimmed, "]")
			if end < 0 {
				st.uncertain = true
				continue
			}
			table = strings.Trim(strings.TrimSpace(trimmed[1:end]), `"'`)
			continue
		}

		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			st.uncertain = true
			continue
		}
		key := strings.Trim(strings.TrimSpace(trimmed[:eq]), `"'`)
		val := strings.TrimSpace(trimmed[eq+1:])

		effTable, effKey := table, key
		// The dotted top-level form `harness.disable_codebase_upload = true` is
		// equivalent to the key inside [harness] and must be honored.
		if table == "" && strings.Contains(key, ".") {
			i := strings.LastIndex(key, ".")
			effTable, effKey = key[:i], key[i+1:]
		}
		if effTable == "" {
			continue
		}

		st.keys[effTable] = append(st.keys[effTable], effKey)

		// Only a bare boolean literal counts. `= "true"`, `= [true]`, or anything else
		// is recorded as uncertain rather than guessed at.
		v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(val), ","))
		switch v {
		case "true", "false":
			st.values[effTable+"."+effKey] = v
		default:
			if isMitigationKey(effTable, effKey) {
				st.uncertain = true
			}
		}
	}

	if inMultiline {
		st.uncertain = true // unterminated string: the file is malformed, trust nothing in it
	}

	for t := range st.keys {
		sort.Strings(st.keys[t])
	}
	return st
}

func isMitigationKey(table, key string) bool {
	for _, m := range Mitigations() {
		if m.Table == table && m.Key == key {
			return true
		}
	}
	return false
}

// stripComment removes a # comment, but only when the # is outside a string --
// otherwise a value like "#!/bin/sh" would be truncated.
func stripComment(line string) string {
	inS, inD := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS && (i == 0 || line[i-1] != '\\') {
				inD = !inD
			}
		case '#':
			if !inS && !inD {
				return line[:i]
			}
		}
	}
	return line
}

func openingMultiline(s string) string {
	for _, d := range []string{`"""`, `'''`} {
		if strings.Contains(s, d) {
			return d
		}
	}
	return ""
}

func closesOnSameLine(s, delim string) bool { return strings.Count(s, delim) >= 2 }
