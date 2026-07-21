package secrets

// The Aho-Corasick prefilter replaced a substring sweep whose only claim was
// "identical answers." These tests hold it to exactly that: collect() must set
// the same present-set the sweep would, over the real corpus and over crafted
// and randomized inputs, plus the structural cases (shared prefixes, suffix
// failure links, buffer boundaries) where an off-by-one in the automaton hides.

import (
	"math/rand"
	"slices"
	"sort"
	"strings"
	"testing"
)

// sweepPresent is the reference the automaton must reproduce byte-for-byte: the
// per-keyword substring sweep that scan() used to run inline.
func sweepPresent(keywords []string, lower string) []bool {
	p := make([]bool, len(keywords))
	for i, kw := range keywords {
		if kw != "" && strings.Contains(lower, kw) {
			p[i] = true
		}
	}
	return p
}

func diff(t *testing.T, keywords []string, got, want []bool, input string) {
	t.Helper()
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keyword %q present=%v, want %v for input %q", keywords[i], got[i], want[i], input)
		}
	}
}

// TestACMatchesSweepOnCorpus is the differential guard against the real ~244
// keyword corpus: the two implementations must agree on every input.
func TestACMatchesSweepOnCorpus(t *testing.T) {
	rs, err := compiledRules()
	if err != nil {
		t.Fatal(err)
	}
	kws := rs.keywords

	inputs := []string{
		"",
		"nothing to see here, just some ordinary prose without any credentials",
		strings.Join(kws, " "),            // every keyword, space separated
		strings.Join(kws, ""),             // every keyword, concatenated (overlaps galore)
		"prefix" + strings.Join(kws, "x"), // keywords glued to filler
	}
	// Each keyword on its own, and each keyword missing its last byte (a near
	// miss that must NOT register).
	for _, kw := range kws {
		inputs = append(inputs, kw)
		if len(kw) > 1 {
			inputs = append(inputs, kw[:len(kw)-1])
		}
	}
	// Deterministic pseudo-random blobs stitched from keyword fragments and
	// filler, so keywords land at arbitrary, unaligned offsets.
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 200; n++ {
		var b strings.Builder
		for j := 0; j < 40; j++ {
			switch rng.Intn(3) {
			case 0:
				b.WriteString(kws[rng.Intn(len(kws))])
			case 1:
				kw := kws[rng.Intn(len(kws))]
				b.WriteString(kw[:1+rng.Intn(len(kw))]) // a prefix of a keyword
			default:
				b.WriteByte(byte('a' + rng.Intn(26)))
			}
		}
		inputs = append(inputs, b.String())
	}

	for _, in := range inputs {
		lower := strings.ToLower(in)
		got := make([]bool, len(kws))
		rs.ac.collect(lower, got)
		diff(t, kws, got, sweepPresent(kws, lower), in)
	}
}

// TestACStructuralCases pins the automaton's tricky bits on a small, legible
// keyword set: shared prefixes, the classic {he,she,his,hers} suffix-link
// overlap, and matches flush against each end of the buffer.
func TestACStructuralCases(t *testing.T) {
	kws := []string{"he", "she", "his", "hers", "app", "apple", "applet"}
	ac := buildAC(kws)

	present := func(s string) []string {
		p := make([]bool, len(kws))
		ac.collect(s, p)
		var out []string
		for i, ok := range p {
			if ok {
				out = append(out, kws[i])
			}
		}
		sort.Strings(out)
		return out
	}

	cases := []struct {
		in   string
		want []string
	}{
		{"ushers", []string{"he", "hers", "she"}}, // "she","he","hers" all end inside "ushers"
		{"he", []string{"he"}},                    // flush at both ends
		{"applet", []string{"app", "apple", "applet"}},
		{"apple", []string{"app", "apple"}},
		{"xapp", []string{"app"}}, // keyword at the tail
		{"appx", []string{"app"}}, // keyword at the head
		{"nomatch", nil},
		{"", nil},
	}
	for _, c := range cases {
		if got := present(c.in); !slices.Equal(got, c.want) {
			t.Errorf("collect(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
