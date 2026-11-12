package grokver

import "testing"

func TestNewerThanObserved(t *testing.T) {
	cases := map[string]bool{
		LatestObserved:  false,
		"1.0.76":        false,
		"0.2.93":        false,
		"1.0.78":        true,
		"1.1.0":         true,
		"2.0.0":         true,
		"v1.0.78":       true,
		"1.0.78-alpha":  true,
		"1.0.77-beta.1": false, // same release line: not newer
		"garbage":       false,
		"":              false,
	}
	for v, want := range cases {
		if got := NewerThanObserved(v); got != want {
			t.Errorf("NewerThanObserved(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.77", "1.0.77", 0},
		{"0.2.111", "0.2.99", 1}, // numeric, not lexical
		{"0.2.99", "1.0.0", -1},
		{"x", "0.0.1", -1},
		{"x", "y", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
