package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// planted builds a buffer of `size` filler bytes with `marker` written at `at`.
func planted(marker string, at, size int) []byte {
	b := bytes.Repeat([]byte{'A'}, size)
	copy(b[at:], marker)
	return b
}

// THE test. An off-by-one in the overlap carry is a silent false negative: the
// scanner reads a grok binary on a compromised host, fails to see the bucket name
// because it straddled a 256 KiB boundary, and reports CLEAN. Nothing else in the
// codebase would catch that, so this plants the marker at EVERY offset around
// EVERY boundary rather than at a single hopeful one.
func TestChunkBoundary(t *testing.T) {
	marker := MarkerBucket
	n := len(marker)

	for _, boundary := range []int{chunkSize, 2 * chunkSize, 3 * chunkSize} {
		// Sweep from "marker ends just before the boundary" through "marker starts
		// just after it" -- every straddling alignment, plus the clean cases either side.
		for at := boundary - n - 1; at <= boundary+1; at++ {
			if at < 0 {
				continue
			}
			size := boundary + chunkSize
			buf := planted(marker, at, size)

			res, err := Stream(bytes.NewReader(buf), []string{marker})
			if err != nil {
				t.Fatalf("boundary=%d at=%d: %v", boundary, at, err)
			}
			if len(res.Hits) != 1 {
				t.Fatalf("boundary=%d at=%d: marker NOT FOUND straddling the chunk boundary "+
					"(this is the silent-false-negative bug: a real grok binary would report CLEAN)",
					boundary, at)
			}
			if got := res.Hits[0].Offset; got != int64(at) {
				t.Errorf("boundary=%d: offset = %d, want %d", boundary, got, at)
			}
		}
	}
}

// Offsets must be absolute file offsets, not window-relative ones -- the report
// prints them as evidence.
func TestOffsetIsAbsolute(t *testing.T) {
	at := 3*chunkSize + 1234
	buf := planted(MarkerBucket, at, 4*chunkSize)
	res, err := Stream(bytes.NewReader(buf), []string{MarkerBucket})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 1 || res.Hits[0].Offset != int64(at) {
		t.Fatalf("hits = %+v, want a single hit at %d", res.Hits, at)
	}
}

func TestMultipleMarkersOnePass(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(strings.Repeat("x", 1000))
	sb.WriteString(MarkerEvent)
	sb.WriteString(strings.Repeat("y", chunkSize))
	sb.WriteString(MarkerBucket)
	sb.WriteString(strings.Repeat("z", 100))

	res, err := Stream(strings.NewReader(sb.String()), DefaultMarkers)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Has(MarkerBucket) || !res.Has(MarkerEvent) {
		t.Fatalf("expected both markers, got %+v", res.Hits)
	}
	if res.Has(MarkerFlag) {
		t.Error("reported a marker that is not present")
	}
	// Hits are ordered by offset so the report is deterministic.
	if res.Hits[0].Marker != MarkerEvent {
		t.Errorf("hits not sorted by offset: %+v", res.Hits)
	}
}

// SizeBytes must count each byte exactly once: the carried-forward overlap is
// re-searched, but it must not be re-counted.
func TestSizeIsCorrectDespiteOverlapCarry(t *testing.T) {
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 77} {
		buf := bytes.Repeat([]byte{'Q'}, size)
		res, err := Stream(bytes.NewReader(buf), DefaultMarkers)
		if err != nil {
			t.Fatal(err)
		}
		if res.SizeBytes != int64(size) {
			t.Errorf("size=%d: SizeBytes = %d -- the overlap region was double-counted", size, res.SizeBytes)
		}
	}
}

func TestHashFile(t *testing.T) {
	content := []byte("grok binary contents")
	p := filepath.Join(t.TempDir(), "grok")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("HashFile = %s", got)
	}
}

func TestEmptyAndTinyInputs(t *testing.T) {
	for _, in := range []string{"", "a", "gs://"} {
		if _, err := Stream(strings.NewReader(in), DefaultMarkers); err != nil {
			t.Errorf("input %q: %v", in, err)
		}
	}
}

func TestClassifyHeader(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		path string
		want Kind
	}{
		{"elf", []byte{0x7F, 'E', 'L', 'F', 0x02}, "/usr/local/bin/grok", KindELF},
		{"macho64", []byte{0xCF, 0xFA, 0xED, 0xFE}, "/opt/grok", KindMachO},
		{"macho-fat", []byte{0xCA, 0xFE, 0xBA, 0xBE}, "/opt/grok", KindMachO},
		{"pe", []byte{'M', 'Z', 0x90, 0x00}, `C:\grok.exe`, KindPE},
		{"shebang", []byte("#!/usr/bin/env node\n"), "/home/u/.local/bin/grok", KindScript},
		// A curl|bash CLI is very plausibly a JS bundle with no executable magic.
		// A gate that only checked ELF would miss exactly the install path used here.
		{"js bundle", []byte("const x = 1;"), "/home/u/.grok/cli.js", KindScript},
		{"extensionless in bin", []byte("plain text"), "/home/u/.local/bin/grok", KindScript},
		{"plain text elsewhere", []byte("hello world"), "/home/u/notes.txt", KindNone},
		{"image", []byte{0x89, 'P', 'N', 'G'}, "/home/u/cat.png", KindNone},
		{"empty", nil, "/home/u/empty", KindNone},
	}
	for _, c := range cases {
		if got := ClassifyHeader(c.head, c.path); got != c.want {
			t.Errorf("%s: ClassifyHeader = %v, want %v", c.name, got, c.want)
		}
	}
}

// A realistically-sized binary must scan fast enough that a whole-home walk stays
// viable: content-reading is the only expensive thing this tool does.
func BenchmarkStream100MB(b *testing.B) {
	buf := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), 100<<20/44)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Stream(bytes.NewReader(buf), DefaultMarkers); err != nil {
			b.Fatal(err)
		}
	}
}
