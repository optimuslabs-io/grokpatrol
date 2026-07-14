package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"

	"github.com/optimuslabs/grokpatrol/internal/hostfs"
)

// chunkSize is the read granularity. At this size bytes.Index is memory-bandwidth
// bound rather than CPU bound, so there is nothing to gain from a hand-rolled
// Boyer-Moore: the stdlib already uses SIMD IndexByte plus Rabin-Karp.
const chunkSize = 256 << 10

// Hit is a marker found at a byte offset. There is deliberately no surrounding
// context or matched text -- an offset locates the evidence without reproducing
// any of the file's bytes.
type Hit struct {
	Marker string
	Offset int64
}

// Result of scanning one file.
//
// SHA256 is NOT computed here. Hashing costs more than the search does (it caps
// throughput at a few hundred MB/s, versus several GB/s for bytes.Index), and it
// is only ever needed for the handful of files that actually match a marker. So
// the scan runs hash-free over every candidate, and HashFile is called afterwards
// on the two or three that hit.
type Result struct {
	Hits      []Hit
	SizeBytes int64
}

func (r Result) Has(marker string) bool {
	for _, h := range r.Hits {
		if h.Marker == marker {
			return true
		}
	}
	return false
}

// Stream searches r for every marker in one pass, and hashes it at the same time.
//
// THE OVERLAP CARRY IS THE WHOLE TRICK. A marker that straddles a chunk boundary
// -- 12 bytes at the end of chunk 1 and 12 at the start of chunk 2 -- is invisible
// to a matcher that searches each chunk independently. So the last (longest
// marker - 1) bytes of each window are carried forward to the front of the next.
//
// An off-by-one in that carry does not crash and does not fail loudly: it silently
// fails to find the bucket name in a grok binary on a compromised host, and the
// tool reports CLEAN. TestChunkBoundary is the only thing standing between that
// bug and a wrong answer, which is why it plants a marker at every offset around
// every boundary rather than at one.
func Stream(r io.Reader, markers []string) (Result, error) {
	if len(markers) == 0 {
		return Result{}, nil
	}
	maxLen := 0
	for _, m := range markers {
		if len(m) > maxLen {
			maxLen = len(m)
		}
	}
	overlap := maxLen - 1
	if overlap < 0 {
		overlap = 0
	}

	buf := make([]byte, overlap+chunkSize)

	first := map[string]int64{} // marker -> first absolute offset
	var (
		windowStart int64 // file offset of buf[0]
		carry       int   // bytes carried from the previous window
		total       int64
	)

	for {
		n, err := io.ReadFull(r, buf[carry:carry+chunkSize])
		total += int64(n)

		window := buf[:carry+n]
		for _, m := range markers {
			if _, done := first[m]; done {
				continue // we only need the first offset; keep looking for the others
			}
			if idx := indexOf(window, m); idx >= 0 {
				first[m] = windowStart + int64(idx)
			}
		}

		if err != nil {
			// io.EOF (nothing read) or ErrUnexpectedEOF (short final read): the final
			// window has already been searched above, so we are done. Any other error is
			// a real read failure.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return Result{}, err
		}

		if overlap > 0 && len(window) >= overlap {
			// Carry the tail forward so a marker spanning the boundary is still contiguous.
			copy(buf[:overlap], window[len(window)-overlap:])
			windowStart += int64(len(window) - overlap)
			carry = overlap
		} else {
			windowStart += int64(len(window))
			carry = 0
		}
	}

	res := Result{SizeBytes: total}
	for m, off := range first {
		res.Hits = append(res.Hits, Hit{Marker: m, Offset: off})
	}
	sort.Slice(res.Hits, func(i, j int) bool { return res.Hits[i].Offset < res.Hits[j].Offset })
	return res, nil
}

// HashFile computes a file's SHA-256. It is called only for files that already
// matched a marker, so the cost is paid two or three times per run rather than
// once per candidate executable in the home directory.
func HashFile(path string) (string, error) {
	f, err := hostfs.OpenRead(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func indexOf(haystack []byte, needle string) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	// bytes.Index on a string needle avoids allocating a []byte per call.
	return indexString(haystack, needle)
}
