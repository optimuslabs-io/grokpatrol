package secrets

// Throughput guard for the content scanner. The keyword prefilter was once one
// substring sweep per keyword (~244 passes over every blob) and it dominated
// --full-secrets-search wall time; ahocorasick.go collapsed it to one pass. This
// benchmark exists so a future change that reintroduces per-keyword work shows up
// as a throughput regression rather than a support ticket. Run:
//
//	go test ./internal/detect/secrets -bench=BenchmarkScanFull -benchmem -run=XXX

import (
	"fmt"
	"strings"
	"testing"
)

// realisticBlob synthesizes source-file-like content of about n bytes: the kind
// of text a history blob actually holds (identifiers, comments, no secrets), so
// the prefilter does its usual work of rejecting almost everything.
func realisticBlob(n int) []byte {
	var b strings.Builder
	line := 0
	for b.Len() < n {
		line++
		fmt.Fprintf(&b, "func handleRequest%d(ctx context.Context, req *Request) (*Response, error) {\n", line)
		b.WriteString("\t// validate the incoming payload before touching the database layer\n")
		b.WriteString("\tif err := req.Validate(); err != nil {\n")
		b.WriteString("\t\treturn nil, fmt.Errorf(\"invalid request for user %s: %w\", req.UserID, err)\n")
		b.WriteString("\t}\n\tresult := computeAggregate(req.Items, req.Window, req.Filters)\n}\n\n")
	}
	return []byte(b.String())
}

func BenchmarkScanFull(b *testing.B) {
	rs, err := compiledRules()
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{4 << 10, 64 << 10, 1 << 20} {
		data := realisticBlob(size)
		b.Run(fmt.Sprintf("%dKB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				rs.scan("internal/server/handler.go", data)
			}
		})
	}
}
