package scan

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A scanner that stores the indicator it hunts for CONTAINS that indicator, so it
// finds itself and reports a clean host as compromised. This is not hypothetical:
// the first real run of grokpatrol against a clean machine reported
// "grok binary: dist/grokpatrol -- contains grok-code-session-traces" and a
// verdict of EXPOSED.
//
// markers.go therefore assembles every marker at runtime, and this test compiles
// the actual binary and greps it to make sure nobody undoes that by writing the
// literal back into a string somewhere.
func TestCompiledBinaryDoesNotContainItsOwnMarkers(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}

	bin := filepath.Join(t.TempDir(), "grokpatrol-selftest")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/grokpatrol")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	blob, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	// EVERY marker, not just the bucket name. The first version of this test checked
	// only MarkerBucket and MarkerEndpoint, and the tool still detected itself on a
	// clean machine -- via `repo_state.upload` and `disable_codebase_upload`, which
	// were sitting in .rodata as the log-event constants and the config key. Any
	// marker matching is enough to report a binary as a grok install, so all of them
	// have to be absent.
	for _, marker := range DefaultMarkers {
		if bytes.Contains(blob, []byte(marker)) {
			t.Errorf("the compiled binary contains the contiguous marker %q.\n"+
				"grokpatrol will now detect ITSELF (and every copy of itself on disk) as a grok install.\n"+
				"Whatever you just added, split the literal -- see internal/scan/markers.go.", marker)
		}
	}

	// Sanity check, so the test above cannot pass for the wrong reason (an empty
	// blob, a binary that failed to build). The markers ARE in there -- reversed --
	// and that reversed form is what must be present.
	if !bytes.Contains(blob, []byte(rev(MarkerBucket))) {
		t.Error("the reversed marker is not in the binary either; this test is not testing what it thinks it is")
	}
}

// The runtime-assembled markers must still be the exact strings we are hunting.
// Splitting a literal is only safe if it reassembles correctly.
func TestMarkersAreAssembledCorrectly(t *testing.T) {
	want := map[string]string{
		MarkerBucket:   "grok-code-session-traces",
		MarkerEvent:    "repo_state.upload",
		MarkerFlag:     "disable_codebase_upload",
		MarkerArchive:  "before_codebase.tar.gz",
		MarkerEndpoint: "cli-chat-proxy.grok.com",
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("marker assembled to %q, want %q -- a split literal was reassembled wrong, "+
				"which means grokpatrol is searching for a string that does not exist", got, expected)
		}
	}
	if strings.Contains(BucketURL(), "gs://grok-code-session-traces/") != true {
		t.Errorf("BucketURL() = %q", BucketURL())
	}
}
