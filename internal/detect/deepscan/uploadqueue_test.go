package deepscan

import (
	"path/filepath"
	"testing"
)

// The content scan must skip files under an upload_queue: they are the victim's own
// staged data, not grok installs, and marker-scanning tens of thousands of them is the
// walk's most expensive dead end. Archives and manifests there are still recorded by
// name elsewhere (structuralFile); this guards only the generic binary probe.
func TestUnderUploadQueue(t *testing.T) {
	yes := []string{
		filepath.Join("/home/u/.grok/upload_queue/turn_3/partial.bin"),
		filepath.Join("/home/u/.grok/upload_queue/state.db"),
		filepath.Join("/srv/UPLOAD_QUEUE/x"), // matched case-insensitively, like structuralDir
	}
	no := []string{
		filepath.Join("/home/u/.grok/bin/grok"),
		filepath.Join("/usr/local/bin/grok"),
		filepath.Join("/home/u/upload_queue_notes/readme"), // a different dir name, not the queue
	}
	for _, p := range yes {
		if !underUploadQueue(p) {
			t.Errorf("underUploadQueue(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if underUploadQueue(p) {
			t.Errorf("underUploadQueue(%q) = true, want false", p)
		}
	}
}
