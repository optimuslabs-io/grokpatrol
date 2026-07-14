package scan

// Markers searched for inside candidate executables.
//
// THEY ARE STORED REVERSED AND FLIPPED AT INIT, ON PURPOSE. No source file in
// this module may contain any marker as a readable literal.
//
// Why this is not paranoia. A scanner that stores the indicator it hunts for
// CONTAINS that indicator, so it finds itself: the first real run of grokpatrol
// against a clean machine reported "grok binary: dist/grokpatrol" and a verdict of
// EXPOSED. The obvious fix -- splitting the literal into pieces and joining them
// at runtime -- was ALSO not enough, and this is the interesting part: the Go
// linker packs string literals contiguously into .rodata, so the fragments
// "repo_state" and ".upload" landed adjacent in the binary and spelled out
// "repo_state.upload" anyway. The scanner matched itself a second time.
//
// Storing each marker reversed means no substring of any marker exists in the
// binary in reading order, whatever the linker does with the layout.
// TestCompiledBinaryDoesNotContainItsOwnMarkers compiles the real binary and greps
// it, so this cannot silently regress.
var (
	// "grok-code-session-traces" -- the GCS bucket the archives went to. Primary.
	MarkerBucket = rev("secart-noisses-edoc-korg")
	// "repo_state.upload" -- the log event name. Present even in a build that
	// renamed the bucket, which is why it is worth matching separately.
	MarkerEvent = rev("daolpu.etats_oper")
	// "disable_codebase_upload" -- the mitigation flag's own name.
	MarkerFlag = rev("daolpu_esabedoc_elbasid")
	// "before_codebase.tar.gz" -- the archive filename.
	MarkerArchive = rev("zg.rat.esabedoc_erofeb")
	// "cli-chat-proxy.grok.com" -- the API host the CLI talks to.
	MarkerEndpoint = rev("moc.korg.yxorp-tahc-ilc")
)

// DefaultMarkers is the set searched in a single pass over each candidate.
//
// The secondary markers matter because absence of the bucket name is NOT proof of
// a clean binary: a build that renamed or obfuscated the bucket would still carry
// the collector. Reporting "this binary contains repo_state.upload but not the
// bucket name" is an honest signal rather than a silent miss.
var DefaultMarkers = []string{
	MarkerBucket,
	MarkerEvent,
	MarkerFlag,
	MarkerArchive,
	MarkerEndpoint,
}

// BucketURL renders the gs:// prefix for report prose, assembled at runtime so the
// contiguous string still never reaches the binary.
func BucketURL() string { return "gs://" + MarkerBucket + "/" }

// rev reverses a string. It runs at package init, so the compiler cannot fold it
// back into the readable literal.
func rev(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
