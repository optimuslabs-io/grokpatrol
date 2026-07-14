package logs

import (
	"runtime"
	"strings"
)

// caseInsensitiveFS drives repo-path grouping. macOS defaults to case-insensitive
// APFS and Windows is case-insensitive, so ~/Work/Repo and ~/work/repo are one
// repository and must collapse to a single ledger row rather than two.
var caseInsensitiveFS = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// fold lowercases for substring matching against log field VALUES, which are
// vendor strings we do not control. It is unrelated to caseInsensitiveFS above:
// that one is about the host filesystem, this one is about schema tolerance.
func fold(s string) string { return strings.ToLower(s) }
