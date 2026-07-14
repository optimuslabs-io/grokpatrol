package scan

import "bytes"

// indexString finds needle in haystack without allocating. bytes.Index takes a
// []byte needle, and converting a string to []byte on every chunk of every file
// would allocate megabytes over a home-dir scan; the compiler elides the
// conversion inside this call.
func indexString(haystack []byte, needle string) int {
	return bytes.Index(haystack, []byte(needle))
}
