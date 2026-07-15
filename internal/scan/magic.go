// Package scan decides which files are worth reading, and reads them once.
package scan

import (
	"bytes"
	"path/filepath"
	"strings"
)

// Candidate kinds, in the order the gate checks them.
type Kind int

const (
	KindNone Kind = iota
	KindELF
	KindMachO
	KindPE
	KindScript // shebang, or a JS/shell bundle by extension
)

func (k Kind) String() string {
	switch k {
	case KindELF:
		return "elf"
	case KindMachO:
		return "mach-o"
	case KindPE:
		return "pe"
	case KindScript:
		return "script"
	}
	return "none"
}

var (
	magicELF = []byte{0x7F, 'E', 'L', 'F'}
	magicPE  = []byte{'M', 'Z'}
	// Mach-O in its four byte orders, plus the two universal/fat headers. CAFEBABE
	// is also a Java .class, which is a harmless false-positive candidate: it costs
	// one streamed read and nothing else.
	magicMachO = [][]byte{
		{0xFE, 0xED, 0xFA, 0xCE}, {0xFE, 0xED, 0xFA, 0xCF},
		{0xCE, 0xFA, 0xED, 0xFE}, {0xCF, 0xFA, 0xED, 0xFE},
		{0xCA, 0xFE, 0xBA, 0xBE}, {0xBE, 0xBA, 0xFE, 0xCA}, {0xCA, 0xFE, 0xBA, 0xBF},
	}
)

// scriptExts admits the shapes a `curl | bash`-installed CLI actually takes.
// Grok is distributed by an install script, so it is entirely plausible that the
// "binary" is a Node/Bun JS bundle or a shell shim with no executable magic at
// all. A gate that only checked for ELF would be a silent false negative on
// exactly the install path the incident used.
var scriptExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".ts": true,
	".sh": true, ".bash": true, ".py": true,
	".dll": true, ".dylib": true, ".so": true, ".node": true, ".jar": true,
}

// binDirs are the directories where an extensionless file is probably a program.
var binDirs = []string{"bin", "sbin", ".bin"}

// ClassifyHeader decides whether a file is worth content-scanning, given its
// first few bytes and its path.
//
// This gate is the entire performance story. Content-reading is the only
// expensive operation in the tool, so everything that is not plausibly an
// executable is rejected here after a single stat and a 4-byte read -- which
// turns an O(bytes in home) problem into O(files in home) plus O(bytes in
// executables), and executables are a rounding error of a home directory.
//
// It deliberately does NOT consult the executable permission bit: that bit does
// not exist on Windows, and on Unix it is set on plenty of things that are not
// programs.
func ClassifyHeader(head []byte, path string) Kind {
	if len(head) >= 4 {
		if bytes.Equal(head[:4], magicELF) {
			return KindELF
		}
		for _, m := range magicMachO {
			if bytes.Equal(head[:4], m) {
				return KindMachO
			}
		}
	}
	if len(head) >= 2 {
		if bytes.Equal(head[:2], magicPE) {
			return KindPE
		}
		if head[0] == '#' && head[1] == '!' {
			return KindScript
		}
	}

	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(base))
	if scriptExts[ext] {
		return KindScript
	}
	// An extensionless file sitting in a bin directory is a program often enough to
	// be worth 50ms of reading.
	if ext == "" && inBinDir(path) {
		return KindScript
	}
	return KindNone
}

func inBinDir(path string) bool {
	parent := strings.ToLower(filepath.Base(filepath.Dir(path)))
	for _, d := range binDirs {
		if parent == d {
			return true
		}
	}
	return false
}

// IsGrokBinaryName forces a file into the content scan regardless of its header.
// If it is literally called grok, we read it.
// GrokCommandNames are the filenames the grok command is invoked as -- the entries
// to look for on $PATH when deciding which discovered install actually runs. Kept as
// one list so the walk's name filter and the $PATH probe cannot drift apart.
var GrokCommandNames = []string{"grok", "grok.exe"}

func IsGrokBinaryName(name string) bool {
	n := strings.ToLower(name)
	for _, c := range GrokCommandNames {
		if n == c {
			return true
		}
	}
	return false
}
