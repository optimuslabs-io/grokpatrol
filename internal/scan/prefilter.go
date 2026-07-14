package scan

import (
	"path/filepath"
	"strings"
)

// neverExecutable are extensions that cannot be a grok binary or a JS/shell
// bundle, whatever their contents. Rejecting them by NAME means we never even
// open them.
//
// This matters twice over:
//
//  1. Performance. The candidate gate still costs an open + a 4-byte read + a
//     close per file, and a home directory has hundreds of thousands of files.
//     Syscalls dominated the first real run (3m22s wall, most of it in sys).
//     Skipping the open for images, video, fonts, docs and data files removes the
//     bulk of that without giving up any coverage that matters.
//
//  2. Honesty of the verdict. macOS TCC denies reads on things like
//     Library/.../*.plist. Treating those denials as "the scan was degraded" would
//     make INDETERMINATE the permanent verdict on every Mac, and a CLEAN result
//     nobody can ever reach is a result nobody will believe. A .plist we cannot
//     read is not a grok binary we might have missed.
var neverExecutable = map[string]bool{
	// images / video / audio
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".ico": true,
	".tif": true, ".tiff": true, ".webp": true, ".heic": true, ".svg": true, ".psd": true,
	".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".webm": true,
	".mp3": true, ".wav": true, ".flac": true, ".aac": true, ".m4a": true, ".ogg": true,
	// fonts
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true, ".eot": true,
	// documents. Note .key is absent on purpose: it is a private-key extension.
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".pages": true, ".numbers": true,
	// data and config that cannot carry a shebang
	".plist": true, ".stats": true, ".db": true, ".sqlite": true, ".sqlite3": true,
	".csv": true, ".tsv": true, ".parquet": true, ".avro": true,
	".log": true, ".lock": true, ".map": true, ".pyc": true, ".pyo": true,
	".css": true, ".scss": true, ".less": true, ".html": true, ".htm": true, ".xml": true,
	".md": true, ".rst": true, ".txt": true, ".yaml": true, ".yml": true, ".toml": true, ".ini": true,
	// compiled/packaged things that are not the grok CLI
	".o": true, ".a": true, ".obj": true, ".lib": true, ".pdb": true,
	".zip": true, ".rar": true, ".7z": true, ".bz2": true, ".xz": true, ".zst": true,
	".dmg": true, ".iso": true, ".img": true, ".vmdk": true, ".qcow2": true,
	// source code (grok ships as a bundle, not as a source tree we would need to grep)
	".go": true, ".rs": true, ".java": true, ".rb": true, ".php": true, ".swift": true,
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".hpp": true, ".cs": true, ".m": true,
}

// SkipByName reports whether a file can be rejected without opening it.
//
// It is deliberately conservative: an unknown extension, and anything with no
// extension at all, still goes through the full magic-byte gate. The only files
// skipped here are ones whose extension makes an executable or a script bundle
// impossible.
func SkipByName(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false // extensionless: could be a binary or a shebang script
	}
	if scriptExts[ext] {
		return false // .js, .sh, .py ... these are exactly what we want to read
	}
	return neverExecutable[ext]
}
