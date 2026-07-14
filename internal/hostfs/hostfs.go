// Package hostfs is the only package in grokpatrol that touches the host
// filesystem. Every read funnels through OpenRead, which is the enforcement
// point for the read-only invariant: there is no function here that creates,
// writes, renames, chmods or removes anything.
package hostfs

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// OpenRead is the ONLY way grokpatrol opens a file. O_RDONLY, no create flag,
// no truncate flag, mode 0 (unused without O_CREATE). Anything that needs bytes
// off the host goes through here.
func OpenRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// ReadFileCapped reads at most max bytes. Every caller in this codebase reads a
// file whose size it has already stat'd and bounded, so an unbounded ReadFile
// never appears -- a 40 GB file must not become a 40 GB allocation.
func ReadFileCapped(path string, max int64) ([]byte, error) {
	f, err := OpenRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 32*1024)
	for int64(len(buf)) < max {
		n, err := f.Read(tmp)
		if n > 0 {
			remaining := max - int64(len(buf))
			if int64(n) > remaining {
				n = int(remaining)
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break // io.EOF or a read error: return what we got
		}
	}
	return buf, nil
}

// Home resolves the user's home directory. os.UserHomeDir is used rather than
// os/user because the latter pulls in cgo, which would break CGO_ENABLED=0
// cross-compilation and put a C dependency in a security tool.
func Home(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return h, nil
}

// GrokHome resolves the grok state dir: an explicit override wins, then
// $GROK_HOME, then ~/.grok.
func GrokHome(override, home string) string {
	if override != "" {
		if abs, err := filepath.Abs(override); err == nil {
			return abs
		}
		return override
	}
	if env := os.Getenv("GROK_HOME"); env != "" {
		return env
	}
	return filepath.Join(home, ".grok")
}

// Display renders a path home-relative (~/work/foo). It is free privacy hygiene,
// it makes golden tests stable across machines, and it is what a reader actually
// wants to look at. Applied centrally by report.Display.
func Display(path, home string) string {
	if home == "" || path == "" {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(os.PathSeparator)
	if strings.HasPrefix(path, prefix) {
		return "~" + string(os.PathSeparator) + path[len(prefix):]
	}
	return path
}

// IsRegular reports whether the entry is a plain file: not a symlink, device,
// socket or fifo. Reading a fifo would block the scanner forever.
func IsRegular(d fs.DirEntry) bool {
	return d.Type().IsRegular()
}

// SystemBinDirs are read-only, outside-home locations where a grok binary
// plausibly lands. Scanned best-effort; a missing dir is not an error.
func SystemBinDirs() []string {
	switch runtime.GOOS {
	case "windows":
		var dirs []string
		for _, env := range []string{"LOCALAPPDATA", "APPDATA", "ProgramFiles"} {
			if v := os.Getenv(env); v != "" {
				dirs = append(dirs, filepath.Join(v, "Programs"), v)
			}
		}
		return dirs
	case "darwin":
		return []string{"/usr/local/bin", "/opt/homebrew/bin", "/opt/homebrew/Cellar"}
	default:
		return []string{"/usr/local/bin", "/usr/bin", "/opt"}
	}
}

// PriorityRoots are the places a grok install actually lives. They are scanned
// first so the common case reports in well under a second even when the full
// home walk takes a minute.
func PriorityRoots(home string) []string {
	roots := []string{
		filepath.Join(home, ".grok"),
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, ".local", "share"),
		filepath.Join(home, "bin"),
		filepath.Join(home, "go", "bin"),
		filepath.Join(home, ".config"),
		filepath.Join(home, ".cache", "grok"),
	}
	if runtime.GOOS == "darwin" {
		roots = append(roots,
			filepath.Join(home, "Library", "Application Support"),
			filepath.Join(home, "Library", "Logs"),
		)
	}
	return roots
}
