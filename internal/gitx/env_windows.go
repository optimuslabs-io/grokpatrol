//go:build windows

package gitx

import (
	"os"
	"os/exec"
)

// setPgid has no Windows equivalent that is worth the complexity here; the
// context timeout still kills the git process itself.
func setPgid(*exec.Cmd) {}

func homeForGit() string {
	if h := os.Getenv("USERPROFILE"); h != "" {
		return h
	}
	return os.Getenv("HOME")
}

func pathForGit() string { return os.Getenv("PATH") }

// platformEnv keeps the handful of variables Windows processes cannot start
// without. Scrubbing SystemRoot would make git fail to launch at all.
func platformEnv() []string {
	var out []string
	for _, k := range []string{"SystemRoot", "SystemDrive", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		if v := os.Getenv(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	return out
}
