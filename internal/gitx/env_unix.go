//go:build !windows

package gitx

import (
	"os"
	"os/exec"
	"syscall"
)

// setPgid puts git in its own process group so that killing it on timeout also
// kills anything it spawned, rather than leaving orphans behind.
func setPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func homeForGit() string { return os.Getenv("HOME") }

func pathForGit() string {
	if p := os.Getenv("PATH"); p != "" {
		return p
	}
	return "/usr/bin:/bin:/usr/local/bin"
}

func platformEnv() []string { return nil }
