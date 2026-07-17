// Package gitx is the ONLY place in grokpatrol that executes a subprocess.
//
// Two invariants live here:
//
//  1. The grok binary is NEVER executed. Not with --version, not with --help.
//     It carries a collector that runs outside the tool-call permission system,
//     so launching it to ask a question could itself start a session and trigger
//     an upload. argv[0] below is the string literal "git" and nothing else.
//
//  2. Nothing this package runs can modify a repository. Every allowlisted
//     subcommand is read-only, and the extra -c flags below stop git itself
//     from repacking or refreshing anything mid-forensics.
//
// A boundary that used to live here has moved. The allowlist historically had
// no `cat-file`, which made "never prints secret values" structural: the tool
// could not read a blob even by mistake. --full-secrets-search needs blob
// contents to run content rules over them, so cat-file is now allowed -- and
// the guarantee it enforced now lives one layer up: blob bytes exist only in
// transient buffers handed to the secrets engine, no model struct can hold
// them (model.Evidence has no content field), and the leak tests grep every
// output channel for planted values. Default scans never invoke cat-file.
package gitx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// allowed subcommands. Every one is read-only: together they answer "which
// files were in the object set that got uploaded", and (only under
// --full-secrets-search) "what is inside those blobs".
//
// cat-file is the deliberate exception to the old "filenames only" posture: it
// is reachable ONLY through the Batch functions below, which hand contents to
// the secrets engine in transient buffers. Nothing that reads a blob may store
// or print it -- that is enforced at the model layer (no content-capable
// field) and by the leak tests, not here.
var allowed = map[string]bool{
	"rev-list":  true,
	"ls-tree":   true,
	"rev-parse": true,
	"version":   true,
	"cat-file":  true,
}

var (
	lookOnce sync.Once
	gitPath  string
	lookErr  error
)

// ErrNoGit means git is not installed. It is not fatal: the caller degrades to a
// working-tree-only scan and says so, rather than reporting a bogus empty result.
var ErrNoGit = errors.New("git not found on PATH")

// ErrDubiousOwnership is git's safe.directory refusal. We surface it rather than
// work around it: injecting `-c safe.directory=*` would disable a real security
// guardrail the user never asked us to touch.
var ErrDubiousOwnership = errors.New("git refuses to operate on this repository (dubious ownership)")

// Available reports whether git can be used at all.
func Available() bool {
	lookOnce.Do(func() { gitPath, lookErr = exec.LookPath("git") })
	return lookErr == nil
}

// readOnlyArgs are prepended to every invocation.
//
//	--no-optional-locks   stops git taking index.lock or refreshing the index
//	gc.auto=0             stops an auto-GC from repacking objects mid-forensics
//	maintenance.auto=0    same, for the newer maintenance machinery
//
// Repacking would not lose data, but a forensic tool must not touch the evidence.
func readOnlyArgs(repo string) []string {
	return []string{
		"--no-optional-locks",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=0",
		"-c", "core.fsmonitor=false",
		"-C", repo,
	}
}

// scrubbedEnv removes anything that could redirect git somewhere else or make it
// block on a prompt. A stray GIT_DIR in the user's shell would silently point
// every command at the wrong repository.
func scrubbedEnv() []string {
	env := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_PAGER=cat",
		"HOME=" + homeForGit(), // git needs HOME to read safe.directory
		"PATH=" + pathForGit(),
		// Deliberately NOT inherited: GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE,
		// GIT_OBJECT_DIRECTORY, GIT_ALTERNATE_OBJECT_DIRECTORIES. A stray GIT_DIR in
		// the user's shell would silently redirect every command below.
	}
	return append(env, platformEnv()...)
}

// Stream runs a read-only git subcommand and hands each output line to fn.
//
// Output is streamed rather than buffered: `rev-list --objects` on a monorepo can
// emit millions of lines, and Output() would materialize all of it in memory.
func Stream(ctx context.Context, repo string, timeout time.Duration, args []string, fn func(line string) error) error {
	if !Available() {
		return ErrNoGit
	}
	if len(args) == 0 || !allowed[args[0]] {
		// A programming error, not a user error: the allowlist is the security boundary.
		return fmt.Errorf("gitx: subcommand %q is not in the read-only allowlist", firstOf(args))
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	full := append(readOnlyArgs(repo), args...)
	cmd := exec.CommandContext(cctx, gitPath, full...) // argv[0] is a literal, never user input
	cmd.Env = scrubbedEnv()
	setPgid(cmd) // so a hung git takes its children with it when killed

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	scanErr := scanLines(stdout, fn)
	waitErr := cmd.Wait()

	if waitErr != nil {
		msg := stderr.String()
		if strings.Contains(msg, "dubious ownership") || strings.Contains(msg, "safe.directory") {
			return ErrDubiousOwnership
		}
		if cctx.Err() != nil {
			return fmt.Errorf("git %s timed out after %s", args[0], timeout)
		}
		return fmt.Errorf("git %s: %s", args[0], firstLine(msg))
	}
	return scanErr
}

// scanLines reads NUL- or newline-delimited output.
func scanLines(r io.Reader, fn func(string) error) error {
	br := bufio.NewReaderSize(r, 256<<10)
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			if ferr := fn(line); ferr != nil {
				io.Copy(io.Discard, br) // drain, so git does not block on a full pipe
				return ferr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// StreamNUL is the same, for `-z` output where paths may legitimately contain
// newlines.
func StreamNUL(ctx context.Context, repo string, timeout time.Duration, args []string, fn func(string) error) error {
	return Stream(ctx, repo, timeout, args, func(chunk string) error {
		for _, part := range strings.Split(chunk, "\x00") {
			if part == "" {
				continue
			}
			if err := fn(part); err != nil {
				return err
			}
		}
		return nil
	})
}

func firstOf(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
