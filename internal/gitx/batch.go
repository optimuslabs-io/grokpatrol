package gitx

// cat-file batch plumbing, used only by --full-secrets-search.
//
// Everything else in this package is line-oriented and stdin-less. Blobs are
// neither: requests must be WRITTEN while responses are READ (git blocks once
// the ~64 KB stdout pipe fills, so write-all-then-read-all deadlocks on any
// real repository), and blob bytes are binary, so the response is parsed by
// its length header, never by line scanning.
//
// The timeout here is a STALL timeout, not a wall-clock one: a repository with
// a hundred thousand blobs legitimately takes longer than any fixed budget,
// but a healthy git never goes quiet mid-batch. The timer resets on every
// response; only silence kills the process.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// CatFileBatchCheck streams `git cat-file --batch-check` over shas: object
// type and size only, no contents. The caller uses it to decide which blobs
// are worth (and safe) to fetch with CatFileBatch. Missing objects are
// reported with size < 0 rather than dropped, so the caller can count them.
func CatFileBatchCheck(ctx context.Context, repo string, stall time.Duration, shas []string, fn func(sha, objType string, size int64) error) error {
	return runBatch(ctx, repo, stall, []string{"cat-file", "--batch-check", "--buffer"}, shas,
		func(br *bufio.Reader, tick func()) error {
			for range shas {
				sha, objType, size, err := readHeader(br)
				if err != nil {
					return err
				}
				tick()
				if err := fn(sha, objType, size); err != nil {
					return err
				}
			}
			return nil
		})
}

// CatFileBatch streams `git cat-file --batch` over shas and hands each blob's
// bytes to fn. The buffer is TRANSIENT: it is reused across objects, so fn
// must not retain it -- which is the point. Contents exist to be matched and
// forgotten; nothing downstream has anywhere to keep them.
//
// Objects larger than maxBytes are drained off the pipe and delivered as
// (sha, nil): the caller must record the skip, because a blob too big to scan
// is an absence of information, never a clean bill of health.
func CatFileBatch(ctx context.Context, repo string, stall time.Duration, maxBytes int64, shas []string, fn func(sha string, data []byte) error) error {
	var buf []byte
	return runBatch(ctx, repo, stall, []string{"cat-file", "--batch", "--buffer"}, shas,
		func(br *bufio.Reader, tick func()) error {
			for range shas {
				sha, _, size, err := readHeader(br)
				if err != nil {
					return err
				}
				tick()
				if size < 0 { // missing object: surface as a skip
					if err := fn(sha, nil); err != nil {
						return err
					}
					continue
				}
				if size > maxBytes {
					if _, err := io.CopyN(io.Discard, br, size+1); err != nil { // +1: trailing LF
						return fmt.Errorf("draining oversized object %s: %w", sha, err)
					}
					tick()
					if err := fn(sha, nil); err != nil {
						return err
					}
					continue
				}
				if int64(cap(buf)) < size {
					buf = make([]byte, size)
				}
				buf = buf[:size]
				if _, err := io.ReadFull(br, buf); err != nil {
					return fmt.Errorf("reading object %s: %w", sha, err)
				}
				if lf, err := br.ReadByte(); err != nil || lf != '\n' {
					return fmt.Errorf("object %s: malformed batch framing", sha)
				}
				tick()
				if err := fn(sha, buf); err != nil {
					return err
				}
			}
			return nil
		})
}

// readHeader parses one `<sha> <type> <size>` batch header. `<sha> missing`
// (and the other single-word statuses) come back as size -1.
func readHeader(br *bufio.Reader) (sha, objType string, size int64, err error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", "", 0, fmt.Errorf("reading batch header: %w", err)
	}
	fields := strings.Fields(strings.TrimSuffix(line, "\n"))
	switch len(fields) {
	case 3:
		size, err = strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return "", "", 0, fmt.Errorf("malformed batch header %q", strings.TrimSpace(line))
		}
		return fields[0], fields[1], size, nil
	case 2: // "<sha> missing" / "<sha> ambiguous"
		return fields[0], fields[1], -1, nil
	default:
		return "", "", 0, fmt.Errorf("malformed batch header %q", strings.TrimSpace(line))
	}
}

// runBatch is the shared harness: spawn, feed stdin from a goroutine, read
// responses under a stall timer, and translate failures the same way Stream
// does (dubious ownership, timeout, first stderr line).
func runBatch(ctx context.Context, repo string, stall time.Duration, args, shas []string, read func(br *bufio.Reader, tick func()) error) error {
	if !Available() {
		return ErrNoGit
	}
	if len(args) == 0 || !allowed[args[0]] {
		return fmt.Errorf("gitx: subcommand %q is not in the read-only allowlist", firstOf(args))
	}
	if len(shas) == 0 {
		return nil
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	full := append(readOnlyArgs(repo), args...)
	cmd := exec.CommandContext(cctx, gitPath, full...) // argv[0] is a literal, never user input
	cmd.Env = scrubbedEnv()
	setPgid(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	// The stall timer: silence for `stall` kills the process group. tick() is
	// called by the reader on every response, so a healthy batch of any length
	// never trips it.
	var timedOut atomic.Bool
	timer := time.AfterFunc(stall, func() { timedOut.Store(true); cancel() })
	tick := func() { timer.Reset(stall) }

	// Feed requests concurrently with reading; see the file comment for why.
	writeErr := make(chan error, 1)
	go func() {
		defer stdin.Close()
		w := bufio.NewWriter(stdin)
		for _, sha := range shas {
			if _, err := w.WriteString(sha + "\n"); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- w.Flush()
	}()

	readErr := read(bufio.NewReaderSize(stdout, 256<<10), tick)
	if readErr != nil {
		io.Copy(io.Discard, stdout) // drain, so git does not block on a full pipe
	}
	waitErr := cmd.Wait()
	timer.Stop()
	werr := <-writeErr

	if waitErr != nil {
		msg := stderr.String()
		if strings.Contains(msg, "dubious ownership") || strings.Contains(msg, "safe.directory") {
			return ErrDubiousOwnership
		}
		if timedOut.Load() {
			return fmt.Errorf("git %s stalled for %s", args[0], stall)
		}
		if cctx.Err() != nil {
			return cctx.Err()
		}
		return fmt.Errorf("git %s: %s", args[0], firstLine(msg))
	}
	if readErr != nil {
		return readErr
	}
	if werr != nil && !errors.Is(werr, io.ErrClosedPipe) {
		return fmt.Errorf("feeding git %s: %w", args[0], werr)
	}
	return nil
}
