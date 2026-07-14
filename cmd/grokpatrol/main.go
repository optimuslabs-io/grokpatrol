// grokpatrol detects, on this host, whether the Grok Build CLI collected and
// queued your git repositories for upload to xAI -- and tells you which secrets
// went with them.
//
// It is read-only, makes no network calls, and never executes the grok binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/optimuslabs/grokpatrol/internal/buildinfo"
	cfgdet "github.com/optimuslabs/grokpatrol/internal/detect/config"
	"github.com/optimuslabs/grokpatrol/internal/detect/deepscan"
	"github.com/optimuslabs/grokpatrol/internal/detect/logs"
	"github.com/optimuslabs/grokpatrol/internal/detect/queue"
	"github.com/optimuslabs/grokpatrol/internal/detect/secrets"
	"github.com/optimuslabs/grokpatrol/internal/detect/version"
	"github.com/optimuslabs/grokpatrol/internal/engine"
	"github.com/optimuslabs/grokpatrol/internal/hostfs"
	"github.com/optimuslabs/grokpatrol/internal/model"
	"github.com/optimuslabs/grokpatrol/internal/report"
)

type repeatable []string

func (r *repeatable) String() string     { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error { *r = append(*r, v); return nil }

func main() {
	os.Exit(run())
}

func run() int {
	var (
		home     = flag.String("home", "", "override the home directory to scan")
		grokHome = flag.String("grok-home", "", "override the Grok state dir (default $GROK_HOME or ~/.grok)")
		scanRoot repeatable
		repos    repeatable

		historyScope = flag.String("history-scope", "head", "git history to search for secrets: head | all | none")
		noGit        = flag.Bool("no-git", false, "never invoke git; search only the working tree for secrets")

		concurrency = flag.Int("concurrency", defaultConcurrency(), "content-scan workers")
		maxFileSize = flag.Int64("max-file-size", 512<<20, "skip files larger than this many bytes")
		maxGitObj   = flag.Int("max-git-objects", 5_000_000, "cap on git objects enumerated per repository")
		timeout     = flag.Duration("timeout", 30*time.Minute, "global deadline")
		detTimeout  = flag.Duration("detector-timeout", 5*time.Minute, "per-detector deadline")
		gitTimeout  = flag.Duration("git-timeout", 60*time.Second, "per-git-invocation deadline")

		followLinks = flag.Bool("follow-symlinks", false, "follow symlinks (off by default: cycles and mount escapes)")
		crossFS     = flag.Bool("cross-filesystem", false, "descend into other mounted filesystems")

		asJSON    = flag.Bool("json", false, "emit the machine-readable report on stdout")
		colorMode = flag.String("color", "auto", "auto | always | never")
		quiet     = flag.Bool("quiet", false, "print only the verdict")
		verbose   = flag.Bool("verbose", false, "print every archive, secret and evidence row instead of a sample")
		failOn    = flag.String("fail-on", "medium", "lowest severity that yields a non-zero exit: none|low|medium|high|critical")
		exitZero  = flag.Bool("exit-zero", false, "always exit 0 unless the tool itself failed")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Var(&scanRoot, "scan-root", "additional root to scan (repeatable)")
	flag.Var(&repos, "repo", "force this repository into secret triage (repeatable)")

	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("grokpatrol %s (%s, built %s, %s)\n",
			buildinfo.Version, buildinfo.Commit, buildinfo.Date, buildinfo.GoVersion())
		return 0
	}

	threshold, ok := model.ParseSeverity(*failOn)
	if *failOn != "none" && !ok {
		fmt.Fprintf(os.Stderr, "grokpatrol: unknown --fail-on value %q\n", *failOn)
		return model.ExitToolError
	}

	if s := *historyScope; s != "head" && s != "all" && s != "none" {
		fmt.Fprintf(os.Stderr, "grokpatrol: unknown --history-scope value %q\n", s)
		return model.ExitToolError
	}

	h, err := hostfs.Home(*home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grokpatrol: cannot resolve home directory: %v\n", err)
		return model.ExitToolError
	}

	env := &engine.Env{
		Home:            h,
		GrokHome:        hostfs.GrokHome(*grokHome, h),
		ScanRoots:       scanRoot,
		FollowSymlinks:  *followLinks,
		CrossFilesystem: *crossFS,
		Concurrency:     *concurrency,
		MaxFileSize:     *maxFileSize,
		UseGit:          !*noGit,
		HistoryScope:    *historyScope,
		MaxGitObjects:   *maxGitObj,
		GitTimeout:      *gitTimeout,
		ExtraRepos:      repos,
	}

	// Ctrl-C produces a partial report rather than nothing: on a machine you are
	// worried about, a truncated answer beats no answer.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	// The scan narrates itself on stderr, so a run that takes a minute on a large
	// disk is not a blank screen -- and so that the list of things being checked is
	// visible without reading the source. Suppressed by --quiet. Never stdout:
	// `grokpatrol --json | jq` must keep working.
	var prog engine.Progress
	if !*quiet {
		p := report.NewProgress(os.Stderr, report.Style{Color: useColor(*colorMode, os.Stderr)})
		p.Header(env.Home)
		prog = p
	}

	eng := &engine.Engine{
		Discover:        deepscan.New(),
		Readers:         []engine.Detector{logs.New(), queue.New(), cfgdet.New(), version.New()},
		Triage:          secrets.New(),
		DetectorTimeout: *detTimeout,
		Progress:        prog,
	}
	rep := eng.Run(ctx, env)

	// Detectors record the paths they actually opened; this is the one place they
	// are rewritten for a reader (~/work/foo). Both renderers get the same report,
	// so the terminal and --json can never disagree about where something was found.
	report.Display(rep, h)

	if *asJSON {
		if err := report.JSON(os.Stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "grokpatrol: %v\n", err)
			return model.ExitToolError
		}
	} else {
		report.Human(os.Stdout, rep, report.Style{
			Color:   useColor(*colorMode, os.Stdout),
			Quiet:   *quiet,
			Verbose: *verbose,
		})
	}

	if *exitZero {
		return 0
	}
	return exitCode(rep, threshold, *failOn == "none")
}

// exitCode maps the verdict onto the scripting contract. Findings never produce
// exit 1: that code is reserved for a failure of the tool itself, so a caller can
// always distinguish "grokpatrol broke" from "grokpatrol found something".
func exitCode(rep *model.Report, threshold model.Severity, failNone bool) int {
	if failNone {
		return 0
	}
	if max, any := rep.MaxSeverity(); any && max < threshold {
		// Findings exist but none reach the threshold the caller cares about.
		if rep.Degraded {
			return model.VerdictIndeterminate.ExitCode()
		}
		return 0
	}
	return rep.Verdict.ExitCode()
}

// useColor decides per stream: the report goes to stdout and the progress monitor
// to stderr, and one of the two is routinely piped while the other is a terminal.
func useColor(mode string, f *os.File) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// defaultConcurrency is capped because this work is IO-bound: on a spinning disk
// or a network mount, 32 workers is slower than 4.
func defaultConcurrency() int {
	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

func usage() {
	fmt.Fprint(os.Stderr, `grokpatrol -- detect Grok Build repository exfiltration on this host

Answers three questions, entirely offline:
  1. Did the Grok Build CLI collect and queue your repositories for upload to xAI?
  2. Which repositories, how many times, and when?
  3. What secrets went with them -- including files you deleted, which stayed in git history?

It is read-only. It makes no network calls. It never executes the grok binary, and
it never reads the contents of a secret: it reports filenames so you know what to rotate.

As it runs, it prints each thing it is checking for, on stderr (--quiet silences it).
The report goes to stdout, so "grokpatrol --json | jq" still works while you watch.

USAGE
  grokpatrol [flags]

EXIT CODES
  0  CLEAN          no Grok artifacts, and the scan was not degraded
  1  tool error     bad flags or an internal failure (never used for findings)
  2  INDETERMINATE  nothing found, but parts of the host could not be read
  3  EXPOSED        Grok present and unmitigated, no evidence of upload
  4  COMPROMISED    evidence of collection or upload

FLAGS
`)
	flag.PrintDefaults()
}
