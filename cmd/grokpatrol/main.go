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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/buildinfo"
	cfgdet "github.com/optimuslabs-io/grokpatrol/internal/detect/config"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/deepscan"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/logs"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/queue"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/secrets"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/version"
	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/report"
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

		fullSecrets  = flag.Bool("full-secrets-search", false, "also scan file CONTENTS for secrets (gitleaks rule set); default matches filenames only and never reads a file")
		maxBlobBytes = flag.Int64("max-blob-scan-bytes", 10<<20, "with --full-secrets-search, skip blobs larger than this many bytes")

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
		noAnim    = flag.Bool("no-animation", false, "skip the animated logo (progress still prints)")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Var(&scanRoot, "scan-root", "additional root to scan (repeatable)")
	flag.Var(&repos, "repo", "force this repository into secret triage (repeatable)")

	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("grokpatrol %s (%s, built %s, %s)\n",
			buildinfo.Version, buildinfo.Commit, buildinfo.Date, buildinfo.GoVersion())
		fmt.Println("github.com/optimuslabs-io/grokpatrol · Optimus Labs")
		return 0
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
		Home:              h,
		GrokHome:          hostfs.GrokHome(*grokHome, h),
		PathDirs:          filepath.SplitList(os.Getenv("PATH")),
		ScanRoots:         scanRoot,
		FollowSymlinks:    *followLinks,
		CrossFilesystem:   *crossFS,
		Concurrency:       *concurrency,
		MaxFileSize:       *maxFileSize,
		UseGit:            !*noGit,
		HistoryScope:      *historyScope,
		MaxGitObjects:     *maxGitObj,
		GitTimeout:        *gitTimeout,
		ExtraRepos:        repos,
		FullSecretsSearch: *fullSecrets,
		MaxBlobScanBytes:  *maxBlobBytes,
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
		style := report.Style{Color: useColor(*colorMode, os.Stderr)}
		p := report.NewProgress(os.Stderr, style)
		// The animated logo plays only into a real terminal: colour on and stderr being a
		// TTY, and not opted out. A pipe/redirect, NO_COLOR, --color never, --no-animation,
		// or GROKPATROL_NO_ANIM all skip it.
		stderrIsTTY := false
		if fi, err := os.Stderr.Stat(); err == nil {
			stderrIsTTY = fi.Mode()&os.ModeCharDevice != 0
		}
		if stderrIsTTY && style.Color && !*noAnim && os.Getenv("GROKPATROL_NO_ANIM") == "" {
			p.Splash()
		}
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

	// Reaching this point means the scan ran and a report was produced -- whatever it
	// found. The exit code answers only "did grokpatrol run", never "what did it find";
	// the verdict is in the report body above (or --json), which is where a caller reads
	// it. See model.ExitToolError.
	return 0
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
	fmt.Fprint(os.Stderr, `grokpatrol — Grok Build repo exfil exposure check

Answers three questions, entirely offline:
  1. Which repositories were collected or queued for upload to xAI?
  2. How many times, and when?
  3. Which secrets went with them -- including files you deleted, which stayed in git history?

It is read-only. It makes no network calls. It never executes the grok binary. By
default it never reads the contents of a secret: it reports filenames so you know what
to rotate. With --full-secrets-search it also matches file contents against the
gitleaks rule set -- values are matched in memory, and still never stored or printed.

As it runs, it prints each thing it is checking for, on stderr (--quiet silences it).
The report goes to stdout, so "grokpatrol --json | jq" still works while you watch.

USAGE
  grokpatrol [flags]

EXIT CODES
  0  the scan ran and printed a report -- CLEAN, INDETERMINATE, EXPOSED or COMPROMISED
     alike. Read VERDICT in the report (or "verdict" in --json) for the finding.
  1  tool error -- bad flags or an internal failure. Never used for a finding.

FLAGS
`)
	flag.PrintDefaults()
}
