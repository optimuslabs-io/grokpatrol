package report

import (
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"
)

// The animated GROKPATROL logo, ported from the Optimus Labs house style in
// optimuslabs-io/perceptron (src/perceptron/cli.py: _animate_banner). Same
// "glitch-decode reveal": the wordmark starts as random mechanical glyphs, a bright
// aqua scan beam sweeps left-to-right, and the columns behind it settle into the real
// letters in a teal->aqua gradient. One deliberate difference from the reference: it
// writes to the caller's io.Writer (the Progress STDERR stream), never stdout, so
// `grokpatrol --json | jq` stays byte-for-byte clean. The caller gates it on stderr
// being a TTY with colour, so a pipe or a log file never sees an escape code.
//
// The wordmark is hand-embedded, not generated at runtime, so nothing new links into
// the binary (grokpatrol is stdlib-only). Regenerate the art with:
//
//	figlet -f standard GROKPATROL
//
// No marker string may appear in this art or its taglines -- the binary scans itself.
const grokPatrolLogoArt = `
  ____ ____    ___  _  __ ____    _  _____ ____    ___  _
 / ___|  _ \  / _ \| |/ /|  _ \  / \|_   _|  _ \  / _ \| |
| |  _| |_) || | | | ' / | |_) |/ _ \ | | | |_) || | | | |
| |_| |  _ < | |_| | . \ |  __// ___ \| | |  _ < | |_| | |___
 \____|_| \_\ \___/|_|\_\|_|  /_/   \_\_| |_| \_\ \___/|_____|`

// logoSubtitle is the three lines beneath the wordmark. heart is "♥" in colour mode
// and degrades to "<3" when unicode/colour is off. The attribution line matches the
// reference's "by Optimus Labs".
func logoSubtitle(heart string) []string {
	return []string{
		"     Grok Build exfiltration audit — offline, read-only",
		"     built with " + heart + " by Optimus Labs",
		"     Learn more at https://optimuslabs.io",
	}
}

// Brand 256-colour ramp (deep teal -> bright aqua), one shade per wordmark row, and
// the bright-aqua scan beam -- both taken verbatim from the reference.
var logoRamp = []int{23, 30, 36, 37, 43, 44}

const logoBeam = "\033[38;5;51m\033[1m"

// Mechanical / glitch glyph pool the scrambled cells draw from (verbatim from the
// reference). No marker character appears here.
var logoGlitch = []rune("#@▒▓█░╳═║╬┼┴┬┤├┯┷┝┥◊◆▰▱◢◣◤◥")

// animateLogo plays the reveal to w. It assumes colour (the caller gates on it); with
// colour off it falls back to the plain, ANSI-free logo so nothing can leak escapes.
func animateLogo(w io.Writer, s Style) {
	if !s.Color {
		plainLogo(w, s)
		return
	}

	art := strings.Split(strings.Trim(grokPatrolLogoArt, "\n"), "\n")
	rows := len(art)
	cols := 0
	for _, line := range art {
		if n := len([]rune(line)); n > cols {
			cols = n
		}
	}
	padded := make([][]rune, rows)
	for i, line := range art {
		r := []rune(line)
		for len(r) < cols {
			r = append(r, ' ')
		}
		padded[i] = r
	}
	settled := make([]string, rows)
	for i := range settled {
		settled[i] = fmt.Sprintf("\033[38;5;%dm\033[1m", logoRamp[min(i, len(logoRamp)-1)])
	}

	glitch := func() rune { return logoGlitch[rand.Intn(len(logoGlitch))] }

	// Frame 0: fully scrambled, dim.
	for r := 0; r < rows; r++ {
		var b strings.Builder
		b.WriteString("\033[2m")
		for c := 0; c < cols; c++ {
			b.WriteRune(glitch())
		}
		b.WriteString(reset)
		fmt.Fprintln(w, b.String())
	}
	time.Sleep(60 * time.Millisecond)

	// Sweep: columns behind the beam settle to the real letters, the beam column glows
	// aqua, columns ahead stay scrambled. Redraw in place each tick.
	step := cols / 60
	if step < 1 {
		step = 1
	}
	for col := 0; col <= cols; col += step {
		fmt.Fprintf(w, "\033[%dF", rows) // cursor up `rows` lines, to column 1
		for r := 0; r < rows; r++ {
			var b strings.Builder
			b.WriteString("\033[2K")
			for c := 0; c < cols; c++ {
				ch := padded[r][c]
				switch {
				case c < col:
					b.WriteString(settled[r])
					b.WriteRune(ch)
				case c < col+step:
					b.WriteString(logoBeam)
					if ch == ' ' {
						b.WriteRune(glitch())
					} else {
						b.WriteRune(ch)
					}
				default:
					b.WriteString("\033[2m")
					b.WriteRune(glitch())
				}
			}
			b.WriteString(reset)
			fmt.Fprintln(w, b.String())
		}
		time.Sleep(18 * time.Millisecond)
	}

	// Final settled redraw -- no beam, all gradient.
	fmt.Fprintf(w, "\033[%dF", rows)
	for r := 0; r < rows; r++ {
		fmt.Fprintf(w, "\033[2K%s%s%s\n", settled[r], string(padded[r]), reset)
	}

	// Subtitle, with colour roles.
	for _, line := range logoSubtitle("♥") {
		fmt.Fprintln(w, subtitleColored(line, s))
		time.Sleep(15 * time.Millisecond)
	}
	fmt.Fprintln(w)
	time.Sleep(300 * time.Millisecond)
}

// subtitleColored gives each subtitle line its role colour: the tagline cyan-bold, the
// attribution green-bold, the link dim.
func subtitleColored(line string, s Style) string {
	switch {
	case strings.Contains(line, "Optimus Labs"):
		return s.c(green+bold, line)
	case strings.Contains(line, "Learn more"):
		return s.c(dim, line)
	case strings.TrimSpace(line) == "":
		return line
	default:
		return s.c(cyan+bold, line)
	}
}

// plainLogo prints the wordmark and subtitle with no ANSI at all -- the non-TTY /
// colour-off fallback. "<3", not "♥", so a plain terminal never shows mojibake.
func plainLogo(w io.Writer, _ Style) {
	fmt.Fprintln(w, strings.Trim(grokPatrolLogoArt, "\n"))
	for _, line := range logoSubtitle("<3") {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
}
