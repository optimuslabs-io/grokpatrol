package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// colPad is the visible gap between columns in colour-safe tables.
const colPad = 2

// maxPathCol is the default visible width for path columns in AFFECTED REPOS /
// CREDENTIAL PATHS. Longer paths are mid-truncated so STATUS/ARCHIVES still fit
// on an ~80-column terminal; full paths remain in --json.
const maxPathCol = 40

// visibleWidth returns the display width of s after stripping CSI SGR sequences
// (the only ANSI this package emits). Tabwriter cannot do this -- it counts
// escape bytes as width, so coloured STATUS cells shoved later columns right
// while --no-color looked fine.
func visibleWidth(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == ';') {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				i = j + 1
				continue
			}
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		if size == 0 {
			break
		}
		n++
		i += size
	}
	return n
}

// writeTable writes rows as a colour-safe fixed-width table. Cells may contain
// ANSI; padding uses visibleWidth so columns line up with colour on.
// Short rows are padded with empty cells to the widest row's column count.
func writeTable(w io.Writer, indent string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	cols := 0
	for _, r := range rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	widths := make([]int, cols)
	for _, r := range rows {
		for i, c := range r {
			if n := visibleWidth(c); n > widths[i] {
				widths[i] = n
			}
		}
	}
	for _, r := range rows {
		fmt.Fprint(w, indent)
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(r) {
				cell = r[i]
			}
			fmt.Fprint(w, cell)
			if i < cols-1 {
				gap := widths[i] - visibleWidth(cell) + colPad
				if gap < colPad {
					gap = colPad
				}
				fmt.Fprint(w, strings.Repeat(" ", gap))
			}
		}
		fmt.Fprintln(w)
	}
}

// truncatePath shortens p for a table PATH column while keeping the useful
// ends (home-relative prefix + basename). No ANSI expected on paths.
func truncatePath(p string, max int) string {
	if max < 8 || utf8.RuneCountInString(p) <= max {
		return p
	}
	runes := []rune(p)
	// Keep more of the tail (basename) than the head.
	tail := max / 2
	if tail < 4 {
		tail = 4
	}
	head := max - tail - 1 // 1 for …
	if head < 3 {
		head = 3
		tail = max - head - 1
	}
	return string(runes[:head]) + "…" + string(runes[len(runes)-tail:])
}
