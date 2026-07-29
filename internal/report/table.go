package report

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// writeTable prints a fixed-width table. It deliberately doesn't use
// text/tabwriter: tabwriter measures raw byte width, and ANSI color codes
// (invisible but non-zero-width to it) would throw off column alignment
// differently per row depending on which color was used. Padding here is
// computed from the plain cell text before any color is applied.
func writeTable(w io.Writer, headers []string, rows [][]string, colorCol int, color bool) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder
	for i, h := range headers {
		sb.WriteString(padCell(h, widths[i], i == len(headers)-1))
	}
	fmt.Fprintln(w, strings.TrimRight(sb.String(), " "))

	for _, row := range rows {
		sb.Reset()
		for i, cell := range row {
			padded := padCell(cell, widths[i], i == len(row)-1)
			if color && i == colorCol {
				padded = severityCode(cell) + padded + ansiReset
			}
			sb.WriteString(padded)
		}
		fmt.Fprintln(w, strings.TrimRight(sb.String(), " "))
	}
}

func padCell(s string, width int, last bool) string {
	if last {
		return s
	}
	return s + strings.Repeat(" ", width-len(s)+2)
}

// relPath renders path relative to root for display; falls back to path
// unchanged if root is empty or the path isn't under it.
func relPath(root, path string) string {
	if root == "" {
		return path
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}
