package report

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type boxColumn struct {
	Header string
	Wrap   int
}

func writeBoxTable(w io.Writer, cols []boxColumn, rows [][]string, colorCol int, color bool) {
	n := len(cols)
	widths := make([]int, n)
	for i, c := range cols {
		widths[i] = len([]rune(c.Header))
	}

	wrapped := make([][][]string, len(rows))
	for ri, row := range rows {
		wrapped[ri] = make([][]string, n)
		for ci := range n {
			text := ""
			if ci < len(row) {
				text = row[ci]
			}
			var lines []string
			if cols[ci].Wrap > 0 {
				lines = wrapText(text, cols[ci].Wrap)
			} else {
				lines = []string{text}
			}
			wrapped[ri][ci] = lines
			for _, line := range lines {
				if l := len([]rune(line)); l > widths[ci] {
					widths[ci] = l
				}
			}
			if cols[ci].Wrap > 0 && widths[ci] > cols[ci].Wrap {
				widths[ci] = cols[ci].Wrap
			}
		}
	}

	headers := make([]string, n)
	for i, c := range cols {
		headers[i] = c.Header
	}

	fmt.Fprintln(w, borderLine(widths, "┌", "┬", "┐"))
	fmt.Fprintln(w, dataLine(headers, widths, -1, false))
	fmt.Fprintln(w, borderLine(widths, "├", "┼", "┤"))
	for ri, row := range rows {
		_ = row
		height := 1
		for ci := range n {
			if len(wrapped[ri][ci]) > height {
				height = len(wrapped[ri][ci])
			}
		}
		for line := range height {
			cells := make([]string, n)
			for ci := range n {
				if line < len(wrapped[ri][ci]) {
					cells[ci] = wrapped[ri][ci][line]
				}
			}
			fmt.Fprintln(w, dataLine(cells, widths, colorCol, color))
		}
		if ri < len(rows)-1 {
			fmt.Fprintln(w, borderLine(widths, "├", "┼", "┤"))
		}
	}
	fmt.Fprintln(w, borderLine(widths, "└", "┴", "┘"))
}

func borderLine(widths []int, left, mid, right string) string {
	var sb strings.Builder
	sb.WriteString(left)
	for i, wd := range widths {
		sb.WriteString(strings.Repeat("─", wd+2))
		if i < len(widths)-1 {
			sb.WriteString(mid)
		} else {
			sb.WriteString(right)
		}
	}
	return sb.String()
}

func dataLine(cells []string, widths []int, colorCol int, color bool) string {
	var sb strings.Builder
	sb.WriteString("│")
	for i, width := range widths {
		text := ""
		if i < len(cells) {
			text = cells[i]
		}
		pad := max(width-len([]rune(text)), 0)
		sb.WriteString(" ")
		if color && i == colorCol && text != "" {
			sb.WriteString(severityCode(text))
			sb.WriteString(text)
			sb.WriteString(ansiReset)
		} else {
			sb.WriteString(text)
		}
		sb.WriteString(strings.Repeat(" ", pad))
		sb.WriteString(" │")
	}
	return sb.String()
}

func wrapText(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	var out []string
	for para := range strings.SplitSeq(s, "\n") {
		out = append(out, wrapParagraph(para, width)...)
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

func wrapParagraph(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	var cur strings.Builder
	for _, word := range words {
		for len(word) > width {
			if cur.Len() > 0 {
				lines = append(lines, cur.String())
				cur.Reset()
			}
			lines = append(lines, word[:width])
			word = word[width:]
		}
		switch {
		case cur.Len() == 0:
			cur.WriteString(word)
		case cur.Len()+1+len(word) > width:
			lines = append(lines, cur.String())
			cur.Reset()
			cur.WriteString(word)
		default:
			cur.WriteString(" ")
			cur.WriteString(word)
		}
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

func mergeRuns(rows [][]string, cols []int) {
	prev := make([]string, len(cols))
	first := true
	for _, row := range rows {
		for ci, col := range cols {
			raw := row[col]
			if !first && raw == prev[ci] {
				row[col] = ""
			} else {
				prev[ci] = raw
			}
		}
		first = false
	}
}

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
