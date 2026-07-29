package report

import (
	"io"
	"os"

	"golang.org/x/term"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBoldRed = "\x1b[1;31m"
	ansiRed     = "\x1b[31m"
	ansiYellow  = "\x1b[33m"
	ansiCyan    = "\x1b[36m"
	ansiGray    = "\x1b[90m"
)

// isColorWriter reports whether w is an interactive terminal that should
// receive ANSI colors, honoring the NO_COLOR convention.
func isColorWriter(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func severityCode(sev string) string {
	switch sev {
	case "CRITICAL":
		return ansiBoldRed
	case "HIGH":
		return ansiRed
	case "MEDIUM", "MODERATE":
		return ansiYellow
	case "LOW":
		return ansiCyan
	default: // INFO, UNKNOWN
		return ansiGray
	}
}

// severityRank orders severities from most to least urgent for sorting; unknown values sort last.
func severityRank(sev string) int {
	switch sev {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM", "MODERATE":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 5
	}
}
