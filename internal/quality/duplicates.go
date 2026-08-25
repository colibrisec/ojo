package quality

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

// Deliberately line-based, not token/AST-based: duplication detection
// doesn't need language-aware parsing (PMD CPD and jscpd both support
// plain lexical modes), and a line-based approach is language-agnostic for
// free — one algorithm for all six languages instead of six per-language
// token-stream extractors, for a "least effort, still correct" tradeoff
// specific to this metric.

const (
	dupWindowLines = 6  // minimum block size considered, in significant (non-blank) lines
	dupMinChars    = 30 // minimum non-whitespace characters in a window — filters trivial matches like runs of "}"
)

var dupExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".ts": true, ".mts": true, ".cts": true, ".tsx": true,
	".php":  true,
	".rb":   true,
	".java": true,
}

type dupLine struct {
	text string // trimmed
	line int    // 1-based original line number
}

type dupWindowRef struct {
	file  string
	lines []dupLine // this file's full significant-line sequence (shared, not copied per window)
	start int       // index into lines
}

func scanDuplicates(root string) ([]model.Issue, error) {
	files := map[string][]dupLine{}
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		if !dupExtensions[filepath.Ext(path)] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var lines []dupLine
		for i, raw := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(raw)
			if t == "" {
				continue
			}
			lines = append(lines, dupLine{text: t, line: i + 1})
		}
		if len(lines) >= dupWindowLines {
			files[path] = lines
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	buckets := map[string][]dupWindowRef{}
	for file, lines := range files {
		for start := 0; start+dupWindowLines <= len(lines); start++ {
			window := lines[start : start+dupWindowLines]
			joined := joinDupLines(window)
			if nonSpaceLen(joined) < dupMinChars {
				continue
			}
			h := hashDupText(joined)
			buckets[h] = append(buckets[h], dupWindowRef{file: file, lines: lines, start: start})
		}
	}

	// Sorted bucket order for deterministic output — map iteration order
	// would otherwise make which occurrence "wins" the overlap-suppression
	// race (see reportedThrough below) vary run to run.
	hashes := make([]string, 0, len(buckets))
	for h := range buckets {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)

	reportedThrough := map[string]int{} // file -> index just past the last reported block, suppresses overlap spam from one long duplicate
	var issues []model.Issue
	for _, h := range hashes {
		refs := buckets[h]
		if len(refs) < 2 {
			continue
		}

		var kept []dupWindowRef
		for _, r := range refs {
			if r.start < reportedThrough[r.file] {
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) < 2 {
			continue
		}

		blockLen := dupWindowLines + extendMatch(kept)
		locs := make([]string, len(kept))
		for i, r := range kept {
			locs[i] = fmt.Sprintf("%s:%d", r.file, r.lines[r.start].line)
		}

		for i, r := range kept {
			others := append(append([]string{}, locs[:i]...), locs[i+1:]...)
			endLine := r.lines[r.start+blockLen-1].line
			issues = append(issues, newIssue("quality-duplicate-code", "MEDIUM", r.file, r.lines[r.start].line,
				"Duplicate code block",
				fmt.Sprintf("lines %d-%d duplicate %s", r.lines[r.start].line, endLine, strings.Join(others, ", "))))
			reportedThrough[r.file] = r.start + blockLen
		}
	}
	return issues, nil
}

// extendMatch returns how many additional lines (beyond the base window)
// every ref in refs keeps matching in lock-step — the minimum across all
// refs, so every occurrence reported for this group shares one common,
// fully-verified duplicate length.
func extendMatch(refs []dupWindowRef) int {
	anchor := refs[0]
	extra := 0
	for {
		next := dupWindowLines + extra
		anchorIdx := anchor.start + next
		if anchorIdx >= len(anchor.lines) {
			return extra
		}
		want := anchor.lines[anchorIdx].text
		for _, r := range refs[1:] {
			idx := r.start + next
			if idx >= len(r.lines) || r.lines[idx].text != want {
				return extra
			}
		}
		extra++
	}
}

func joinDupLines(lines []dupLine) string {
	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = l.text
	}
	return strings.Join(parts, "\n")
}

func nonSpaceLen(s string) int {
	n := 0
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' {
			n++
		}
	}
	return n
}

func hashDupText(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
