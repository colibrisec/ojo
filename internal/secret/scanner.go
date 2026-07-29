// Package secret scans source files for hardcoded credentials using a
// regex + keyword + entropy rule set (see default_rules.yaml).
package secret

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

const maxFileSize = 5 << 20 // 5MB; ponytail: skip large files rather than chunk-scan them

// Scan walks root and returns one Issue per secret-shaped match.
func Scan(root string) ([]model.Issue, error) {
	rules, err := DefaultRules()
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	err = walk.Walk(root, func(path string, d fs.DirEntry) error {
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil // ponytail: unreadable file, skip rather than fail the scan
		}
		defer f.Close()

		if isBinary(f) {
			return nil
		}

		lineNum := 0
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			lower := strings.ToLower(line)
			for _, r := range rules {
				if !ruleApplies(r, line, lower) {
					continue
				}
				issues = append(issues, model.Issue{
					Scanner:  "secret",
					RuleID:   r.ID,
					Title:    r.Description,
					Severity: r.Severity,
					File:     path,
					Line:     lineNum,
					Match:    redact(line),
					Message:  fmt.Sprintf("%s detected", r.Description),
				})
			}
		}
		return nil
	})
	return issues, err
}

func ruleApplies(r Rule, line, lowerLine string) bool {
	if len(r.Keywords) > 0 {
		matched := false
		for _, kw := range r.Keywords {
			if strings.Contains(lowerLine, kw) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	m := r.compiled.FindString(line)
	if m == "" {
		return false
	}
	if r.MinEntropy > 0 && shannonEntropy(m) < r.MinEntropy {
		return false
	}
	return true
}

// redact keeps a match readable in reports without printing the full secret.
func redact(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 80 {
		line = line[:80] + "..."
	}
	return line
}

func isBinary(f *os.File) bool {
	defer f.Seek(0, 0)
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return bytes.IndexByte(buf[:n], 0) != -1
}
