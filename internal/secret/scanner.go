package secret

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

const maxFileSize = 5 << 20

// configExts are file extensions commonly used for configuration, where
// hardcoded secrets are the expected failure mode. Scanning is limited to
// these (plus configNames below) instead of every source file, to keep
// noise/runtime down on large repos.
// ponytail: extension allowlist, add entries if a common config format is missing rather than reworking the approach.
var configExts = map[string]bool{
	".env": true, ".yaml": true, ".yml": true, ".json": true, ".toml": true,
	".ini": true, ".cfg": true, ".conf": true, ".properties": true, ".xml": true,
	".pem": true, ".key": true, ".md": true,
}

var configNames = map[string]bool{
	"dockerfile": true, ".npmrc": true, ".pypirc": true, ".netrc": true,
	".htpasswd": true, ".git-credentials": true, ".dockercfg": true,
}

func isConfigFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if configNames[base] || strings.HasPrefix(base, ".env") {
		return true
	}
	return configExts[filepath.Ext(base)]
}

func Scan(root string) ([]model.Issue, error) {
	rules, err := DefaultRules()
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	err = walk.Walk(root, func(path string, d fs.DirEntry) error {
		if !isConfigFile(path) {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		if isBinary(f) {
			return nil
		}

		lineNum := 0
		isTestFile := isLikelyTestFile(path)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			lower := strings.ToLower(line)
			for _, r := range rules {
				ok, m := ruleApplies(r, line, lower)
				if !ok {
					continue
				}
				if isTestFile && looksLikePlaceholder(m) {
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

func ruleApplies(r Rule, line, lowerLine string) (bool, string) {
	if len(r.Keywords) > 0 {
		matched := false
		for _, kw := range r.Keywords {
			if strings.Contains(lowerLine, kw) {
				matched = true
				break
			}
		}
		if !matched {
			return false, ""
		}
	}
	m := r.compiled.FindString(line)
	if m == "" {
		return false, ""
	}
	if r.MinEntropy > 0 && shannonEntropy(m) < r.MinEntropy {
		return false, ""
	}
	return true, m
}

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
