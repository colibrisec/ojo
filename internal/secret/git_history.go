package secret

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

// ponytail: shells out to the system git binary (git log -p) rather than
// adding a go-git dependency -- git is already a hard requirement to have
// a repo to scan in the first place, and -p's unified diff is exactly the
// "what lines were added, in what file, at what line" data this needs.

var hunkHeaderRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// ScanGitHistory greps every line ever added (git log -p on the currently
// checked-out branch's history, -U0 so each hunk is only changed lines) for
// the same rules Scan checks the working tree with. This is what catches a
// secret that was committed and later removed -- Scan can't see it, since
// it never exists on disk at scan time.
//
// ponytail ceiling: the current branch's reachable history only, not every
// branch/tag (no --all) -- predictable ("scan what's checked out plus its
// ancestry"), and bounded. Add --all if secrets hiding in unmerged
// branches turns out to matter. One Issue per commit a secret was added
// in, not deduplicated -- each is a real historical exposure (same
// precedent as gitleaks/trufflehog).
func ScanGitHistory(ctx context.Context, root string, extraRules []Rule) ([]model.Issue, error) {
	rules, err := DefaultRules()
	if err != nil {
		return nil, err
	}
	rules, err = mergeRules(rules, extraRules)
	if err != nil {
		return nil, err
	}

	if err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return nil, fmt.Errorf("%s is not a git repository: %w", root, err)
	}

	cmd := exec.CommandContext(ctx, "git", "-C", root, "log", "-p", "--no-color", "--unified=0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var issues []model.Issue
	var commit, path string
	var isTestFile bool
	lineNum := 0

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "commit "):
			commit = strings.TrimSpace(strings.TrimPrefix(line, "commit "))
			if len(commit) > 7 {
				commit = commit[:7]
			}
		case strings.HasPrefix(line, "+++ "):
			if line == "+++ /dev/null" {
				path = "" // file deleted in this commit, nothing to scan
			} else {
				path = strings.TrimPrefix(line, "+++ b/")
				isTestFile = isLikelyTestFile(path)
			}
		case hunkHeaderRe.MatchString(line):
			m := hunkHeaderRe.FindStringSubmatch(line)
			lineNum, _ = strconv.Atoi(m[1])
		case strings.HasPrefix(line, "+"):
			if path != "" && isConfigFile(path) {
				content := line[1:]
				lower := strings.ToLower(content)
				for _, r := range rules {
					ok, m := ruleApplies(r, content, lower)
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
						Match:    redact(content),
						Message:  fmt.Sprintf("%s detected in git history (commit %s)", r.Description, commit),
					})
				}
			}
			lineNum++
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	if scanErr != nil {
		return nil, scanErr
	}
	if waitErr != nil {
		return nil, fmt.Errorf("git log: %w", waitErr)
	}
	return issues, nil
}
