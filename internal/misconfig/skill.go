package misconfig

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/colibrisec/ojo/internal/model"
)

func isSkillFile(name string) bool {
	return strings.EqualFold(name, "SKILL.md")
}

// fetchExecuteRe matches a remote-fetch command whose output is piped
// straight into a shell/interpreter -- the classic curl-pipe-bash
// supply-chain pattern, just as risky inside a skill's instructions or
// bundled script as it is in a Dockerfile RUN line.
var fetchExecuteRe = regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|iex|invoke-expression)\b`)

// credentialPaths are well-known credential file locations -- a concrete,
// enumerable signal, the same kind internal/secret's rules key on, not a
// generic notion of "sensitive data" that would need semantic judgment.
var credentialPaths = []string{
	".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".netrc",
	".npmrc", ".git-credentials", ".docker/config.json", ".env",
}

// exfilVerbRe is deliberately narrow -- a handful of concrete transfer
// verbs, not an attempt at general "sounds like exfiltration" semantics.
var exfilVerbRe = regexp.MustCompile(`(?i)\b(curl|wget|post|upload|send)\b`)

// dangerousUnscopedTools are grants with no legitimate scoped form to
// distinguish from -- a bare wildcard or an unrestricted shell-exec tool.
// "Bash(git:*)" is a normal, scoped grant and doesn't match any of these.
var dangerousUnscopedTools = map[string]bool{
	"*": true, "bash": true, "bash(*)": true, "shell": true, "execute": true,
}

func skillChecks(body, path string) []model.Issue {
	var issues []model.Issue

	if tool, ok := skillBroadToolPermission(skillFrontmatter(body)); ok {
		issues = append(issues, newIssue("skill-broad-tool-permissions", "MEDIUM", path, 1,
			"Skill grants itself broad/unscoped tool permissions in its frontmatter",
			"allowed-tools: "+tool))
	}

	for i, line := range strings.Split(body, "\n") {
		lineNo := i + 1
		if fetchExecuteRe.MatchString(line) {
			issues = append(issues, newIssue("skill-fetch-execute", "HIGH", path, lineNo,
				"Skill fetches a remote script and pipes it directly into a shell",
				strings.TrimSpace(line)))
		}
		lower := strings.ToLower(line)
		for _, cp := range credentialPaths {
			if strings.Contains(lower, cp) && exfilVerbRe.MatchString(line) {
				issues = append(issues, newIssue("skill-credential-exfil-reference", "HIGH", path, lineNo,
					"Skill references a credential file alongside an outbound-transfer command",
					strings.TrimSpace(line)))
				break
			}
		}
		if hasInjectionLanguage(line) {
			issues = append(issues, newIssue("skill-prompt-injection-language", "MEDIUM", path, lineNo,
				"Skill contains known prompt-injection phrasing",
				strings.TrimSpace(line)))
		}
		if r, ok := findHiddenUnicode(line); ok {
			issues = append(issues, newIssue("skill-hidden-unicode", "HIGH", path, lineNo,
				"Skill contains a hidden/invisible Unicode character",
				"U+"+unicodeCodepoint(r)))
		}
	}
	return issues
}

// skillFrontmatter parses a SKILL.md's leading "---"-delimited YAML block.
// Frontmatter is optional; both a missing block and a parse failure return
// nil, a normal "nothing to check" rather than an error.
func skillFrontmatter(body string) map[string]any {
	rest := body
	switch {
	case strings.HasPrefix(rest, "---\r\n"):
		rest = rest[len("---\r\n"):]
	case strings.HasPrefix(rest, "---\n"):
		rest = rest[len("---\n"):]
	default:
		return nil
	}
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return nil
	}
	var fm map[string]any
	if yaml.Unmarshal([]byte(rest[:end]), &fm) != nil {
		return nil
	}
	return fm
}

func skillBroadToolPermission(fm map[string]any) (string, bool) {
	switch t := fm["allowed-tools"].(type) {
	case string:
		if dangerousUnscopedTools[strings.ToLower(strings.TrimSpace(t))] {
			return t, true
		}
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && dangerousUnscopedTools[strings.ToLower(strings.TrimSpace(s))] {
				return s, true
			}
		}
	}
	return "", false
}

func scanSkill(path string) ([]model.Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return skillChecks(string(data), path), nil
}
