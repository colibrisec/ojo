package misconfig

import (
	"bufio"
	"os"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type Instruction struct {
	Cmd  string // upper-cased, e.g. "FROM"
	Args string
	Line int
}

func isDockerfile(name string) bool {
	return name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.")
}

func parseDockerfile(data []byte) []Instruction {
	var out []Instruction
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0
	var pending strings.Builder
	pendingStart := 0

	flush := func() {
		line := strings.TrimSpace(pending.String())
		pending.Reset()
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		args := ""
		if len(parts) == 2 {
			args = strings.TrimSpace(parts[1])
		}
		out = append(out, Instruction{Cmd: cmd, Args: args, Line: pendingStart})
	}

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimRight(raw, " \t\r")
		if pending.Len() == 0 {
			pendingStart = lineNum
		}
		if strings.HasSuffix(trimmed, "\\") {
			pending.WriteString(strings.TrimSuffix(trimmed, "\\"))
			pending.WriteString(" ")
			continue
		}
		pending.WriteString(trimmed)
		flush()
	}
	if pending.Len() > 0 {
		flush()
	}
	return out
}

func dockerfileChecks(instrs []Instruction, path string) []model.Issue {
	var issues []model.Issue

	lastUser := ""
	lastFrom := ""
	for _, in := range instrs {
		switch in.Cmd {
		case "USER":
			lastUser = in.Args
		case "FROM":
			lastFrom = in.Args
			if !strings.Contains(lastFrom, "@sha256:") && (!strings.Contains(lastFrom, ":") || strings.HasSuffix(lastFrom, ":latest")) {
				issues = append(issues, newIssue("dockerfile-latest-tag", "HIGH", path, in.Line,
					"FROM image has no pinned tag (or uses :latest): "+lastFrom,
					"Image "+lastFrom+" is not pinned to a specific, immutable tag or digest"))
			}
		case "ENV", "ARG":
			nameUpper := strings.ToUpper(in.Args)
			for _, kw := range []string{"PASSWORD", "SECRET", "API_KEY", "APIKEY", "TOKEN"} {
				if strings.Contains(nameUpper, kw) {
					issues = append(issues, newIssue("dockerfile-secret-env", "MEDIUM", path, in.Line,
						"Potential secret baked into image via "+in.Cmd,
						in.Cmd+" "+in.Args))
					break
				}
			}
		case "ADD":
			if !strings.Contains(in.Args, "http://") && !strings.Contains(in.Args, "https://") {
				issues = append(issues, newIssue("dockerfile-add-instead-of-copy", "LOW", path, in.Line,
					"ADD used for local files; prefer COPY (ADD has surprising auto-extract/remote-fetch semantics)",
					"ADD "+in.Args))
			}
		}
	}
	if lastUser == "" || lastUser == "root" || lastUser == "0" {
		issues = append(issues, newIssue("dockerfile-root-user", "HIGH", path, 1,
			"Container runs as root (no non-root USER instruction)",
			"final effective user: "+orDefault(lastUser, "root (default)")))
	}
	return issues
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func scanDockerfile(path string) ([]model.Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return dockerfileChecks(parseDockerfile(data), path), nil
}
