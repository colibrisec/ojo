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
	hasHealthcheck := false
	globalArgs := map[string]string{} // ARGs declared before the first FROM
	stages := map[string]bool{}
	seenFrom := false
	for _, in := range instrs {
		switch in.Cmd {
		case "FROM":
			seenFrom = true
			// New stage: USER/HEALTHCHECK reset to Docker defaults for that stage.
			lastUser = ""
			hasHealthcheck = false
			image, stage := parseFrom(in.Args)
			resolved := expandArgs(image, globalArgs)
			if !stages[strings.ToLower(image)] && !imagePinned(resolved) {
				issues = append(issues, newIssue("dockerfile-latest-tag", "HIGH", path, in.Line,
					"FROM image has no pinned tag (or uses :latest): "+in.Args,
					"Image "+resolved+" is not pinned to a specific, immutable tag or digest"))
			}
			if stage != "" {
				stages[strings.ToLower(stage)] = true
			}
		case "USER":
			lastUser = in.Args
		case "HEALTHCHECK":
			if strings.EqualFold(strings.TrimSpace(in.Args), "NONE") {
				hasHealthcheck = false
			} else {
				hasHealthcheck = true
			}
		case "ENV", "ARG":
			pairs := parseEnvArgs(in.Cmd, in.Args)
			if in.Cmd == "ARG" && !seenFrom {
				for _, kv := range pairs {
					globalArgs[kv.name] = kv.value
				}
			}
			for _, kv := range pairs {
				if secretVarName(kv.name) {
					issues = append(issues, newIssue("dockerfile-secret-env", "MEDIUM", path, in.Line,
						"Potential secret baked into image via "+in.Cmd+" "+kv.name,
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
	if !hasHealthcheck {
		issues = append(issues, newIssue("dockerfile-no-healthcheck", "LOW", path, 1,
			"No HEALTHCHECK instruction defined", "image has no HEALTHCHECK"))
	}
	return issues
}

// parseFrom splits "FROM [--platform=x] image [AS name]".
func parseFrom(args string) (image, stage string) {
	fields := strings.Fields(args)
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return "", ""
	}
	image = fields[0]
	if len(fields) >= 3 && strings.EqualFold(fields[1], "AS") {
		stage = fields[2]
	}
	return image, stage
}

// expandArgs substitutes $NAME / ${NAME} / ${NAME:-default} from ARG defaults.
func expandArgs(s string, args map[string]string) string {
	return os.Expand(s, func(name string) string {
		def := ""
		if i := strings.Index(name, ":-"); i >= 0 {
			name, def = name[:i], name[i+2:]
		}
		if v, ok := args[name]; ok && v != "" {
			return v
		}
		return def
	})
}

func imagePinned(image string) bool {
	if image == "scratch" || strings.Contains(image, "@sha256:") {
		return true
	}
	// A ':' after the last '/' is a tag; one before it is a registry port.
	tag := image[strings.LastIndex(image, "/")+1:]
	i := strings.LastIndex(tag, ":")
	return i >= 0 && tag[i+1:] != "" && tag[i+1:] != "latest"
}

type envPair struct{ name, value string }

// parseEnvArgs reads ENV's "k=v k2=v2" and legacy "k v" forms, and ARG's
// "name[=default] ...".
func parseEnvArgs(cmd, args string) []envPair {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	if cmd == "ENV" {
		first := strings.Fields(args)[0]
		if !strings.Contains(first, "=") {
			name, value, _ := strings.Cut(args, " ")
			return []envPair{{name, unquote(strings.TrimSpace(value))}}
		}
	}
	var out []envPair
	for _, tok := range splitShellWords(args) {
		name, value, _ := strings.Cut(tok, "=")
		out = append(out, envPair{name, unquote(value)})
	}
	return out
}

// splitShellWords splits on unquoted whitespace, keeping quotes in place.
func splitShellWords(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			cur.WriteRune(r)
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

var (
	secretNameWords = map[string]bool{"PASSWORD": true, "PASSWD": true, "SECRET": true, "TOKEN": true, "APIKEY": true, "CREDENTIALS": true}
	secretNamePairs = [][2]string{{"API", "KEY"}, {"PRIVATE", "KEY"}, {"CLIENT", "SECRET"}}
	// NAME_FILE / NAME_PATH point at a secret (Docker secrets convention); they don't hold one.
	secretNameRefSuffix = map[string]bool{"FILE": true, "PATH": true, "DIR": true}
)

// secretVarName matches whole underscore- or camelCase-separated parts of a
// variable name: GITHUB_TOKEN, DB_PASSWORD, API_KEY, apiKey match;
// TOKENIZERS_PARALLELISM and DB_PASSWORD_FILE don't.
func secretVarName(name string) bool {
	parts := nameParts(name)
	if len(parts) == 0 || secretNameRefSuffix[parts[len(parts)-1]] {
		return false
	}
	for i, p := range parts {
		if secretNameWords[p] {
			return true
		}
		if i+1 < len(parts) {
			for _, pair := range secretNamePairs {
				if p == pair[0] && parts[i+1] == pair[1] {
					return true
				}
			}
		}
	}
	return false
}

func nameParts(name string) []string {
	var parts []string
	var cur strings.Builder
	prevLower := false
	flush := func() {
		if cur.Len() > 0 {
			parts = append(parts, strings.ToUpper(cur.String()))
			cur.Reset()
		}
	}
	for _, r := range name {
		switch {
		case r == '_' || r == '-' || r == '.':
			flush()
			prevLower = false
			continue
		case r >= 'A' && r <= 'Z' && prevLower:
			flush()
		}
		cur.WriteRune(r)
		prevLower = r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
	}
	flush()
	return parts
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
