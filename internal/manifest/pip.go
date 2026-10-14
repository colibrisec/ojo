package manifest

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type pipRequirementsParser struct{}

func (pipRequirementsParser) Match(name string) bool {
	return strings.HasSuffix(name, ".txt") &&
		(strings.HasPrefix(name, "requirements") || strings.HasSuffix(name, "requirements.txt"))
}

var (
	pipReqRe  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)
	pipSpecRe = regexp.MustCompile(`^(===|==|~=|!=|<=|>=|<|>)\s*(\S+)$`)
	pipEggRe  = regexp.MustCompile(`#egg=([A-Za-z0-9._-]+)`)
)

func (p pipRequirementsParser) Parse(path string) ([]model.Package, error) {
	pkgs, _, err := p.ParsePartial(path)
	return pkgs, err
}

func (pipRequirementsParser) ParsePartial(path string) ([]model.Package, []Unscannable, error) {
	var pkgs []model.Package
	var skipped []Unscannable
	err := parsePipFile(path, map[string]bool{}, &pkgs, &skipped)
	return pkgs, skipped, err
}

func parsePipFile(path string, visited map[string]bool, pkgs *[]model.Package, skipped *[]Unscannable) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if visited[abs] {
		return nil
	}
	visited[abs] = true

	lines, err := pipLogicalLines(path)
	if err != nil {
		return err
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "-") {
			if inc, ok := pipInclude(line); ok {
				// A missing include is skipped like any unreadable manifest.
				_ = parsePipFile(filepath.Join(filepath.Dir(path), inc), visited, pkgs, skipped)
			} else if target, ok := pipEditable(line); ok {
				*skipped = append(*skipped, Unscannable{Name: pipURLName(target), Source: path, Reason: "editable install"})
			}
			continue
		}
		if pkg, skip, ok := parsePipRequirement(line, path); ok {
			if skip != nil {
				*skipped = append(*skipped, *skip)
			} else {
				*pkgs = append(*pkgs, pkg)
			}
		}
	}
	return nil
}

// pipLogicalLines joins backslash continuations and strips comments.
func pipLogicalLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	var cur strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		if strings.HasSuffix(raw, `\`) {
			cur.WriteString(strings.TrimSuffix(raw, `\`))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(raw)
		line := cur.String()
		cur.Reset()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "\t#"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func pipOption(line string, short, long string) (string, bool) {
	for _, prefix := range []string{long + "=", long + " ", short + " ", short} {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[len(prefix):]), true
		}
	}
	return "", false
}

func pipInclude(line string) (string, bool) {
	inc, ok := pipOption(line, "-r", "--requirement")
	return inc, ok && inc != ""
}

func pipEditable(line string) (string, bool) {
	target, ok := pipOption(line, "-e", "--editable")
	return target, ok && target != ""
}

func pipURLName(target string) string {
	if m := pipEggRe.FindStringSubmatch(target); m != nil {
		return m[1]
	}
	return target
}

func parsePipRequirement(line, path string) (model.Package, *Unscannable, bool) {
	if i := strings.Index(line, ";"); i >= 0 {
		line = line[:i] // environment markers aren't evaluated
	}
	if i := strings.Index(line, " -"); i >= 0 {
		line = line[:i] // per-requirement options such as --hash
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return model.Package{}, nil, false
	}

	m := pipReqRe.FindStringSubmatch(line)
	if m != nil && strings.HasPrefix(strings.TrimSpace(m[3]), "@") {
		return model.Package{}, &Unscannable{Name: m[1], Source: path, Reason: "URL or path"}, true
	}
	if strings.Contains(line, "://") || strings.HasPrefix(line, ".") || strings.HasPrefix(line, "/") {
		return model.Package{}, &Unscannable{Name: pipURLName(line), Source: path, Reason: "URL or path"}, true
	}
	if m == nil {
		return model.Package{}, nil, false
	}
	name, spec := m[1], strings.TrimSpace(m[3])

	spec = strings.TrimSuffix(strings.TrimPrefix(spec, "("), ")")
	if spec != "" {
		for _, clause := range strings.Split(spec, ",") {
			sm := pipSpecRe.FindStringSubmatch(strings.TrimSpace(clause))
			if sm == nil {
				continue
			}
			if (sm[1] == "==" && !strings.HasSuffix(sm[2], ".*")) || sm[1] == "===" {
				return model.Package{Name: name, Version: sm[2], Ecosystem: model.EcosystemPyPI, Source: path}, nil, true
			}
		}
	}
	reason := "version range"
	if spec == "" {
		reason = "no version"
	}
	return model.Package{}, &Unscannable{Name: name, Source: path, Reason: reason}, true
}
