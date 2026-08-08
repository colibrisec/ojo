package manifest

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type pipRequirementsParser struct{}

func (pipRequirementsParser) Match(name string) bool { return name == "requirements.txt" }

var pipPinRe = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)`)

func (pipRequirementsParser) Parse(path string) ([]model.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []model.Package
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := pipPinRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pkgs = append(pkgs, model.Package{
			Name: m[1], Version: m[2], Ecosystem: model.EcosystemPyPI, Source: path,
		})
	}
	return pkgs, scanner.Err()
}
