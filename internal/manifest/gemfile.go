package manifest

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

type gemfileLockParser struct{}

func (gemfileLockParser) Match(name string) bool { return name == "Gemfile.lock" }

var specLineRe = regexp.MustCompile(`^ {4}(\S+) \(([^)]+)\)`)

func (gemfileLockParser) Parse(path string) ([]model.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []model.Package
	inSpecs := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.TrimRight(line, " ") == "  specs:":
			inSpecs = true
		case !inSpecs:
			// not in a specs block, nothing to do
		case line == "" || indentOf(line) <= 2:
			inSpecs = false
		case indentOf(line) == 4:
			if m := specLineRe.FindStringSubmatch(line); m != nil {
				pkgs = append(pkgs, model.Package{Name: m[1], Version: m[2], Ecosystem: model.EcosystemRubyGems, Source: path})
			}
		}
	}
	return pkgs, scanner.Err()
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}
