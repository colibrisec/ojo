package image

import (
	"bufio"
	"bytes"

	"github.com/colibrisec/ojo/internal/model"
)

// parseApk reads an Alpine `lib/apk/db/installed` file: blank-line separated
// stanzas of two-char-prefixed fields (P: name, V: version).
func parseApk(data []byte, ecosystem model.Ecosystem) []model.Package {
	var pkgs []model.Package
	var name, version string

	flush := func() {
		if name != "" && version != "" {
			pkgs = append(pkgs, model.Package{Name: name, Version: version, Ecosystem: ecosystem, Source: "apk"})
		}
		name, version = "", ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'P':
			name = line[2:]
		case 'V':
			version = line[2:]
		}
	}
	flush()
	return pkgs
}
