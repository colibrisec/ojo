package image

import (
	"bufio"
	"bytes"
	"net/textproto"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

func parseDpkg(data []byte, ecosystem model.Ecosystem) []model.Package {
	var pkgs []model.Package
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(data)))

	for {
		header, err := reader.ReadMIMEHeader()
		if len(header) == 0 && err != nil {
			break
		}
		status := header.Get("Status")
		if !strings.Contains(status, "installed") {
			continue
		}
		name := header.Get("Package")
		version := header.Get("Version")
		if name != "" && version != "" {
			pkgs = append(pkgs, model.Package{Name: name, Version: version, Ecosystem: ecosystem, Source: "dpkg"})
		}
		if err != nil {
			break
		}
	}
	return pkgs
}
