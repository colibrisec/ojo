package image

import (
	"bufio"
	"bytes"
	"net/textproto"
	"slices"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

// maxCopyrightSize bounds one copyright file; real ones are a few KB, with
// rare outliers (large vendored trees) in the low hundreds.
const maxCopyrightSize = 1 << 20

// dpkgCopyrightPackage returns the binary package a
// usr/share/doc/<package>/copyright path belongs to.
func dpkgCopyrightPackage(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "usr/share/doc/")
	if !ok {
		return "", false
	}
	pkg, ok := strings.CutSuffix(rest, "/copyright")
	if !ok || pkg == "" || strings.Contains(pkg, "/") {
		return "", false
	}
	return pkg, true
}

// dpkgCopyrightLicense extracts the license short names from a copyright
// file in Debian's machine-readable format (DEP-5), joined in order of
// first appearance. dpkg's own database records no license; this file is
// the only place one is declared. Older free-form copyright files have no
// reliable structure and yield "".
func dpkgCopyrightLicense(data []byte) string {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("Format:")) {
		return ""
	}
	var names []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), maxCopyrightSize)
	for scanner.Scan() {
		value, ok := strings.CutPrefix(scanner.Text(), "License:")
		if !ok {
			continue
		}
		name := strings.TrimSpace(value)
		if name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return strings.Join(names, " AND ")
}

func parseDpkg(data []byte, ecosystem model.Ecosystem, licenses map[string]string) []model.Package {
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
			var origin string
			if f := strings.Fields(header.Get("Source")); len(f) > 0 {
				origin = f[0]
			}
			pkgs = append(pkgs, model.Package{Name: name, Version: version, Origin: origin, Ecosystem: ecosystem, Source: "dpkg", License: licenses[name]})
		}
		if err != nil {
			break
		}
	}
	return pkgs
}
