package image

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

func Scan(ctx context.Context, ref, platform string) ([]model.Package, string, error) {
	rc, err := extractFS(ctx, ref, platform)
	if err != nil {
		return nil, "", fmt.Errorf("pulling %s: %w", ref, err)
	}
	defer rc.Close()

	files, err := readImageFS(tar.NewReader(rc))
	if err != nil {
		return nil, "", fmt.Errorf("reading image filesystem: %w", err)
	}

	info := parseOSRelease(files.osRelease)
	eco := osEcosystem(info)
	if eco == "" {
		return nil, "", fmt.Errorf("could not determine OS/version for %s (no os-release found); cannot safely scope an OSV query", ref)
	}
	osLabel := strings.TrimSpace(info["ID"] + " " + info["VERSION_ID"])

	var pkgs []model.Package
	switch {
	case files.apkDB != nil:
		pkgs = parseApk(files.apkDB, eco)
	case files.dpkgStatus != nil:
		pkgs = parseDpkg(files.dpkgStatus, eco)
	case isRPMBased(info):
		return nil, "", fmt.Errorf("rpm-based image (%s): rpm package scanning is not supported yet", info["ID"])
	}
	return append(pkgs, dedupeNpm(files.npm)...), osLabel, nil
}

func dedupeNpm(pkgs []model.Package) []model.Package {
	seen := map[string]bool{}
	var out []model.Package
	for _, p := range pkgs {
		key := p.Name + "@" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

type imageFiles struct {
	osRelease, apkDB, dpkgStatus []byte
	npm                          []model.Package
}

func readImageFS(tr *tar.Reader) (imageFiles, error) {
	var files imageFiles
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return imageFiles{}, err
		}
		name := cleanPath(hdr.Name)
		switch name {
		case "etc/os-release", "usr/lib/os-release":
			if b, err := io.ReadAll(tr); err == nil && len(b) > 0 {
				files.osRelease = b
			}
		case "lib/apk/db/installed":
			files.apkDB, _ = io.ReadAll(tr)
		case "var/lib/dpkg/status":
			files.dpkgStatus, _ = io.ReadAll(tr)
		default:
			if hdr.Typeflag != tar.TypeReg || !nodePackageJSONRe.MatchString(name) {
				continue
			}
			if b, err := io.ReadAll(io.LimitReader(tr, maxPackageJSONSize)); err == nil {
				if pkg, ok := nodePackage(name, b); ok {
					files.npm = append(files.npm, pkg)
				}
			}
		}
	}
	return files, nil
}

func cleanPath(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	return strings.TrimPrefix(strings.TrimPrefix(name, "./"), "/")
}
