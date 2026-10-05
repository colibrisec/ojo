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
	return scanFS(rc, ref)
}

func scanFS(r io.Reader, ref string) ([]model.Package, string, error) {
	files, err := readImageFS(tar.NewReader(r))
	if err != nil {
		return nil, "", fmt.Errorf("reading image filesystem: %w", err)
	}

	info := parseOSRelease(files.osRelease)
	eco := osEcosystem(info)
	if eco == "" {
		if files.apkDB != nil || files.dpkgStatus != nil || files.rpmDB != nil {
			return nil, "", fmt.Errorf("could not determine OS/version for %s (no os-release found); cannot safely scope an OSV query", ref)
		}
		// No os-release and no OS package database: a scratch-style image
		// (e.g. a single static binary). There are no OS packages to scope,
		// and npm packages carry their own ecosystem.
		return dedupeNpm(files.npm), "no OS", nil
	}
	osLabel := strings.TrimSpace(info["ID"] + " " + info["VERSION_ID"])

	var pkgs []model.Package
	switch {
	case files.apkDB != nil:
		pkgs = parseApk(files.apkDB, eco)
	case files.dpkgStatus != nil:
		pkgs = parseDpkg(files.dpkgStatus, eco, files.dpkgLicenses)
	case files.rpmDB != nil:
		pkgs, err = parseRpm(files.rpmDB, eco)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", ref, err)
		}
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
	osRelease, apkDB, dpkgStatus, rpmDB []byte
	dpkgLicenses                        map[string]string // binary package name -> license, from its copyright file
	npm                                 []model.Package
}

// osPackageSources are the Package.Source values this package gives OS
// packages (as opposed to Node.js ones, whose Source is a path).
var osPackageSources = map[string]bool{"apk": true, "dpkg": true, "rpm": true}

// advisoryEcosystems are the OSV ecosystem prefixes ojo knows how to form
// for an image's OS packages.
var advisoryEcosystems = []string{"Alpine:", "Debian:", "Ubuntu:", "Rocky Linux:", "AlmaLinux:", "Red Hat:"}

// WithoutAdvisories returns the distribution ID of pkgs' OS packages if it
// is one OSV publishes no advisories for (Fedora, CentOS, Amazon Linux,
// Oracle Linux, SUSE, ...), or "" if they can be checked. Such packages can
// still be listed in an SBOM, but a vulnerability scan of them would report
// nothing at all -- which must not be mistaken for a clean result.
func WithoutAdvisories(pkgs []model.Package) string {
	for _, p := range pkgs {
		if !osPackageSources[p.Source] {
			continue
		}
		known := false
		for _, prefix := range advisoryEcosystems {
			known = known || strings.HasPrefix(string(p.Ecosystem), prefix)
		}
		if !known {
			return string(p.Ecosystem)
		}
	}
	return ""
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
			if hdr.Typeflag != tar.TypeReg {
				continue
			}
			if rpmDBPaths[name] {
				if b, err := io.ReadAll(io.LimitReader(tr, maxRPMDBSize)); err == nil && len(b) > 0 {
					files.rpmDB = b
				}
				continue
			}
			if pkg, ok := dpkgCopyrightPackage(name); ok {
				if b, err := io.ReadAll(io.LimitReader(tr, maxCopyrightSize)); err == nil {
					if l := dpkgCopyrightLicense(b); l != "" {
						if files.dpkgLicenses == nil {
							files.dpkgLicenses = map[string]string{}
						}
						files.dpkgLicenses[pkg] = l
					}
				}
				continue
			}
			if !nodePackageJSONRe.MatchString(name) {
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
