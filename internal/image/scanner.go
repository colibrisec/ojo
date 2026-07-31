package image

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

// Scan pulls ref, reads its OS package database, and returns the installed
// packages as model.Package values ready for osv.Scan, plus an "os label"
// (e.g. "debian 13") suitable for a report target header.
func Scan(ctx context.Context, ref string) ([]model.Package, string, error) {
	rc, err := extractFS(ctx, ref)
	if err != nil {
		return nil, "", fmt.Errorf("pulling %s: %w", ref, err)
	}
	defer rc.Close()

	osRelease, apkDB, dpkgStatus, err := readImageFS(tar.NewReader(rc))
	if err != nil {
		return nil, "", fmt.Errorf("reading image filesystem: %w", err)
	}

	info := parseOSRelease(osRelease)
	eco := osEcosystem(info)
	if eco == "" {
		return nil, "", fmt.Errorf("could not determine OS/version for %s (no os-release found); cannot safely scope an OSV query", ref)
	}
	osLabel := strings.TrimSpace(info["ID"] + " " + info["VERSION_ID"])

	var pkgs []model.Package
	switch {
	case apkDB != nil:
		pkgs = parseApk(apkDB, eco)
	case dpkgStatus != nil:
		pkgs = parseDpkg(dpkgStatus, eco)
	case isRPMBased(info):
		return nil, "", fmt.Errorf("rpm-based image (%s): rpm package scanning is not supported yet", info["ID"])
	}
	return pkgs, osLabel, nil
}

// readImageFS scans a flattened image filesystem tar for os-release and OS
// package database files.
func readImageFS(tr *tar.Reader) (osRelease, apkDB, dpkgStatus []byte, err error) {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}
		// /etc/os-release is commonly a symlink to /usr/lib/os-release (tar
		// symlink entries carry no content, just Linkname), so read both
		// candidate paths and keep whichever actually has bytes.
		switch cleanPath(hdr.Name) {
		case "etc/os-release", "usr/lib/os-release":
			if b, err := io.ReadAll(tr); err == nil && len(b) > 0 {
				osRelease = b
			}
		case "lib/apk/db/installed":
			apkDB, _ = io.ReadAll(tr)
		case "var/lib/dpkg/status":
			dpkgStatus, _ = io.ReadAll(tr)
		}
	}
	return osRelease, apkDB, dpkgStatus, nil
}

// cleanPath normalizes a tar entry name to forward-slash form and strips any
// leading "./" or "/". ponytail: on Windows, mutate.Extract builds entry
// names with filepath.Join, which yields backslash separators — normalize
// rather than depend on that implementation detail staying OS-specific.
func cleanPath(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	return strings.TrimPrefix(strings.TrimPrefix(name, "./"), "/")
}
