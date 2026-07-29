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
// packages as model.Package values ready for osv.Scan.
func Scan(ctx context.Context, ref string) ([]model.Package, error) {
	rc, err := extractFS(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pulling %s: %w", ref, err)
	}
	defer rc.Close()

	var osRelease, apkDB, dpkgStatus []byte
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading image filesystem: %w", err)
		}
		switch cleanPath(hdr.Name) {
		case "etc/os-release":
			osRelease, _ = io.ReadAll(tr)
		case "lib/apk/db/installed":
			apkDB, _ = io.ReadAll(tr)
		case "var/lib/dpkg/status":
			dpkgStatus, _ = io.ReadAll(tr)
		}
	}

	info := parseOSRelease(osRelease)
	eco := osEcosystem(info)

	var pkgs []model.Package
	switch {
	case apkDB != nil:
		pkgs = parseApk(apkDB, eco)
	case dpkgStatus != nil:
		pkgs = parseDpkg(dpkgStatus, eco)
	case isRPMBased(info):
		return nil, fmt.Errorf("rpm-based image (%s): rpm package scanning is not supported yet", info["ID"])
	}
	return pkgs, nil
}

// cleanPath normalizes a tar entry name to forward-slash form and strips any
// leading "./" or "/". ponytail: on Windows, mutate.Extract builds entry
// names with filepath.Join, which yields backslash separators — normalize
// rather than depend on that implementation detail staying OS-specific.
func cleanPath(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	return strings.TrimPrefix(strings.TrimPrefix(name, "./"), "/")
}
