package image

import (
	"fmt"
	"os"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	_ "modernc.org/sqlite" // go-rpmdb opens SQLite rpm databases through database/sql's "sqlite" driver

	"github.com/colibrisec/ojo/internal/model"
)

// maxRPMDBSize bounds how much of an rpm database is buffered: far above any
// real one (a full desktop install is ~200MB), low enough that a crafted
// image can't exhaust memory.
const maxRPMDBSize = 1 << 30

// rpmDBPaths are the places an rpm database lives. The directory moved from
// /var/lib/rpm to /usr/lib/sysimage/rpm (Fedora 36+, SUSE), and the file
// name depends on the backend: Berkeley DB (Packages), NDB (Packages.db) or
// SQLite (rpmdb.sqlite).
var rpmDBPaths = map[string]bool{
	"var/lib/rpm/Packages":              true,
	"var/lib/rpm/Packages.db":           true,
	"var/lib/rpm/rpmdb.sqlite":          true,
	"usr/lib/sysimage/rpm/Packages":     true,
	"usr/lib/sysimage/rpm/Packages.db":  true,
	"usr/lib/sysimage/rpm/rpmdb.sqlite": true,
}

// parseRpm reads an rpm database of any backend. go-rpmdb needs a real file
// to open, so the bytes read out of the image go through a temp file.
func parseRpm(data []byte, ecosystem model.Ecosystem) ([]model.Package, error) {
	tmp, err := os.CreateTemp("", "ojo-rpmdb-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}

	db, err := rpmdb.Open(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("opening rpm database: %w", err)
	}
	defer db.Close()
	infos, err := db.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("reading rpm database: %w", err)
	}

	pkgs := make([]model.Package, 0, len(infos))
	for _, info := range infos {
		if pkg, ok := rpmPackage(info, ecosystem); ok {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs, nil
}

func rpmPackage(info *rpmdb.PackageInfo, ecosystem model.Ecosystem) (model.Package, bool) {
	// gpg-pubkey entries are imported signing keys stored as pseudo-packages.
	if info.Name == "" || info.Version == "" || info.Name == "gpg-pubkey" {
		return model.Package{}, false
	}
	version := info.Version
	if info.Release != "" {
		version += "-" + info.Release
	}
	if epoch := info.EpochNum(); epoch > 0 {
		version = fmt.Sprintf("%d:%s", epoch, version)
	}
	return model.Package{
		Name:      info.Name,
		Version:   version,
		Origin:    rpmSourceName(info.SourceRpm),
		Ecosystem: ecosystem,
		Source:    "rpm",
		License:   info.License,
	}, true
}

// rpmSourceName extracts the source package name from a SOURCERPM value
// ("openssl-3.0.7-27.el9.src.rpm" -> "openssl"). Advisories are filed
// against the source package, and Rocky Linux's are only matched by it.
func rpmSourceName(sourceRpm string) string {
	s := strings.TrimSuffix(sourceRpm, ".rpm")
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".src"), ".nosrc")
	for range 2 { // drop -release, then -version
		i := strings.LastIndex(s, "-")
		if i <= 0 {
			return ""
		}
		s = s[:i]
	}
	return s
}
