package image

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	"github.com/colibrisec/ojo/internal/model"
)

// rpmSQLiteDB builds a SQLite-backend rpm database holding one package.
// testdata/rpm-header.bin is a real rpm header blob (publicsuffix-list-dafsa
// from Fedora 35, taken from go-rpmdb's own MIT-licensed test data) -- the
// header format is involved enough that a hand-built one would mostly test
// the builder.
func rpmSQLiteDB(t *testing.T) []byte {
	t.Helper()
	blob, err := os.ReadFile("testdata/rpm-header.bin")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rpmdb.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO Packages (blob) VALUES (?)", blob); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseRpm(t *testing.T) {
	pkgs, err := parseRpm(rpmSQLiteDB(t), "Rocky Linux:9")
	if err != nil {
		t.Fatal(err)
	}
	want := model.Package{
		Name: "publicsuffix-list-dafsa", Version: "20210518-2.fc35", Origin: "publicsuffix-list",
		Ecosystem: "Rocky Linux:9", Source: "rpm", License: "MPLv2.0",
	}
	if len(pkgs) != 1 || pkgs[0] != want {
		t.Fatalf("got %+v, want %+v", pkgs, want)
	}
}

func TestParseRpmRejectsGarbage(t *testing.T) {
	if _, err := parseRpm([]byte("not an rpm database"), "Rocky Linux:9"); err == nil {
		t.Error("expected an error for an unreadable rpm database")
	}
}

func TestRpmPackage(t *testing.T) {
	epoch := 1
	pkg, ok := rpmPackage(&rpmdb.PackageInfo{
		Name: "openssl-libs", Version: "3.0.7", Release: "27.el9", Epoch: &epoch,
		SourceRpm: "openssl-3.0.7-27.el9.src.rpm", License: "ASL 2.0",
	}, "Rocky Linux:9")
	if !ok || pkg.Version != "1:3.0.7-27.el9" || pkg.Origin != "openssl" || pkg.License != "ASL 2.0" {
		t.Errorf("unexpected package: %+v", pkg)
	}

	// No epoch: OSV versions omit a zero epoch rather than writing "0:".
	pkg, _ = rpmPackage(&rpmdb.PackageInfo{Name: "bash", Version: "5.1.8", Release: "9.el9"}, "Rocky Linux:9")
	if pkg.Version != "5.1.8-9.el9" {
		t.Errorf("version = %q", pkg.Version)
	}

	if _, ok := rpmPackage(&rpmdb.PackageInfo{Name: "gpg-pubkey", Version: "8483c65d", Release: "5ccc5b19"}, "Rocky Linux:9"); ok {
		t.Error("gpg-pubkey is an imported signing key, not a package")
	}
}

func TestRpmSourceName(t *testing.T) {
	cases := map[string]string{
		"openssl-3.0.7-27.el9.src.rpm":            "openssl",
		"python-setuptools-53.0.0-12.el9.src.rpm": "python-setuptools",
		"kmod-nvidia-1.0-1.nosrc.rpm":             "kmod-nvidia",
		"(none)":                                  "",
		"":                                        "",
	}
	for in, want := range cases {
		if got := rpmSourceName(in); got != want {
			t.Errorf("rpmSourceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanFSRockyLinux(t *testing.T) {
	for _, dbPath := range []string{"var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"} {
		pkgs, label, err := scanFS(bytes.NewReader(imageTar(t, map[string]string{
			"etc/os-release": "ID=\"rocky\"\nVERSION_ID=\"9.4\"\n",
			dbPath:           string(rpmSQLiteDB(t)),
		})), "test")
		if err != nil {
			t.Fatalf("%s: %v", dbPath, err)
		}
		if label != "rocky 9.4" || len(pkgs) != 1 || pkgs[0].Ecosystem != "Rocky Linux:9" || pkgs[0].Name != "publicsuffix-list-dafsa" {
			t.Errorf("%s: got %+v (%s)", dbPath, pkgs, label)
		}
		if got := WithoutAdvisories(pkgs); got != "" {
			t.Errorf("Rocky Linux has OSV advisories, got %q", got)
		}
	}
}

// A distribution OSV has no advisories for is still enumerated (an SBOM of
// it is perfectly good), but flagged so a vulnerability scan can refuse
// instead of reporting a misleading zero.
func TestScanFSRpmDistroWithoutAdvisories(t *testing.T) {
	pkgs, _, err := scanFS(bytes.NewReader(imageTar(t, map[string]string{
		"etc/os-release":           "ID=fedora\nVERSION_ID=42\n",
		"var/lib/rpm/rpmdb.sqlite": string(rpmSQLiteDB(t)),
		"usr/lib/node_modules/npm/node_modules/tar/package.json": `{"name":"tar","version":"7.5.11"}`,
	})), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected the rpm package and the npm package, got %+v", pkgs)
	}
	if got := WithoutAdvisories(pkgs); got != "fedora" {
		t.Errorf("WithoutAdvisories = %q, want fedora", got)
	}
}

func TestWithoutAdvisoriesIgnoresNodePackages(t *testing.T) {
	pkgs := []model.Package{
		{Name: "tar", Version: "7.5.11", Ecosystem: model.EcosystemNpm, Source: "usr/lib/node_modules/tar/package.json"},
		{Name: "musl", Version: "1.2.5-r0", Ecosystem: "Alpine:v3.20", Source: "apk"},
	}
	if got := WithoutAdvisories(pkgs); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestImageLicenses(t *testing.T) {
	pkgs, _, err := scanFS(bytes.NewReader(imageTar(t, map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=12\n",
		"var/lib/dpkg/status": "Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.13.dfsg-1\nSource: zlib\n\nPackage: adduser\nStatus: install ok installed\nVersion: 3.134\n\n",
		"usr/share/doc/zlib1g/copyright": "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: zlib\n\n" +
			"Files: *\nCopyright: 1995-2022 Jean-loup Gailly and Mark Adler\nLicense: Zlib\n\n" +
			"Files: debian/*\nCopyright: 2000-2017 Mark Brown\nLicense: Zlib\n\n" +
			"Files: contrib/dotzlib/*\nLicense: BSL-1.0\n\nLicense: Zlib\n This software is provided 'as-is'...\n",
		"usr/share/doc/adduser/copyright":              "This package was first put together by Ian Murdock.\n\nLicense: GPL, see /usr/share/common-licenses/GPL\n",
		"usr/share/doc/zlib1g/examples/copyright":      "Format: x\nLicense: Bogus\n",
		"usr/lib/node_modules/legacy/package.json":     `{"name":"legacy","version":"1.0.0","license":{"type":"BSD-3-Clause","url":"x"}}`,
		"usr/lib/node_modules/modern/package.json":     `{"name":"modern","version":"2.0.0","license":"MIT"}`,
		"usr/lib/node_modules/unlicensed/package.json": `{"name":"unlicensed","version":"3.0.0"}`,
	})), "test")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.License
	}
	want := map[string]string{
		"zlib1g":     "Zlib AND BSL-1.0", // each short name once, in order of first appearance
		"adduser":    "",                 // free-form copyright file: no reliable structure to read
		"legacy":     "BSD-3-Clause",
		"modern":     "MIT",
		"unlicensed": "",
	}
	for name, w := range want {
		if l, ok := got[name]; !ok || l != w {
			t.Errorf("%s: license %q (found=%v), want %q", name, l, ok, w)
		}
	}
}

func TestParseApkReadsLicense(t *testing.T) {
	pkgs := parseApk([]byte("P:musl\nV:1.2.5-r0\nL:MIT\n\nP:busybox\nV:1.36.1-r29\nL:GPL-2.0-only\n\n"), "Alpine:v3.20")
	if len(pkgs) != 2 || pkgs[0].License != "MIT" || pkgs[1].License != "GPL-2.0-only" {
		t.Errorf("unexpected packages: %+v", pkgs)
	}
	if strings.Contains(pkgs[1].License, "MIT") {
		t.Error("license leaked from the previous package")
	}
}

func TestWithoutAdvisoriesAmazonLinux(t *testing.T) {
	covered := []model.Package{{Name: "openssl-libs", Ecosystem: "Amazon Linux:2023", Source: "rpm"}}
	if got := WithoutAdvisories(covered); got != "" {
		t.Errorf("Amazon Linux 2023 has advisories, got %q", got)
	}
	al1 := []model.Package{{Name: "openssl", Ecosystem: osEcosystem(map[string]string{"ID": "amzn", "VERSION_ID": "2018.03"}), Source: "rpm"}}
	if got := WithoutAdvisories(al1); got != "amzn" {
		t.Errorf("WithoutAdvisories = %q, want amzn for Amazon Linux 1", got)
	}
}
