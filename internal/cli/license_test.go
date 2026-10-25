package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func stubLicenses(t *testing.T, licenses map[string]string) {
	stubLicenseLookup(t, func(pkgs []model.Package) ([]model.Package, error) {
		for i := range pkgs {
			pkgs[i].License = licenses[pkgs[i].Name]
		}
		return pkgs, nil
	})
}

func TestFsCmd_LicenseScannerReportsDenied(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "django==3.2.0\nmysql-connector==8.0.0\nmystery==1.0\n")
	write(t, dir, ".ojo.yaml", "license:\n  deny: [GPL-2.0-only]\n")
	stubLicenses(t, map[string]string{"django": "BSD-3-Clause", "mysql-connector": "GPL-2.0"})

	out, err := run(t, dir, "--scanners", "license", "--config", filepath.Join(dir, ".ojo.yaml"))
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v: %s", err, out)
	}
	if !strings.Contains(out, "license-denied") || !strings.Contains(out, "mysql-connector@8.0.0") {
		t.Errorf("expected a denied-license finding, got %q", out)
	}
	if strings.Contains(out, "django@3.2.0 is licensed") {
		t.Errorf("django shouldn't be flagged: %q", out)
	}
	if !strings.Contains(out, "warning: 1 package(s) have no known license") || !strings.Contains(out, "mystery@1.0") {
		t.Errorf("expected a warning about the unknown license, got %q", out)
	}
}

func TestFsCmd_LicenseScannerCleanPolicy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "django==3.2.0\n")
	write(t, dir, ".ojo.yaml", "license:\n  allow: [BSD-*, MIT]\n")
	stubLicenses(t, map[string]string{"django": "BSD-3-Clause"})

	out, err := run(t, dir, "--scanners", "license", "--config", filepath.Join(dir, ".ojo.yaml"))
	if err != nil {
		t.Fatalf("expected a clean scan, got %v: %s", err, out)
	}
}

func TestFsCmd_LicenseScannerNeedsPolicy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".ojo.yaml", "scanners: license\n")
	_, err := run(t, dir, "--config", filepath.Join(dir, ".ojo.yaml"))
	if err == nil || !strings.Contains(err.Error(), "needs a policy") {
		t.Errorf("expected a missing-policy error, got %v", err)
	}
}

func writePolicy(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, ".ojo.yaml", yaml)
	return filepath.Join(dir, ".ojo.yaml")
}

func TestImageCmd_LicenseScanner(t *testing.T) {
	// Fedora has no advisories, so this also checks that license-only
	// scans don't need them.
	stubImageScan(t, []model.Package{
		{Name: "bash", Version: "5.2", Ecosystem: "Fedora:39", Source: "rpm", License: "GPL-3.0-or-later"},
		{Name: "zlib", Version: "1.3", Ecosystem: "Fedora:39", Source: "rpm", License: "Zlib"},
	}, "fedora 39", nil)
	stubOSVScan(t, nil, errors.New("vuln scan shouldn't run"))
	policy := writePolicy(t, "license:\n  deny: [GPL-3.0-*]\n")

	out, err := runImage(t, "--scanners", "license", "--config", policy, "fedora:39")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v: %s", err, out)
	}
	if !strings.Contains(out, "license-denied") || !strings.Contains(out, "bash@5.2") || strings.Contains(out, "zlib@1.3 is licensed") {
		t.Errorf("expected only bash to be denied, got %q", out)
	}
}

func TestImageCmd_LicenseFindingsSuppressedByIgnoreFile(t *testing.T) {
	stubImageScan(t, []model.Package{{Name: "bash", Version: "5.2", Ecosystem: "Debian:12", Source: "dpkg", License: "GPL-3.0-or-later"}}, "debian 12", nil)
	policy := writePolicy(t, "license:\n  deny: [GPL-3.0-*]\n")
	ignoreFile := filepath.Join(t.TempDir(), ".ojoignore")
	if err := os.WriteFile(ignoreFile, []byte("license-denied dpkg  # accepted by legal\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runImage(t, "--scanners", "license", "--config", policy, "--ignore-file", ignoreFile, "debian:12")
	if err != nil {
		t.Fatalf("expected the finding to be suppressed, got %v: %s", err, out)
	}
}

func TestImageCmd_UnknownScanner(t *testing.T) {
	_, err := runImage(t, "--scanners", "secret", "alpine:latest")
	if err == nil || !strings.Contains(err.Error(), `unknown scanner "secret" for ojo image`) {
		t.Errorf("expected an unknown-scanner error, got %v", err)
	}
}

func TestImageCmd_LicenseScannerNeedsPolicy(t *testing.T) {
	_, err := runImage(t, "--scanners", "license", "--config", writePolicy(t, "format: table\n"), "alpine:latest")
	if err == nil || !strings.Contains(err.Error(), "needs a policy") {
		t.Errorf("expected a missing-policy error, got %v", err)
	}
}

func TestSBOMCmd_LicenseScanner(t *testing.T) {
	path := writeSBOM(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [
  {"type": "library", "name": "django", "version": "3.2.0", "purl": "pkg:pypi/django@3.2.0", "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
  {"type": "library", "name": "glibc", "version": "2.38-1.fc39", "purl": "pkg:rpm/fedora/glibc@2.38-1.fc39?distro=fedora-39", "licenses": [{"license": {"id": "LGPL-2.1-or-later"}}]}
]}`)
	stubOSVScan(t, nil, nil)
	policy := writePolicy(t, "license:\n  allow: [BSD-*, MIT]\n")

	out, err := runSBOM(t, "--scanners", "vuln,license", "--config", policy, path)
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v: %s", err, out)
	}
	if !strings.Contains(out, "license-not-allowed") || !strings.Contains(out, "glibc@2.38-1.fc39") || strings.Contains(out, "django@3.2.0 is licensed") {
		t.Errorf("expected only glibc to be flagged, got %q", out)
	}
}
