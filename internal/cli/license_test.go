package cli

import (
	"errors"
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
