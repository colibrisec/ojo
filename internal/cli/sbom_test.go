package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func runSBOM(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := sbomCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

const testCycloneDX = `{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [
  {"type": "library", "name": "django", "version": "3.2.0", "purl": "pkg:pypi/django@3.2.0"},
  {"type": "library", "name": "glibc", "version": "2.38-1.fc39", "purl": "pkg:rpm/fedora/glibc@2.38-1.fc39?distro=fedora-39"},
  {"type": "library", "name": "vendored", "version": "1.0"}
]}`

func writeSBOM(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSBOMCmd_ScansListedPackages(t *testing.T) {
	path := writeSBOM(t, testCycloneDX)
	var asked []model.Package
	old := osvScan
	osvScan = func(_ context.Context, pkgs []model.Package) ([]model.Finding, error) {
		asked = pkgs
		return []model.Finding{{Package: pkgs[0], Vulns: []model.Vulnerability{{ID: "CVE-2022-28346", Severity: "CRITICAL"}}}}, nil
	}
	t.Cleanup(func() { osvScan = old })

	out, err := runSBOM(t, path)
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if len(asked) != 1 || asked[0].Name != "django" || asked[0].Ecosystem != model.EcosystemPyPI {
		t.Errorf("expected only django to be checked, got %+v", asked)
	}
	if !strings.Contains(out, "CVE-2022-28346") {
		t.Errorf("expected the finding in output, got %q", out)
	}
	if !strings.Contains(out, "warning: 2 SBOM entries") || !strings.Contains(out, "vendored") || !strings.Contains(out, `no advisories for "fedora"`) {
		t.Errorf("expected a warning naming the unchecked entries, got %q", out)
	}
}

func TestSBOMCmd_ConvertsToSPDX(t *testing.T) {
	path := writeSBOM(t, testCycloneDX)
	out, err := runSBOM(t, "-f", "spdx", path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out, `"spdxVersion": "SPDX-2.3"`) || !strings.Contains(out, "pkg:pypi/django@3.2.0") || !strings.Contains(out, "pkg:rpm/fedora/glibc@2.38-1.fc39") {
		t.Errorf("got %q", out)
	}
}

func TestSBOMCmd_BadFileIsAnError(t *testing.T) {
	if _, err := runSBOM(t, writeSBOM(t, `{"hello": "world"}`)); err == nil {
		t.Error("expected an error for a file that isn't an SBOM")
	}
	if _, err := runSBOM(t, filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestFsCmd_SPDXFormat(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "django==3.2.0\n")
	out, err := run(t, dir, "-f", "spdx", "--no-license-lookup")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out, `"spdxVersion": "SPDX-2.3"`) || !strings.Contains(out, "pkg:pypi/django@3.2.0") {
		t.Errorf("got %q", out)
	}
}
