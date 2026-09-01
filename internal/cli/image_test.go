package cli

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/kev"
	"github.com/colibrisec/ojo/internal/model"
)

// runImage mirrors fs_test.go's run helper. Cases that need image.Scan/
// osv.Scan to succeed use stubImageScan/stubOSVScan (deps_test.go) rather
// than a real registry pull or OSV.dev call.
func runImage(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := imageCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestImageCmd_RequiresExactlyOneArg(t *testing.T) {
	if _, err := runImage(t); err == nil {
		t.Error("expected an error with no image ref given")
	}
	if _, err := runImage(t, "ref1", "ref2"); err == nil {
		t.Error("expected an error with more than one image ref given")
	}
}

func TestImageCmd_BadConfigPathIsAnError(t *testing.T) {
	dir := t.TempDir()
	_, err := runImage(t, "--config", filepath.Join(dir, "nope.yaml"), "alpine:latest")
	if err == nil {
		t.Error("expected an error for a missing explicit --config path")
	}
}

func TestImageCmd_BadCycloneDXVersionIsAnError(t *testing.T) {
	_, err := runImage(t, "--cyclonedx-version", "9.9", "alpine:latest")
	if err == nil {
		t.Error("expected an error for an unsupported CycloneDX version")
	}
}

func TestImageCmd_NoPackagesFound(t *testing.T) {
	stubImageScan(t, nil, "debian 12", nil)
	out, err := runImage(t, "alpine:latest")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out, "No OS packages found") {
		t.Errorf("got %q", out)
	}
}

func TestImageCmd_ImageScanErrorPropagates(t *testing.T) {
	stubImageScan(t, nil, "", errors.New("pull failed"))
	_, err := runImage(t, "alpine:latest")
	if err == nil || !strings.Contains(err.Error(), "pull failed") {
		t.Errorf("expected the image.Scan error to propagate, got %v", err)
	}
}

func TestImageCmd_SBOMFormat(t *testing.T) {
	stubImageScan(t, []model.Package{{Name: "musl", Version: "1.2.3", Ecosystem: model.EcosystemGo}}, "alpine 3.19", nil)
	out, err := runImage(t, "-f", "sbom", "alpine:latest")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out, "pkg:golang/musl@1.2.3") {
		t.Errorf("got %q", out)
	}
}

func TestImageCmd_OSVScanErrorPropagates(t *testing.T) {
	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, nil, errors.New("osv down"))
	_, err := runImage(t, "alpine:latest")
	if err == nil || !strings.Contains(err.Error(), "osv down") {
		t.Errorf("expected the osv.Scan error to propagate, got %v", err)
	}
}

func TestImageCmd_NoFindingsExitsClean(t *testing.T) {
	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, nil, nil)
	out, err := runImage(t, "alpine:latest")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out, "No issues found") {
		t.Errorf("got %q", out)
	}
}

func TestImageCmd_FindingsReturnErrFindingsFound(t *testing.T) {
	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, []model.Finding{{
		Package: model.Package{Name: "x", Version: "1"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1", Severity: "HIGH"}},
	}}, nil)

	out, err := runImage(t, "alpine:latest")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, "CVE-2024-1") {
		t.Errorf("got %q", out)
	}
}

func TestImageCmd_JSONAndSARIFFormats(t *testing.T) {
	finding := []model.Finding{{
		Package: model.Package{Name: "x", Version: "1"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1", Severity: "HIGH"}},
	}}

	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, finding, nil)
	out, err := runImage(t, "-f", "json", "alpine:latest")
	if !errors.Is(err, ErrFindingsFound) || !strings.Contains(out, "CVE-2024-1") {
		t.Errorf("json: err=%v out=%q", err, out)
	}

	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, finding, nil)
	out, err = runImage(t, "-f", "sarif", "alpine:latest")
	if !errors.Is(err, ErrFindingsFound) || !strings.Contains(out, "CVE-2024-1") || !strings.Contains(out, `"$schema"`) {
		t.Errorf("sarif: err=%v out=%q", err, out)
	}
}

func TestImageCmd_VEXFormat(t *testing.T) {
	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, []model.Finding{{
		Package: model.Package{Name: "x", Version: "1"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}, nil)

	out, err := runImage(t, "-f", "vex", "alpine:latest")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, `"CVE-2024-1"`) || !strings.Contains(out, `"status": "affected"`) {
		t.Errorf("got %q", out)
	}
}

func TestImageCmd_IgnoreFileSuppresses(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".ojoignore", "CVE-2024-1  *  # accepted risk\n")

	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, []model.Finding{{
		Package: model.Package{Name: "x", Version: "1", Source: "img"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}, nil)

	out, err := runImage(t, "--ignore-file", filepath.Join(dir, ".ojoignore"), "alpine:latest")
	if err != nil {
		t.Fatalf("expected the finding to be suppressed (no error), got %v", err)
	}
	if !strings.Contains(out, "No issues found") {
		t.Errorf("got %q", out)
	}
}

func TestImageCmd_VexFileSuppresses(t *testing.T) {
	dir := t.TempDir()
	vexDoc := `{"@context":"https://openvex.dev/ns/v0.2.0","author":"t","timestamp":"2026-01-01T00:00:00Z","version":1,` +
		`"statements":[{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:generic/x@1"}],"status":"not_affected"}]}`
	write(t, dir, "accept.vex.json", vexDoc)

	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, []model.Finding{{
		Package: model.Package{Name: "x", Version: "1"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}, nil)

	out, err := runImage(t, "--vex-file", filepath.Join(dir, "accept.vex.json"), "alpine:latest")
	if err != nil {
		t.Fatalf("expected the finding to be suppressed (no error), got %v", err)
	}
	if !strings.Contains(out, "No issues found") {
		t.Errorf("got %q", out)
	}
}

func TestImageCmd_KevFlagAnnotates(t *testing.T) {
	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, []model.Finding{{
		Package: model.Package{Name: "x", Version: "1"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}, nil)
	stubKevLoad(t, kev.Set{"CVE-2024-1": kev.Entry{DateAdded: "2024-01-01"}}, false, nil)

	out, err := runImage(t, "--kev", "alpine:latest")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, "KEV") {
		t.Errorf("expected a KEV marker in output, got %q", out)
	}
}

func TestImageCmd_KevLoadErrorPropagates(t *testing.T) {
	stubImageScan(t, []model.Package{{Name: "x", Version: "1"}}, "debian 12", nil)
	stubOSVScan(t, []model.Finding{{Package: model.Package{Name: "x", Version: "1"}, Vulns: []model.Vulnerability{{ID: "CVE-2024-1"}}}}, nil)
	stubKevLoad(t, nil, false, errors.New("feed unreachable"))

	_, err := runImage(t, "--kev", "alpine:latest")
	if err == nil || !strings.Contains(err.Error(), "feed unreachable") {
		t.Errorf("expected the KEV load error to propagate, got %v", err)
	}
}
