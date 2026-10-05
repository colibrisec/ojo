package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestFsCmd_SBOMIncludesLookedUpLicenses(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "django==3.2.0\n")
	stubLicenseLookup(t, func(pkgs []model.Package) ([]model.Package, error) {
		pkgs[0].License = "BSD-3-Clause"
		return pkgs, nil
	})

	out, err := run(t, dir, "-f", "sbom")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"id": "BSD-3-Clause"`) {
		t.Errorf("expected the license in the SBOM, got %q", out)
	}
}

func TestFsCmd_NoLicenseLookupStaysOffline(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "django==3.2.0\n")
	stubLicenseLookup(t, func(pkgs []model.Package) ([]model.Package, error) {
		t.Error("license lookup ran despite --no-license-lookup")
		return pkgs, nil
	})

	out, err := run(t, dir, "-f", "sbom", "--no-license-lookup")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pkg:pypi/django@3.2.0") {
		t.Errorf("expected the component regardless, got %q", out)
	}
}

// A failed lookup must not cost the user their SBOM.
func TestFsCmd_LicenseLookupFailureIsAWarning(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "django==3.2.0\n")
	stubLicenseLookup(t, func(pkgs []model.Package) ([]model.Package, error) {
		return pkgs, errors.New("deps.dev unreachable")
	})

	out, err := run(t, dir, "-f", "sbom")
	if err != nil {
		t.Fatalf("expected the SBOM despite the failed lookup, got %v", err)
	}
	if !strings.Contains(out, "warning: license lookup failed") || !strings.Contains(out, "pkg:pypi/django@3.2.0") {
		t.Errorf("expected a warning and the component, got %q", out)
	}
}

const podfileLock = "PODS:\n  - Alamofire (5.9.1)\n  - PrivatePod (1.0.0)\n"

func TestFsCmd_VulnScanResolvesPods(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Podfile.lock", podfileLock)
	stubPodResolve(t, func(pkgs []model.Package) ([]model.Package, int) {
		for i := range pkgs {
			if pkgs[i].Name == "Alamofire" {
				pkgs[i].Origin = "github.com/Alamofire/Alamofire"
			}
		}
		return pkgs, 1
	})
	var scanned []model.Package
	old := osvScan
	osvScan = func(ctx context.Context, pkgs []model.Package) ([]model.Finding, error) {
		scanned = pkgs
		return nil, nil
	}
	t.Cleanup(func() { osvScan = old })

	out, err := run(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 2 || scanned[0].Origin != "github.com/Alamofire/Alamofire" {
		t.Errorf("expected the resolved pods to reach the OSV scan, got %+v", scanned)
	}
	if !strings.Contains(out, "1 CocoaPods pod(s)") || !strings.Contains(out, "not checked") {
		t.Errorf("expected a warning about the unresolved pod, got %q", out)
	}
}

func TestFsCmd_SBOMListsPods(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Podfile.lock", podfileLock)
	stubPodResolve(t, func(pkgs []model.Package) ([]model.Package, int) {
		pkgs[0].License = "MIT"
		return pkgs, 1
	})

	out, err := run(t, dir, "-f", "sbom")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pkg:cocoapods/Alamofire@5.9.1", "pkg:cocoapods/PrivatePod@1.0.0", `"id": "MIT"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in the SBOM, got %q", want, out)
		}
	}
}

var fedoraPackages = []model.Package{{Name: "bash", Version: "5.2.37-1.fc42", Ecosystem: "fedora", Source: "rpm", License: "GPL-3.0-or-later"}}

// Reporting "no vulnerabilities" for a distribution there is no advisory
// data for would be a false all-clear.
func TestImageCmd_RefusesVulnScanWithoutAdvisoryData(t *testing.T) {
	stubImageScan(t, fedoraPackages, "fedora 42", nil)
	stubOSVScan(t, nil, nil)

	_, err := runImage(t, "fedora:42")
	if err == nil || !strings.Contains(err.Error(), "no advisories") || !strings.Contains(err.Error(), "fedora") {
		t.Errorf("expected a no-advisories error, got %v", err)
	}
}

func TestImageCmd_SBOMWorksWithoutAdvisoryData(t *testing.T) {
	stubImageScan(t, fedoraPackages, "fedora 42", nil)

	out, err := runImage(t, "-f", "sbom", "fedora:42")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"name": "bash"`) || !strings.Contains(out, `"id": "GPL-3.0-or-later"`) {
		t.Errorf("expected bash and its license in the SBOM, got %q", out)
	}
}
