package cli

import (
	"context"
	"os"
	"testing"

	"github.com/colibrisec/ojo/internal/kev"
	"github.com/colibrisec/ojo/internal/model"
)

// TestMain keeps every test in this package off the network by default:
// SBOM output would otherwise ask deps.dev and the CocoaPods CDN for
// licenses. Tests that exercise those paths install their own stubs.
func TestMain(m *testing.M) {
	licenseLookup = func(ctx context.Context, pkgs []model.Package) ([]model.Package, error) {
		return pkgs, nil
	}
	podResolve = func(ctx context.Context, pkgs []model.Package) ([]model.Package, int) {
		return pkgs, 0
	}
	os.Exit(m.Run())
}

func stubLicenseLookup(t *testing.T, fn func([]model.Package) ([]model.Package, error)) {
	t.Helper()
	old := licenseLookup
	licenseLookup = func(ctx context.Context, pkgs []model.Package) ([]model.Package, error) {
		return fn(pkgs)
	}
	t.Cleanup(func() { licenseLookup = old })
}

func stubPodResolve(t *testing.T, fn func([]model.Package) ([]model.Package, int)) {
	t.Helper()
	old := podResolve
	podResolve = func(ctx context.Context, pkgs []model.Package) ([]model.Package, int) {
		return fn(pkgs)
	}
	t.Cleanup(func() { podResolve = old })
}

func stubImageScan(t *testing.T, pkgs []model.Package, osLabel string, err error) {
	t.Helper()
	old := imageScan
	imageScan = func(ctx context.Context, ref, platform string) ([]model.Package, string, error) {
		return pkgs, osLabel, err
	}
	t.Cleanup(func() { imageScan = old })
}

func stubOSVScan(t *testing.T, findings []model.Finding, err error) {
	t.Helper()
	old := osvScan
	osvScan = func(ctx context.Context, pkgs []model.Package) ([]model.Finding, error) {
		return findings, err
	}
	t.Cleanup(func() { osvScan = old })
}

func stubKevLoad(t *testing.T, set kev.Set, stale bool, err error) {
	t.Helper()
	old := kevLoad
	kevLoad = func(cachePath string) (kev.Set, bool, error) {
		return set, stale, err
	}
	t.Cleanup(func() { kevLoad = old })
}

// stubALASScan replaces the Amazon Linux advisory lookup, recording the
// packages it was asked about in *got.
func stubALASScan(t *testing.T, got *[]model.Package, findings []model.Finding, err error) {
	t.Helper()
	old := alasScan
	alasScan = func(ctx context.Context, pkgs []model.Package) ([]model.Finding, error) {
		*got = pkgs
		return findings, err
	}
	t.Cleanup(func() { alasScan = old })
}
