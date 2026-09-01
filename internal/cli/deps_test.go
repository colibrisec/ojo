package cli

import (
	"context"
	"testing"

	"github.com/colibrisec/ojo/internal/kev"
	"github.com/colibrisec/ojo/internal/model"
)

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
