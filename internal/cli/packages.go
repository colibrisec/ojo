package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/colibrisec/ojo/internal/model"
)

const noLicenseLookupUsage = "don't look up package licenses online (deps.dev, CocoaPods) for SBOM output; only licenses found locally are included"

func hasPods(pkgs []model.Package) bool {
	for _, p := range pkgs {
		if p.Ecosystem == model.EcosystemCocoaPods {
			return true
		}
	}
	return false
}

// resolvePods fills in the repository (and license) of CocoaPods packages,
// which a vulnerability scan needs to match them against OSV's SwiftURL
// advisories. Pods that can't be resolved are skipped by the scan, so say
// how many -- silently checking fewer packages than were found would read
// as a clean result.
func resolvePods(cmd *cobra.Command, pkgs []model.Package) []model.Package {
	if !hasPods(pkgs) {
		return pkgs
	}
	pkgs, unresolved := podResolve(cmd.Context(), pkgs)
	if unresolved > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %d CocoaPods pod(s) have no public podspec with a git source and were not checked for vulnerabilities\n", unresolved)
	}
	return pkgs
}

// withLicenses fills in package licenses for SBOM output from the online
// sources. A failed lookup is a warning, not an error: the SBOM is still
// complete as an inventory, just without the licenses that needed the
// network.
func withLicenses(cmd *cobra.Command, pkgs []model.Package, skip bool) []model.Package {
	if skip || len(pkgs) == 0 {
		return pkgs
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "Looking up package licenses...")
	if hasPods(pkgs) {
		pkgs, _ = podResolve(cmd.Context(), pkgs)
	}
	pkgs, err := licenseLookup(cmd.Context(), pkgs)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: license lookup failed, the SBOM may be missing licenses: %v\n", err)
	}
	return pkgs
}
