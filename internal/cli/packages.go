package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/colibrisec/ojo/internal/config"
	"github.com/colibrisec/ojo/internal/license"
	"github.com/colibrisec/ojo/internal/manifest"
	"github.com/colibrisec/ojo/internal/model"
)

const noLicenseLookupUsage = "don't look up package licenses online (deps.dev, CocoaPods); only licenses found locally are used"

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
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: license lookup failed, some licenses may be missing: %v\n", err)
	}
	return pkgs
}

// warnUnscannable names the dependencies a vulnerability scan skipped, since
// a quiet skip reads as a clean result.
func warnUnscannable(cmd *cobra.Command, root string, unpinned []manifest.Unscannable, what string) {
	if len(unpinned) == 0 {
		return
	}
	const shown = 5
	var names []string
	for i, u := range unpinned {
		if i == shown {
			names = append(names, fmt.Sprintf("and %d more", len(unpinned)-shown))
			break
		}
		rel, err := filepath.Rel(root, u.Source)
		if err != nil {
			rel = u.Source
		}
		names = append(names, fmt.Sprintf("%s (%s, %s)", u.Name, rel, u.Reason))
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "warning: %d %s and were not checked for vulnerabilities: %s\n", len(unpinned), what, strings.Join(names, "; "))
}

// licenseScan checks discovered packages against the .ojo.yaml license
// policy.
func licenseScan(cmd *cobra.Command, root string, cfg config.License, noLookup bool) ([]model.Issue, error) {
	if len(cfg.Allow) == 0 && len(cfg.Deny) == 0 && cfg.Unknown != "fail" {
		return nil, fmt.Errorf("the license scanner needs a policy: set license.allow or license.deny in .ojo.yaml")
	}
	pkgs, err := manifest.Discover(root)
	if err != nil {
		return nil, fmt.Errorf("discovering manifests: %w", err)
	}
	pkgs = withLicenses(cmd, pkgs, noLookup)
	policy := license.Policy{Allow: cfg.Allow, Deny: cfg.Deny, Exceptions: cfg.Exceptions, FailUnknown: cfg.Unknown == "fail"}
	issues, unknown := policy.Check(pkgs)
	if len(unknown) > 0 && (cfg.Unknown == "" || cfg.Unknown == "warn") {
		const shown = 5
		var names []string
		for i, p := range unknown {
			if i == shown {
				names = append(names, fmt.Sprintf("and %d more", len(unknown)-shown))
				break
			}
			names = append(names, p.Name+"@"+p.Version)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %d package(s) have no known license and weren't checked against the license policy: %s\n", len(unknown), strings.Join(names, ", "))
	}
	return issues, nil
}
