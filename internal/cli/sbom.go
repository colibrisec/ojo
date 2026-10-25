package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/colibrisec/ojo/internal/config"
	"github.com/colibrisec/ojo/internal/image"
	"github.com/colibrisec/ojo/internal/manifest"
	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/report"
	"github.com/colibrisec/ojo/internal/sbom"
)

func sbomCmd() *cobra.Command {
	var format string
	var configPath string
	var ignoreFile string
	var cyclonedxVersion string
	var kevFlag bool
	var vexFile string
	var sarifOmitSuppressed bool
	var noLicenseLookup bool
	var scanners string

	cmd := &cobra.Command{
		Use:   "sbom [file]",
		Short: "Scan the packages listed in a CycloneDX or SPDX SBOM for vulnerabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			if cfg.Format != "" && !cmd.Flags().Changed("format") {
				format = cfg.Format
			}
			sbomVersion, err := report.ParseCycloneDXVersion(cyclonedxVersion)
			if err != nil {
				return err
			}

			runVuln, runLicense, err := packageScanners("sbom", scanners, cfg.License)
			if err != nil {
				return err
			}

			res, err := sbom.Read(path)
			if err != nil {
				return err
			}
			switch format {
			case "sbom":
				return report.SBOM(cmd.OutOrStdout(), res.Packages, sbomVersion)
			case "spdx":
				return report.SPDX(cmd.OutOrStdout(), res.Packages, path, Version, time.Now())
			}

			var findings []model.Finding
			if runVuln {
				pkgs, skipped := checkable(res.Packages)
				warnUnscannable(cmd, "", append(res.Skipped, skipped...), "SBOM entries can't be matched to a package ojo checks")
				if len(pkgs) > 0 {
					findings, err = imageVulns(cmd, resolvePods(cmd, pkgs))
					if err != nil {
						return err
					}
				}
			}
			var issues []model.Issue
			if runLicense {
				issues = checkLicenses(cmd, res.Packages, cfg.License, noLicenseLookup)
			}
			return writeFindings(cmd, fmt.Sprintf("%s (%s)", path, res.Format), findings, issues, findingsOutput{
				format: format, ignoreFile: ignoreFile, vexFile: vexFile, kev: kevFlag, sarifOmitSuppressed: sarifOmitSuppressed,
			})
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, sbom, spdx, sarif, vex (sbom and spdx convert the input)")
	cmd.Flags().StringVar(&scanners, "scanners", "vuln", "comma-separated scanners to run: vuln, license")
	cmd.Flags().BoolVar(&noLicenseLookup, "no-license-lookup", false, noLicenseLookupUsage)
	cmd.Flags().StringVar(&configPath, "config", "", "path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)")
	cmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "path to a .ojoignore file (default: .ojoignore in the current directory, if present)")
	cmd.Flags().StringVar(&cyclonedxVersion, "cyclonedx-version", "", "CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)")
	cmd.Flags().BoolVar(&kevFlag, "kev", false, "flag findings whose CVE is in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation); annotation only, doesn't affect exit code")
	cmd.Flags().BoolVar(&sarifOmitSuppressed, "sarif-omit-suppressed", false, "omit results suppressed by .ojoignore or a VEX file from -f sarif output instead of marking them suppressed; for consumers such as GitHub code scanning that ignore SARIF suppressions")
	cmd.Flags().StringVar(&vexFile, "vex-file", "", "path to an OpenVEX document; suppresses findings its not_affected/fixed statements cover (matched by product purl and CVE/alias)")
	return cmd
}

// checkable drops OS packages of distributions ojo has no advisories for.
func checkable(pkgs []model.Package) ([]model.Package, []manifest.Unscannable) {
	var keep []model.Package
	var skipped []manifest.Unscannable
	for _, p := range pkgs {
		if osSources[p.Source] && !image.HasAdvisories(p.Ecosystem) {
			skipped = append(skipped, manifest.Unscannable{Name: p.Name, Source: p.Source, Reason: fmt.Sprintf("no advisories for %q", p.Ecosystem)})
			continue
		}
		keep = append(keep, p)
	}
	return keep, skipped
}

var osSources = map[string]bool{"dpkg": true, "apk": true, "rpm": true}
