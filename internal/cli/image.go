package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/colibrisec/ojo/internal/config"
	"github.com/colibrisec/ojo/internal/ignore"
	"github.com/colibrisec/ojo/internal/image"
	"github.com/colibrisec/ojo/internal/osv"
	"github.com/colibrisec/ojo/internal/report"
	"github.com/colibrisec/ojo/internal/vex"
)

func imageCmd() *cobra.Command {
	var format string
	var configPath string
	var ignoreFile string
	var platform string
	var cyclonedxVersion string
	var kevFlag bool
	var vexFile string

	cmd := &cobra.Command{
		Use:   "image [ref]",
		Short: "Scan a container image for vulnerable OS packages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]

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
			pkgs, osLabel, err := image.Scan(cmd.Context(), ref, platform)
			if err != nil {
				return err
			}
			if len(pkgs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No OS packages found.")
				return nil
			}

			if format == "sbom" {
				return report.SBOM(cmd.OutOrStdout(), pkgs, sbomVersion)
			}

			findings, err := osv.Scan(cmd.Context(), pkgs)
			if err != nil {
				return fmt.Errorf("querying OSV: %w", err)
			}
			if kevFlag {
				if err := annotateKEV(cmd, findings); err != nil {
					return err
				}
			}

			ignoreRules, err := ignore.Load(ignoreFile)
			if err != nil {
				return fmt.Errorf("loading ignore file: %w", err)
			}
			vexStatements, err := vex.Load(vexFile)
			if err != nil {
				return fmt.Errorf("loading VEX file: %w", err)
			}
			kept, suppressed, _, _ := ignore.Apply(findings, nil, ignoreRules, "", time.Now())
			findings = kept
			if len(vexStatements) > 0 {
				vexKept, vexSuppressed := vex.Apply(findings, vexStatements)
				findings = vexKept
				suppressed = append(suppressed, vexSuppressed...)
			}

			rep := report.Report{Target: fmt.Sprintf("%s (%s)", ref, osLabel), Findings: findings, SuppressedFindings: suppressed}
			switch format {
			case "json":
				if err := rep.JSON(cmd.OutOrStdout()); err != nil {
					return err
				}
			case "sarif":
				if err := rep.SARIF(cmd.OutOrStdout(), ""); err != nil {
					return err
				}
			case "vex":
				doc := vex.Generate(findings, "ojo "+Version, time.Now())
				if err := vex.Write(cmd.OutOrStdout(), doc); err != nil {
					return err
				}
			default:
				rep.Table(cmd.OutOrStdout(), "")
			}

			if len(findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, sbom, sarif, vex")
	cmd.Flags().StringVar(&configPath, "config", "", "path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)")
	cmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "path to a .ojoignore file (default: .ojoignore in the current directory, if present)")
	cmd.Flags().StringVar(&platform, "platform", "", "image platform to pull as os/arch, e.g. linux/arm64 (default: linux/amd64)")
	cmd.Flags().StringVar(&cyclonedxVersion, "cyclonedx-version", "", "CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)")
	cmd.Flags().BoolVar(&kevFlag, "kev", false, "flag findings whose CVE is in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation); annotation only, doesn't affect exit code")
	cmd.Flags().StringVar(&vexFile, "vex-file", "", "path to an OpenVEX document; suppresses findings its not_affected/fixed statements cover (matched by product purl and CVE/alias)")
	return cmd
}
