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
)

func imageCmd() *cobra.Command {
	var format string
	var configPath string
	var ignoreFile string
	var platform string
	var cyclonedxVersion string

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

			ignoreRules, err := ignore.Load(ignoreFile)
			if err != nil {
				return fmt.Errorf("loading ignore file: %w", err)
			}
			kept, suppressed, _, _ := ignore.Apply(findings, nil, ignoreRules, "", time.Now())
			findings = kept

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
			default:
				rep.Table(cmd.OutOrStdout(), "")
			}

			if len(findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, sbom, sarif")
	cmd.Flags().StringVar(&configPath, "config", "", "path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)")
	cmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "path to a .ojoignore file (default: .ojoignore in the current directory, if present)")
	cmd.Flags().StringVar(&platform, "platform", "", "image platform to pull as os/arch, e.g. linux/arm64 (default: linux/amd64)")
	cmd.Flags().StringVar(&cyclonedxVersion, "cyclonedx-version", "", "CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)")
	return cmd
}
