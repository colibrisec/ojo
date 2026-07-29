package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/colibrisec/ojo/internal/manifest"
	"github.com/colibrisec/ojo/internal/misconfig"
	"github.com/colibrisec/ojo/internal/osv"
	"github.com/colibrisec/ojo/internal/report"
	"github.com/colibrisec/ojo/internal/sast"
	"github.com/colibrisec/ojo/internal/secret"
)

func fsCmd() *cobra.Command {
	var format string
	var scanners string

	cmd := &cobra.Command{
		Use:   "fs [path]",
		Short: "Scan a filesystem path for vulnerabilities, secrets, and misconfiguration",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}

			if format == "sbom" {
				pkgs, err := manifest.Discover(root)
				if err != nil {
					return fmt.Errorf("discovering manifests: %w", err)
				}
				return report.SBOM(cmd.OutOrStdout(), pkgs)
			}

			var rep report.Report
			for _, s := range strings.Split(scanners, ",") {
				switch strings.TrimSpace(s) {
				case "vuln":
					pkgs, err := manifest.Discover(root)
					if err != nil {
						return fmt.Errorf("discovering manifests: %w", err)
					}
					findings, err := osv.Scan(cmd.Context(), pkgs)
					if err != nil {
						return fmt.Errorf("querying OSV: %w", err)
					}
					rep.Findings = findings
				case "secret":
					issues, err := secret.Scan(root)
					if err != nil {
						return fmt.Errorf("scanning secrets: %w", err)
					}
					rep.Issues = append(rep.Issues, issues...)
				case "misconfig":
					issues, err := misconfig.Scan(root)
					if err != nil {
						return fmt.Errorf("scanning misconfig: %w", err)
					}
					rep.Issues = append(rep.Issues, issues...)
				case "sast":
					issues, err := sast.Scan(root)
					if err != nil {
						return fmt.Errorf("running sast: %w", err)
					}
					rep.Issues = append(rep.Issues, issues...)
				case "":
					// no-op, allows trailing commas
				default:
					return fmt.Errorf("unknown scanner %q (available: vuln, secret, misconfig, sast)", s)
				}
			}

			switch format {
			case "json":
				if err := rep.JSON(cmd.OutOrStdout()); err != nil {
					return err
				}
			default:
				rep.Table(cmd.OutOrStdout(), root)
			}

			if len(rep.Findings) > 0 || len(rep.Issues) > 0 {
				os.Exit(1) // non-zero exit on findings, matches trivy/CI scanner convention
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, sbom")
	cmd.Flags().StringVar(&scanners, "scanners", "vuln,secret", "comma-separated scanners to run: vuln, secret, misconfig, sast")
	return cmd
}
