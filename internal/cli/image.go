package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/colibrisec/ojo/internal/image"
	"github.com/colibrisec/ojo/internal/osv"
	"github.com/colibrisec/ojo/internal/report"
)

func imageCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "image [ref]",
		Short: "Scan a container image for vulnerable OS packages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			pkgs, osLabel, err := image.Scan(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if len(pkgs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No OS packages found.")
				return nil
			}

			if format == "sbom" {
				return report.SBOM(cmd.OutOrStdout(), pkgs)
			}

			findings, err := osv.Scan(cmd.Context(), pkgs)
			if err != nil {
				return fmt.Errorf("querying OSV: %w", err)
			}

			rep := report.Report{Target: fmt.Sprintf("%s (%s)", ref, osLabel), Findings: findings}
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
	return cmd
}
