package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/colibrisec/ojo/internal/config"
	"github.com/colibrisec/ojo/internal/customrules"
	"github.com/colibrisec/ojo/internal/ignore"
	"github.com/colibrisec/ojo/internal/manifest"
	"github.com/colibrisec/ojo/internal/misconfig"
	"github.com/colibrisec/ojo/internal/osv"
	"github.com/colibrisec/ojo/internal/quality"
	"github.com/colibrisec/ojo/internal/report"
	"github.com/colibrisec/ojo/internal/sast"
	"github.com/colibrisec/ojo/internal/secret"
	"github.com/colibrisec/ojo/internal/vex"
)

func fsCmd() *cobra.Command {
	var format string
	var scanners string
	var configPath string
	var gitlab bool
	var rulesDir string
	var ignoreFile string
	var cyclonedxVersion string
	var secretRulesFile string
	var secretGitHistory bool
	var kevFlag bool
	var vexFile string

	cmd := &cobra.Command{
		Use:   "fs [path]",
		Short: "Scan a filesystem path for vulnerabilities, secrets, and misconfiguration",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}

			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			if cfg.Format != "" && !cmd.Flags().Changed("format") {
				format = cfg.Format
			}
			if cfg.Scanners != "" && !cmd.Flags().Changed("scanners") {
				scanners = cfg.Scanners
			}

			sbomVersion, err := report.ParseCycloneDXVersion(cyclonedxVersion)
			if err != nil {
				return err
			}

			if format == "sbom" {
				pkgs, err := manifest.Discover(root)
				if err != nil {
					return fmt.Errorf("discovering manifests: %w", err)
				}
				return report.SBOM(cmd.OutOrStdout(), pkgs, sbomVersion)
			}

			if gitlab {
				scanners = "vuln,secret,misconfig,sast"
			}

			rulesDirPath := rulesDir
			if rulesDirPath == "" {
				rulesDirPath = filepath.Join(root, ".ojo", "rules")
			} else if _, err := os.Stat(rulesDirPath); err != nil {
				return fmt.Errorf("loading custom rules: %w", err)
			}
			customRules, err := customrules.Load(rulesDirPath)
			if err != nil {
				return fmt.Errorf("loading custom rules: %w", err)
			}
			extraSecretRules, err := secret.LoadRules(secretRulesFile)
			if err != nil {
				return fmt.Errorf("loading secret rules file: %w", err)
			}

			ignoreRules, err := ignore.Load(ignoreFile)
			if err != nil {
				return fmt.Errorf("loading ignore file: %w", err)
			}
			vexStatements, err := vex.Load(vexFile)
			if err != nil {
				return fmt.Errorf("loading VEX file: %w", err)
			}

			rep := report.Report{Target: root}
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
					if kevFlag {
						if err := annotateKEV(cmd, findings); err != nil {
							return err
						}
					}
					rep.Findings = findings
				case "secret":
					issues, err := secret.Scan(root, extraSecretRules)
					if err != nil {
						return fmt.Errorf("scanning secrets: %w", err)
					}
					rep.Issues = append(rep.Issues, issues...)
					if secretGitHistory {
						histIssues, err := secret.ScanGitHistory(cmd.Context(), root, extraSecretRules)
						if err != nil {
							return fmt.Errorf("scanning git history for secrets: %w", err)
						}
						rep.Issues = append(rep.Issues, histIssues...)
					}
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
					customIssues, err := customrules.Scan(root, customRules)
					if err != nil {
						return fmt.Errorf("running custom rules: %w", err)
					}
					rep.Issues = append(rep.Issues, customIssues...)
				case "quality":
					issues, err := quality.Scan(root)
					if err != nil {
						return fmt.Errorf("running quality: %w", err)
					}
					rep.Issues = append(rep.Issues, issues...)
				case "":
					// no-op, allows trailing commas
				default:
					return fmt.Errorf("unknown scanner %q (available: vuln, secret, misconfig, sast, quality)", s)
				}
			}

			kept, suppressedFindings, keptIssues, suppressedIssues := ignore.Apply(rep.Findings, rep.Issues, ignoreRules, root, time.Now())
			rep.Findings, rep.Issues = kept, keptIssues
			rep.SuppressedFindings, rep.SuppressedIssues = suppressedFindings, suppressedIssues
			if len(vexStatements) > 0 {
				vexKept, vexSuppressed := vex.Apply(rep.Findings, vexStatements)
				rep.Findings = vexKept
				rep.SuppressedFindings = append(rep.SuppressedFindings, vexSuppressed...)
			}

			if gitlab {
				pkgs, err := manifest.Discover(root)
				if err != nil {
					return fmt.Errorf("discovering manifests: %w", err)
				}
				files := []struct {
					name  string
					write func(io.Writer) error
				}{
					{"gl-dependency-scanning-report.json", func(w io.Writer) error { return rep.GitLabDependencyScanning(w, root, Version) }},
					{"gl-sast-report.json", func(w io.Writer) error { return rep.GitLabSAST(w, root, Version) }},
					{"gl-secret-detection-report.json", func(w io.Writer) error { return rep.GitLabSecretDetection(w, root, Version) }},
					{"gl-sbom-report.cdx.json", func(w io.Writer) error { return report.SBOM(w, pkgs, sbomVersion) }},
				}
				for _, f := range files {
					out, err := os.Create(f.name)
					if err != nil {
						return fmt.Errorf("writing %s: %w", f.name, err)
					}
					err = f.write(out)
					out.Close()
					if err != nil {
						return fmt.Errorf("writing %s: %w", f.name, err)
					}
					fmt.Fprintln(cmd.OutOrStdout(), "wrote", f.name)
				}
			} else {
				switch format {
				case "json":
					if err := rep.JSON(cmd.OutOrStdout()); err != nil {
						return err
					}
				case "sarif":
					if err := rep.SARIF(cmd.OutOrStdout(), root); err != nil {
						return err
					}
				case "vex":
					doc := vex.Generate(rep.Findings, "ojo "+Version, time.Now())
					if err := vex.Write(cmd.OutOrStdout(), doc); err != nil {
						return err
					}
				default:
					rep.Table(cmd.OutOrStdout(), root)
				}
			}

			if len(rep.Findings) > 0 || len(rep.Issues) > 0 {
				os.Exit(1) // non-zero exit on findings, matches trivy/CI scanner convention
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, sbom, sarif, vex")
	cmd.Flags().StringVar(&scanners, "scanners", "vuln", "comma-separated scanners to run: vuln, secret, misconfig, sast, quality")
	cmd.Flags().StringVar(&configPath, "config", "", "path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)")
	cmd.Flags().BoolVarP(&gitlab, "gitlab", "g", false, "write GitLab-compatible security reports (gl-dependency-scanning-report.json, gl-sast-report.json, gl-secret-detection-report.json, gl-sbom-report.cdx.json) instead of -f/--format output; runs all scanners")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "directory of custom *.yaml SAST rules (default: <path>/.ojo/rules, if present); runs alongside --scanners sast")
	cmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "path to a .ojoignore file (default: .ojoignore in the current directory, if present)")
	cmd.Flags().StringVar(&cyclonedxVersion, "cyclonedx-version", "", "CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)")
	cmd.Flags().StringVar(&secretRulesFile, "secret-rules-file", "", "path to a YAML file of additional secret rules (same shape as the built-in rules), run alongside --scanners secret")
	cmd.Flags().BoolVar(&secretGitHistory, "secret-git-history", false, "also scan git commit history (current branch) for secrets that were committed and later removed; requires root to be a git repository")
	cmd.Flags().BoolVar(&kevFlag, "kev", false, "flag findings whose CVE is in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation); annotation only, doesn't affect exit code")
	cmd.Flags().StringVar(&vexFile, "vex-file", "", "path to an OpenVEX document; suppresses findings its not_affected/fixed statements cover (matched by product purl and CVE/alias)")
	return cmd
}
