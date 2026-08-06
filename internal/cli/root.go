// Package cli wires ojo's cobra commands.
package cli

import "github.com/spf13/cobra"

// Version is set at build time via -ldflags "-X .../internal/cli.Version=vX.Y.Z".
var Version = "dev"

// Root builds the top-level ojo command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "ojo",
		Short: "ojo is a security scanner for dependencies, secrets, misconfig, and code",
		Long: `ojo is a security scanner for dependencies, secrets, misconfig, and code.

Scanners (--scanners, comma-separated, ojo fs only):
  vuln       known CVEs in dependency manifests (default)
  secret     hardcoded credentials, API keys, tokens
  misconfig  Dockerfile / Kubernetes / Terraform misconfiguration
  sast       source-level issues (Go, Python, JS/TS, PHP, Ruby, Java)

Output formats (-f/--format, both commands):
  table      human-readable box-drawn table (default)
  json       machine-readable
  sbom       CycloneDX SBOM of discovered packages, skips vulnerability scanning
  sarif      SARIF 2.1.0, for GitHub code scanning and similar tooling`,
		Example: `  ojo fs .
  ojo fs --scanners vuln,secret,misconfig,sast .
  ojo fs -f sarif . > results.sarif
  ojo image python:3.14-slim`,
		Version: Version,
	}
	root.AddCommand(fsCmd())
	root.AddCommand(imageCmd())
	return root
}
