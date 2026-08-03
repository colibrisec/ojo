// Package cli wires ojo's cobra commands.
package cli

import "github.com/spf13/cobra"

// Version is set at build time via -ldflags "-X .../internal/cli.Version=vX.Y.Z".
var Version = "dev"

// Root builds the top-level ojo command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:     "ojo",
		Short:   "ojo is a security scanner for dependencies, secrets, misconfig, and code",
		Version: Version,
	}
	root.AddCommand(fsCmd())
	root.AddCommand(imageCmd())
	return root
}
