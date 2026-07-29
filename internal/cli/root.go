// Package cli wires ojo's cobra commands.
package cli

import "github.com/spf13/cobra"

// Root builds the top-level ojo command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "ojo",
		Short: "ojo is a security scanner for dependencies, secrets, misconfig, and code",
	}
	root.AddCommand(fsCmd())
	root.AddCommand(imageCmd())
	return root
}
