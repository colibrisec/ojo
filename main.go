package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/colibrisec/ojo/internal/cli"
)

// run turns cli.Root()'s result into a process exit code, printing err to
// stderr unless it's the "exit 1, print nothing extra" sentinel. Separated
// from main so it's testable without actually running a command.
func run(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	if !errors.Is(err, cli.ErrFindingsFound) {
		fmt.Fprintln(stderr, err)
	}
	return 1
}

func main() {
	os.Exit(run(cli.Root().ExecuteContext(context.Background()), os.Stderr))
}
