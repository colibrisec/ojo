package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/colibrisec/ojo/internal/cli"
)

func main() {
	err := cli.Root().ExecuteContext(context.Background())
	if err == nil {
		return
	}
	if !errors.Is(err, cli.ErrFindingsFound) {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}
