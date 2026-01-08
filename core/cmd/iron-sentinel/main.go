package main

import (
	"os"

	"iron-sentinel/core/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
