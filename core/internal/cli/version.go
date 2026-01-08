package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"iron-sentinel/core/internal/version"
)

func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("%s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}
