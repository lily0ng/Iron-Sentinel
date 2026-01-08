package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"iron-sentinel/core/internal/version"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "iron-sentinel",
		Short:         "Iron-Sentinel incident response platform (Linux)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(NewTriageCmd())
	cmd.AddCommand(NewServerCmd())
	cmd.AddCommand(NewDeployAgentCmd())
	cmd.AddCommand(NewInstallCmd())
	cmd.AddCommand(NewVersionCmd())

	cmd.SetVersionTemplate(fmt.Sprintf("%s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH))
	cmd.Version = version.Version

	return cmd
}
