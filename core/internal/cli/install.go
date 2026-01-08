package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewInstallCmd() *cobra.Command {
	var pm string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install dependencies via package manager integration (scaffold)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("install is scaffolded (pm=%s)\n", pm)
			return nil
		},
	}

	cmd.Flags().StringVar(&pm, "pm", "", "Package manager (apt|yum|dnf|pacman|zypper)")
	_ = cmd.MarkFlagRequired("pm")
	return cmd
}
