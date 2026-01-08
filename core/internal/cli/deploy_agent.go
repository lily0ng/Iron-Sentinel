package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewDeployAgentCmd() *cobra.Command {
	var networkCIDR string

	cmd := &cobra.Command{
		Use:   "deploy-agent",
		Short: "Deploy lightweight endpoint agents (scaffold)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("deploy-agent is scaffolded (network=%s)\n", networkCIDR)
			return nil
		},
	}

	cmd.Flags().StringVar(&networkCIDR, "network", "", "Network CIDR (e.g. 192.168.1.0/24)")
	_ = cmd.MarkFlagRequired("network")
	return cmd
}
