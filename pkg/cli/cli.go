package cli

import "github.com/spf13/cobra"

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(initCaCmd())
	cmd.AddCommand(initCertCmd())
	cmd.AddCommand(initTrusteeCmd())
	return cmd
}
