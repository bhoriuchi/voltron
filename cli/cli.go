package cli

import "github.com/spf13/cobra"

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(initKeygenCmd())
	return cmd
}
