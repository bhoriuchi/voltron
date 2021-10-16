package cli

import (
	"os"

	"github.com/bhoriuchi/voltron/pkg/ca"
	"github.com/spf13/cobra"
)

func initCaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "CA commands",
	}

	cmd.AddCommand(initCaInitCmd())
	return cmd
}

func initCaInitCmd() *cobra.Command {
	var (
		config     string
		trusteeDir string
		outDir     string
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "initializes a new CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			return ca.Init(config, trusteeDir, outDir)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&config, "config", "c", os.Getenv("VOLTRON_INIT_CONFIG"), "Configuration file")
	flags.StringVarP(&trusteeDir, "trustee_dir", "t", os.Getenv("VOLTRON_INIT_TRUSTEE_DIR"), "Directory where trustee public key files reside")
	flags.StringVarP(&outDir, "out", "o", os.Getenv("VOLTRON_INIT_OUTPUT_DIR"), "Output directory for CA files and encrypted key parts")
	return cmd
}
