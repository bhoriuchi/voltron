package cli

import (
	"io/ioutil"
	"path/filepath"

	"github.com/bhoriuchi/voltron/pkg/ca"
	"github.com/spf13/cobra"
)

func initCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Certificate commands",
	}

	cmd.AddCommand(initCertRequestCmd())
	return cmd
}

func initCertRequestCmd() *cobra.Command {
	var configFile string
	req := ca.CertRequest{}

	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if configFile != "" {
				if configFile, err = filepath.Abs(configFile); err != nil {
					return err
				}
				content, err := ioutil.ReadFile(configFile)
				if err != nil {
					return err
				}

				if err := req.Load(content); err != nil {
					return err
				}
			}

			if err := req.NewCSR(true); err != nil {
				return err
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&configFile, "config", "c", "", "Configuration file")
	flags.StringVar(&req.CSR, "csr", "", "CSR file to output")
	flags.IntVar(&req.KeyBits, "key-bits", 4096, "Key bits")
	flags.StringVar(&req.Organization, "organization", "", "Organization")
	flags.StringVar(&req.OU, "organizational-unit", "", "Organizational Unit")
	flags.StringVar(&req.Country, "country", "", "Country")
	flags.StringVar(&req.State, "state", "", "State")
	flags.StringVar(&req.Locality, "locality", "", "Locality")
	flags.StringVar(&req.CN, "cn", "", "Common name")
	flags.StringVar(&req.IP, "ip", "", "Comma separated list of IPs")
	flags.StringVar(&req.Domain, "domain", "", "Comma separated list of domains")
	flags.StringVar(&req.URI, "uri", "", "Comma separated list of URIs")
	return cmd
}
