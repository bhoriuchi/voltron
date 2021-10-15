package cli

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/bhoriuchi/voltron/key"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func initKeygenCmd() *cobra.Command {
	var (
		typ string
	)

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "generate a new keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Enter key pass phrase: ")
			pwd, err := term.ReadPassword(0)
			if err != nil {
				return err
			}

			k, err := key.GenerateKey(typ)
			if err != nil {
				return fmt.Errorf("failed to generate key: %s", err)
			}

			pkb, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				return fmt.Errorf("failed to marshal private key: %s", err)
			}

			pkBlock := &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: pkb,
			}

			if len(pwd) > 0 {
				if pkBlock, err = x509.EncryptPEMBlock(
					rand.Reader,
					"ENCRYPTED EC PRIVATE KEY",
					pkb,
					pwd,
					x509.PEMCipherAES256,
				); err != nil {
					return err
				}
			}

			pkPem := pem.EncodeToMemory(pkBlock)

			pubkb, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to marshal public key: %s", err)
			}

			pubBlock := pem.Block{
				Type:  "EC PUBLIC KEY",
				Bytes: pubkb,
			}

			pubPem := pem.EncodeToMemory(&pubBlock)

			wd, err := os.Getwd()
			if err != nil {
				return err
			}

			if err := ioutil.WriteFile(filepath.Join(wd, "voltron-private-key.pem"), pkPem, 0600); err != nil {
				return err
			}

			if err := ioutil.WriteFile(filepath.Join(wd, "voltron-pub-key.pem"), pubPem, 0644); err != nil {
				return err
			}

			fmt.Printf("\nGenerated keys in %s\n", wd)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&typ, "type", "t", "", "Key type")
	return cmd
}
