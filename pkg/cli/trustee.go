package cli

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/bhoriuchi/voltron/pkg/trustee"
	"github.com/iancoleman/strcase"
	"github.com/spf13/cobra"
	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"golang.org/x/term"
)

func initTrusteeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trustee",
		Short: "Trustee subcommands",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.AddCommand(initTrusteeKeygenCmd())
	cmd.AddCommand(initTrusteeImportKeypartCmd())
	return cmd
}

func initTrusteeImportKeypartCmd() *cobra.Command {
	var (
		keypart string
		pk      string
		out     string
	)

	cmd := &cobra.Command{
		Use:   "import-keypart",
		Short: "Import an encrypted key part",
		RunE: func(cmd *cobra.Command, args []string) error {
			t := &trustee.Trustee{}
			if err := t.Import(keypart, pk); err != nil {
				return err
			}

			fmt.Printf("\n%s\n", base64.URLEncoding.EncodeToString(t.KeyShare))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&keypart, "keypart", "p", "", "Encrypted key part file")
	flags.StringVarP(&pk, "private-key", "k", "", "Trustee's private key file")
	flags.StringVarP(&out, "out", "o", "keypart.txt", "Output file")
	return cmd
}

func initTrusteeKeygenCmd() *cobra.Command {
	var (
		keyBits int
		name    string
	)

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new trustee keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				pkPem []byte
			)
			if name == "" {
				return fmt.Errorf("no key name specified")
			}

			fmt.Printf("Enter key pass phrase: ")
			passwd, err := term.ReadPassword(0)
			if err != nil {
				fmt.Println("")
				return err
			}
			fmt.Println("")

			key, err := pkix.CreateRSAKey(keyBits)
			if err != nil {
				return fmt.Errorf("failed to generate key: %s", err)
			}

			// export the private key
			if len(passwd) > 0 {
				if pkPem, err = key.ExportEncryptedPrivate(passwd); err != nil {
					return err
				}
			} else {
				if pkPem, err = key.ExportPrivate(); err != nil {
					return err
				}
			}

			pub, ok := key.Public.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("public key is not RSA type")
			}

			pubkb := x509.MarshalPKCS1PublicKey(pub)
			pubBlock := pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: pubkb,
			}

			pubPem := pem.EncodeToMemory(&pubBlock)

			wd, err := os.Getwd()
			if err != nil {
				return err
			}

			if err := ioutil.WriteFile(filepath.Join(wd, strings.ToLower(strcase.ToSnake(name)+".key")), pkPem, depot.LeafPerm); err != nil {
				return err
			}

			if err := ioutil.WriteFile(filepath.Join(wd, strings.ToLower(strcase.ToSnake(name)+".pub")), pubPem, depot.LeafPerm); err != nil {
				return err
			}

			fmt.Printf("\nGenerated keys in %s\n", wd)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.IntVar(&keyBits, "key-bits", 4096, "Key bits")
	flags.StringVarP(&name, "name", "n", "", "Key name")
	return cmd
}
