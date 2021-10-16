package trustee

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/bhoriuchi/voltron/pkg/util"
	"github.com/iancoleman/strcase"
	"github.com/square/certstrap/pkix"
	"golang.org/x/term"
)

type Trustee struct {
	Name      string
	PublicKey *rsa.PublicKey
	KeyShare  []byte
}

// Export encrypts and writes the encrypted key part to disk
func (t *Trustee) Export(cn, outPath string) error {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, t.PublicKey, t.KeyShare, nil)
	if err != nil {
		return err
	}

	if outPath, err = filepath.Abs(outPath); err != nil {
		return err
	}

	outFile := filepath.Join(outPath, strings.ToLower(fmt.Sprintf("%s_%s.enc.keypart", t.Name, strcase.ToSnake(cn))))
	if err := ioutil.WriteFile(outFile, ciphertext, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted keypart to %s: %s", outFile, err)
	}

	return nil
}

// Import reads and decrypts the key part
func (t *Trustee) Import(keypartPath, pkPath string) error {
	var (
		err error
		key *pkix.Key
	)

	if keypartPath, err = filepath.Abs(keypartPath); err != nil {
		return fmt.Errorf("failed to get absolute path to keypart file: %s", err)
	}

	if pkPath, err = filepath.Abs(pkPath); err != nil {
		return fmt.Errorf("failed to get absolute path to private key file: %s", err)
	}

	keypartMaterial, err := ioutil.ReadFile(keypartPath)
	if err != nil {
		return fmt.Errorf("failed to read key part file %s: %s", keypartPath, err)
	}

	pkMaterial, err := ioutil.ReadFile(pkPath)
	if err != nil {
		return fmt.Errorf("failed to read private key material: %s: %s", pkPath, err)
	}

	pkPem, _ := pem.Decode(pkMaterial)
	if pkPem == nil {
		return fmt.Errorf("private key is not in PEM format")
	}

	if util.IsEncryptedPEMBlock(pkPem) {
		fmt.Printf("Enter key pass phrase: ")
		passwd, err := term.ReadPassword(0)
		if err != nil {
			fmt.Println("")
			return err
		}
		fmt.Println("")
		if key, err = pkix.NewKeyFromEncryptedPrivateKeyPEM(pkMaterial, []byte(passwd)); err != nil {
			return err
		}
	} else {
		if key, err = pkix.NewKeyFromPrivateKeyPEM(pkMaterial); err != nil {
			return err
		}
	}

	rsaPk, ok := key.Private.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not RSA type")
	}

	t.PublicKey = &rsaPk.PublicKey
	hash := sha512.New()
	if t.KeyShare, err = rsa.DecryptOAEP(hash, rand.Reader, rsaPk, keypartMaterial, nil); err != nil {
		return fmt.Errorf("failed to decrypt key part material: %s", err)
	}

	return nil
}
