package ca

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/bhoriuchi/voltron/pkg/util"
	"github.com/ghodss/yaml"
	"github.com/iancoleman/strcase"
	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"golang.org/x/term"
)

type CertRequest struct {
	Key          string `json:"key" yaml:"key"`
	CSR          string `json:"csr" yaml:"csr"`
	KeyBits      int    `json:"key_bits" yaml:"key_bits"`
	Organization string `json:"organization" yaml:"organization"`
	OU           string `json:"organizational_unit" yaml:"organizational_unit"`
	Country      string `json:"country" yaml:"country"`
	State        string `json:"state" yaml:"state"`
	Locality     string `json:"locality" yaml:"locality"`
	CN           string `json:"common_name" yaml:"common_name"`
	IP           string `json:"ip" yaml:"ip"`
	Domain       string `json:"domain" yaml:"domain"`
	URI          string `json:"uri" yaml:"uri"`
}

type Request struct {
	ID        string       `yaml:"id" json:"id"`
	PublicKey string       `yaml:"public_key" json:"public_key"`
	Request   *CertRequest `yaml:"request" json:"request"`
}

type Response struct {
	ID               string `yaml:"id" json:"id"`
	EncryptedKeypart string `yaml:"encrypted_keypart" json:"encrypted_keypart"`
}

func (c *CertRequest) Load(content []byte) error {
	content = bytes.TrimSpace(content)
	if bytes.HasPrefix(content, []byte("{")) && bytes.HasSuffix(content, []byte("}")) {
		return json.Unmarshal(content, c)
	}

	return yaml.Unmarshal(content, c)
}

// NewCSR creates a new certificate signing request
func (c *CertRequest) NewCSR(stdout bool) error {
	passphrase := ""
	if c.KeyBits < 0 {
		c.KeyBits = 4096
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	name := ""
	ips, err := pkix.ParseAndValidateIPs(c.IP)
	if err != nil {
		return err
	}

	uris, err := pkix.ParseAndValidateURIs(c.URI)
	if err != nil {
		return err
	}

	domains := strings.Split(c.Domain, ",")
	if c.Domain == "" {
		domains = nil
	}

	switch {
	case len(c.CN) != 0:
		name = c.CN
	case len(domains) != 0:
		name = domains[0]
	default:
		return fmt.Errorf("must provide a common name or domain")
	}

	if c.CSR == "" {
		c.CSR = filepath.Join(wd, strings.ToLower(strcase.ToSnake(name))+".csr")
	} else if c.CSR, err = filepath.Abs(c.CSR); err != nil {
		return err
	}

	if exists, err := fileExists(c.CSR); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("csr %s already exists", c.CSR)
	}

	var key *pkix.Key
	if c.Key != "" {
		keyPath, err := filepath.Abs(c.Key)
		if err != nil {
			return err
		}

		keyMaterial, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(keyMaterial)
		if block == nil {
			return fmt.Errorf("key is not PEM encoded")
		}

		if util.IsEncryptedPEMBlock(block) {
			passphrase, err := term.ReadPassword(0)
			if err != nil {
				fmt.Println("")
				return err
			}
			fmt.Println("")
			if key, err = pkix.NewKeyFromEncryptedPrivateKeyPEM(keyMaterial, []byte(passphrase)); err != nil {
				return err
			}
		} else if key, err = pkix.NewKeyFromPrivateKeyPEM(keyMaterial); err != nil {
			return err
		}
	} else {
		if key, err = pkix.CreateRSAKey(c.KeyBits); err != nil {
			return err
		}
	}

	csr, err := pkix.CreateCertificateSigningRequest(
		key,
		c.OU,
		ips,
		domains,
		uris,
		c.Organization,
		c.Country,
		c.State,
		c.Locality,
		name,
	)

	if err != nil {
		return err
	}

	// write the csr
	csrMaterial, err := csr.Export()
	if err != nil {
		return err
	}

	if stdout {
		fmt.Println(string(csrMaterial))
	}

	if err := ioutil.WriteFile(c.CSR, csrMaterial, depot.LeafPerm); err != nil {
		return err
	}

	// write the key
	if c.Key == "" {
		var km []byte
		if passphrase != "" {
			if km, err = key.ExportEncryptedPrivate([]byte(passphrase)); err != nil {
				return err
			}
		} else {
			if km, err = key.ExportPrivate(); err != nil {
				return err
			}
		}

		keyPath := filepath.Join(wd, strings.ToLower(strcase.ToSnake(name))+".key")

		if exists, err := fileExists(keyPath); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("key file %s already exists", keyPath)
		}

		if err := ioutil.WriteFile(keyPath, km, depot.LeafPerm); err != nil {
			return err
		}
	}

	return nil
}
