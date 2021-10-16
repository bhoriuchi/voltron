package ca

import (
	"bytes"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bhoriuchi/voltron/pkg/trustee"
	"github.com/ghodss/yaml"
	"github.com/hashicorp/vault/shamir"
	"github.com/iancoleman/strcase"
	"github.com/sethvargo/go-password/password"
	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
)

type CAConfig struct {
	expiry        time.Duration
	KeyThreshold  int      `json:"key_threshold" yaml:"key_threshold"`
	KeyShares     int      `json:"key_shares" yaml:"key_shares"`
	KeyBits       int      `json:"key_bits" yaml:"key_bits"`
	Expires       string   `json:"expires" yaml:"expires"`
	Organization  string   `json:"organization" yaml:"organization"`
	OU            string   `json:"organizational_unit" yaml:"organizational_unit"`
	Country       string   `json:"country" yaml:"country"`
	State         string   `json:"state" yaml:"state"`
	Locality      string   `json:"locality" yaml:"locality"`
	CN            string   `json:"common_name" yaml:"common_name"`
	PermitDomains []string `json:"permit_domains" yaml:"permit_domains"`
}

// Load loads the config content
func (c *CAConfig) Load(content []byte) error {
	content = bytes.TrimSpace(content)
	if bytes.HasPrefix(content, []byte("{")) && bytes.HasSuffix(content, []byte("}")) {
		return json.Unmarshal(content, c)
	}

	return yaml.Unmarshal(content, c)
}

func (c *CAConfig) Validate() error {
	var err error

	// validate expires
	c.expiry, err = time.ParseDuration(c.Expires)
	if err != nil {
		return fmt.Errorf("failed to parse expires: %s", err)
	}

	if c.Organization == "" {
		return fmt.Errorf("no organization specified")
	}

	if c.OU == "" {
		return fmt.Errorf("no organizational unit specified")
	}

	if c.Country == "" {
		return fmt.Errorf("no country specified")
	}

	if c.State == "" {
		return fmt.Errorf("no state specified")
	}

	if c.Locality == "" {
		return fmt.Errorf("no locality specified")
	}

	if c.CN == "" {
		return fmt.Errorf("no common name specified")
	}

	if c.KeyThreshold < 2 {
		return fmt.Errorf("key threshold must be at least 2")
	}

	if c.KeyShares < c.KeyThreshold {
		return fmt.Errorf("key shares must be greater than the key threshold")
	}

	return nil
}

func Init(configPath, trusteePath, outPath string) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %s", err)
	}

	if outPath == "" {
		outPath = filepath.Join(wd, "out")
	}

	if err := os.MkdirAll(outPath, 0755); err != nil {
		return fmt.Errorf("failed to create output path %s: %s", outPath, err)
	}

	if configPath, err = filepath.Abs(configPath); err != nil {
		return err
	}

	if trusteePath, err = filepath.Abs(trusteePath); err != nil {
		return err
	}

	configContent, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %s", err)
	}

	config := &CAConfig{}
	if err := config.Load(configContent); err != nil {
		return err
	}

	if err := config.Validate(); err != nil {
		return err
	}

	certFile := filepath.Join(outPath, strings.ToLower(strcase.ToSnake(config.CN)+".crt"))
	keyFile := filepath.Join(outPath, strings.ToLower(strcase.ToSnake(config.CN)+".key"))
	crlFile := filepath.Join(outPath, strings.ToLower(strcase.ToSnake(config.CN)+".crl"))

	// validate that the files dont exist before trying to make them
	if ok, err := fileExists(certFile); err != nil {
		return fmt.Errorf("failed to read %s: %s", certFile, err)
	} else if ok {
		return fmt.Errorf("file %s exists", certFile)
	}

	if ok, err := fileExists(keyFile); err != nil {
		return fmt.Errorf("failed to read %s: %s", keyFile, err)
	} else if ok {
		return fmt.Errorf("file %s exists", keyFile)
	}

	if ok, err := fileExists(crlFile); err != nil {
		return fmt.Errorf("failed to read %s: %s", crlFile, err)
	} else if ok {
		return fmt.Errorf("file %s exists", crlFile)
	}

	// read trustee keys
	trusteeKeys, err := readTrusteeKeys(trusteePath)
	if err != nil {
		return err
	}

	if len(trusteeKeys) != config.KeyShares {
		return fmt.Errorf("found %d trustee public keys, expected %d", len(trusteeKeys), config.KeyShares)
	}

	// generate a strong random passphrase
	passphrase, err := password.Generate(64, 10, 0, false, true)
	if err != nil {
		return err
	}

	fmt.Println("PASSPHRASE", passphrase) // TODO: remove this after testing

	// split the passphrase
	byteParts, err := shamir.Split([]byte(passphrase), config.KeyShares, config.KeyThreshold)
	if err != nil {
		return err
	}

	// map the key parts to trustees
	idx := 0
	trustees := map[string]*trustee.Trustee{}
	for name, pub := range trusteeKeys {
		trustees[name] = &trustee.Trustee{
			Name:      name,
			PublicKey: pub,
			KeyShare:  byteParts[idx],
		}
		idx++
	}

	// create the CA key
	if config.KeyBits == 0 {
		config.KeyBits = 4096
	}

	key, err := pkix.CreateRSAKey(config.KeyBits)
	if err != nil {
		return err
	}

	expiresTime := time.Now().Add(config.expiry)

	// create the cert
	crt, err := pkix.CreateCertificateAuthority(
		key,
		config.OU,
		expiresTime,
		config.Organization,
		config.Country,
		config.State,
		config.Locality,
		config.CN,
	)

	if err != nil {
		return err
	}

	keyMaterial, err := key.ExportEncryptedPrivate([]byte(passphrase))
	if err != nil {
		return fmt.Errorf("failed to export encrypted private key: %s", err)
	}

	caCrt, err := crt.Export()
	if err != nil {
		return fmt.Errorf("failed to export CA cert: %s", err)
	}

	crl, err := pkix.CreateCertificateRevocationList(key, crt, expiresTime)
	if err != nil {
		return fmt.Errorf("failed to create CRL: %s", err)
	}

	crlMaterial, err := crl.Export()
	if err != nil {
		return fmt.Errorf("failed to export CRL: %s", err)
	}

	if err := ioutil.WriteFile(keyFile, keyMaterial, depot.LeafPerm); err != nil {
		return fmt.Errorf("failed to write key file %s: %s", keyFile, err)
	}

	if err := ioutil.WriteFile(certFile, caCrt, depot.LeafPerm); err != nil {
		return fmt.Errorf("failed to write cert file %s: %s", certFile, err)
	}

	if err := ioutil.WriteFile(crlFile, crlMaterial, depot.LeafPerm); err != nil {
		return fmt.Errorf("failed to write CRL file %s: %s", crlFile, err)
	}

	// finally write the encrypted shared key parts to disk
	if err := writeTrusteeEncryptedParts(trustees, config.CN, outPath); err != nil {
		return err
	}

	return nil
}

// writes the encrypted passphrase parts to the output path
// these encrypted parts can only be decrypted by the trustee's private key
// corresponding to the supplied trustee public key in order to securely
// transfer the trustees key part
func writeTrusteeEncryptedParts(trustees map[string]*trustee.Trustee, cn, outPath string) error {
	for _, t := range trustees {
		if err := t.Export(cn, outPath); err != nil {
			return err
		}
	}

	return nil
}

// readTrusteeKeys reads the trustee keys into a map, validates that exactly
// expected number of unique public keys exist in the trustee path
func readTrusteeKeys(trusteePath string) (map[string]*rsa.PublicKey, error) {
	// check that there are enough trustee public keys
	trusteeHash := map[string]string{}
	trusteeKeys := map[string]*rsa.PublicKey{}

	files, err := ioutil.ReadDir(trusteePath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if strings.EqualFold(filepath.Ext(file.Name()), ".pub") {
			fpath := filepath.Join(trusteePath, file.Name())
			material, err := ioutil.ReadFile(fpath)
			if err != nil {
				return nil, err
			}

			sum := md5.Sum(material)
			sumstr := fmt.Sprintf("%x", sum)

			if match, ok := trusteeHash[sumstr]; ok {
				return nil, fmt.Errorf("trustee keys %q and %q contain the same key material", sumstr, match)
			}

			trusteeHash[sumstr] = file.Name()

			pb, _ := pem.Decode(material)
			if pb == nil {
				return nil, fmt.Errorf("invalid PEM encoding for %q", fpath)
			}

			pub, err := x509.ParsePKCS1PublicKey(pb.Bytes)
			if err != nil {
				return nil, err
			}

			name := filepath.Base(file.Name())
			bname := strings.TrimSuffix(name, filepath.Ext(name))
			trusteeKeys[bname] = pub
		}
	}

	return trusteeKeys, nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}
