package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

const (
	ES256 = "ES256"
	ES384 = "ES384"
	ES512 = "ES512"
)

// GenerateKey generates the appropriate key type
func GenerateKey(keyType string) (pk *ecdsa.PrivateKey, err error) {
	switch keyType {
	case ES384:
		pk, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ES256:
		pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ES512:
		fallthrough
	default:
		pk, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	}

	return
}
