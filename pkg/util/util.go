package util

import (
	"crypto/x509"
	"encoding/pem"
)

func IsEncryptedPEMBlock(b *pem.Block) bool {
	return x509.IsEncryptedPEMBlock(b)
}
