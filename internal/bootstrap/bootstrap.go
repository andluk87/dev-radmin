// Package bootstrap implements the observed helper RSA key transport for research.
// This stage alone does not authenticate a peer; SRP proof verification must follow.
package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
)

var ErrBootstrap = errors.New("invalid legacy RSA bootstrap")

const Version uint32 = 3

// ParseKey accepts only a complete PEM RSA private key without trailing data.
func ParseKey(data []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return nil, ErrBootstrap
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrBootstrap
		}
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if key == nil || key.N.BitLen() < 1536 || key.N.BitLen() > 4096 || len(key.Primes) != 2 {
		return nil, ErrBootstrap
	}
	if err := key.Validate(); err != nil {
		return nil, ErrBootstrap
	}
	return key, nil
}

// Decode consumes one RSA PKCS#1 v1.5 ciphertext. The three metadata words are
// returned separately from the 64-byte transport material; neither is logged.
func Decode(key *rsa.PrivateKey, record []byte) ([3]uint32, []byte, error) {
	var metadata [3]uint32
	if key == nil || len(record) != key.Size() {
		return metadata, nil, ErrBootstrap
	}
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, key, record)
	if err != nil {
		return metadata, nil, ErrBootstrap
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	if len(plain) != 76 {
		return metadata, nil, ErrBootstrap
	}
	for i := range metadata {
		metadata[i] = binary.LittleEndian.Uint32(plain[i*4:])
	}
	return metadata, append([]byte(nil), plain[12:]...), nil
}
