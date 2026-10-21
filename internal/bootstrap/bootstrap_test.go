package bootstrap

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"testing"
)

func TestKeyTransportAndInvalidRequests(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1536)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 76)
	for i, value := range []uint32{3, 42, 7} {
		binary.LittleEndian.PutUint32(plain[i*4:], value)
	}
	for i := 12; i < len(plain); i++ {
		plain[i] = byte(i)
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	metadata, material, err := Decode(key, encrypted)
	if err != nil || metadata != [3]uint32{3, 42, 7} || !bytes.Equal(material, plain[12:]) {
		t.Fatal("key transport mismatch", err)
	}
	shortPlain, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plain[:75])
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{nil, encrypted[:191], make([]byte, key.Size()), shortPlain} {
		_, material, err := Decode(key, input)
		if err == nil || material != nil {
			t.Fatal("invalid RSA request released key material")
		}
	}
}
func TestPrivateKeyParsing(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1536)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	parsed, err := ParseKey(encoded)
	if err != nil || parsed.N.Cmp(key.N) != 0 {
		t.Fatal("valid key rejected", err)
	}
	for _, input := range [][]byte{nil, append(append([]byte(nil), encoded...), []byte("extra")...), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}})} {
		if _, err := ParseKey(input); err == nil {
			t.Fatal("invalid private key accepted")
		}
	}
}
