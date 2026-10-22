package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"dev-radmin/internal/bootstrap"
	"dev-radmin/internal/channel"
	"dev-radmin/internal/wire"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type bootstrapDuplex struct {
	io.Reader
	io.Writer
}

func TestBootstrapStructuralFailures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1536)
	if err != nil {
		t.Fatal(err)
	}
	frames := func(bodies ...[]byte) []byte {
		var out bytes.Buffer
		for _, body := range bodies {
			if err := wire.WriteFrame(&out, body, 4096); err != nil {
				t.Fatal(err)
			}
		}
		return out.Bytes()
	}
	version := []byte{3, 0, 0, 0}
	for _, tc := range []struct {
		name        string
		input       []byte
		stage, kind string
	}{
		{"empty_tcp_probe", nil, "version_frame", "eof"},
		{"truncated_prefix", []byte{0, 0}, "version_frame", "truncated"},
		{"oversized_frame", []byte{0, 0, 0x20, 0}, "version_frame", "frame_too_large"},
		{"wrong_version_size", frames([]byte{3}), "version_size", "invalid_bootstrap"},
		{"wrong_version", frames([]byte{4, 0, 0, 0}), "version_value", "invalid_bootstrap"},
		{"missing_rsa", frames(version), "rsa_frame", "eof"},
		{"wrong_rsa_size", frames(version, []byte{1}), "rsa_size", "invalid_bootstrap"},
		{"bad_rsa_record", frames(version, make([]byte, key.Size())), "rsa_decode", "invalid_bootstrap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			envelope, diag, err := bootstrapChannel(bootstrapDuplex{bytes.NewReader(tc.input), &output}, key)
			if err == nil || envelope != nil || diag["stage"] != tc.stage || diag["error_kind"] != tc.kind {
				t.Fatalf("unexpected diagnostics: %v %v", diag, err)
			}
			if output.Len() != 0 {
				t.Fatal("rejected bootstrap received a reply")
			}
			if tc.name == "empty_tcp_probe" && !errors.Is(err, io.EOF) {
				t.Fatal("probe not identified as EOF")
			}
		})
	}
}

func TestBootstrapCreatesCompatibleChannel(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1536)
	if err != nil {
		t.Fatal(err)
	}
	material := bytes.Repeat([]byte{19}, 64)
	plain := make([]byte, 76)
	binary.LittleEndian.PutUint32(plain, bootstrap.Version)
	copy(plain[12:], material)
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	var input, output bytes.Buffer
	wire.WriteFrame(&input, []byte{3, 0, 0, 0}, 4096)
	wire.WriteFrame(&input, encrypted, 4096)
	envelope, diag, err := bootstrapChannel(bootstrapDuplex{&input, &output}, key)
	if err != nil || diag != nil {
		t.Fatalf("bootstrap: %v %v", diag, err)
	}
	reply, err := wire.ReadFrame(&output, 4096)
	if err != nil || !bytes.Equal(reply, []byte{3, 0, 0, 0}) {
		t.Fatal("bad version reply")
	}
	nativeEquivalent, _ := channel.New(material[:32], material[:32])
	ciphertext, err := envelope.Encrypt([]byte("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := nativeEquivalent.Decrypt(ciphertext)
	if err != nil || string(decrypted) != "synthetic" {
		t.Fatal("bad channel key")
	}
	if len(rsaPublicFingerprint(key)) != 64 {
		t.Fatal("missing public fingerprint")
	}
}
