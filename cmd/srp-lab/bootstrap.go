package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"dev-radmin/internal/bootstrap"
	"dev-radmin/internal/channel"
	"dev-radmin/internal/wire"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
)

// bootstrapChannel returns structural diagnostics only. No key material, RSA
// plaintext, ciphertext, account metadata, or packet bodies enter the log map.
func bootstrapChannel(c io.ReadWriter, key *rsa.PrivateKey) (*channel.Channel, map[string]any, error) {
	fail := func(stage string, err error, extra map[string]any) (*channel.Channel, map[string]any, error) {
		if extra == nil {
			extra = make(map[string]any)
		}
		extra["stage"] = stage
		extra["error_kind"] = bootstrapErrorKind(err)
		return nil, extra, err
	}
	if key == nil {
		return fail("configuration", bootstrap.ErrBootstrap, nil)
	}
	version, err := wire.ReadFrame(c, 4096)
	if err != nil {
		return fail("version_frame", err, nil)
	}
	if len(version) != 4 {
		return fail("version_size", bootstrap.ErrBootstrap, map[string]any{"frame_bytes": len(version), "expected_bytes": 4})
	}
	value := binary.LittleEndian.Uint32(version)
	if value != bootstrap.Version {
		return fail("version_value", bootstrap.ErrBootstrap, map[string]any{"protocol_version": value, "expected_version": bootstrap.Version})
	}
	request, err := wire.ReadFrame(c, 4096)
	if err != nil {
		return fail("rsa_frame", err, nil)
	}
	if len(request) != key.Size() {
		return fail("rsa_size", bootstrap.ErrBootstrap, map[string]any{"frame_bytes": len(request), "expected_bytes": key.Size()})
	}
	_, material, err := bootstrap.Decode(key, request)
	if err != nil {
		return fail("rsa_decode", err, map[string]any{"frame_bytes": len(request)})
	}
	defer clearBytes(material)
	envelope, err := channel.New(material[:32], material[:32])
	if err != nil {
		return fail("channel_initialization", err, nil)
	}
	reply := make([]byte, 4)
	binary.LittleEndian.PutUint32(reply, bootstrap.Version)
	if err := wire.WriteFrame(c, reply, 4096); err != nil {
		return fail("version_reply", err, nil)
	}
	return envelope, nil, nil
}

func bootstrapErrorKind(err error) string {
	switch {
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated"
	case errors.Is(err, wire.ErrFrameTooLarge):
		return "frame_too_large"
	case errors.Is(err, bootstrap.ErrBootstrap):
		return "invalid_bootstrap"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return "io"
}

func rsaPublicFingerprint(key *rsa.PrivateKey) string {
	if key == nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}
