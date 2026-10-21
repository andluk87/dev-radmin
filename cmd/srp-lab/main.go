// srp-lab serves inner helper messages for interoperability experiments.
// It also supports own-key RSA bootstrap and CChannel; no VPN control commands or data plane are implemented.
package main

import (
	"crypto/rsa"
	"dev-radmin/internal/bootstrap"
	"dev-radmin/internal/channel"
	"dev-radmin/internal/srp"
	"dev-radmin/internal/wire"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func event(name string, extra map[string]any) {
	if extra == nil {
		extra = make(map[string]any)
	}
	extra["event"] = name
	extra["vpn_ready"] = false
	_ = json.NewEncoder(os.Stdout).Encode(extra)
}

func serve(c net.Conn, record srp.Record, encKey, decKey []byte, rsaKey *rsa.PrivateKey) {
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		event("io_error", nil)
		return
	}
	server, err := srp.NewServer(record, nil)
	if err != nil {
		event("invalid_record", nil)
		return
	}
	var envelope *channel.Channel
	if rsaKey != nil {
		version, e := wire.ReadFrame(c, 4096)
		if e != nil || len(version) != 4 || binary.LittleEndian.Uint32(version) != bootstrap.Version {
			event("rejected", map[string]any{"reason": "bootstrap"})
			return
		}
		request, e := wire.ReadFrame(c, 4096)
		if e != nil {
			event("rejected", map[string]any{"reason": "bootstrap"})
			return
		}
		_, material, e := bootstrap.Decode(rsaKey, request)
		if e != nil {
			event("rejected", map[string]any{"reason": "bootstrap"})
			return
		}
		// RvROLClient passes the same RSession buffer twice to CChannel, whose
		// constructor uses the first 32 bytes of each supplied buffer.
		envelope, e = channel.New(material[:32], material[:32])
		for i := range material {
			material[i] = 0
		}
		if e != nil {
			event("invalid_channel_config", nil)
			return
		}
		reply := make([]byte, 4)
		binary.LittleEndian.PutUint32(reply, bootstrap.Version)
		if wire.WriteFrame(c, reply, 4096) != nil {
			event("write_error", nil)
			return
		}
	}
	if encKey != nil {
		envelope, err = channel.New(encKey, decKey)
		if err != nil {
			event("invalid_channel_config", nil)
			return
		}
	}
	for i := 0; i < 3; i++ {
		input, err := wire.ReadFrame(c, 4096)
		if err != nil {
			event("read_error", nil)
			return
		}
		if envelope != nil {
			input, err = envelope.Decrypt(input)
			if err != nil {
				event("rejected", map[string]any{"reason": "channel"})
				return
			}
		}
		output, done, err := server.Step(input)
		if err != nil {
			reason := "protocol"
			if errors.Is(err, srp.ErrAuthentication) {
				reason = "authentication"
			}
			event("rejected", map[string]any{"reason": reason})
			return
		}
		if envelope != nil {
			output, err = envelope.Encrypt(output)
			if err != nil {
				event("channel_error", nil)
				return
			}
		}
		if err = wire.WriteFrame(c, output, 4096); err != nil {
			event("write_error", nil)
			return
		}
		if done {
			key, err := server.SessionKey()
			if err != nil || len(key) != 40 {
				event("key_error", nil)
				return
			}
			for j := range key {
				key[j] = 0
			}
			event("authentication_complete", nil)
			return
		}
	}
	event("incomplete", nil)
}

func decodeRecord(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return errors.New("record must be a regular file of at most 4096 bytes")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 4097))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		return errors.New("invalid record JSON")
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing record JSON")
	}
	return nil
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:17302", "lab listener; no complete Radmin compatibility")
	path := flag.String("record", "", "JSON credential record (user_id, salt_hex, verifier_hex)")
	channelPath := flag.String("channel-record", "", "optional fixed directional AES keys JSON for CChannel-only experiments")
	rsaPath := flag.String("rsa-key", "", "optional own RSA private PEM: version frame, RSession key transport, then encrypted SRP")
	once := flag.Bool("once", false, "exit after a single test connection")
	flag.Parse()
	if *rsaPath != "" && *channelPath != "" {
		return errors.New("-rsa-key and -channel-record are mutually exclusive")
	}
	if *path == "" {
		return errors.New("-record is required; no default account exists")
	}
	var cfg struct {
		UserID   uint64 `json:"user_id"`
		Salt     string `json:"salt_hex"`
		Verifier string `json:"verifier_hex"`
	}
	if err := decodeRecord(*path, &cfg); err != nil {
		return err
	}
	salt, err := hex.DecodeString(cfg.Salt)
	if err != nil {
		return errors.New("invalid salt encoding")
	}
	v, err := hex.DecodeString(cfg.Verifier)
	if err != nil {
		return errors.New("invalid verifier encoding")
	}
	record := srp.Record{UserID: cfg.UserID, Salt: salt, Verifier: v}
	if _, err = srp.NewServer(record, nil); err != nil {
		return err
	}
	var encKey, decKey []byte
	var rsaKey *rsa.PrivateKey
	if *rsaPath != "" {
		f, e := os.Open(*rsaPath)
		if e != nil {
			return e
		}
		data, e := io.ReadAll(io.LimitReader(f, 16385))
		f.Close()
		if e != nil || len(data) > 16384 {
			return errors.New("invalid RSA key file size")
		}
		rsaKey, e = bootstrap.ParseKey(data)
		for i := range data {
			data[i] = 0
		}
		if e != nil {
			return e
		}
	}
	if *channelPath != "" {
		var keys struct {
			Enc string `json:"enc_key_hex"`
			Dec string `json:"dec_key_hex"`
		}
		if err = decodeRecord(*channelPath, &keys); err != nil {
			return err
		}
		encKey, err = hex.DecodeString(keys.Enc)
		if err != nil {
			return errors.New("invalid channel encryption key encoding")
		}
		decKey, err = hex.DecodeString(keys.Dec)
		if err != nil {
			return errors.New("invalid channel decryption key encoding")
		}
		if _, err = channel.New(encKey, decKey); err != nil {
			return err
		}
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	event("listening", map[string]any{"address": listener.Addr().String(), "channel_enabled": encKey != nil || rsaKey != nil, "rsa_bootstrap": rsaKey != nil})
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		serve(c, record, encKey, decKey, rsaKey)
		if *once {
			return nil
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
