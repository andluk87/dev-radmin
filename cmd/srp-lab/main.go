// srp-lab serves inner helper messages for interoperability experiments.
// It also supports own-key RSA bootstrap and CChannel; no VPN control commands or data plane are implemented.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"dev-radmin/internal/bootstrap"
	"dev-radmin/internal/channel"
	"dev-radmin/internal/control"
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
	"os/signal"
	"strconv"
	"syscall"
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

type postAuthOptions struct {
	loginEndpoint string
	keepalive     bool
	echo          bool
	controlCode   *uint32
}

func serve(c net.Conn, record srp.Record, encKey, decKey []byte, rsaKey *rsa.PrivateKey, postAuth postAuthOptions) {
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
			if postAuth.echo || postAuth.keepalive || postAuth.loginEndpoint != "" || postAuth.controlCode != nil {
				err = envelope.Rekey(key[:32], key[:32])
			}
			for j := range key {
				key[j] = 0
			}
			if err != nil {
				event("key_error", nil)
				return
			}
			event("authentication_complete", nil)
			if postAuth.echo {
				if err = echoRecord(c, envelope); err != nil {
					event("post_auth_rejected", nil)
					return
				}
				event("post_auth_echo_complete", nil)
			}
			if postAuth.loginEndpoint != "" {
				if err = loginRecord(c, envelope, postAuth.loginEndpoint); err != nil {
					event("login_record_rejected", nil)
					return
				}
				event("login_record_complete", nil)
			}
			if postAuth.keepalive {
				if err = keepaliveRecord(c, envelope); err != nil {
					event("keepalive_rejected", nil)
					return
				}
				event("keepalive_complete", nil)
			}
			if postAuth.controlCode != nil {
				if err = controlRecord(c, envelope, *postAuth.controlCode); err != nil {
					event("control_rejected", nil)
					return
				}
				event("control_error_sent", nil)
			}
			return
		}
	}
	event("incomplete", nil)
}

// echoRecord exchanges one bounded synthetic record after authenticated rekeying.
// It is a lab probe, not a VPN control command.
func echoRecord(c net.Conn, envelope *channel.Channel) error {
	input, err := wire.ReadFrame(c, 4096)
	if err != nil {
		return err
	}
	plain, err := envelope.Decrypt(input)
	if err != nil {
		return err
	}
	defer clearBytes(plain)
	output, err := envelope.Encrypt(plain)
	if err != nil {
		return err
	}
	return wire.WriteFrame(c, output, 4096)
}

// controlRecord decodes one authenticated native control request and returns an
// explicitly selected experimental error. No VPN operation is claimed or run.
func controlRecord(c net.Conn, envelope *channel.Channel, code uint32) error {
	input, err := wire.ReadFrame(c, control.MaxMessage+24)
	if err != nil {
		return err
	}
	plain, err := envelope.Decrypt(input)
	if err != nil {
		return err
	}
	defer clearBytes(plain)
	request, err := control.DecodeRequest(plain)
	if err != nil {
		return err
	}
	for _, field := range request.Fields {
		defer clearBytes(field.Value)
	}
	event("control_request", map[string]any{"command": request.Command, "field_count": len(request.Fields)})
	output, err := control.EncodeError(code)
	if err != nil {
		return err
	}
	defer clearBytes(output)
	encrypted, err := envelope.Encrypt(output)
	if err != nil {
		return err
	}
	return wire.WriteFrame(c, encrypted, control.MaxMessage+24)
}

// loginRecord verifies the native-decodable modern login envelope and following
// IsAlive exchange after authenticated SRP. It does not create network state.
func loginRecord(c net.Conn, envelope *channel.Channel, endpoint string) error {
	record, err := wire.ReadFrame(c, control.MaxMessage+24)
	if err != nil {
		return err
	}
	plain, err := envelope.Decrypt(record)
	if err != nil {
		return err
	}
	defer clearBytes(plain)
	request, err := control.DecodeRequest(plain)
	if err != nil {
		return err
	}
	for _, field := range request.Fields {
		defer clearBytes(field.Value)
	}
	if request.Command != 20 {
		return errors.New("expected initial command 20")
	}
	login, err := control.EncodeLoginComplete(control.LoginComplete{Version: 75, Value25B: 1, EndpointsA: []string{endpoint}, EndpointsB: []string{endpoint}})
	if err != nil {
		return err
	}
	encrypted, err := envelope.Encrypt(login)
	if err != nil {
		return err
	}
	if err = wire.WriteFrame(c, encrypted, control.MaxMessage+24); err != nil {
		return err
	}
	return keepaliveRecord(c, envelope)
}

// keepaliveRecord tests one native IsAlive exchange without creating a VPN login.
func keepaliveRecord(c net.Conn, envelope *channel.Channel) error {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	nonce := binary.BigEndian.Uint64(random[:])
	record, err := envelope.Encrypt(control.EncodeIsAlive(nonce))
	if err != nil {
		return err
	}
	if err = wire.WriteFrame(c, record, 4096); err != nil {
		return err
	}
	record, err = wire.ReadFrame(c, 4096)
	if err != nil {
		return err
	}
	plain, err := envelope.Decrypt(record)
	if err != nil {
		return err
	}
	defer clearBytes(plain)
	reply, err := control.DecodeIsAliveReply(plain)
	if err != nil {
		return err
	}
	if reply != nonce {
		return errors.New("keepalive nonce mismatch")
	}
	return nil
}

func clearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
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
	postAuthEcho := flag.Bool("post-auth-echo", false, "exchange one synthetic encrypted record after SRP rekey; requires an encrypted channel")
	postAuthLogin := flag.String("post-auth-login", "", "experimental native version75 LoginComplete/IsAlive with this endpoint; no network operations")
	postAuthKeepalive := flag.Bool("post-auth-keepalive", false, "exchange one synthetic native IsAlive probe after SRP rekey; no VPN login")
	controlCode := flag.String("control-error-code", "", "decode one authenticated control request and reply with this numeric experimental error code")
	maxConnections := flag.Int("max-connections", 16, "maximum concurrent lab connections")
	once := flag.Bool("once", false, "exit after a single test connection")
	flag.Parse()
	if *rsaPath != "" && *channelPath != "" {
		return errors.New("-rsa-key and -channel-record are mutually exclusive")
	}
	if (*postAuthEcho || *postAuthKeepalive || *postAuthLogin != "" || *controlCode != "") && *rsaPath == "" && *channelPath == "" {
		return errors.New("post-auth modes require -rsa-key or -channel-record")
	}
	if (*postAuthKeepalive && (*postAuthEcho || *controlCode != "" || *postAuthLogin != "")) || (*postAuthLogin != "" && (*postAuthEcho || *controlCode != "")) {
		return errors.New("post-auth modes are mutually exclusive")
	}
	postAuth := postAuthOptions{echo: *postAuthEcho, keepalive: *postAuthKeepalive, loginEndpoint: *postAuthLogin}
	if *controlCode != "" {
		if *postAuthEcho {
			return errors.New("-control-error-code and -post-auth-echo are mutually exclusive")
		}
		value, err := strconv.ParseUint(*controlCode, 0, 32)
		if err != nil {
			return errors.New("invalid -control-error-code: expected uint32")
		}
		code := uint32(value)
		postAuth.controlCode = &code
	}
	if *maxConnections < 1 || *maxConnections > 1024 {
		return errors.New("-max-connections must be between 1 and 1024")
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveListener(ctx, listener, *maxConnections, *once, func(c net.Conn) {
		serve(c, record, encKey, decKey, rsaKey, postAuth)
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
