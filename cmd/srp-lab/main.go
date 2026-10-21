// srp-lab serves inner helper messages for interoperability experiments.
// It is not a Radmin VPN server and does not accept the captured outer handshake.
package main

import (
	"dev-radmin/internal/srp"
	"dev-radmin/internal/wire"
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

func serve(c net.Conn, record srp.Record) {
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
	for i := 0; i < 3; i++ {
		input, err := wire.ReadFrame(c, 4096)
		if err != nil {
			event("read_error", nil)
			return
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

func run() error {
	listen := flag.String("listen", "127.0.0.1:17302", "lab listener; no complete Radmin compatibility")
	path := flag.String("record", "", "JSON credential record (user_id, salt_hex, verifier_hex)")
	once := flag.Bool("once", false, "exit after a single test connection")
	flag.Parse()
	if *path == "" {
		return errors.New("-record is required; no default account exists")
	}
	f, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return errors.New("credential record must be a regular file of at most 4096 bytes")
	}
	var cfg struct {
		UserID   uint64 `json:"user_id"`
		Salt     string `json:"salt_hex"`
		Verifier string `json:"verifier_hex"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, 4097))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cfg); err != nil {
		return errors.New("invalid credential JSON")
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing credential JSON")
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
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	event("listening", map[string]any{"address": listener.Addr().String()})
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		serve(c, record)
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
