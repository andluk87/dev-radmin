package main

import (
	"bytes"
	"dev-radmin/internal/channel"
	"dev-radmin/internal/control"
	"dev-radmin/internal/wire"
	"net"
	"testing"
	"time"
)

func TestEchoRecord(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt"}[corrupt], func(t *testing.T) {
			key := bytes.Repeat([]byte{9}, 32)
			client, _ := channel.New(key, key)
			server, _ := channel.New(key, key)
			// Exercise nonzero CBC state in each direction before rekeying.
			for _, pair := range [][2]*channel.Channel{{client, server}, {server, client}} {
				record, _ := pair[0].Encrypt([]byte("previous authentication record"))
				if _, err := pair[1].Decrypt(record); err != nil {
					t.Fatal(err)
				}
			}
			key = bytes.Repeat([]byte{17}, 32)
			if err := client.Rekey(key, key); err != nil {
				t.Fatal(err)
			}
			if err := server.Rekey(key, key); err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(3 * time.Second))
			b.SetDeadline(time.Now().Add(3 * time.Second))
			done := make(chan error, 1)
			go func() { defer b.Close(); done <- echoRecord(b, server) }()
			plain := []byte("synthetic payload")
			record, _ := client.Encrypt(plain)
			if corrupt {
				record[0] ^= 1
			}
			if err := wire.WriteFrame(a, record, 4096); err != nil {
				t.Fatal(err)
			}
			response, err := wire.ReadFrame(a, 4096)
			if corrupt {
				if err == nil {
					t.Fatal("corrupt record received response")
				}
				if err := <-done; err == nil {
					t.Fatal("corrupt record accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.Decrypt(response)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("echo mismatch: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestControlRecord(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "native_error_reply", true: "malformed_control"}[invalid], func(t *testing.T) {
			key := bytes.Repeat([]byte{6}, 32)
			client, _ := channel.New(key, key)
			server, _ := channel.New(key, key)
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(3 * time.Second))
			b.SetDeadline(time.Now().Add(3 * time.Second))
			done := make(chan error, 1)
			go func() { defer b.Close(); done <- controlRecord(b, server, 7) }()
			raw, err := control.EncodeRequest(control.Request{Command: 20})
			if err != nil {
				t.Fatal(err)
			}
			if invalid {
				raw = append(raw, 1)
			}
			record, err := client.Encrypt(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := wire.WriteFrame(a, record, control.MaxMessage+24); err != nil {
				t.Fatal(err)
			}
			reply, err := wire.ReadFrame(a, control.MaxMessage+24)
			if invalid {
				if err == nil {
					t.Fatal("malformed request got a response")
				}
				if err := <-done; err == nil {
					t.Fatal("malformed request accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			plain, err := client.Decrypt(reply)
			expected, _ := control.EncodeError(7)
			if err != nil || !bytes.Equal(plain, expected) {
				t.Fatalf("wrong control response: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
