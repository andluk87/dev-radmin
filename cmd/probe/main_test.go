package main

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestTCPFragmentedPrefixAndLimit(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	var out bytes.Buffer
	o := &observer{out: &out}
	done := make(chan struct{})
	go func() { o.tcp(server, 4, time.Second); close(done) }()
	if _, err := client.Write([]byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{3, 4}); err != nil {
		t.Fatal(err)
	}
	<-done
	var e observation
	if err := json.Unmarshal(out.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Prefix != "01020304" || e.Bytes != 4 || e.ReadResult != "prefix_limit" {
		t.Fatalf("unexpected observation: %+v", e)
	}
	if o.connections.Load() != 1 {
		t.Fatal("connection not counted")
	}
}

func TestTCPTimeoutRetainsPartialInput(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	var out bytes.Buffer
	o := &observer{out: &out}
	done := make(chan struct{})
	go func() { o.tcp(server, 64, 50*time.Millisecond); close(done) }()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader did not time out")
	}
	var e observation
	if err := json.Unmarshal(out.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Bytes != 5 || e.ReadResult != "timeout" || e.Prefix != "68656c6c6f" {
		t.Fatalf("unexpected observation: %+v", e)
	}
}

func TestTCPEOFIsNotAnEmptySuccessfulHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	o := &observer{out: &out}
	done := make(chan struct{})
	go func() { o.tcp(server, 64, time.Second); close(done) }()
	_ = client.Close()
	<-done
	var e observation
	if err := json.Unmarshal(out.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Bytes != 0 || e.ReadResult != "eof" {
		t.Fatalf("unexpected observation: %+v", e)
	}
}
