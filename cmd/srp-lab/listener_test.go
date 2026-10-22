package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func testListener(t *testing.T, max int, once bool, handle func(net.Conn)) (net.Listener, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveListener(ctx, listener, max, once, handle) }()
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = listener.Close() })
	return listener, cancel, done
}

func dialListener(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return connection
}

func listenerResult(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not stop")
	}
}

func TestListenerConcurrentAndCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	finished := make(chan struct{}, 2)
	listener, cancel, done := testListener(t, 2, false, func(connection net.Conn) {
		started <- struct{}{}
		defer func() { finished <- struct{}{} }()
		var message [1]byte
		if _, err := io.ReadFull(connection, message[:]); err == nil {
			_, _ = connection.Write(message[:])
		}
	})
	slow := dialListener(t, listener)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first client did not start")
	}
	fast := dialListener(t, listener)
	if _, err := fast.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err := io.ReadFull(fast, response[:]); err != nil || response[0] != 42 {
		t.Fatalf("second client blocked by first: %v", err)
	}
	cancel()
	listenerResult(t, done)
	if _, err := slow.Read(response[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("active connection was not closed: %v", err)
	}
	if len(finished) != 2 {
		t.Fatal("serveListener returned before its handlers")
	}
}

func TestListenerConnectionLimit(t *testing.T) {
	started := make(chan struct{}, 3)
	listener, cancel, done := testListener(t, 1, false, func(connection net.Conn) {
		started <- struct{}{}
		var message [1]byte
		_, _ = connection.Read(message[:])
	})
	_ = dialListener(t, listener)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first client did not start")
	}
	rejected := dialListener(t, listener)
	var response [1]byte
	if _, err := rejected.Read(response[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("excess connection was not closed: %v", err)
	}
	if len(started) != 0 {
		t.Fatal("excess client entered handler")
	}
	cancel()
	listenerResult(t, done)
}

func TestListenerOnce(t *testing.T) {
	started := make(chan struct{}, 2)
	listener, _, done := testListener(t, 4, true, func(connection net.Conn) {
		started <- struct{}{}
		var message [1]byte
		_, _ = connection.Read(message[:])
	})
	first := dialListener(t, listener)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first client did not start")
	}
	// A second connection can queue in the OS backlog, but must never be handled.
	second := dialListener(t, listener)
	_ = first.Close()
	listenerResult(t, done)
	if len(started) != 0 {
		t.Fatal("once mode handled another client")
	}
	var response [1]byte
	if _, err := second.Read(response[:]); err == nil {
		t.Fatal("listener left queued connection open")
	}
}

func TestListenerOnceCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	listener, cancel, done := testListener(t, 1, true, func(connection net.Conn) {
		started <- struct{}{}
		var message [1]byte
		_, _ = connection.Read(message[:])
	})
	_ = dialListener(t, listener)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("client did not start")
	}
	cancel()
	listenerResult(t, done)
}

func TestListenerCancellationWithoutClients(t *testing.T) {
	_, cancel, done := testListener(t, 1, false, func(net.Conn) {
		t.Error("unexpected client")
	})
	cancel()
	listenerResult(t, done)
}
