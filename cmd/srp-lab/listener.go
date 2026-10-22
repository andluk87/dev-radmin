package main

import (
	"context"
	"errors"
	"net"
	"sync"
)

// serveListener owns listener and accepted connections. Handlers must return when
// their connection closes. Cancellation closes both the listener and connections
// before waiting for handlers, including the synchronous single-connection mode.
func serveListener(ctx context.Context, listener net.Listener, maxConnections int, once bool, handle func(net.Conn)) error {
	if maxConnections < 1 {
		return errors.New("max connections must be positive")
	}
	if handle == nil {
		return errors.New("connection handler is required")
	}
	runCtx, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-runCtx.Done()
		_ = listener.Close()
		mu.Lock()
		connections := make([]net.Conn, 0, len(active))
		for connection := range active {
			connections = append(connections, connection)
		}
		mu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	defer func() {
		cancel()
		<-stopped
		workers.Wait()
	}()

	run := func(connection net.Conn) {
		defer workers.Done()
		defer func() {
			_ = connection.Close()
			mu.Lock()
			delete(active, connection)
			mu.Unlock()
		}()
		handle(connection)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return err
		}
		mu.Lock()
		if runCtx.Err() != nil || len(active) >= maxConnections {
			mu.Unlock()
			_ = connection.Close()
			if runCtx.Err() != nil {
				return nil
			}
			continue
		}
		active[connection] = struct{}{}
		workers.Add(1)
		mu.Unlock()
		if once {
			run(connection)
			return nil
		}
		go run(connection)
	}
}
