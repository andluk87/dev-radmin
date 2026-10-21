// probe observes connections from an explicitly configured test client.
// It does not implement the Radmin VPN protocol or forward VPN traffic.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type observation struct {
	Time       string `json:"time"`
	Transport  string `json:"transport"`
	Peer       string `json:"peer"`
	Bytes      int    `json:"bytes_observed"`
	Prefix     string `json:"prefix_hex"`
	SHA256     string `json:"sha256_observed_bytes"`
	ReadResult string `json:"read_result"`
}

type observer struct {
	mu          sync.Mutex
	out         io.Writer
	connections atomic.Uint64
	packets     atomic.Uint64
}

func (o *observer) record(transport, peer string, b []byte, result string) {
	digest := sha256.Sum256(b)
	e := observation{time.Now().UTC().Format(time.RFC3339Nano), transport, peer,
		len(b), hex.EncodeToString(b), hex.EncodeToString(digest[:]), result}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := json.NewEncoder(o.out).Encode(e); err != nil {
		log.Printf("write observation: %v", err)
	}
}

func (o *observer) tcp(c net.Conn, limit int, timeout time.Duration) {
	defer c.Close()
	o.connections.Add(1)
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return
	}
	b := make([]byte, limit)
	n, err := io.ReadFull(c, b)
	result := "prefix_limit"
	if err != nil {
		switch {
		case os.IsTimeout(err):
			result = "timeout"
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			result = "eof"
		default:
			result = "read_error"
		}
	}
	o.record("tcp", c.RemoteAddr().String(), b[:n], result)
}

func main() {
	listen := flag.String("listen", ":4899", "TCP and UDP observation address (chosen test port, not a recovered protocol default)")
	health := flag.String("health", "127.0.0.1:8080", "HTTP health address")
	limit := flag.Int("prefix-bytes", 64, "maximum observed bytes per connection/datagram (1..4096)")
	timeout := flag.Duration("read-timeout", 3*time.Second, "maximum time to collect a TCP prefix")
	check := flag.Bool("healthcheck", false, "check the configured HTTP health endpoint and exit")
	flag.Parse()
	if *check {
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://" + *health + "/healthz")
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("health status: %d", resp.StatusCode)
		}
		return
	}
	if *limit < 1 || *limit > 4096 || *timeout <= 0 || *timeout > time.Minute {
		log.Fatal("invalid capture limit or timeout")
	}
	tcp, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	hl, err := net.Listen("tcp", *health)
	if err != nil {
		log.Fatal(err)
	}
	defer hl.Close()
	o := &observer{out: os.Stdout}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"service": "radmin-protocol-probe", "vpn_ready": false,
			"tcp_connections": o.connections.Load(), "udp_datagrams": o.packets.Load()})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second, WriteTimeout: 2 * time.Second}
	go func() {
		if err := srv.Serve(hl); err != nil && err != http.ErrServerClosed {
			log.Printf("health server: %v", err)
		}
	}()
	go func() {
		buf := make([]byte, *limit+1)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			o.packets.Add(1)
			result := "datagram"
			if n > *limit {
				n = *limit
				result = "truncated_datagram"
			}
			o.record("udp", peer.String(), buf[:n], result)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = tcp.Close(); _ = udp.Close() }()
	log.Printf("diagnostic listener tcp+udp=%s health=%s; does not authenticate clients or provide VPN", tcp.Addr(), hl.Addr())
	slots := make(chan struct{}, 16)
	var handlers sync.WaitGroup
	for {
		c, err := tcp.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("accept: %v", err)
			}
			break
		}
		select {
		case slots <- struct{}{}:
			handlers.Add(1)
			go func() { defer handlers.Done(); defer func() { <-slots }(); o.tcp(c, *limit, *timeout) }()
		default:
			_ = c.Close()
		}
	}
	handlers.Wait()
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	fmt.Fprintln(os.Stderr, "probe stopped")
}
