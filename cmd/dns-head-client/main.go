// dns-head-client opens a tunnel to a dns-head-server over a DNS-headered
// UDP socket and exposes one or both of:
//   - a local SOCKS5 listener (-socks 127.0.0.1:1080), and/or
//   - a set of TCP port-forwards (-forward :8080=example.com:80, repeatable)
// Each accepted local connection opens a new multiplexed stream over the
// tunnel; the server side dials whichever target was named in the per-stream
// hello.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ebrahimkh/dns-head/transports"
	"github.com/ebrahimkh/dns-head/transports/kcptr"
	_ "github.com/ebrahimkh/dns-head/transports/quictr"
	_ "github.com/ebrahimkh/dns-head/transports/rawtr"
	_ "github.com/ebrahimkh/dns-head/transports/skcptr"
	_ "github.com/ebrahimkh/dns-head/transports/srawtr"
	"github.com/ebrahimkh/dns-head/tunnel"
)

// forwardList is a repeatable -forward flag: each value is "local=remote",
// e.g. ":8080=example.com:80".
type forwardList []forwardSpec
type forwardSpec struct{ local, remote string }

func (f *forwardList) String() string { return fmt.Sprintf("%v", *f) }
func (f *forwardList) Set(v string) error {
	eq := strings.IndexByte(v, '=')
	if eq < 0 {
		return fmt.Errorf("bad -forward %q: want LOCAL=REMOTE (e.g. :8080=example.com:80)", v)
	}
	*f = append(*f, forwardSpec{local: v[:eq], remote: v[eq+1:]})
	return nil
}

func main() {
	var forwards forwardList
	var (
		server    = flag.String("server", "", "server address host:port")
		socks     = flag.String("socks", "", "local SOCKS5 listen address (empty disables SOCKS5)")
		domain    = flag.String("domain", "www.example.com", "DNS name used in the header (must match server)")
		psk       = flag.String("psk", "", "shared secret (required, must match server)")
		transport = flag.String("transport", "skcp", "reliability layer: "+strings.Join(transports.Names(), ","))
	)
	flag.Var(&forwards, "forward", "TCP port-forward LOCAL=REMOTE (repeatable, e.g. :8080=example.com:80)")
	flag.Parse()

	if *server == "" || *psk == "" {
		fmt.Fprintln(os.Stderr, "error: -server and -psk are required")
		os.Exit(2)
	}
	if *socks == "" && len(forwards) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one of -socks or -forward is required")
		os.Exit(2)
	}
	tr, err := transports.Get(*transport)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	cfg := transports.Config{Domain: *domain, PSK: *psk}
	rc := &reconnectingClient{server: *server, cfg: cfg, tr: tr}
	if err := rc.ensure(context.Background()); err != nil {
		log.Fatalf("dial: %v", err)
	}

	if tr.Name() == "kcp" {
		log.Printf("kcp tunables: %s", kcptr.LogTunables())
	}

	var listeners []net.Listener
	closeAll := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}

	if *socks != "" {
		ln, err := net.Listen("tcp", *socks)
		if err != nil {
			log.Fatalf("socks listen: %v", err)
		}
		listeners = append(listeners, ln)
		log.Printf("dns-head-client[%s]: SOCKS5 on %s -> %s (domain=%q)", tr.Name(), *socks, *server, *domain)
		go acceptLoop(ln, func(c net.Conn) { handleSocks(c, rc) })
	}

	for _, fwd := range forwards {
		ln, err := net.Listen("tcp", fwd.local)
		if err != nil {
			log.Fatalf("forward listen %s: %v", fwd.local, err)
		}
		listeners = append(listeners, ln)
		target, err := parseTarget(fwd.remote)
		if err != nil {
			log.Fatalf("bad -forward target %q: %v", fwd.remote, err)
		}
		log.Printf("dns-head-client[%s]: forward %s -> %s via %s", tr.Name(), fwd.local, fwd.remote, *server)
		go acceptLoop(ln, func(c net.Conn) { handleForward(c, rc, target) })
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	closeAll()
}

func acceptLoop(ln net.Listener, handler func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handler(c)
	}
}

func parseTarget(hostport string) (tunnel.Target, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return tunnel.Target{}, err
	}
	p, err := strconvAtoi16(port)
	if err != nil {
		return tunnel.Target{}, fmt.Errorf("port: %w", err)
	}
	return tunnel.Target{Host: host, Port: p}, nil
}

func strconvAtoi16(s string) (uint16, error) {
	var v uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		v = v*10 + uint32(c-'0')
		if v > 65535 {
			return 0, fmt.Errorf("port out of range: %q", s)
		}
	}
	return uint16(v), nil
}

// handleForward implements TCP port-forwarding: every accepted local conn
// opens a tunnel stream to the fixed remote target.
func handleForward(c net.Conn, rc *reconnectingClient, target tunnel.Target) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	s, err := rc.open(ctx, target)
	cancel()
	if err != nil {
		log.Printf("tunnel open %s: %v", target, err)
		return
	}
	defer s.Close()
	pipe(s, c)
}

type reconnectingClient struct {
	mu     sync.Mutex
	server string
	cfg    transports.Config
	tr     transports.Transport
	cur    transports.Conn
}

func (r *reconnectingClient) ensure(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil {
		return nil
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := r.tr.Dial(dctx, r.server, r.cfg)
	if err != nil {
		return err
	}
	r.cur = c
	return nil
}

func (r *reconnectingClient) open(ctx context.Context, t tunnel.Target) (transports.Stream, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := r.ensure(ctx); err != nil {
			return nil, err
		}
		r.mu.Lock()
		cur := r.cur
		r.mu.Unlock()
		s, err := cur.OpenStream(ctx)
		if err == nil {
			if err := tunnel.WriteHello(s, r.cfg.PSK, t); err != nil {
				s.Close()
				return nil, err
			}
			return s, nil
		}
		log.Printf("open stream failed (attempt %d): %v", attempt+1, err)
		r.mu.Lock()
		if r.cur == cur {
			_ = r.cur.Close()
			r.cur = nil
		}
		r.mu.Unlock()
	}
	return nil, errors.New("tunnel unavailable")
}

// --- minimal SOCKS5 (CONNECT, no auth) ---

func handleSocks(c net.Conn, rc *reconnectingClient) {
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	target, err := socksHandshake(c)
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		log.Printf("socks: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	s, err := rc.open(ctx, target)
	cancel()
	if err != nil {
		log.Printf("tunnel open %s: %v", target, err)
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer s.Close()

	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	pipe(s, c)
}

func socksHandshake(c net.Conn) (tunnel.Target, error) {
	var t tunnel.Target
	hdr, err := readN(c, 2)
	if err != nil {
		return t, err
	}
	if hdr[0] != 0x05 {
		return t, fmt.Errorf("bad socks version 0x%x", hdr[0])
	}
	if _, err := readN(c, int(hdr[1])); err != nil {
		return t, err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return t, err
	}
	req, err := readN(c, 4)
	if err != nil {
		return t, err
	}
	if req[0] != 0x05 {
		return t, fmt.Errorf("bad socks version 0x%x", req[0])
	}
	if req[1] != 0x01 {
		return t, fmt.Errorf("unsupported socks command 0x%x", req[1])
	}
	switch req[3] {
	case 0x01:
		b, err := readN(c, 4)
		if err != nil {
			return t, err
		}
		t.Host = net.IP(b).String()
	case 0x04:
		b, err := readN(c, 16)
		if err != nil {
			return t, err
		}
		t.Host = net.IP(b).String()
	case 0x03:
		l, err := readN(c, 1)
		if err != nil {
			return t, err
		}
		name, err := readN(c, int(l[0]))
		if err != nil {
			return t, err
		}
		t.Host = string(name)
	default:
		return t, fmt.Errorf("bad ATYP 0x%x", req[3])
	}
	p, err := readN(c, 2)
	if err != nil {
		return t, err
	}
	t.Port = binary.BigEndian.Uint16(p)
	return t, nil
}

func readN(c net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(c, buf)
	return buf, err
}

func pipe(a transports.Stream, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		_ = a.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}
