// dns-head-server accepts connections over a DNS-headered UDP socket and
// dials targets requested per stream by clients. The reliability layer is
// pluggable via -transport.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
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

func main() {
	var (
		listen    = flag.String("listen", ":443", "UDP listen address")
		domain    = flag.String("domain", "www.example.com", "DNS name used in the header (must match client)")
		psk       = flag.String("psk", "", "shared secret (required, must match client)")
		transport = flag.String("transport", "skcp", "reliability layer: "+strings.Join(transports.Names(), ","))
	)
	flag.Parse()

	if *psk == "" {
		fmt.Fprintln(os.Stderr, "error: -psk is required")
		os.Exit(2)
	}

	tr, err := transports.Get(*transport)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	cfg := transports.Config{Domain: *domain, PSK: *psk}
	ln, err := tr.Listen(*listen, cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	log.Printf("dns-head-server[%s]: listening on udp/%s (domain=%q)", tr.Name(), *listen, *domain)
	if tr.Name() == "kcp" {
		log.Printf("kcp tunables: %s", kcptr.LogTunables())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		<-sigc
		log.Printf("dns-head-server: shutting down")
		cancel()
		ln.Close()
	}()

	for {
		c, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go serveConn(ctx, c, cfg.PSK)
	}
}

func serveConn(ctx context.Context, c transports.Conn, psk string) {
	remote := c.RemoteAddr()
	log.Printf("conn open from %s", remote)
	defer log.Printf("conn close from %s", remote)
	defer c.Close()

	for {
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		go serveStream(s, psk, remote)
	}
}

type deadliner interface {
	SetReadDeadline(time.Time) error
}

func serveStream(s transports.Stream, psk string, peer net.Addr) {
	if d, ok := s.(deadliner); ok {
		_ = d.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	got, target, err := tunnel.ReadHello(s)
	if d, ok := s.(deadliner); ok {
		_ = d.SetReadDeadline(time.Time{})
	}
	if err != nil {
		log.Printf("[%s] hello: %v", peer, err)
		_ = s.Close()
		return
	}
	if !tunnel.AuthOK(got, psk) {
		log.Printf("[%s] bad psk", peer)
		_ = s.Close()
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := net.Dialer{}
	tc, err := d.DialContext(dialCtx, "tcp", target.String())
	if err != nil {
		log.Printf("[%s] dial %s: %v", peer, target, err)
		_ = s.Close()
		return
	}
	defer tc.Close()
	log.Printf("[%s] -> %s", peer, target)

	pipe(s, tc)
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
