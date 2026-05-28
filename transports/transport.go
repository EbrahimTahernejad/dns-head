// Package transports defines a pluggable reliability layer that sits between
// the DNS-headered UDP socket and the application stream layer.
//
// Three implementations are registered:
//
//   - "quic": quic-go over the DNS-header wrapper. Modern, TLS 1.3 AEAD baked
//     in, but uses Cubic congestion control which backs off hard on lossy
//     long-RTT paths.
//
//   - "kcp": kcp-go tuned for blast mode (no FEC, no duplication, no
//     congestion control) with xtaci/smux for stream multiplexing. Same
//     reliability semantics as Xray's mKCP but with the wasteful features
//     turned off. AEAD via kcp-go's built-in AES-128.
//
//   - "raw": a small from-scratch reliable byte transport with no congestion
//     control + smux on top. AEAD via chacha20-poly1305. The lightest of the
//     three; no third-party reliability code.
package transports

import (
	"context"
	"errors"
	"io"
	"net"
)

// Stream is the per-logical-flow byte channel exposed to the cmd layer.
type Stream interface {
	io.ReadWriteCloser
}

// Conn is a single client<->server tunnel. Streams are multiplexed on it.
type Conn interface {
	OpenStream(ctx context.Context) (Stream, error)
	AcceptStream(ctx context.Context) (Stream, error)
	RemoteAddr() net.Addr
	Close() error
}

// Listener accepts incoming Conns on the server side.
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
}

// Config carries common knobs that every transport needs.
type Config struct {
	Domain string // DNS name embedded in the wire header
	PSK    string // shared secret for symmetric encryption when the transport needs one
}

// Transport is the factory for a given reliability layer.
type Transport interface {
	Name() string
	Listen(addr string, cfg Config) (Listener, error)
	Dial(ctx context.Context, serverAddr string, cfg Config) (Conn, error)
}

var registry = map[string]Transport{}

// Register adds a Transport under its name. Called from init() in each
// transport package.
func Register(t Transport) { registry[t.Name()] = t }

// Get returns the named transport.
func Get(name string) (Transport, error) {
	t, ok := registry[name]
	if !ok {
		names := make([]string, 0, len(registry))
		for n := range registry {
			names = append(names, n)
		}
		return nil, errors.New("unknown transport " + name + " (available: " + join(names) + ")")
	}
	return t, nil
}

// Names lists registered transports for help output.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
