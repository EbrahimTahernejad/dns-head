// Package dnsheader prepends a fixed DNS-query header to every outgoing UDP
// datagram and strips it on read, so an on-path observer sees what looks like
// a stream of DNS queries to a single domain. The 2-byte transaction ID at the
// start of the header is randomized per packet; everything else is fixed.
//
// The header format is byte-for-byte compatible with Xray-core's
// transport/internet/headers/dns header, so traffic generated here is
// indistinguishable on the wire from an mKCP+dns-header tunnel.
package dnsheader

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// Header is an immutable, pre-built DNS-query template for a given domain.
type Header struct {
	tmpl []byte
}

// New builds a DNS query for domain (A / IN). The same instance can be reused
// from many goroutines.
func New(domain string) (*Header, error) {
	if domain == "" {
		return nil, errors.New("dnsheader: empty domain")
	}
	var h []byte
	h = binary.BigEndian.AppendUint16(h, 0x0000) // Transaction ID (randomized per packet)
	h = binary.BigEndian.AppendUint16(h, 0x0100) // Flags: standard query, RD=1
	h = binary.BigEndian.AppendUint16(h, 0x0001) // Questions: 1
	h = binary.BigEndian.AppendUint16(h, 0x0000) // Answer RRs
	h = binary.BigEndian.AppendUint16(h, 0x0000) // Authority RRs
	h = binary.BigEndian.AppendUint16(h, 0x0000) // Additional RRs

	qname, err := packDomain(domain)
	if err != nil {
		return nil, err
	}
	h = append(h, qname...)
	h = binary.BigEndian.AppendUint16(h, 0x0001) // QTYPE A
	h = binary.BigEndian.AppendUint16(h, 0x0001) // QCLASS IN
	return &Header{tmpl: h}, nil
}

// Size returns the header length in bytes.
func (h *Header) Size() int { return len(h.tmpl) }

// stamp writes a fresh header into dst (which must be >= Size() bytes).
func (h *Header) stamp(dst []byte) {
	copy(dst, h.tmpl)
	var txid [2]byte
	_, _ = rand.Read(txid[:])
	dst[0] = txid[0]
	dst[1] = txid[1]
}

// packDomain encodes "example.com" as DNS labels: 7example3com0.
func packDomain(name string) ([]byte, error) {
	if name[len(name)-1] != '.' {
		name = name + "."
	}
	out := make([]byte, 0, len(name)+1)
	begin := 0
	for i := 0; i < len(name); i++ {
		if name[i] != '.' {
			continue
		}
		ll := i - begin
		if ll == 0 || ll >= 64 {
			return nil, fmt.Errorf("dnsheader: bad label length %d", ll)
		}
		out = append(out, byte(ll))
		out = append(out, name[begin:i]...)
		begin = i + 1
	}
	out = append(out, 0)
	return out, nil
}

// PacketConn wraps an underlying net.PacketConn and transparently prepends
// the DNS header on writes and strips it on reads. It satisfies
// net.PacketConn so it can be handed directly to quic-go.
type PacketConn struct {
	inner net.PacketConn
	hdr   *Header
	bat   *batcher // nil unless batched send is enabled
}

// Wrap returns a PacketConn that adds the DNS header to inner. When the
// inner conn is a *net.UDPConn and batching is enabled (default on Linux),
// outgoing writes are coalesced into sendmmsg batches.
func Wrap(inner net.PacketConn, h *Header) *PacketConn {
	pc := &PacketConn{inner: inner, hdr: h}
	if batchEnabled {
		if udp, ok := inner.(*net.UDPConn); ok {
			pc.bat = newBatcher(udp)
		}
	}
	return pc
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// Read into a temporary buffer large enough for header + payload. We could
	// read directly into p with an offset, but quic-go expects the returned n
	// to match the payload length, so we stage and copy.
	hsz := c.hdr.Size()
	buf := make([]byte, hsz+len(p))
	n, addr, err := c.inner.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n < hsz {
		// Garbage / too short — surface as a benign empty read so callers retry.
		return 0, addr, nil
	}
	payload := buf[hsz:n]
	copied := copy(p, payload)
	return copied, addr, nil
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	hsz := c.hdr.Size()
	out := make([]byte, hsz+len(p))
	c.hdr.stamp(out[:hsz])
	copy(out[hsz:], p)
	if c.bat != nil {
		c.bat.enqueue(out, addr)
		return len(p), nil
	}
	n, err := c.inner.WriteTo(out, addr)
	if n < hsz {
		return 0, err
	}
	return n - hsz, err
}

func (c *PacketConn) Close() error {
	if c.bat != nil {
		c.bat.close()
	}
	return c.inner.Close()
}
func (c *PacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *PacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *PacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *PacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// SetReadBuffer / SetWriteBuffer / SyscallConn pass through so quic-go can
// apply its socket-buffer tuning and GSO/GRO optimizations on the underlying
// UDP socket through our wrapper.

type bufSetter interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func (c *PacketConn) SetReadBuffer(n int) error {
	if s, ok := c.inner.(bufSetter); ok {
		return s.SetReadBuffer(n)
	}
	return nil
}

func (c *PacketConn) SetWriteBuffer(n int) error {
	if s, ok := c.inner.(bufSetter); ok {
		return s.SetWriteBuffer(n)
	}
	return nil
}

type syscaller interface {
	SyscallConn() (syscall.RawConn, error)
}

func (c *PacketConn) SyscallConn() (syscall.RawConn, error) {
	if s, ok := c.inner.(syscaller); ok {
		return s.SyscallConn()
	}
	return nil, errors.New("dnsheader: underlying conn does not support SyscallConn")
}
