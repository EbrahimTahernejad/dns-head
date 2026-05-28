package dnsheader

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestHeaderParsesAsDNSQuery decodes the bytes a Header writes and verifies
// they form a syntactically valid DNS query for the configured domain. If
// this test passes, an on-path observer running `tcpdump -nn 'port 53'`-style
// DNS parsing will see what looks like a real DNS query.
func TestHeaderParsesAsDNSQuery(t *testing.T) {
	const domain = "www.cloudflare.com"
	h, err := New(domain)
	if err != nil {
		t.Fatal(err)
	}
	if h.Size() < 12 {
		t.Fatalf("header too short: %d", h.Size())
	}

	// Stamp twice — txid must differ but the rest must match.
	a := make([]byte, h.Size())
	b := make([]byte, h.Size())
	h.stamp(a)
	h.stamp(b)
	if bytes.Equal(a[:2], b[:2]) {
		// Could collide by chance but probability is ~1/65536 — re-stamp once.
		h.stamp(b)
	}
	if bytes.Equal(a[:2], b[:2]) {
		t.Errorf("txid not randomized: %x vs %x", a[:2], b[:2])
	}
	if !bytes.Equal(a[2:], b[2:]) {
		t.Errorf("non-txid bytes drifted between stamps")
	}

	// Validate fixed DNS-header fields after the txid.
	flags := binary.BigEndian.Uint16(a[2:4])
	if flags != 0x0100 {
		t.Errorf("flags = 0x%04x, want 0x0100", flags)
	}
	if got := binary.BigEndian.Uint16(a[4:6]); got != 1 {
		t.Errorf("qdcount = %d, want 1", got)
	}
	for _, off := range []int{6, 8, 10} { // ANCOUNT, NSCOUNT, ARCOUNT
		if got := binary.BigEndian.Uint16(a[off : off+2]); got != 0 {
			t.Errorf("count at %d = %d, want 0", off, got)
		}
	}

	// Walk the QNAME labels.
	off := 12
	var labels []string
	for off < len(a) {
		l := int(a[off])
		if l == 0 {
			off++
			break
		}
		off++
		if off+l > len(a) {
			t.Fatalf("label overruns buffer")
		}
		labels = append(labels, string(a[off:off+l]))
		off += l
	}
	got := joinDots(labels)
	if got != domain {
		t.Errorf("qname = %q, want %q", got, domain)
	}
	if off+4 != len(a) {
		t.Fatalf("trailing bytes wrong: off=%d len=%d", off, len(a))
	}
	if qtype := binary.BigEndian.Uint16(a[off : off+2]); qtype != 1 {
		t.Errorf("qtype = %d, want 1 (A)", qtype)
	}
	if qclass := binary.BigEndian.Uint16(a[off+2 : off+4]); qclass != 1 {
		t.Errorf("qclass = %d, want 1 (IN)", qclass)
	}
}

func joinDots(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "."
		}
		out += p
	}
	return out
}
