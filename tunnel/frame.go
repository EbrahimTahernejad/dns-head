package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Stream framing for dns-head.
//
// Each new QUIC stream opened by the client starts with:
//
//   [1 byte  PSK length L][L bytes PSK]
//   [1 byte  ATYP][address bytes][2 bytes port BE]
//
// where ATYP follows SOCKS5 semantics:
//   1 = IPv4 (4 bytes)
//   3 = domain name, 1-byte length prefix + name
//   4 = IPv6 (16 bytes)
//
// After this header the stream is a raw bidirectional byte pipe between the
// client-side caller and the server-side dial target.

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	maxPSKLen = 255
)

// Target is a destination host:port the client asks the server to dial.
type Target struct {
	Host string // either an IP literal or a domain name
	Port uint16
}

// String renders as "host:port" for logging.
func (t Target) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port))) }

// WriteHello writes the PSK and target header to w. The server reads them in
// the same order.
func WriteHello(w io.Writer, psk string, t Target) error {
	if len(psk) > maxPSKLen {
		return errors.New("tunnel: psk too long")
	}
	buf := []byte{byte(len(psk))}
	buf = append(buf, psk...)

	if ip := net.ParseIP(t.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, atypIPv4)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, atypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(t.Host) == 0 || len(t.Host) > 255 {
			return fmt.Errorf("tunnel: bad host length %d", len(t.Host))
		}
		buf = append(buf, atypDomain, byte(len(t.Host)))
		buf = append(buf, t.Host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], t.Port)
	buf = append(buf, port[:]...)
	_, err := w.Write(buf)
	return err
}

// ReadHello reads the PSK and target header from r. It returns the offered PSK
// and target; the caller is responsible for comparing the PSK to the expected
// value.
func ReadHello(r io.Reader) (psk string, t Target, err error) {
	var one [1]byte
	if _, err = io.ReadFull(r, one[:]); err != nil {
		return
	}
	plen := int(one[0])
	if plen > 0 {
		pbuf := make([]byte, plen)
		if _, err = io.ReadFull(r, pbuf); err != nil {
			return
		}
		psk = string(pbuf)
	}

	if _, err = io.ReadFull(r, one[:]); err != nil {
		return
	}
	switch one[0] {
	case atypIPv4:
		var ip [4]byte
		if _, err = io.ReadFull(r, ip[:]); err != nil {
			return
		}
		t.Host = net.IP(ip[:]).String()
	case atypIPv6:
		var ip [16]byte
		if _, err = io.ReadFull(r, ip[:]); err != nil {
			return
		}
		t.Host = net.IP(ip[:]).String()
	case atypDomain:
		if _, err = io.ReadFull(r, one[:]); err != nil {
			return
		}
		name := make([]byte, one[0])
		if _, err = io.ReadFull(r, name); err != nil {
			return
		}
		t.Host = string(name)
	default:
		err = fmt.Errorf("tunnel: unknown ATYP %d", one[0])
		return
	}

	var port [2]byte
	if _, err = io.ReadFull(r, port[:]); err != nil {
		return
	}
	t.Port = binary.BigEndian.Uint16(port[:])
	return
}

// AuthOK returns true if got == want in constant time.
func AuthOK(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	var v byte
	for i := 0; i < len(got); i++ {
		v |= got[i] ^ want[i]
	}
	return v == 0
}
