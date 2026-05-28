// Package quictr is the QUIC reliability layer over the DNS-header wrapper.
package quictr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/ebrahimkh/dns-head/dnsheader"
	"github.com/ebrahimkh/dns-head/transports"
)

const alpn = "dnsh-quic/1"

type transport struct{}

func (transport) Name() string { return "quic" }

func init() { transports.Register(transport{}) }

func quicCfg() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIncomingStreams:             1 << 16,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     32 << 20,
	}
}

func (transport) Listen(addr string, cfg transports.Config) (transports.Listener, error) {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	hdr, err := dnsheader.New(cfg.Domain)
	if err != nil {
		udp.Close()
		return nil, err
	}
	tlsConf, err := selfSignedTLS()
	if err != nil {
		udp.Close()
		return nil, err
	}
	pc := dnsheader.Wrap(udp, hdr)
	ln, err := quic.Listen(pc, tlsConf, quicCfg())
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &listener{pc: pc, ln: ln}, nil
}

func (transport) Dial(ctx context.Context, serverAddr string, cfg transports.Config) (transports.Conn, error) {
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	hdr, err := dnsheader.New(cfg.Domain)
	if err != nil {
		udp.Close()
		return nil, err
	}
	pc := dnsheader.Wrap(udp, hdr)
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		pc.Close()
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}
	qc, err := tr.Dial(ctx, raddr, clientTLS(), quicCfg())
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &conn{qc: qc}, nil
}

type listener struct {
	pc net.PacketConn
	ln *quic.Listener
}

func (l *listener) Accept(ctx context.Context) (transports.Conn, error) {
	qc, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &conn{qc: qc}, nil
}

func (l *listener) Close() error {
	err := l.ln.Close()
	l.pc.Close()
	return err
}

type conn struct{ qc *quic.Conn }

func (c *conn) OpenStream(ctx context.Context) (transports.Stream, error) {
	s, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (c *conn) AcceptStream(ctx context.Context) (transports.Stream, error) {
	s, err := c.qc.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (c *conn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }
func (c *conn) Close() error         { return c.qc.CloseWithError(0, "bye") }

func selfSignedTLS() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: "dns-head"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func clientTLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
		MinVersion:         tls.VersionTLS13,
	}
}
