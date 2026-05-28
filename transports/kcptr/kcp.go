// Package kcptr is the kcp-go reliability layer tuned for blast mode (no FEC,
// no duplication, no congestion control), with xtaci/smux on top for stream
// multiplexing.
package kcptr

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"github.com/ebrahimkh/dns-head/dnsheader"
	"github.com/ebrahimkh/dns-head/transports"
)

type transport struct{}

func (transport) Name() string { return "kcp" }

func init() { transports.Register(transport{}) }

// LogTunables prints all kcp/smux tunables on first use. Useful when
// experimenting with env-driven values.
func LogTunables() string {
	return "kcp[mtu=" + strconv.Itoa(KcpMtu) +
		" snd=" + strconv.Itoa(KcpSndWnd) + " rcv=" + strconv.Itoa(KcpRcvWnd) +
		" tti=" + strconv.Itoa(KcpInterval) + " resend=" + strconv.Itoa(KcpResend) +
		" nodelay=" + strconv.Itoa(KcpNoDelay) + " nc=" + strconv.Itoa(KcpNoCong) +
		" fec=" + strconv.Itoa(KcpData) + ":" + strconv.Itoa(KcpParity) +
		" sockrbuf=" + strconv.Itoa(SockReadBuf) + " sockwbuf=" + strconv.Itoa(SockWriteBuf) +
		"] smux[v=" + strconv.Itoa(SmuxVersion) +
		" stream=" + strconv.Itoa(SmuxMaxStreamBuffer) + " recv=" + strconv.Itoa(SmuxMaxReceiveBuffer) + "]"
}

// Tunables. Each is env-overridable for live experimentation without
// rebuilding (DNSH_KCP_MTU, DNSH_KCP_SNDWND, etc).
var (
	KcpMtu       = envInt("DNSH_KCP_MTU", 1250)
	KcpSndWnd    = envInt("DNSH_KCP_SNDWND", 2048)
	KcpRcvWnd    = envInt("DNSH_KCP_RCVWND", 2048)
	KcpInterval  = envInt("DNSH_KCP_TTI", 10)
	KcpResend    = envInt("DNSH_KCP_RESEND", 2)
	KcpNoDelay   = envInt("DNSH_KCP_NODELAY", 1)
	KcpNoCong    = envInt("DNSH_KCP_NC", 1)
	KcpData      = envInt("DNSH_KCP_DATASHARDS", 0)
	KcpParity    = envInt("DNSH_KCP_PARITYSHARDS", 0)
	SockReadBuf  = envInt("DNSH_KCP_SOCKRBUF", 16<<20)
	SockWriteBuf = envInt("DNSH_KCP_SOCKWBUF", 16<<20)

	SmuxMaxStreamBuffer  = envInt("DNSH_SMUX_STREAMBUF", 8<<20)
	SmuxMaxReceiveBuffer = envInt("DNSH_SMUX_RECVBUF", 64<<20)
	SmuxKeepAlive        = time.Duration(envInt("DNSH_SMUX_KEEPALIVE_S", 15)) * time.Second
	SmuxVersion          = envInt("DNSH_SMUX_VERSION", 2)
)

func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func kcpTune(s *kcp.UDPSession) {
	s.SetMtu(KcpMtu)
	s.SetWindowSize(KcpSndWnd, KcpRcvWnd)
	s.SetNoDelay(KcpNoDelay, KcpInterval, KcpResend, KcpNoCong)
	s.SetACKNoDelay(true)
	s.SetStreamMode(true)
	s.SetWriteDelay(false)
	_ = s.SetReadBuffer(SockReadBuf)
	_ = s.SetWriteBuffer(SockWriteBuf)
}

func smuxCfg() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = SmuxVersion
	c.KeepAliveInterval = SmuxKeepAlive
	c.KeepAliveTimeout = 4 * SmuxKeepAlive
	c.MaxStreamBuffer = SmuxMaxStreamBuffer
	c.MaxReceiveBuffer = SmuxMaxReceiveBuffer
	return c
}

func block(psk string) kcp.BlockCrypt {
	k := sha256.Sum256([]byte(psk))
	b, _ := kcp.NewAESBlockCrypt(k[:16]) // AES-128
	return b
}

func (t transport) Listen(addr string, cfg transports.Config) (transports.Listener, error) {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	hdr, err := dnsheader.New(cfg.Domain)
	if err != nil {
		udp.Close()
		return nil, err
	}
	pc := dnsheader.Wrap(udp, hdr)
	ln, err := kcp.ServeConn(block(cfg.PSK), KcpData, KcpParity, pc)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &listener{pc: pc, ln: ln}, nil
}

func (t transport) Dial(ctx context.Context, serverAddr string, cfg transports.Config) (transports.Conn, error) {
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
	sess, err := kcp.NewConn2(mustResolve(serverAddr), block(cfg.PSK), KcpData, KcpParity, pc)
	if err != nil {
		pc.Close()
		return nil, err
	}
	kcpTune(sess)
	mux, err := smux.Client(sess, smuxCfg())
	if err != nil {
		sess.Close()
		pc.Close()
		return nil, err
	}
	return &conn{sess: sess, mux: mux, pc: pc}, nil
}

func mustResolve(s string) *net.UDPAddr {
	a, _ := net.ResolveUDPAddr("udp", s)
	return a
}

type listener struct {
	pc net.PacketConn
	ln *kcp.Listener
}

func (l *listener) Accept(ctx context.Context) (transports.Conn, error) {
	// kcp-go's Accept blocks; honor ctx by closing the listener on cancel.
	done := make(chan struct{})
	var sess *kcp.UDPSession
	var err error
	go func() {
		sess, err = l.ln.AcceptKCP()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	kcpTune(sess)
	mux, err := smux.Server(sess, smuxCfg())
	if err != nil {
		sess.Close()
		return nil, err
	}
	return &conn{sess: sess, mux: mux}, nil
}

func (l *listener) Close() error {
	err := l.ln.Close()
	l.pc.Close()
	return err
}

type conn struct {
	sess *kcp.UDPSession
	mux  *smux.Session
	pc   net.PacketConn // only set on the dialing side; nil on accepted side (owned by listener)
}

func (c *conn) OpenStream(ctx context.Context) (transports.Stream, error) {
	return openWithCtx(ctx, c.mux.OpenStream)
}

func (c *conn) AcceptStream(ctx context.Context) (transports.Stream, error) {
	return openWithCtx(ctx, func() (*smux.Stream, error) { return c.mux.AcceptStream() })
}

func (c *conn) RemoteAddr() net.Addr { return c.sess.RemoteAddr() }

func (c *conn) Close() error {
	err := c.mux.Close()
	c.sess.Close()
	if c.pc != nil {
		c.pc.Close()
	}
	return err
}

// openWithCtx runs fn in a goroutine so context cancellation translates into
// an early return (smux itself doesn't take a context).
func openWithCtx(ctx context.Context, fn func() (*smux.Stream, error)) (transports.Stream, error) {
	type res struct {
		s   *smux.Stream
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := fn()
		ch <- res{s, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.s, nil
	}
}

var _ = errors.New
