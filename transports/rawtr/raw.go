// Package rawtr is a from-scratch reliable byte transport with no congestion
// control plus xtaci/smux for stream multiplexing. AEAD is chacha20-poly1305
// keyed off the PSK via HKDF-SHA256. Designed for paths where Cubic-style
// backoff (as in QUIC) kills throughput.
package rawtr

import (
	"context"
	"crypto/cipher"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/ebrahimkh/dns-head/dnsheader"
	"github.com/ebrahimkh/dns-head/transports"
)

type transport struct{}

func (transport) Name() string { return "raw" }

func init() { transports.Register(transport{}) }

func smuxCfg() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveInterval = 15 * time.Second
	c.KeepAliveTimeout = 60 * time.Second
	c.MaxStreamBuffer = 4 << 20
	c.MaxReceiveBuffer = 32 << 20
	return c
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
	aead, err := newAEAD(cfg.PSK)
	if err != nil {
		udp.Close()
		return nil, err
	}
	pc := dnsheader.Wrap(udp, hdr)
	l := &listener{
		pc:       pc,
		aead:     aead,
		accept:   make(chan transports.Conn, 16),
		sessions: make(map[string]*session),
		closed:   make(chan struct{}),
	}
	go l.demuxLoop()
	return l, nil
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
	aead, err := newAEAD(cfg.PSK)
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

	sess := newSession(pc, raddr, aead, make(chan []byte, 4096))
	// Client read loop dispatches incoming packets straight to its single session.
	go clientReadLoop(pc, aead, sess)

	muxCh := make(chan smuxResult, 1)
	go func() {
		mux, err := smux.Client(sess, smuxCfg())
		muxCh <- smuxResult{mux, err}
	}()
	select {
	case <-ctx.Done():
		sess.Close()
		pc.Close()
		return nil, ctx.Err()
	case r := <-muxCh:
		if r.err != nil {
			sess.Close()
			pc.Close()
			return nil, r.err
		}
		return &conn{sess: sess, mux: r.mux, ownsPC: true, pc: pc}, nil
	}
}

type smuxResult struct {
	mux *smux.Session
	err error
}

type listener struct {
	pc       net.PacketConn
	aead     cipher.AEAD
	accept   chan transports.Conn
	sessions map[string]*session
	sessMu   sync.Mutex
	closed   chan struct{}
	closeOnce sync.Once
}

func (l *listener) Accept(ctx context.Context) (transports.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, errors.New("rawtr: listener closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.sessMu.Lock()
		for _, s := range l.sessions {
			s.Close()
		}
		l.sessMu.Unlock()
		l.pc.Close()
	})
	return nil
}

func (l *listener) demuxLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-l.closed:
			return
		default:
		}
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
				continue
			}
		}
		body, err := open(l.aead, buf[:n])
		if err != nil {
			// either not for us or a bad/replayed frame — silently drop
			continue
		}

		key := addr.String()
		l.sessMu.Lock()
		sess, ok := l.sessions[key]
		if !ok {
			sess = newSession(l.pc, addr, l.aead, make(chan []byte, 4096))
			l.sessions[key] = sess
			l.sessMu.Unlock()
			go l.spawnAccepted(sess)
		} else {
			l.sessMu.Unlock()
		}
		sess.dispatchFrame(body)
	}
}

func (l *listener) spawnAccepted(sess *session) {
	mux, err := smux.Server(sess, smuxCfg())
	if err != nil {
		sess.Close()
		return
	}
	c := &conn{sess: sess, mux: mux}
	select {
	case l.accept <- c:
	case <-l.closed:
		mux.Close()
		sess.Close()
	}
}

// clientReadLoop is used on the dialing side where we own the UDP socket and
// only ever talk to one server.
func clientReadLoop(pc net.PacketConn, aead cipher.AEAD, sess *session) {
	buf := make([]byte, 65536)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			sess.Close()
			return
		}
		body, err := open(aead, buf[:n])
		if err != nil {
			continue
		}
		sess.dispatchFrame(body)
	}
}

type conn struct {
	sess   *session
	mux    *smux.Session
	ownsPC bool
	pc     net.PacketConn
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
	if c.ownsPC && c.pc != nil {
		c.pc.Close()
	}
	return err
}

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
