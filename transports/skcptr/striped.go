// Package skcptr is "striped KCP": opens N parallel KCP+smux sessions
// (each on its own UDP source port) and stripes byte chunks of a single
// logical stream round-robin across them, then reassembles in order on the
// peer. Real bandwidth aggregation for a single TCP connection on links
// where one KCP flow is capped (per-flow shaping, tail-drop on a single
// queue, etc).
//
// Wire-level: each sub-stream is a regular smux stream over kcp-go. On top
// we frame each chunk as:
//
//   [4B chunk-len BE][8B chunk-seq BE][chunk-bytes]
//
// chunk-seq is a per-logical-stream monotonic counter, so the receiver can
// reorder chunks across sub-streams.
//
// On stream open, the client picks a 16B logical-stream-id and opens one
// sub-stream on EACH of N sub-conns, writing the id first. The server
// matches sub-streams by id; once N have attached, the logical stream is
// ready and the application-layer hello is read on sub 0.
package skcptr

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ebrahimkh/dns-head/transports"
	_ "github.com/ebrahimkh/dns-head/transports/kcptr" // register kcp so we can grab it
)

// NumLanes is N — the number of parallel KCP sessions per logical tunnel.
var NumLanes = func() int {
	if v := os.Getenv("DNSH_SKCP_LANES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 16
}()

// ChunkSize is the max bytes per striped chunk. Smaller = finer granularity,
// more header overhead. 16 KB is a good compromise (overhead is 12B/16KB ≈
// 0.07%).
const ChunkSize = 16 * 1024

type transport struct{}

func (transport) Name() string { return "skcp" }

func init() { transports.Register(transport{}) }

// kcpInner returns the registered "kcp" transport (lazy to avoid init-order
// surprises).
func kcpInner() transports.Transport {
	t, err := transports.Get("kcp")
	if err != nil {
		panic("skcp: kcp transport not registered: " + err.Error())
	}
	return t
}

func (transport) Listen(addr string, cfg transports.Config) (transports.Listener, error) {
	// One UDP listener, kcp-go demuxes by remote addr — so N clients with N
	// source ports yield N kcp.UDPSessions naturally. Group them into logical
	// tunnels keyed by the client's remote IP (port varies per sub-conn).
	inner, err := kcpInner().Listen(addr, cfg)
	if err != nil {
		return nil, err
	}
	l := &listener{
		inner:   inner,
		pending: make(map[string]*pendingConn),
		ready:   make(chan transports.Conn, 16),
		closed:  make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

func (transport) Dial(ctx context.Context, serverAddr string, cfg transports.Config) (transports.Conn, error) {
	subs := make([]transports.Conn, NumLanes)
	for i := 0; i < NumLanes; i++ {
		c, err := kcpInner().Dial(ctx, serverAddr, cfg)
		if err != nil {
			for j := 0; j < i; j++ {
				subs[j].Close()
			}
			return nil, err
		}
		subs[i] = c
	}
	return &dialConn{subs: subs}, nil
}

// ----- client-side conn -----

type dialConn struct {
	subs []transports.Conn
}

func (c *dialConn) OpenStream(ctx context.Context) (transports.Stream, error) {
	var lid [16]byte
	if _, err := rand.Read(lid[:]); err != nil {
		return nil, err
	}
	subStreams := make([]transports.Stream, len(c.subs))
	for i, sc := range c.subs {
		s, err := sc.OpenStream(ctx)
		if err != nil {
			for j := 0; j < i; j++ {
				subStreams[j].Close()
			}
			return nil, err
		}
		// Tag the sub-stream with the logical id + lane index.
		hdr := [17]byte{}
		copy(hdr[:16], lid[:])
		hdr[16] = byte(i)
		if _, err := s.Write(hdr[:]); err != nil {
			s.Close()
			for j := 0; j < i; j++ {
				subStreams[j].Close()
			}
			return nil, err
		}
		subStreams[i] = s
	}
	return newLogicalStream(subStreams), nil
}

func (c *dialConn) AcceptStream(ctx context.Context) (transports.Stream, error) {
	// Striped client doesn't currently accept server-pushed streams.
	return nil, errors.New("skcp: AcceptStream not implemented on client side")
}

func (c *dialConn) RemoteAddr() net.Addr { return c.subs[0].RemoteAddr() }

func (c *dialConn) Close() error {
	var firstErr error
	for _, s := range c.subs {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ----- server-side listener -----

type listener struct {
	inner     transports.Listener
	pending   map[string]*pendingConn // keyed by client IP
	mu        sync.Mutex
	ready     chan transports.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

type pendingConn struct {
	subs    []transports.Conn // we collect underlying kcp+smux conns by remote IP
	streams map[string]*streamCollector
	mu      sync.Mutex
}

type streamCollector struct {
	lid     [16]byte
	subs    []transports.Stream // sized NumLanes; nil until each arrives
	count   int
	mu      sync.Mutex
	cond    *sync.Cond
	deliver chan transports.Stream
}

func (l *listener) acceptLoop() {
	for {
		c, err := l.inner.Accept(context.Background())
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
				return
			}
		}
		go l.handleSubConn(c)
	}
}

// handleSubConn: a new sub-conn arrived. Stash it under the client IP key,
// accept streams forever, and route them to the right streamCollector by
// logical-stream-id (read from the first 17 bytes of each stream).
func (l *listener) handleSubConn(sc transports.Conn) {
	ip := remoteIP(sc.RemoteAddr())
	l.mu.Lock()
	p, ok := l.pending[ip]
	if !ok {
		p = &pendingConn{streams: make(map[string]*streamCollector)}
		l.pending[ip] = p
	}
	p.mu.Lock()
	p.subs = append(p.subs, sc)
	subCount := len(p.subs)
	p.mu.Unlock()
	l.mu.Unlock()

	// Once we have at least NumLanes sub-conns from this client IP, we publish
	// a striped Conn to the user. But the logical-stream identity is per-stream
	// not per-conn, so we just publish the Conn on the first sub-conn arrival.
	if subCount == 1 {
		ctx := context.Background()
		conn := &acceptConn{subs: p, remote: sc.RemoteAddr()}
		select {
		case l.ready <- conn:
		case <-ctx.Done():
		case <-l.closed:
			return
		}
	}

	for {
		s, err := sc.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go p.dispatchStream(s)
	}
}

// dispatchStream reads the 17-byte header, finds-or-creates the
// streamCollector, attaches the sub-stream.
func (p *pendingConn) dispatchStream(s transports.Stream) {
	var hdr [17]byte
	if _, err := io.ReadFull(s, hdr[:]); err != nil {
		s.Close()
		return
	}
	lane := int(hdr[16])
	if lane >= NumLanes {
		s.Close()
		return
	}
	lidKey := string(hdr[:16])

	p.mu.Lock()
	sc, ok := p.streams[lidKey]
	if !ok {
		sc = &streamCollector{
			subs:    make([]transports.Stream, NumLanes),
			deliver: make(chan transports.Stream, 1),
		}
		copy(sc.lid[:], hdr[:16])
		sc.cond = sync.NewCond(&sc.mu)
		p.streams[lidKey] = sc
	}
	p.mu.Unlock()

	sc.mu.Lock()
	if sc.subs[lane] != nil {
		// Duplicate / replay — drop.
		sc.mu.Unlock()
		s.Close()
		return
	}
	sc.subs[lane] = s
	sc.count++
	complete := sc.count == NumLanes
	sc.mu.Unlock()

	if complete {
		// All N lanes arrived → publish a single logical Stream for the user.
		ls := newLogicalStream(sc.subs)
		select {
		case sc.deliver <- ls:
		default:
		}
	}
}

type acceptConn struct {
	subs   *pendingConn
	remote net.Addr
}

func (a *acceptConn) OpenStream(ctx context.Context) (transports.Stream, error) {
	return nil, errors.New("skcp: server-initiated streams not supported")
}

func (a *acceptConn) AcceptStream(ctx context.Context) (transports.Stream, error) {
	// Wait for a streamCollector to publish a completed logicalStream.
	// We scan the existing collectors and also wait for new ones.
	for {
		a.subs.mu.Lock()
		for _, sc := range a.subs.streams {
			select {
			case ls := <-sc.deliver:
				a.subs.mu.Unlock()
				return ls, nil
			default:
			}
		}
		a.subs.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (a *acceptConn) RemoteAddr() net.Addr { return a.remote }

func (a *acceptConn) Close() error {
	a.subs.mu.Lock()
	defer a.subs.mu.Unlock()
	for _, sc := range a.subs.subs {
		sc.Close()
	}
	return nil
}

func (l *listener) Accept(ctx context.Context) (transports.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, errors.New("skcp: listener closed")
	}
}

func (l *listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.inner.Close()
	})
	return err
}

func remoteIP(a net.Addr) string {
	if u, ok := a.(*net.UDPAddr); ok {
		return u.IP.String()
	}
	host, _, _ := net.SplitHostPort(a.String())
	return host
}

// ----- the striped logical stream -----

// logicalStream takes a slice of N underlying sub-streams and presents a
// single byte-stream view, with bytes chunked round-robin across sub-streams
// and reassembled in order on the receive side.
type logicalStream struct {
	subs []transports.Stream

	// send
	sendMu  sync.Mutex
	sendSeq uint64

	// receive
	recvMu      sync.Mutex
	recvCond    *sync.Cond
	recvNext    uint64
	recvHole    map[uint64][]byte
	recvReady   []byte
	recvClosed  bool
	recvLiveSub int
}

func newLogicalStream(subs []transports.Stream) *logicalStream {
	ls := &logicalStream{
		subs:        subs,
		recvHole:    make(map[uint64][]byte, 32),
		recvLiveSub: len(subs),
	}
	ls.recvCond = sync.NewCond(&ls.recvMu)
	for _, s := range subs {
		go ls.readSub(s)
	}
	return ls
}

func (l *logicalStream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > ChunkSize {
			n = ChunkSize
		}
		l.sendMu.Lock()
		seq := l.sendSeq
		l.sendSeq++
		l.sendMu.Unlock()

		idx := int(seq % uint64(len(l.subs)))
		hdr := make([]byte, 12+n)
		binary.BigEndian.PutUint32(hdr[0:4], uint32(n))
		binary.BigEndian.PutUint64(hdr[4:12], seq)
		copy(hdr[12:], p[:n])
		if _, err := l.subs[idx].Write(hdr); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (l *logicalStream) Read(p []byte) (int, error) {
	l.recvMu.Lock()
	defer l.recvMu.Unlock()
	for len(l.recvReady) == 0 {
		if l.recvClosed && l.recvLiveSub == 0 && len(l.recvHole) == 0 {
			return 0, io.EOF
		}
		l.recvCond.Wait()
	}
	n := copy(p, l.recvReady)
	l.recvReady = l.recvReady[n:]
	return n, nil
}

func (l *logicalStream) readSub(s transports.Stream) {
	defer func() {
		l.recvMu.Lock()
		l.recvLiveSub--
		if l.recvLiveSub == 0 {
			l.recvClosed = true
			l.recvCond.Broadcast()
		}
		l.recvMu.Unlock()
	}()
	hdr := make([]byte, 12)
	for {
		if _, err := io.ReadFull(s, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[0:4])
		seq := binary.BigEndian.Uint64(hdr[4:12])
		if n > 4*ChunkSize { // sanity
			return
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(s, data); err != nil {
			return
		}

		l.recvMu.Lock()
		if seq < l.recvNext {
			// duplicate — drop
		} else if seq == l.recvNext {
			l.recvReady = append(l.recvReady, data...)
			l.recvNext++
			for {
				d, ok := l.recvHole[l.recvNext]
				if !ok {
					break
				}
				delete(l.recvHole, l.recvNext)
				l.recvReady = append(l.recvReady, d...)
				l.recvNext++
			}
			l.recvCond.Broadcast()
		} else {
			l.recvHole[seq] = data
		}
		l.recvMu.Unlock()
	}
}

func (l *logicalStream) Close() error {
	var firstErr error
	for _, s := range l.subs {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.recvMu.Lock()
	l.recvClosed = true
	l.recvCond.Broadcast()
	l.recvMu.Unlock()
	return firstErr
}
