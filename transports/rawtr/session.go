package rawtr

import (
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// session is one reliable bidirectional byte stream over an AEAD-wrapped UDP
// connection. There is no congestion control: the sender holds up to
// WindowSegs * segMax bytes in flight and retransmits any unacked segment
// after rto. smux is layered on top by the caller for stream multiplexing.
//
// session satisfies net.Conn.
const (
	segMax     = 1100             // payload bytes per DATA segment; fits within DNS header + IP/UDP under 1500B path MTU
	rtoInitial = 200 * time.Millisecond
	rtoMin     = 60 * time.Millisecond
	rtoMax     = 4 * time.Second
	pingPeriod = 10 * time.Second
	rtxTickMs  = 20 // retransmit timer tick

	sackMaxRanges = 8 // up to N SACK ranges per ACK
)

var (
	// WindowSegs caps the sender's in-flight segments. At segMax=1100 and
	// 150 ms RTT, 4096 segs = 4.5 MB in flight ≈ 240 Mbps ceiling.
	WindowSegs = envInt("DNSH_RAW_WINDOW", 4096)
	// RecvBudgetSegs caps how many out-of-order segments the receiver will
	// buffer (memory ceiling). Bigger = tolerates more reordering / longer
	// gaps but uses more RAM.
	RecvBudgetSegs = envInt("DNSH_RAW_RECVBUDGET", 8192)
	// MaxRetxPerTick limits retransmits per 20 ms tick to avoid ARQ
	// storm collapse on lossy paths.
	MaxRetxPerTick = envInt("DNSH_RAW_MAXRETX", 256)
)

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// sender's in-flight record.
type segment struct {
	seq     uint32
	payload []byte
	sentAt  time.Time
	retries int  // incremented on each retx; RTT samples skipped if > 0 (Karn)
	acked   bool // marked true via SACK before cumulative ack removes it
}

type session struct {
	pc     net.PacketConn // shared on server; owned on client
	remote net.Addr
	aead   cipher.AEAD

	outCh chan []byte // serialized writes

	// send side
	sendMu     sync.Mutex
	sendCond   *sync.Cond
	sendClosed bool
	nextSeq    uint32
	minUnacked uint32 // lowest seq still in unacked map (for SACK encoding)
	unacked    map[uint32]*segment
	rtt        time.Duration
	rto        time.Duration

	// recv side
	recvMu       sync.Mutex
	recvCond     *sync.Cond
	recvReady    []byte
	recvHole     map[uint32][]byte
	expSeq       uint32 // next seqno to deliver
	peerClosed   bool
	lastActivity time.Time
	ackPending   bool      // an in-order ACK is overdue
	lastAckSent  time.Time // throttle ACK rate

	// deadlines
	rdDeadline time.Time
	wrDeadline time.Time

	// lifecycle
	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

func newSession(pc net.PacketConn, remote net.Addr, aead cipher.AEAD, outCh chan []byte) *session {
	s := &session{
		pc:           pc,
		remote:       remote,
		aead:         aead,
		outCh:        outCh,
		unacked:      make(map[uint32]*segment, 64),
		recvHole:     make(map[uint32][]byte, 64),
		nextSeq:      1,
		minUnacked:   1,
		expSeq:       1,
		rto:          rtoInitial,
		closed:       make(chan struct{}),
		lastActivity: time.Now(),
	}
	s.sendCond = sync.NewCond(&s.sendMu)
	s.recvCond = sync.NewCond(&s.recvMu)
	go s.txLoop()
	go s.rtxLoop()
	go s.idleLoop()
	go s.ackLoop()
	return s
}

// ----- Read / Write surface -----

func (s *session) Read(p []byte) (int, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	for len(s.recvReady) == 0 {
		if s.peerClosed && len(s.recvHole) == 0 {
			return 0, io.EOF
		}
		select {
		case <-s.closed:
			return 0, errClosed(s)
		default:
		}
		if !s.rdDeadline.IsZero() && !time.Now().Before(s.rdDeadline) {
			return 0, &net.OpError{Op: "read", Net: "rawtr", Err: errTimeout{}}
		}
		s.waitCond(s.recvCond, s.rdDeadline)
	}
	n := copy(p, s.recvReady)
	s.recvReady = s.recvReady[n:]
	return n, nil
}

func (s *session) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.sendMu.Lock()
		for len(s.unacked) >= WindowSegs && !s.sendClosed {
			select {
			case <-s.closed:
				s.sendMu.Unlock()
				return written, errClosed(s)
			default:
			}
			if !s.wrDeadline.IsZero() && !time.Now().Before(s.wrDeadline) {
				s.sendMu.Unlock()
				return written, &net.OpError{Op: "write", Net: "rawtr", Err: errTimeout{}}
			}
			s.waitCond(s.sendCond, s.wrDeadline)
		}
		if s.sendClosed {
			s.sendMu.Unlock()
			return written, errClosed(s)
		}
		take := len(p)
		if take > segMax {
			take = segMax
		}
		seq := s.nextSeq
		s.nextSeq++
		seg := &segment{seq: seq, payload: append([]byte(nil), p[:take]...), sentAt: time.Now()}
		s.unacked[seq] = seg
		s.sendMu.Unlock()

		s.sendFrame(buildDATA(seg))
		p = p[take:]
		written += take
	}
	return written, nil
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		s.sendMu.Lock()
		s.sendClosed = true
		s.sendMu.Unlock()
		s.sendFrame([]byte{tFIN})
		close(s.closed)
		s.sendCond.Broadcast()
		s.recvCond.Broadcast()
	})
	return nil
}

func (s *session) LocalAddr() net.Addr  { return s.pc.LocalAddr() }
func (s *session) RemoteAddr() net.Addr { return s.remote }

func (s *session) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	s.SetWriteDeadline(t)
	return nil
}
func (s *session) SetReadDeadline(t time.Time) error {
	s.recvMu.Lock()
	s.rdDeadline = t
	s.recvMu.Unlock()
	s.recvCond.Broadcast()
	return nil
}
func (s *session) SetWriteDeadline(t time.Time) error {
	s.sendMu.Lock()
	s.wrDeadline = t
	s.sendMu.Unlock()
	s.sendCond.Broadcast()
	return nil
}

// ----- incoming frame dispatch -----

func (s *session) dispatchFrame(body []byte) {
	if len(body) < 1 {
		return
	}
	s.recvMu.Lock()
	s.lastActivity = time.Now()
	s.recvMu.Unlock()

	switch body[0] {
	case tDATA:
		if len(body) < 1+4+2 {
			return
		}
		seq := getU32(body, 1)
		ln := int(getU16(body, 5))
		if 1+4+2+ln > len(body) {
			return
		}
		payload := body[1+4+2 : 1+4+2+ln]
		s.onData(seq, payload)
	case tACK:
		s.onAck(body[1:])
	case tFIN:
		s.recvMu.Lock()
		s.peerClosed = true
		s.recvMu.Unlock()
		s.recvCond.Broadcast()
	case tPING:
		if len(body) >= 1+8 {
			pong := make([]byte, 1+8)
			pong[0] = tPONG
			copy(pong[1:], body[1:1+8])
			s.sendFrame(pong)
		}
	case tPONG:
	}
}

func (s *session) onData(seq uint32, payload []byte) {
	s.recvMu.Lock()
	outOfOrder := false
	if seq < s.expSeq {
		// dup — ack immediately so sender stops retransmitting
		s.recvMu.Unlock()
		s.sendACKNow()
		return
	}
	if seq == s.expSeq {
		s.recvReady = append(s.recvReady, payload...)
		s.expSeq++
		for {
			p, ok := s.recvHole[s.expSeq]
			if !ok {
				break
			}
			delete(s.recvHole, s.expSeq)
			s.recvReady = append(s.recvReady, p...)
			s.expSeq++
		}
	} else {
		outOfOrder = true
		if len(s.recvHole) >= RecvBudgetSegs {
			// drop
		} else if _, exists := s.recvHole[seq]; !exists {
			s.recvHole[seq] = append([]byte(nil), payload...)
		}
	}
	s.ackPending = true
	now := time.Now()
	// Send ACK immediately on out-of-order (so sender learns about gaps fast)
	// or if it's been a few ms since the last one. Otherwise let the ackLoop
	// flush periodically — saves a packet per data packet on the happy path.
	sendNow := outOfOrder || now.Sub(s.lastAckSent) >= 2*time.Millisecond
	if sendNow {
		s.lastAckSent = now
		s.ackPending = false
	}
	s.recvMu.Unlock()
	s.recvCond.Broadcast()
	if sendNow {
		s.sendACKNow()
	}
}

// onAck processes an ACK frame body. Layout:
//
//	[4B ackUpTo][1B sackRangeCount][N × (4B start, 4B end-exclusive)]
//
// Where ackUpTo is the smallest seq the peer has NOT yet delivered (cumulative
// ack), and SACK ranges describe out-of-order seqs the peer has buffered.
func (s *session) onAck(body []byte) {
	if len(body) < 4+1 {
		return
	}
	ackUpTo := getU32(body, 0)
	sackCount := int(body[4])
	off := 5
	if 5+sackCount*8 > len(body) {
		return
	}
	type rng struct{ s, e uint32 }
	sacks := make([]rng, 0, sackCount)
	for i := 0; i < sackCount; i++ {
		st := getU32(body, off)
		en := getU32(body, off+4)
		off += 8
		sacks = append(sacks, rng{st, en})
	}

	s.sendMu.Lock()
	freed := 0
	for seq, seg := range s.unacked {
		acked := false
		if seq < ackUpTo {
			acked = true
		} else {
			for _, r := range sacks {
				if seq >= r.s && seq < r.e {
					acked = true
					break
				}
			}
		}
		if !acked {
			continue
		}
		// Karn's algorithm: only sample RTT on segments never retransmitted.
		if seg.retries == 0 {
			rtt := time.Since(seg.sentAt)
			if s.rtt == 0 {
				s.rtt = rtt
			} else {
				s.rtt = s.rtt*7/8 + rtt/8
			}
		}
		delete(s.unacked, seq)
		freed++
	}
	// Advance minUnacked.
	if len(s.unacked) == 0 {
		s.minUnacked = s.nextSeq
	} else if ackUpTo > s.minUnacked {
		s.minUnacked = ackUpTo
	}
	if s.rtt > 0 {
		s.rto = clamp(s.rtt*2, rtoMin, rtoMax)
	}
	s.sendMu.Unlock()
	if freed > 0 {
		s.sendCond.Broadcast()
	}
}

// sendACKNow builds and queues an ACK frame with cumulative ack + up to
// sackMaxRanges SACK ranges describing the contiguous chunks currently in
// recvHole.
func (s *session) sendACKNow() {
	s.recvMu.Lock()
	exp := s.expSeq
	holes := len(s.recvHole)
	// Fast path: no out-of-order buffered, only emit cumulative ack.
	var ranges [][2]uint32
	if holes > 0 {
		ranges = make([][2]uint32, 0, sackMaxRanges)
		seq := exp
		// Scan only as far ahead as could plausibly contain holes (bounded by
		// the number of holes — a tighter bound than a fixed window).
		maxScan := uint32(holes)*2 + 8
		limit := exp + maxScan
		for seq < limit && len(ranges) < sackMaxRanges {
			for seq < limit {
				if _, ok := s.recvHole[seq]; ok {
					break
				}
				seq++
			}
			if seq >= limit {
				break
			}
			start := seq
			for seq < limit {
				if _, ok := s.recvHole[seq]; !ok {
					break
				}
				seq++
			}
			ranges = append(ranges, [2]uint32{start, seq})
		}
	}
	s.recvMu.Unlock()

	frame := make([]byte, 1+4+1+len(ranges)*8)
	frame[0] = tACK
	putU32(frame, 1, exp)
	frame[5] = byte(len(ranges))
	off := 6
	for _, r := range ranges {
		putU32(frame, off, r[0])
		putU32(frame, off+4, r[1])
		off += 8
	}
	s.sendFrame(frame)
}

// ackLoop flushes pending in-order ACKs every few ms. Out-of-order ACKs are
// flushed immediately by onData.
func (s *session) ackLoop() {
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-s.closed:
			return
		}
		s.recvMu.Lock()
		need := s.ackPending
		if need {
			s.ackPending = false
			s.lastAckSent = time.Now()
		}
		s.recvMu.Unlock()
		if need {
			s.sendACKNow()
		}
	}
}

func (s *session) sendFrame(body []byte) {
	sealed := seal(s.aead, body)
	select {
	case s.outCh <- sealed:
	case <-s.closed:
	}
}

// ----- background loops -----

func (s *session) txLoop() {
	for {
		select {
		case b := <-s.outCh:
			_, _ = s.pc.WriteTo(b, s.remote)
		case <-s.closed:
			return
		}
	}
}

// rtxLoop scans unacked segments every rtxTickMs and retransmits up to
// MaxRetxPerTick whose age exceeds the current RTO.
func (s *session) rtxLoop() {
	t := time.NewTicker(time.Duration(rtxTickMs) * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-s.closed:
			return
		}
		now := time.Now()
		s.sendMu.Lock()
		rto := s.rto
		// Collect oldest-first up to MaxRetxPerTick. Map order is random;
		// we approximate by picking the segments past RTO and capping count.
		var due []*segment
		for _, seg := range s.unacked {
			if now.Sub(seg.sentAt) >= rto {
				due = append(due, seg)
				if len(due) >= MaxRetxPerTick {
					break
				}
			}
		}
		s.sendMu.Unlock()
		for _, seg := range due {
			s.sendMu.Lock()
			// Re-verify under lock (might have been ACKed by SACK between snapshot and retx).
			if cur, ok := s.unacked[seg.seq]; ok && cur == seg {
				seg.sentAt = now
				seg.retries++
				s.sendMu.Unlock()
				s.sendFrame(buildDATA(seg))
			} else {
				s.sendMu.Unlock()
			}
		}
	}
}

func (s *session) idleLoop() {
	t := time.NewTicker(pingPeriod)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-s.closed:
			return
		}
		s.recvMu.Lock()
		idle := time.Since(s.lastActivity)
		s.recvMu.Unlock()
		if idle > 90*time.Second {
			s.closeErr = errors.New("rawtr: idle timeout")
			s.Close()
			return
		}
		ping := make([]byte, 1+8)
		ping[0] = tPING
		putU64(ping, 1, uint64(time.Now().UnixNano()))
		s.sendFrame(ping)
	}
}

func (s *session) waitCond(c *sync.Cond, deadline time.Time) {
	if deadline.IsZero() {
		c.Wait()
		return
	}
	timer := time.AfterFunc(time.Until(deadline), func() { c.Broadcast() })
	defer timer.Stop()
	c.Wait()
}

// ----- helpers -----

func buildDATA(seg *segment) []byte {
	frame := make([]byte, 1+4+2+len(seg.payload))
	frame[0] = tDATA
	putU32(frame, 1, seg.seq)
	putU16(frame, 5, uint16(len(seg.payload)))
	copy(frame[7:], seg.payload)
	return frame
}

func putU64(b []byte, off int, v uint64) {
	b[off] = byte(v >> 56)
	b[off+1] = byte(v >> 48)
	b[off+2] = byte(v >> 40)
	b[off+3] = byte(v >> 32)
	b[off+4] = byte(v >> 24)
	b[off+5] = byte(v >> 16)
	b[off+6] = byte(v >> 8)
	b[off+7] = byte(v)
}

func clamp(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

func errClosed(s *session) error {
	if s.closeErr != nil {
		return s.closeErr
	}
	return io.ErrClosedPipe
}
