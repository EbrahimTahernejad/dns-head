package dnsheader

import (
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"

	"golang.org/x/net/ipv4"
)

// Batched send: when enabled, WriteTo enqueues datagrams onto a small queue
// drained by a flusher goroutine that issues `sendmmsg(2)` via
// ipv4.PacketConn.WriteBatch. The caller still sees synchronous WriteTo
// semantics (we return after copying the buffer; the actual send is deferred
// by microseconds). Goal: reduce per-packet syscall overhead when many
// packets per second flow out (skcp with many lanes is the obvious win).
//
// Off-platform (non-Linux) WriteBatch falls back to per-packet WriteTo
// inside x/net/ipv4 — no harm, no measurable speed change.

var (
	// batchEnabled returns whether we should run the flusher path.
	// Override via DNSH_BATCH=0|1 (default 1 on Linux, 0 elsewhere).
	batchEnabled = func() bool {
		if v := os.Getenv("DNSH_BATCH"); v != "" {
			n, err := strconv.Atoi(v)
			return err == nil && n != 0
		}
		return runtime.GOOS == "linux"
	}()

	// batchMaxQueue caps how many datagrams the queue can hold before WriteTo
	// blocks (back-pressuring the producer). Bigger queue = more chance to
	// build a big sendmmsg batch, but also more latency.
	batchMaxQueue = func() int {
		if v := os.Getenv("DNSH_BATCH_QUEUE"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return n
			}
		}
		return 256
	}()
)

// batcher runs alongside a PacketConn to coalesce outgoing datagrams.
type batcher struct {
	xconn *ipv4.PacketConn // wraps the *net.UDPConn

	mu      sync.Mutex
	cond    *sync.Cond
	queue   []ipv4.Message
	closing bool
}

func newBatcher(udp *net.UDPConn) *batcher {
	b := &batcher{
		xconn: ipv4.NewPacketConn(udp),
		queue: make([]ipv4.Message, 0, batchMaxQueue),
	}
	b.cond = sync.NewCond(&b.mu)
	go b.flushLoop()
	return b
}

// enqueue blocks if the queue is full (back-pressure). buf must already
// include the DNS header.
func (b *batcher) enqueue(buf []byte, addr net.Addr) {
	b.mu.Lock()
	for len(b.queue) >= batchMaxQueue && !b.closing {
		b.cond.Wait()
	}
	if b.closing {
		b.mu.Unlock()
		return
	}
	b.queue = append(b.queue, ipv4.Message{
		Buffers: [][]byte{buf},
		Addr:    addr,
	})
	b.mu.Unlock()
	b.cond.Signal() // wake the flusher
}

func (b *batcher) flushLoop() {
	for {
		b.mu.Lock()
		for len(b.queue) == 0 && !b.closing {
			b.cond.Wait()
		}
		if b.closing && len(b.queue) == 0 {
			b.mu.Unlock()
			return
		}
		// Swap out the batch.
		batch := b.queue
		b.queue = make([]ipv4.Message, 0, batchMaxQueue)
		// Releasing the lock now wakes any blocked producers in enqueue.
		b.cond.Broadcast()
		b.mu.Unlock()

		// Drain in chunks. WriteBatch returns how many it sent; loop on partial.
		for len(batch) > 0 {
			n, err := b.xconn.WriteBatch(batch, 0)
			if err != nil || n == 0 {
				// On error we just drop the rest. The reliability layer above
				// (kcp/raw) will retransmit.
				break
			}
			batch = batch[n:]
		}
	}
}

func (b *batcher) close() {
	b.mu.Lock()
	b.closing = true
	b.mu.Unlock()
	b.cond.Broadcast()
}
