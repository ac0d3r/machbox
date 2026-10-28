package vsock

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// A macOS guest stops sending on a vsock after about 230 KiB until the host
// sends something back, so data piles up in the guest's send queue. Both
// ends therefore wrap the connection in a framed stream where the receiver
// acknowledges what it has read and the sender keeps at most window bytes
// unacknowledged: every ack lets the guest send again.
const (
	frameData byte = iota
	frameAck

	headerLen = 5
	maxFrame  = 16 << 10
	window    = 64 << 10

	// closeTimeout bounds how long Close waits for the peer to read the rest.
	closeTimeout = 10 * time.Second
)

var errProtocol = errors.New("vsock: flow control protocol error")

type flowConn struct {
	net.Conn
	rd, wd *deadline

	writeMu sync.Mutex // serializes Write calls
	frameMu sync.Mutex // serializes frames on Conn
	wbuf    []byte

	mu       sync.Mutex
	changed  chan struct{} // closed and replaced when the fields below change
	inflight int           // bytes sent, not yet acknowledged
	buf      []byte        // bytes received, not yet read
	consumed int           // bytes read, not yet acknowledged
	err      error         // why the read loop stopped
	closed   bool
}

// FlowControl wraps c in the windowed framing both ends of the agent
// connection use. It is transparent to the protocol carried over it.
func FlowControl(c net.Conn) net.Conn {
	fc := &flowConn{
		Conn:    c,
		rd:      newDeadline(),
		wd:      newDeadline(),
		wbuf:    make([]byte, headerLen+maxFrame),
		changed: make(chan struct{}),
	}
	go fc.readLoop()
	return fc
}

// broadcast wakes everyone waiting on changed; c.mu must be held.
func (c *flowConn) broadcast() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *flowConn) readLoop() {
	hdr := make([]byte, headerLen)
	for {
		if _, err := io.ReadFull(c.Conn, hdr); err != nil {
			c.stop(err)
			return
		}
		n := int(binary.BigEndian.Uint32(hdr[1:]))
		switch hdr[0] {
		case frameAck:
			c.mu.Lock()
			if n > c.inflight {
				c.mu.Unlock()
				c.stop(errProtocol)
				return
			}
			c.inflight -= n
			c.broadcast()
			c.mu.Unlock()
		case frameData:
			if n > maxFrame {
				c.stop(errProtocol)
				return
			}
			p := make([]byte, n)
			if _, err := io.ReadFull(c.Conn, p); err != nil {
				c.stop(io.ErrUnexpectedEOF)
				return
			}
			c.mu.Lock()
			if len(c.buf)+c.consumed+n > window {
				c.mu.Unlock()
				c.stop(errProtocol)
				return
			}
			c.buf = append(c.buf, p...)
			c.broadcast()
			c.mu.Unlock()
		default:
			c.stop(fmt.Errorf("%w: frame type %#x", errProtocol, hdr[0]))
			return
		}
	}
}

func (c *flowConn) stop(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
	c.broadcast()
}

// wait releases c.mu until the state changes or done is closed, and reports
// whether the state changed.
func (c *flowConn) wait(done <-chan struct{}) bool {
	ch := c.changed
	c.mu.Unlock()
	defer c.mu.Lock()
	select {
	case <-ch:
		return true
	case <-done:
		return false
	}
}

func (c *flowConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	for len(c.buf) == 0 {
		switch {
		case c.closed:
			c.mu.Unlock()
			return 0, net.ErrClosed
		case c.err != nil:
			err := c.err
			c.mu.Unlock()
			return 0, err
		}
		if !c.wait(c.rd.wait()) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	c.consumed += n
	ack := 0
	if len(c.buf) == 0 || c.consumed >= window/4 {
		ack, c.consumed = c.consumed, 0
	}
	c.mu.Unlock()

	if ack > 0 {
		// A failed ack surfaces on the next Write or Read.
		_ = c.writeFrame(frameAck, nil, ack)
	}
	return n, nil
}

func (c *flowConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	n := 0
	for n < len(b) {
		c.mu.Lock()
		for c.inflight >= window {
			switch {
			case c.closed:
				c.mu.Unlock()
				return n, net.ErrClosed
			case c.err != nil:
				c.mu.Unlock()
				return n, io.ErrClosedPipe
			}
			if !c.wait(c.wd.wait()) {
				c.mu.Unlock()
				return n, os.ErrDeadlineExceeded
			}
		}
		m := min(len(b)-n, window-c.inflight, maxFrame)
		c.inflight += m
		c.mu.Unlock()

		if err := c.writeFrame(frameData, b[n:n+m], m); err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

func (c *flowConn) writeFrame(typ byte, p []byte, n int) error {
	c.frameMu.Lock()
	defer c.frameMu.Unlock()
	c.wbuf[0] = typ
	binary.BigEndian.PutUint32(c.wbuf[1:headerLen], uint32(n))
	m := copy(c.wbuf[headerLen:], p)
	_, err := c.Conn.Write(c.wbuf[:headerLen+m])
	return err
}

// Close waits until the peer has read everything sent, then closes: a vsock
// closed with data still queued loses that data.
func (c *flowConn) Close() error {
	timeout := make(chan struct{})
	timer := time.AfterFunc(closeTimeout, func() { close(timeout) })
	defer timer.Stop()

	c.mu.Lock()
	for c.inflight > 0 && c.err == nil && !c.closed {
		if !c.wait(timeout) {
			break
		}
	}
	c.closed = true
	c.broadcast()
	c.mu.Unlock()
	return c.Conn.Close()
}

// The read loop must never time out, so read deadlines apply only to Read.
func (c *flowConn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return c.Conn.SetWriteDeadline(t)
}

func (c *flowConn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	return nil
}

func (c *flowConn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	return c.Conn.SetWriteDeadline(t)
}

// deadline is a resettable timer channel, as in net.Pipe.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func newDeadline() *deadline {
	return &deadline{cancel: make(chan struct{})}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // wait for the timer callback to close cancel
	}
	d.timer = nil

	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
