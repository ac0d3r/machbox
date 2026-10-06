package vm

import (
	"context"
	"fmt"
	"net"
)

// ConnectVsock dials the guest agent AF_VSOCK listener (host → guest) via
// Virtualization.framework. Calls are serialized for the lifetime of each
// Connect: overlapping Connects during ShowGraphic have SIGTRAPed.
func (i *VMInstance) ConnectVsock(ctx context.Context, port uint32) (net.Conn, error) {
	i.vsockMu.Lock()
	defer i.vsockMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("connect to guest port %d: %w", port, err)
	}

	devices := i.vm.SocketDevices()
	if len(devices) == 0 {
		return nil, fmt.Errorf("no virtio socket device available")
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := devices[0].Connect(port)
		if err != nil {
			ch <- result{err: fmt.Errorf("connect to guest port %d: %w", port, err)}
			return
		}
		ch <- result{conn: conn}
	}()

	select {
	case <-ctx.Done():
		// Drain Connect before unlocking so the next Dial cannot overlap.
		r := <-ch
		if r.conn != nil {
			_ = r.conn.Close()
		}
		return nil, fmt.Errorf("connect to guest port %d: %w", port, ctx.Err())
	case r := <-ch:
		return r.conn, r.err
	}
}
