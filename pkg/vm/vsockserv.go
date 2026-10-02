package vm

import (
	"context"
	"fmt"
	"net"
	"sync"

	vz "github.com/Code-Hex/vz/v3"
	"github.com/sirupsen/logrus"
)

const (
	DefaultVsockPort uint32 = 12345
)

type VsockServer struct {
	device   *vz.VirtioSocketDevice
	listener *vz.VirtioSocketListener
	conns    sync.Map // key: net.Conn, value: struct{}
}

func NewVsockServer(device *vz.VirtioSocketDevice) *VsockServer {
	return &VsockServer{device: device}
}

func (v *VsockServer) AcceptLoop(ctx context.Context, port uint32, handler func(net.Conn)) (err error) {
	v.listener, err = v.device.Listen(port)
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", port, err)
	}

	go func() {
		defer v.listener.Close()

		for {
			select {
			case <-ctx.Done():
				logrus.Debugf("AcceptLoop on port %d stopped by context", port)
				return
			default:
			}

			conn, err := v.listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logrus.Errorf("accept on port %d: %v, stopping accept loop", port, err)
				return
			}

			v.trackConn(conn)
			go func(c net.Conn) {
				defer v.untrackConn(c)
				handler(c)
			}(conn)
		}
	}()

	return nil
}

func (v *VsockServer) Close() {
	v.conns.Range(func(key, _ any) bool {
		_ = key.(net.Conn).Close()
		v.conns.Delete(key)
		return true
	})

	_ = v.listener.Close()
}

func (v *VsockServer) trackConn(conn net.Conn) {
	v.conns.Store(conn, struct{}{})
}

func (v *VsockServer) untrackConn(conn net.Conn) {
	_ = conn.Close()
	v.conns.Delete(conn)
}
