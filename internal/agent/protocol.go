package agent

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

type msgType uint8

const (
	msgGuestInfo msgType = iota + 1 // 1
	msgTask                          // 2
	msgACK                           // 3
	msgTaskResult                    // 4
	msgSetWorkDir                    // 5
	_                                // 6 reserved
	msgStreamTaskData                // 7
	msgStreamTaskEnd                 // 8
)

type message struct {
	Type    msgType
	Payload []byte
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *message) encode(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, uint8(m.Type)); err != nil {
		return err
	}
	if len(m.Payload) > 0xFFFFFFFF {
		return fmt.Errorf("payload length %d exceeds uint32 max", len(m.Payload))
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(m.Payload))); err != nil {
		return err
	}
	return writeFull(w, m.Payload)
}

func decodeMessage(r io.Reader) (*message, error) {
	var t uint8
	if err := binary.Read(r, binary.BigEndian, &t); err != nil {
		return nil, err
	}
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &message{Type: msgType(t), Payload: payload}, nil
}

type conn struct {
	rwc io.ReadWriteCloser
}

func wrapConn(rwc io.ReadWriteCloser) *conn { return &conn{rwc: rwc} }

func (c *conn) Close() error { return c.rwc.Close() }

func (c *conn) send(t msgType, payload []byte) error {
	return (&message{Type: t, Payload: payload}).encode(c.rwc)
}

func (c *conn) sendJSON(t msgType, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.send(t, data)
}

func (c *conn) recv() (*message, error) { return decodeMessage(c.rwc) }

func (c *conn) recvJSON(want msgType, v any) error {
	msg, err := c.recv()
	if err != nil {
		return err
	}
	if msg.Type != want {
		return fmt.Errorf("unexpected message type: got %d, want %d", msg.Type, want)
	}
	return json.Unmarshal(msg.Payload, v)
}

type ack struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type streamTaskEnd struct {
	Error string `json:"error,omitempty"`
}
