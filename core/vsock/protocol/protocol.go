package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// MsgType defines the type of protocol message.
type MsgType uint8

const (
	MsgGuestInfo MsgType = iota + 1
	MsgTask
	MsgACK
	MsgTaskResult
	MsgSetWorkDir
	MsgSessionEnd
	MsgStreamTaskData
	MsgStreamTaskEnd
)

// Message is the wire format for all protocol communication.
type Message struct {
	Type    MsgType
	Payload []byte
}

// writeFull writes all bytes in p to w, retrying on short writes.
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

// Encode writes the message to w in TLV format:
// [1 byte type][4 bytes length][payload...]
func (m *Message) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, uint8(m.Type)); err != nil {
		return err
	}
	payloadLen := len(m.Payload)
	if payloadLen > 0xFFFFFFFF {
		return fmt.Errorf("payload length %d exceeds uint32 max", payloadLen)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(payloadLen)); err != nil {
		return err
	}
	return writeFull(w, m.Payload)
}

// Decode reads a message from r.
func Decode(r io.Reader) (*Message, error) {
	var msgType uint8
	if err := binary.Read(r, binary.BigEndian, &msgType); err != nil {
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
	return &Message{Type: MsgType(msgType), Payload: payload}, nil
}

// Conn wraps a ReadWriteCloser with protocol helpers.
type Conn struct {
	rwc io.ReadWriteCloser
}

// Wrap wraps an existing connection.
func Wrap(rwc io.ReadWriteCloser) *Conn {
	return &Conn{rwc: rwc}
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.rwc.Close() }

// Send sends a raw message.
func (c *Conn) Send(msgType MsgType, payload []byte) error {
	msg := &Message{Type: msgType, Payload: payload}
	return msg.Encode(c.rwc)
}

// SendJSON marshals v to JSON and sends it as a typed message.
func (c *Conn) SendJSON(msgType MsgType, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Send(msgType, data)
}

// Recv reads the next message.
func (c *Conn) Recv() (*Message, error) {
	return Decode(c.rwc)
}

// RecvJSON reads the next message and unmarshals it into v.
// It returns an error if the message type does not match want.
func (c *Conn) RecvJSON(want MsgType, v any) error {
	msg, err := c.Recv()
	if err != nil {
		return err
	}
	if msg.Type != want {
		return fmt.Errorf("unexpected message type: got %d, want %d", msg.Type, want)
	}
	return json.Unmarshal(msg.Payload, v)
}

// ACK is a generic acknowledgment.
type ACK struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Task describes an analysis command to execute inside the guest.
type Task struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	WorkDir string   `json:"work_dir,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
	Stream  bool     `json:"stream,omitempty"`
}

// Result carries the outcome of a finished Task.
type TaskResult struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
}

type StreamTaskEnd struct {
	Error string `json:"error,omitempty"`
}

// GuestInfo is sent by the guest-agent to report VM system information.
type GuestInfo struct {
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	OSVersion    string `json:"os_version"`
	BuildVersion string `json:"build_version"`
	SIPDisabled  bool   `json:"sip_disabled"`
}

// WorkDir tells the guest where to store files and run tasks.
type WorkDir struct {
	SharePath string `json:"share_path"`
	WorkPath  string `json:"work_path"`
}

// SessionEnd signals the end of an analysis session.
type SessionEnd struct {
	KeepRunning bool `json:"keep_running"`
}
