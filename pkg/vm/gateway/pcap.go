package gateway

import (
	"bufio"
	"encoding/binary"
	"os"
	"sync"
	"time"
)

const (
	pcapSnapLen       = 65535
	pcapLinkEthernet  = 1
	pcapMagicMicrosec = 0xa1b2c3d4
)

// pcapWriter writes Ethernet frames in libpcap format. A nil writer drops
// them.
type pcapWriter struct {
	mu  sync.Mutex
	f   *os.File
	w   *bufio.Writer
	err error
}

func newPcapWriter(path string) (*pcapWriter, error) {
	// #nosec G304 -- path is chosen by the caller (the job directory).
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	p := &pcapWriter{f: f, w: bufio.NewWriterSize(f, 256<<10)}
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:], pcapMagicMicrosec)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], pcapSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:], pcapLinkEthernet)
	if _, err := p.w.Write(hdr[:]); err != nil {
		_ = f.Close()
		return nil, err
	}
	return p, nil
}

func (p *pcapWriter) write(frame []byte) {
	if p == nil {
		return
	}
	now := time.Now()
	n := min(len(frame), pcapSnapLen)
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:], uint32(now.Unix()))           // #nosec G115 -- valid until 2106
	binary.LittleEndian.PutUint32(hdr[4:], uint32(now.Nanosecond()/1e3)) // #nosec G115 -- < 1e6
	binary.LittleEndian.PutUint32(hdr[8:], uint32(n))                    // #nosec G115 -- <= pcapSnapLen
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(frame)))          // #nosec G115 -- one datagram

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return
	}
	if _, p.err = p.w.Write(hdr[:]); p.err == nil {
		_, p.err = p.w.Write(frame[:n])
	}
}

func (p *pcapWriter) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = p.w.Flush()
	}
	if err := p.f.Close(); p.err == nil {
		p.err = err
	}
	return p.err
}
