package gateway

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	mdns "github.com/miekg/dns"
)

// upstream records the names the gateway's DNS asks the host about.
type upstream struct {
	mu    sync.Mutex
	asked []string
}

func (u *upstream) ask(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.asked = append(u.asked, name)
	return errors.New("no such host")
}

func (u *upstream) LookupIPAddr(_ context.Context, h string) ([]net.IPAddr, error) {
	return nil, u.ask(h)
}
func (u *upstream) LookupCNAME(_ context.Context, h string) (string, error) { return "", u.ask(h) }
func (u *upstream) LookupMX(_ context.Context, n string) ([]*net.MX, error) { return nil, u.ask(n) }
func (u *upstream) LookupNS(_ context.Context, n string) ([]*net.NS, error) { return nil, u.ask(n) }
func (u *upstream) LookupSRV(_ context.Context, _, _, n string) (string, []*net.SRV, error) {
	return "", nil, u.ask(n)
}
func (u *upstream) LookupTXT(_ context.Context, n string) ([]string, error) { return nil, u.ask(n) }

func TestDNSZones(t *testing.T) {
	tests := []struct {
		name     string
		opts     Options
		qtype    uint16
		query    string
		upstream bool // asked the host
	}{
		{"none: a", Options{Egress: EgressNone}, mdns.TypeA, "example.com.", false},
		{"none: txt", Options{Egress: EgressNone}, mdns.TypeTXT, "c2.example.com.", false},
		{"none: aaaa", Options{Egress: EgressNone}, mdns.TypeAAAA, "c2.example.com.", false},
		{"public: a", Options{Egress: EgressPublic}, mdns.TypeA, "example.com.", true},
		{"all: a", Options{Egress: EgressAll}, mdns.TypeA, "example.com.", true},
	}
	for _, tt := range tests {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		up := &upstream{}
		srv, _ := dns.NewWithUpstreamResolver(pc, nil, dnsZones(tt.opts), up)
		go func() { _ = srv.Serve() }()

		m := new(mdns.Msg)
		m.SetQuestion(tt.query, tt.qtype)
		r, _, err := new(mdns.Client).Exchange(m, pc.LocalAddr().String())
		_ = pc.Close()
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if len(r.Answer) > 0 {
			t.Errorf("%s: answered %v", tt.name, r.Answer)
		}
		if asked := len(up.asked) > 0; asked != tt.upstream {
			t.Errorf("%s: asked the host %v (%v), want %v", tt.name, asked, up.asked, tt.upstream)
		}
	}
}
