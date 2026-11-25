package job

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ac0d3r/machbox/internal/plugin"
	"github.com/ac0d3r/machbox/pkg/vm/gateway"
)

const demoPlugin = "../../testdata/plugins/demo"

type demoReport struct {
	Info *struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"info"`
	Run []struct {
		Event  string `json:"event"`
		Status *int   `json:"status"`
	} `json:"run"`
}

// The demo plugin's tools are plain sh, so its workflows run unchanged
// against the loopback agent. Samples here are harmless scripts.
func TestDemoPluginAnalyze(t *testing.T) {
	tests := []struct {
		name, script string
		duration     string
		wantEvent    string
		wantStatus   int
	}{
		{"exits", "#!/bin/sh\necho hello from sample\nexit 3\n", "10", "exit", 3},
		{"killed", "#!/bin/sh\nsleep 30\n", "1", "killed", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sample := filepath.Join(t.TempDir(), "sample.sh")
			writeFile(t, sample, tt.script, 0o644)

			j, _, err := runLocal(t, demoPlugin, "analyze", []string{sample, "--duration", tt.duration})
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range j.Steps {
				if s.Status != StatusSucceeded {
					t.Errorf("step %s: %s %s", s.ID, s.Status, s.Error)
				}
			}

			var r demoReport
			readJSON(t, filepath.Join(j.Dir, "outputs", "report", "report.json"), &r)
			if r.Info == nil || r.Info.Name != "sample.sh" || r.Info.Size != int64(len(tt.script)) || len(r.Info.SHA256) != 64 {
				t.Errorf("report info = %+v", r.Info)
			}
			if len(r.Run) != 2 || r.Run[0].Event != "start" || r.Run[1].Event != tt.wantEvent {
				t.Fatalf("report run = %+v", r.Run)
			}
			if tt.wantEvent == "exit" && (r.Run[1].Status == nil || *r.Run[1].Status != tt.wantStatus) {
				t.Errorf("exit status = %v, want %d", r.Run[1].Status, tt.wantStatus)
			}
		})
	}

	t.Run("sample log", func(t *testing.T) {
		sample := filepath.Join(t.TempDir(), "sample.sh")
		writeFile(t, sample, "#!/bin/sh\necho hello from sample\n", 0o644)
		j, _, err := runLocal(t, demoPlugin, "analyze", []string{sample})
		if err != nil {
			t.Fatal(err)
		}
		log, err := os.ReadFile(filepath.Join(j.Dir, "logs", "run.log"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(log), "sample: hello from sample") {
			t.Errorf("run log = %q", log)
		}
	})
}

// The network workflows' settings; their effect needs a real guest.
func TestDemoPluginNetworkManifest(t *testing.T) {
	p, err := plugin.Load(demoPlugin)
	if err != nil {
		t.Fatal(err)
	}
	if wf := p.Workflows["network"]; wf.Network != "gateway" || wf.Egress != gateway.EgressPublic || wf.AIProxy != nil {
		t.Errorf("network: %s egress %s, ai_proxy %v", wf.Network, wf.Egress, wf.AIProxy)
	}
	for _, name := range []string{"ai", "ai-shell"} {
		wf := p.Workflows[name]
		if wf.Network != "gateway" || wf.Egress != gateway.EgressNone ||
			wf.AIProxy == nil || wf.AIProxy.KeyEnv != "ANTHROPIC_API_KEY" {
			t.Errorf("%s: %s egress %s, ai_proxy %+v", name, wf.Network, wf.Egress, wf.AIProxy)
		}
	}
	if wf := p.Workflows["ai-shell"]; len(wf.Steps) != 0 || !wf.Attach.Enabled || len(wf.Attach.Command) == 0 {
		t.Errorf("ai-shell: steps %d, attach %+v", len(wf.Steps), wf.Attach)
	}
}

type probeResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Curl   int    `json:"curl"`
}

// probe runs workflow and returns its probe.jsonl. Local servers stand in
// for the guest's targets.
func probe(t *testing.T, workflow string, args ...string) []probeResult {
	t.Helper()
	j, _, err := runLocal(t, demoPlugin, workflow, args)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(j.Dir, "outputs", "probe.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rs []probeResult
	for sc := bufio.NewScanner(f); sc.Scan(); {
		var r probeResult
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("%v: %s", err, sc.Bytes())
		}
		rs = append(rs, r)
	}
	return rs
}

func TestDemoPluginProbe(t *testing.T) {
	var (
		mu     sync.Mutex
		header http.Header
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		header = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close() // refused

	rs := probe(t, "network", "--public", up.URL+"/", "--private", down.URL+"/")
	if len(rs) != 2 || rs[0].Status != http.StatusNoContent || rs[0].Curl != 0 || rs[1].Status != 0 || rs[1].Curl != 7 {
		t.Errorf("network probe = %+v", rs)
	}

	rs = probe(t, "ai", "--proxy", up.URL+"/v1/models", "--public", "http://no-such-host.invalid/")
	if len(rs) != 2 || rs[0].Status != http.StatusNoContent || rs[1].Status != 0 || rs[1].Curl != 6 {
		t.Errorf("ai probe = %+v", rs)
	}
	mu.Lock()
	defer mu.Unlock()
	if header.Get("X-Api-Key") != "machbox" || header.Get("Anthropic-Version") == "" {
		t.Errorf("proxy request headers = %v", header)
	}
}

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v\n%s", name, err, data)
	}
}
