package job

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
