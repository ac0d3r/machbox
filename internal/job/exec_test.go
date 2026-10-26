package job

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/plugin"
)

const testManifest = `
manifest_version: 1
name: demo
version: 0.1.0
workflows:
  analyze:
    inputs:
      sample: { type: file, required: true }
      label:  { default: none }
    steps:
      - id: static
        run: [tools/static, "${{ output }}", "${{ inputs.sample }}", "${{ inputs.label }}"]
        output: static.json
      - id: dynamic
        run: [tools/dynamic, "${{ output }}"]
        output: dynamic.jsonl
        continue_on_error: true
      - id: slow
        run: [sh, -c, "echo slow; sleep 30"]
        timeout: 1s
        continue_on_error: true
      - id: report
        when: always
        run: [sh, -c, 'cat "$1" "$2" > "$0"', "${{ output }}", "${{ steps.static.output }}", "${{ steps.dynamic.output }}"]
        output: out/report.json
      - id: missing
        run: [sh, -c, "echo no output written"]
        output: missing.json
      - id: after
        run: [sh, -c, "echo should not run"]
      - id: cleanup
        when: failure
        run: [sh, -c, "echo cleanup in $PWD"]
`

var testTools = map[string]string{
	// The sample copy in the workdir must be writable.
	"static": `#!/bin/sh
echo "static on $2 ($3)"
echo tampered >> "$2" || exit 1
printf '{"name":"%s"}\n' "$(basename "$2")" > "$1"
`,
	"dynamic": `#!/bin/sh
echo dynamic
echo '{"partial":true}' > "$1"
exit 2
`,
}

func TestExecuteWorkflow(t *testing.T) {
	pluginDir := t.TempDir()
	writeFile(t, filepath.Join(pluginDir, plugin.ManifestName), testManifest, 0o644)
	for name, script := range testTools {
		writeFile(t, filepath.Join(pluginDir, "tools", name), script, 0o755)
	}
	sample := filepath.Join(t.TempDir(), "Sample.bin")
	writeFile(t, sample, "MZ", 0o444)

	j, wd, err := runLocal(t, pluginDir, "analyze", []string{sample})
	if err == nil || !strings.Contains(err.Error(), "step missing") {
		t.Fatalf("execute error = %v, want failure of step missing", err)
	}

	want := map[string]Status{
		"static":  StatusSucceeded,
		"dynamic": StatusFailed,
		"slow":    StatusTimedOut,
		"report":  StatusSucceeded,
		"missing": StatusFailed,
		"after":   StatusSkipped,
		"cleanup": StatusSucceeded,
	}
	for _, s := range j.Steps {
		if s.Status != want[s.ID] {
			t.Errorf("step %s: status %s, want %s (error: %s)", s.ID, s.Status, want[s.ID], s.Error)
		}
	}

	// Outputs, including the partial one of a failed step, are collected.
	assertFile(t, filepath.Join(j.Dir, "outputs", "static.json"), `{"name":"Sample.bin"}`+"\n")
	assertFile(t, filepath.Join(j.Dir, "outputs", "dynamic.jsonl"), `{"partial":true}`+"\n")
	assertFile(t, filepath.Join(j.Dir, "outputs", "out", "report.json"),
		`{"name":"Sample.bin"}`+"\n"+`{"partial":true}`+"\n")
	assertFile(t, filepath.Join(j.Dir, "logs", "static.log"), "static on inputs/sample/Sample.bin (none)\n")
	assertFile(t, filepath.Join(j.Dir, "logs", "slow.log"), "slow\n")
	assertFile(t, filepath.Join(j.Dir, "logs", "cleanup.log"), "cleanup in "+wd.WorkPath+"\n")
	if _, err := os.Stat(filepath.Join(j.Dir, "logs", "after.log")); !os.IsNotExist(err) {
		t.Errorf("skipped step has a log: %v", err)
	}
	if got, _ := os.ReadFile(sample); string(got) != "MZ" {
		t.Errorf("host sample modified: %q", got)
	}

	data, err := os.ReadFile(filepath.Join(j.Dir, recordName))
	if err != nil {
		t.Fatal(err)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Status != StatusFailed || rec.Inputs["sample"] != sample || rec.Steps[0].Output != "outputs/static.json" {
		t.Errorf("record = %+v", rec)
	}
}

func TestPullOutputSizeLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a file larger than MaxOutputSize")
	}
	work := t.TempDir()
	f, err := os.Create(filepath.Join(work, "big"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxOutputSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	j := &Job{Dir: t.TempDir()}
	if _, err := j.pullOutput(context.Background(), startAgent(t), agent.WorkDir{WorkPath: work}, "big"); err == nil {
		t.Fatal("oversized output accepted")
	}
	if entries, _ := os.ReadDir(filepath.Join(j.Dir, outputsDir)); len(entries) != 0 {
		t.Errorf("partial output left behind: %v", entries)
	}
}

// runLocal runs a workflow against a guest agent serving on loopback: its
// tasks run on this machine, and share and workdir are plain directories.
func runLocal(t *testing.T, pluginDir, workflow string, args []string) (*Job, agent.WorkDir, error) {
	t.Helper()
	p, err := plugin.Load(pluginDir)
	if err != nil {
		t.Fatal(err)
	}
	wf, err := p.Workflow(workflow)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := wf.ParseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	j, err := create(filepath.Join(t.TempDir(), "job"), p, wf, inputs, &db.VM{UUID: "u", Name: "b"})
	if err != nil {
		t.Fatal(err)
	}

	wd := agent.WorkDir{SharePath: t.TempDir(), WorkPath: filepath.Join(t.TempDir(), "work")}
	if err := os.Mkdir(wd.WorkPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := j.share(func(hostPath, name string) error {
		dst := filepath.Join(wd.SharePath, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return exec.Command("cp", "-R", hostPath, dst).Run()
	}); err != nil {
		t.Fatal(err)
	}

	err = j.execute(context.Background(), startAgent(t), wd, nil)
	j.finish(err)
	return j, wd, err
}

func startAgent(t *testing.T) *agent.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &agent.Server{Info: func() (agent.GuestInfo, error) { return agent.GuestInfo{}, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	c := agent.NewClient(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	})
	t.Cleanup(func() {
		_ = c.Close()
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return c
}

func writeFile(t *testing.T, name, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, name, want string) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil {
		t.Error(err)
		return
	}
	if string(got) != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}
