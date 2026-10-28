package job

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/plugin"
)

func newManifestJob(t *testing.T, manifest string) (*Job, agent.WorkDir) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, plugin.ManifestName), manifest, 0o644)
	p, err := plugin.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	wf, _ := p.Workflow("w")
	j, err := create(filepath.Join(t.TempDir(), "job"), p, wf, map[string]string{}, &db.VM{UUID: "u", Name: "b"})
	if err != nil {
		t.Fatal(err)
	}
	return j, agent.WorkDir{SharePath: dir, WorkPath: t.TempDir()}
}

func TestStepLogCapAndStderr(t *testing.T) {
	old := maxLogSize
	maxLogSize = 256
	t.Cleanup(func() { maxLogSize = old })

	j, wd := newManifestJob(t, `
manifest_version: 1
name: p
workflows:
  w:
    env: {GREETING: hello}
    steps:
      - id: env
        run: [sh, -c, 'echo "$GREETING $WHO"; echo to-stderr >&2']
        env: {WHO: "${{ plugin_dir }}"}
      - id: flood
        run: [sh, -c, "yes | head -c 100000"]
`)
	if err := j.execute(context.Background(), startAgent(t), wd, nil); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(j.Dir, "logs", "env.log"), "hello "+wd.SharePath+"/plugin\nto-stderr\n")

	log, err := os.ReadFile(filepath.Join(j.Dir, "logs", "flood.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(log), strings.Repeat("y\n", 128)+"\n[machbox: log truncated at 256 bytes, 99744 bytes dropped]") {
		t.Errorf("flood log = %q", log)
	}
	if j.Steps[1].Status != StatusSucceeded {
		t.Errorf("flooding step: %s %s", j.Steps[1].Status, j.Steps[1].Error)
	}
}

// hangingGuest models a guest whose agent stopped answering (e.g. a
// sample SIGSTOPped it): tasks never end on their own.
type hangingGuest struct{ Guest }

func (hangingGuest) CopyTask(ctx context.Context, _ *agent.Task, _ io.Writer) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestHostEnforcesStepTimeout(t *testing.T) {
	old := hostGrace
	hostGrace = 100 * time.Millisecond
	t.Cleanup(func() { hostGrace = old })

	j, wd := newManifestJob(t, `
manifest_version: 1
name: p
workflows:
  w:
    steps:
      - id: stuck
        run: [x]
        timeout: 1s
`)
	start := time.Now()
	err := j.execute(context.Background(), hangingGuest{startAgent(t)}, wd, nil)
	if err == nil || j.Steps[0].Status != StatusTimedOut {
		t.Fatalf("err = %v, status %s", err, j.Steps[0].Status)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("gave up after %s", d)
	}
}

func TestTermWriter(t *testing.T) {
	var out strings.Builder
	w := &termWriter{w: &out}
	for _, chunk := range []string{"ok\tline\n\x1b]0;evil\x07\r", "é\xc2", "\x9b31m done\x7f\n"} {
		if n, err := w.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if got := out.String(); got != "ok\tline\n?]0;evil??é?31m done?\n" {
		t.Errorf("terminal output = %q", got)
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("ok\tline\n\x1b]52;c;evil\x07\x9b31m"); got != "ok\tline\n?]52;c;evil??31m" {
		t.Errorf("sanitize = %q", got)
	}
	long := sanitize(strings.Repeat("é", maxErrorLen))
	if !strings.HasSuffix(long, "… (truncated)") || len(long) > maxErrorLen+len("… (truncated)") {
		t.Errorf("long message not capped: %d bytes", len(long))
	}
}
