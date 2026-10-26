package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCompatibleAgent(t *testing.T) {
	if err := CompatibleAgent(AgentVersion); err != nil {
		t.Fatalf("matching agent version: %v", err)
	}
	if CompatibleAgent("") == nil {
		t.Fatal("empty agent version should fail")
	}
	if CompatibleAgent(AgentVersion+".x") == nil {
		t.Fatal("mismatched agent version should fail")
	}
}

type testAgent struct {
	client  *Client
	dial    DialFunc
	mounted chan string
}

// startAgent serves the agent API on loopback TCP, which, like the guest's
// vsock connections, supports deadlines (needed for request cancellation).
func startAgent(t *testing.T) *testAgent {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ta := &testAgent{mounted: make(chan string, 1)}
	srv := &Server{
		Info: func() (GuestInfo, error) {
			return GuestInfo{OSName: "macOS", AgentVersion: AgentVersion, Username: "root"}, nil
		},
		MountShare: func(p string) error { ta.mounted <- p; return nil },
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	ta.dial = func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
	ta.client = NewClient(ta.dial)
	t.Cleanup(func() { _ = ta.client.Close() })
	return ta
}

func TestInfoAndProbe(t *testing.T) {
	ta := startAgent(t)
	ctx := context.Background()

	info, err := ta.client.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.AgentVersion != AgentVersion || info.OSName != "macOS" {
		t.Errorf("info = %+v", info)
	}
	if _, err := Probe(ctx, ta.dial); err != nil {
		t.Errorf("Probe: %v", err)
	}

	c, _, err := WaitReady(ctx, ta.dial, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestWaitReadyTimesOut(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) { return nil, errors.New("down") }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := WaitReady(ctx, dial, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestSetWorkdir(t *testing.T) {
	ta := startAgent(t)
	wd, err := ta.client.SetWorkdir(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(wd.WorkPath) })

	if got := <-ta.mounted; got != wd.SharePath {
		t.Errorf("mounted %q, want %q", got, wd.SharePath)
	}
	if info, err := os.Stat(wd.WorkPath); err != nil || !info.IsDir() {
		t.Errorf("workdir not created: %v", err)
	}
}

func TestRunTask(t *testing.T) {
	ta := startAgent(t)
	ctx := context.Background()

	out, err := ta.client.RunTask(ctx, &Task{Command: "sh", Args: []string{"-c", "echo hi"}})
	if err != nil || out != "hi" {
		t.Fatalf("RunTask = %q, %v", out, err)
	}

	_, err = ta.client.RunTask(ctx, &Task{Command: "sh", Args: []string{"-c", "echo boom >&2; exit 3"}})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failing task err = %v", err)
	}
}

func TestBadRequestIsAnError(t *testing.T) {
	ta := startAgent(t)
	err := ta.client.doJSON(context.Background(), "POST", pathExec, map[string]any{"bogus": 1}, nil)
	if err == nil || !strings.Contains(err.Error(), "decode request") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunTaskCancelKillsProcess(t *testing.T) {
	ta := startAgent(t)
	pidFile := filepath.Join(t.TempDir(), "pid")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := ta.client.RunTask(ctx, &Task{
			Command: "sh",
			Args:    []string{"-c", `echo $$ > "$1"; exec sleep 30`, "_", pidFile},
			Timeout: 60,
		})
		errCh <- err
	}()

	pid := waitPID(t, pidFile)
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	waitExited(t, pid)
}

func TestRunStreamTask(t *testing.T) {
	ta := startAgent(t)
	r, err := ta.client.RunStreamTask(context.Background(),
		&Task{Command: "sh", Args: []string{"-c", "echo a; echo b"}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "a\nb\n" {
		t.Fatalf("stream = %q, %v", got, err)
	}
}

func TestRunStreamTaskFailure(t *testing.T) {
	ta := startAgent(t)
	r, err := ta.client.RunStreamTask(context.Background(),
		&Task{Command: "sh", Args: []string{"-c", "echo partial; echo bad >&2; exit 2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if string(got) != "partial\n" {
		t.Errorf("stdout = %q", got)
	}
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("err = %v, want task failure with stderr", err)
	}
}

func TestRunStreamTaskStartFailure(t *testing.T) {
	ta := startAgent(t)
	if _, err := ta.client.RunStreamTask(context.Background(),
		&Task{Command: "/nonexistent/machbox-tool"}); err == nil {
		t.Fatal("expected start error")
	}
}

// A timeout is the normal end of a dynamic run: output so far is kept and no
// error is reported, even when a child process still holds stdout open.
func TestRunStreamTaskTimeoutIsNormalEnd(t *testing.T) {
	ta := startAgent(t)
	start := time.Now()
	r, err := ta.client.RunStreamTask(context.Background(), &Task{
		Command: "sh",
		Args:    []string{"-c", "echo started; (sleep 30) & wait"},
		Timeout: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "started\n" {
		t.Fatalf("stream = %q, %v", got, err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("stream ended after %s, want ~1s", d)
	}
}

func waitPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("task did not start")
	return 0
}

func waitExited(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("task process %d still running after cancel", pid)
}
