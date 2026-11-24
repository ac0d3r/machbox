package job

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
)

// The remote command must reach the workdir and pass every argument
// through two shells intact, as sshd runs it: $SHELL -c <command>.
func TestRemoteCommand(t *testing.T) {
	work := filepath.Join(t.TempDir(), `it's a "dir" $x`)
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "SHELL=/bin/bash", "HOME="+t.TempDir())
	run := func(remote string) string {
		t.Helper()
		cmd := exec.Command("/bin/bash", "-c", remote)
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", remote, err)
		}
		return string(out)
	}

	args := []string{"/bin/sh", "-c", `printf '%s|' "$PWD" "$@"`, "sh", "a b", "it's", "$HOME", "*", `\`}
	got := run(remoteCommand(work, args))
	want := work + "|a b|it's|$HOME|*|\\|"
	if got != want {
		t.Errorf("command output = %q\nwant %q", got, want)
	}

	// The login shell: with no command, an interactive shell reads stdin.
	cmd := exec.Command("/bin/bash", "-c", remoteCommand(work, nil))
	cmd.Env = env
	cmd.Stdin = strings.NewReader("pwd\n")
	out, err := cmd.Output()
	if err != nil || !strings.Contains(string(out), work) {
		t.Errorf("login shell pwd = %q, %v; want %s", out, err, work)
	}
}

func TestSSHArgsIsolateTheSession(t *testing.T) {
	args := sshArgs("/k/id", "/k/known_hosts", "/run dir/100%/sock", "whoami", "cd /w && exec x")
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		"-F\n/dev/null", "IdentityAgent=none", "ForwardAgent=no", "ClearAllForwardings=yes",
		"PermitLocalCommand=no", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/k/known_hosts",
		"GlobalKnownHostsFile=/dev/null", "PasswordAuthentication=no", "SendEnv=LANG LC_*",
		"ProxyCommand=" + ncPath + " -U '/run dir/100%%/sock'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("ssh arguments lack %q:\n%s", want, joined)
		}
	}
	// The user is an option's value and the command follows --: neither
	// can be read as an option.
	if i := slices.Index(args, "-l"); i < 0 || args[i+1] != "whoami" {
		t.Errorf("user not passed with -l: %q", args)
	}
	if n := len(args); args[n-3] != sshHostAlias || args[n-2] != "--" || args[n-1] != "cd /w && exec x" {
		t.Errorf("args end with %q", args[n-3:])
	}
}

func TestConsoleUserIsChecked(t *testing.T) {
	for _, ok := range []string{"whoami", "john.doe", "_admin", "a-b_c"} {
		if !userRe.MatchString(ok) {
			t.Errorf("user %q refused", ok)
		}
	}
	for _, bad := range []string{"", "-oProxyCommand=x", "a b", "a;b", "a\nb", "../x", "é"} {
		if userRe.MatchString(bad) {
			t.Errorf("user %q accepted", bad)
		}
	}
}

// scriptGuest answers RunTask with fixed output and records the task.
type scriptGuest struct {
	Guest
	out  string
	task *agent.Task
}

func (g *scriptGuest) RunTask(_ context.Context, task *agent.Task) (string, error) {
	g.task = task
	return g.out, nil
}

func TestPrepareGuest(t *testing.T) {
	g := &scriptGuest{out: "noise\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK+x/y= root@guest\n"}
	key, err := prepareGuest(context.Background(), g, "whoami", "/tmp/w", "ssh-ed25519 AAAA machbox")
	if err != nil {
		t.Fatal(err)
	}
	if key != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK+x/y=" {
		t.Errorf("host key = %q", key)
	}
	// Values are arguments of the script, never part of it.
	if want := []string{"-c", prepareScript, "sh", "whoami", "/tmp/w", "ssh-ed25519 AAAA machbox"}; !slices.Equal(g.task.Args, want) {
		t.Errorf("task args = %q", g.task.Args)
	}

	for _, out := range []string{"", "ssh-rsa AAAA", "@cert-authority * ssh-ed25519 AAAA", "ssh-ed25519 !!"} {
		if _, err := prepareGuest(context.Background(), &scriptGuest{out: out}, "u", "/w", "k"); err == nil {
			t.Errorf("host key output %q accepted", out)
		}
	}
}

func TestSessionDirFallsBackForLongPaths(t *testing.T) {
	// t.TempDir is too deep on macOS for a socket path; a run dir is not.
	short, err := os.MkdirTemp("/tmp", "mb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	dir, cleanup, err := sessionDir(short)
	if err != nil || dir != filepath.Join(short, "ssh") {
		t.Fatalf("sessionDir = %s, %v", dir, err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("session dir mode: %v, %v", info, err)
	}
	cleanup()
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cleanup left %s", dir)
	}

	long := filepath.Join(t.TempDir(), strings.Repeat("x", 120))
	dir, cleanup, err = sessionDir(long)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if strings.HasPrefix(dir, long) || len(filepath.Join(dir, "sock")) > maxSockPath {
		t.Errorf("session dir %s for a long run dir", dir)
	}
}

// sshGuest reaches a fake sshd through a real agent's /v1/ssh.
type sshGuest struct {
	Guest
	c *agent.Client
}

func (g sshGuest) DialSSH(ctx context.Context) (io.ReadWriteCloser, error) { return g.c.DialSSH(ctx) }

func startSSHAgent(t *testing.T, sshAddr string) *agent.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&agent.Server{SSHAddr: sshAddr}).Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	return agent.NewClient(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	})
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func TestBridge(t *testing.T) {
	g := sshGuest{c: startSSHAgent(t, echoServer(t))}
	sock := filepath.Join(t.TempDir(), "sock")
	b, err := bridge(context.Background(), sock, g)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(sock); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode: %v, %v", info, err)
	}

	// Two connections in turn, like ssh retrying, both reach sshd.
	for range 2 {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, "hello\n"); err != nil {
			t.Fatal(err)
		}
		if line, err := bufio.NewReader(c).ReadString('\n'); err != nil || line != "hello\n" {
			t.Fatalf("echo = %q, %v", line, err)
		}
		_ = c.Close()
	}

	// An open connection does not keep close from returning.
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "x\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { b.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("bridge close hung on an open connection")
	}
	if b.lastErr() != nil {
		t.Errorf("lastErr = %v", b.lastErr())
	}
}

func TestBridgeRecordsDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	g := sshGuest{c: startSSHAgent(t, addr)}
	sock := filepath.Join(t.TempDir(), "sock")
	b, err := bridge(context.Background(), sock, g)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, c) // closed by the bridge
	_ = c.Close()
	if err := b.lastErr(); err == nil || !strings.Contains(err.Error(), "Remote Login") {
		t.Errorf("lastErr = %v", err)
	}
}

func fakeSSH(t *testing.T, script string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	writeFile(t, path, "#!/bin/sh\n"+script+"\n", 0o755)
	old := sshPath
	sshPath = path
	t.Cleanup(func() { sshPath = old })
}

func TestRunSSHExitCode(t *testing.T) {
	fakeSSH(t, "exit 3")
	code, err := runSSH(context.Background(), nil)
	if err != nil || code != 3 {
		t.Errorf("runSSH = %d, %v; want 3", code, err)
	}
}

// Cancelling sends SIGHUP, which ssh handles by restoring the terminal.
func TestRunSSHCancelSendsHUP(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hup")
	fakeSSH(t, `trap 'touch "`+marker+`"; exit 255' HUP; while :; do sleep 0.1; done`)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	code, err := runSSH(ctx, nil)
	if err != nil || code != 255 {
		t.Errorf("runSSH = %d, %v; want 255", code, err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("ssh did not get SIGHUP")
	}
}

func TestBanner(t *testing.T) {
	j := &Job{Dir: "/jobs/j"}
	var b strings.Builder
	j.banner(&b, &session{baseline: "base", user: "u", workDir: "/tmp/w"})
	if s := b.String(); !strings.Contains(s, "base · u · /tmp/w") || !strings.Contains(s, "exit: end the session") ||
		!strings.Contains(s, "/jobs/j/"+sessionLog) || strings.Contains(s, "job failed") {
		t.Errorf("banner:\n%s", s)
	}

	j.Status = StatusFailed
	b.Reset()
	j.banner(&b, &session{baseline: "base", user: "u", workDir: "/tmp/w", command: []string{"/usr/local/bin/claude"}, gui: true})
	if s := b.String(); !strings.Contains(s, "· /usr/local/bin/claude · job failed") ||
		!strings.Contains(s, "quit claude or close the VM window: end the session") {
		t.Errorf("banner:\n%s", s)
	}
}

// stuckGuest models an agent a sample stopped: a dial answers only when
// its ctx ends.
type stuckGuest struct{ Guest }

func (stuckGuest) DialSSH(ctx context.Context) (io.ReadWriteCloser, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// Once ssh gives up (~.), close must not wait on a dial the guest never
// answers.
func TestBridgeCloseEndsPendingDials(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sock")
	b, err := bridge(context.Background(), sock, stuckGuest{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // the dial is pending
	_ = c.Close()
	closed := make(chan struct{})
	go func() { b.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("bridge close waited on a dial to a stuck agent")
	}
}
