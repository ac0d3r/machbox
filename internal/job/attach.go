package job

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"

	"github.com/sirupsen/logrus"
)

// The host tools a session uses; all ship with macOS.
var (
	sshPath    = "/usr/bin/ssh"
	keygenPath = "/usr/bin/ssh-keygen"
	ncPath     = "/usr/bin/nc"
)

const (
	// sshHostAlias names the guest in ssh's arguments and known_hosts.
	sshHostAlias = "machbox"
	// sessionLog receives machbox's own log while ssh owns the terminal.
	sessionLog = "machbox.log"
	// prepareTimeout bounds setting up the guest for the session.
	prepareTimeout = 2 * time.Minute
	// sshStopDelay is how long ssh gets to restore the terminal and exit
	// after SIGHUP before it is killed.
	sshStopDelay = 5 * time.Second
	// maxSockPath is the longest unix socket path macOS accepts.
	maxSockPath = 103
)

var (
	// userRe is a macOS short user name. The console user comes from the
	// guest, which a sample may control: it goes into ssh's arguments.
	userRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,254}$`)
	// hostKeyRe is the guest's ed25519 host key, as its .pub file starts.
	hostKeyRe = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+={0,2}`)
)

// attachGuest is the guest a session needs.
type attachGuest interface {
	Guest
	DialSSH(ctx context.Context) (io.ReadWriteCloser, error)
}

// CheckAttach reports why this host cannot attach a session, before
// anything boots.
func CheckAttach() error {
	for _, p := range []string{sshPath, keygenPath, ncPath} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("attach needs %s: %w", p, err)
		}
	}
	return nil
}

// session is what attach needs to know about the job.
type session struct {
	guest    attachGuest
	runDir   string // the run's private directory; removed with the run
	user     string // the guest's console user
	workDir  string
	command  []string // empty: the login shell
	baseline string
	gui      bool
}

// attach runs the terminal session of machbox run --attach: the host's ssh,
// through a unix socket this process connects to the guest's sshd over
// vsock, logged in as the console user in the workdir. It returns when ssh
// exits or ctx is cancelled (the VM stopped).
func (j *Job) attach(ctx context.Context, s *session) error {
	if !userRe.MatchString(s.user) {
		return fmt.Errorf("guest console user %q is not a valid user name", s.user)
	}
	dir, cleanup, err := sessionDir(s.runDir)
	if err != nil {
		return err
	}
	defer cleanup()

	key := filepath.Join(dir, "id")
	// #nosec G204 -- fixed tool; key is our own path.
	if out, err := exec.CommandContext(ctx, keygenPath, "-q", "-t", "ed25519", "-N", "", "-C", "machbox", "-f", key).CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-keygen: %w: %s", err, strings.TrimSpace(string(out)))
	}
	pub, err := os.ReadFile(key + ".pub") // #nosec G304 -- ssh-keygen wrote it in our session directory
	if err != nil {
		return err
	}
	hostKey, err := prepareGuest(ctx, s.guest, s.user, s.workDir, strings.TrimSpace(string(pub)))
	if err != nil {
		return err
	}
	knownHosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(sshHostAlias+" "+hostKey+"\n"), 0o600); err != nil {
		return err
	}

	sock := filepath.Join(dir, "sock")
	b, err := bridge(ctx, sock, s.guest)
	if err != nil {
		return err
	}
	defer b.close()

	j.banner(os.Stderr, s)
	restore, err := logTo(filepath.Join(j.Dir, sessionLog))
	if err != nil {
		return err
	}
	code, err := runSSH(ctx, sshArgs(key, knownHosts, sock, s.user, remoteCommand(s.workDir, s.command)))
	restore()
	switch {
	case err != nil:
		return err
	case ctx.Err() != nil:
		logrus.Info("session ended: VM stopped")
	case code == 255 && b.lastErr() != nil:
		return fmt.Errorf("session: %w", b.lastErr())
	case code == 255:
		logrus.Info("session disconnected")
	default:
		logrus.Infof("session ended (exit %d)", code)
	}
	return nil
}

// sessionDir makes a private directory for the session's key, known_hosts
// and socket in the run directory, or in $TMPDIR when the socket's path
// would be too long there.
func sessionDir(runDir string) (dir string, cleanup func(), err error) {
	dir = filepath.Join(runDir, "ssh")
	if len(filepath.Join(dir, "sock")) <= maxSockPath {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return "", nil, err
		}
		return dir, func() { _ = os.RemoveAll(dir) }, nil
	}
	dir, err = os.MkdirTemp("", "machbox-ssh-")
	if err != nil {
		return "", nil, err
	}
	if len(filepath.Join(dir, "sock")) > maxSockPath {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("no directory short enough for a unix socket (%s)", dir)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// prepareScript runs as root in the guest: it gives the workdir to the
// console user, lets the session's key log in as them and prints the
// guest's host key. Values come as arguments, never as code.
const prepareScript = `set -eu
u=$1 wd=$2 key=$3
g=$(/usr/bin/id -gn "$u")
home=$(/usr/bin/dscl . -read "/Users/$u" NFSHomeDirectory)
home=${home#NFSHomeDirectory: }
/usr/sbin/chown -R "$u:$g" "$wd"
/bin/mkdir -p "$home/.ssh"
printf '%s\n' "$key" >>"$home/.ssh/authorized_keys"
/usr/sbin/chown "$u:$g" "$home/.ssh" "$home/.ssh/authorized_keys"
/bin/chmod 700 "$home/.ssh"
/bin/chmod 600 "$home/.ssh/authorized_keys"
/bin/cat /etc/ssh/ssh_host_ed25519_key.pub`

// prepareGuest runs prepareScript and returns the guest's host key.
func prepareGuest(ctx context.Context, g Guest, user, workDir, pubKey string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, prepareTimeout)
	defer cancel()
	out, err := g.RunTask(ctx, &agent.Task{
		Command: "/bin/sh",
		Args:    []string{"-c", prepareScript, "sh", user, workDir, pubKey},
		Timeout: int(prepareTimeout / time.Second),
	})
	if err != nil {
		return "", fmt.Errorf("prepare the guest for the session: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	hostKey := hostKeyRe.FindString(strings.TrimSpace(lines[len(lines)-1]))
	if hostKey == "" {
		return "", errors.New("prepare the guest for the session: no ed25519 host key (is Remote Login on?)")
	}
	return hostKey, nil
}

// sessionBridge accepts ssh's connections (through nc) on a unix socket
// and connects each to the guest's sshd.
type sessionBridge struct {
	ln    net.Listener
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	err   error // the last failure to reach the guest's sshd
}

func bridge(ctx context.Context, sock string, g attachGuest) (*sessionBridge, error) {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	b := &sessionBridge{ln: ln, conns: map[net.Conn]struct{}{}}
	b.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.track(c, true)
			b.wg.Go(func() {
				defer b.track(c, false)
				stream, err := g.DialSSH(ctx)
				if err != nil {
					b.mu.Lock()
					b.err = err
					b.mu.Unlock()
					_ = c.Close()
					return
				}
				agent.Splice(c, stream)
			})
		}
	})
	return b, nil
}

func (b *sessionBridge) track(c net.Conn, open bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if open {
		b.conns[c] = struct{}{}
	} else {
		delete(b.conns, c)
	}
}

// lastErr returns the last failure to reach the guest's sshd.
func (b *sessionBridge) lastErr() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// close stops accepting, ends open connections and waits for them.
func (b *sessionBridge) close() {
	_ = b.ln.Close()
	b.mu.Lock()
	for c := range b.conns {
		_ = c.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

// sshArgs keeps ssh to the session: no user config, agent or forwarding
// reaches a guest a sample may control, and the guest is known only by the
// host key read from it.
func sshArgs(key, knownHosts, sock, user, remote string) []string {
	return []string{
		"-tt", "-F", "/dev/null",
		"-o", "LogLevel=ERROR",
		"-i", key,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "HostKeyAlias=" + sshHostAlias,
		// ssh runs it with the shell and expands %-tokens in it.
		"-o", "ProxyCommand=" + ncPath + " -U " + strings.ReplaceAll(shellQuote(sock), "%", "%%"),
		"-l", user,
		sshHostAlias, "--", remote,
	}
}

// remoteCommand is what the guest user's shell runs: the session starts in
// the workdir, in an interactive login shell so its PATH is the user's.
func remoteCommand(workDir string, command []string) string {
	if len(command) == 0 {
		return "cd " + shellQuote(workDir) + ` && exec "$SHELL" -l`
	}
	quoted := make([]string, len(command))
	for i, a := range command {
		quoted[i] = shellQuote(a)
	}
	return "cd " + shellQuote(workDir) + ` && exec "$SHELL" -lic ` + shellQuote("exec "+strings.Join(quoted, " "))
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runSSH runs ssh on this process's terminal and returns its exit code.
// When ctx is cancelled, ssh gets SIGHUP, which it handles by restoring
// the terminal; it is killed only if it does not exit then.
func runSSH(ctx context.Context, args []string) (int, error) {
	cmd := exec.Command(sshPath, args...) // #nosec G204 -- fixed tool; arguments built by sshArgs
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start ssh: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = cmd.Process.Signal(syscall.SIGHUP)
		select {
		case err = <-done:
		case <-time.After(sshStopDelay):
			_ = cmd.Process.Kill()
			err = <-done
		}
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 0, fmt.Errorf("ssh: %w", err)
	}
	return 0, nil
}

// banner tells the user the terminal now belongs to the guest.
func (j *Job) banner(w io.Writer, s *session) {
	parts := []string{s.baseline, s.user, s.workDir}
	if len(s.command) > 0 {
		parts = append(parts, s.command[0])
	}
	if j.Status == StatusFailed {
		parts = append(parts, "job failed")
	}
	end := "exit"
	if len(s.command) > 0 {
		end = "quit " + filepath.Base(s.command[0])
	}
	if s.gui {
		end += " or close the VM window"
	}
	title := "── " + strings.Join(parts, " · ") + " "
	rule := strings.Repeat("─", 72)
	fmt.Fprintf(w, "\n%s%s\n   %s: end the session and discard the VM · ~.: disconnect\n   machbox log: %s\n%s\n",
		title, strings.Repeat("─", max(72-len([]rune(title)), 3)),
		end, filepath.Join(j.Dir, sessionLog), rule)
}

// logTo sends machbox's log to path until restore is called, so nothing
// but ssh writes to the terminal during the session.
func logTo(path string) (restore func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- in the job directory
	if err != nil {
		return nil, err
	}
	l := logrus.StandardLogger()
	prev := l.Out
	l.SetOutput(f)
	return func() {
		l.SetOutput(prev)
		_ = f.Close()
	}, nil
}
