package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTaskTimeout = 60 * time.Second
	// After a task is killed, Wait gives up on its stdout/stderr pipes after
	// this long; children it spawned (e.g. a sample's) may still hold them.
	taskWaitDelay = 2 * time.Second
	maxRequestBody     = 1 << 20
)

// Server is the guest-agent HTTP API.
type Server struct {
	Info       func() (GuestInfo, error)
	MountShare func(sharePath string) error
}

// Serve handles requests until ctx is cancelled or the listener fails.
// Cancelling ctx also cancels running tasks.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	hs := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		_ = hs.Close()
	}()

	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler returns the agent's HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+pathInfo, s.handleInfo)
	mux.HandleFunc("POST "+pathWorkDir, s.handleWorkDir)
	mux.HandleFunc("POST "+pathExec, s.handleExec)
	mux.HandleFunc("POST "+pathExecStream, s.handleExecStream)
	return mux
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	info, err := s.Info()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("collect guest info: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleWorkDir(w http.ResponseWriter, r *http.Request) {
	var wd WorkDir
	if !readJSON(w, r, &wd) {
		return
	}
	if wd.SharePath != "" && s.MountShare != nil {
		if err := s.MountShare(wd.SharePath); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("mount share: %w", err))
			return
		}
	}
	if wd.WorkPath != "" {
		if err := os.MkdirAll(wd.WorkPath, 0o750); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("mkdir workdir: %w", err))
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	var task Task
	if !readJSON(w, r, &task) {
		return
	}
	ctx, cancel := taskContext(r.Context(), &task)
	defer cancel()
	cmd := taskCommand(ctx, &task)

	var ret TaskResult
	if out, err := cmd.Output(); err != nil {
		ret.Error = execErr(err)
	} else {
		ret.OK = true
		ret.Output = string(out)
	}
	writeJSON(w, http.StatusOK, ret)
}

// handleExecStream streams the task's stdout as the response body and
// reports how it ended in trailers, since the status line is already sent
// by then. A task that cannot be started is a plain HTTP error.
func (s *Server) handleExecStream(w http.ResponseWriter, r *http.Request) {
	var task Task
	if !readJSON(w, r, &task) {
		return
	}
	ctx, cancel := taskContext(r.Context(), &task)
	defer cancel()

	cmd := taskCommand(ctx, &task)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := cmd.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Trailer", trailerTaskError+", "+trailerTaskTimedOut)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)

	// Killing the task does not end the read if a child it spawned still
	// holds stdout; closing our end on timeout/cancel does.
	go func() {
		<-ctx.Done()
		_ = stdout.Close()
	}()

	var copyErr error
	buf := make([]byte, 32*1024)
	for {
		n, err := stdout.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				copyErr = werr // host went away; ctx cancellation kills the task
				break
			}
			_ = rc.Flush()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				copyErr = err
			}
			break
		}
	}
	if copyErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()

	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	var msg string
	switch {
	case timedOut:
		msg = context.DeadlineExceeded.Error()
	case copyErr != nil:
		msg = copyErr.Error()
	case waitErr != nil:
		msg = waitErr.Error()
	}
	if msg != "" {
		if s := strings.TrimSpace(stderr.String()); s != "" {
			msg = fmt.Sprintf("%s (stderr: %s)", msg, s)
		}
	}
	w.Header().Set(trailerTaskError, msg)
	w.Header().Set(trailerTaskTimedOut, strconv.FormatBool(timedOut))
}

func taskContext(parent context.Context, task *Task) (context.Context, context.CancelFunc) {
	timeout := defaultTaskTimeout
	if task.Timeout > 0 {
		timeout = time.Duration(task.Timeout) * time.Second
	}
	return context.WithTimeout(parent, timeout)
}

func taskCommand(ctx context.Context, task *Task) *exec.Cmd {
	// #nosec G204 -- guest-agent executes commands from the trusted host.
	cmd := exec.CommandContext(ctx, task.Command, task.Args...)
	cmd.Dir = task.WorkDir
	cmd.WaitDelay = taskWaitDelay
	return cmd
}

func execErr(err error) string {
	var eerr *exec.ExitError
	if errors.As(err, &eerr) {
		return fmt.Sprintf("%s (stderr: %s)", err.Error(), strings.TrimSpace(string(eerr.Stderr)))
	}
	return err.Error()
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "write response: %v\n", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, apiError{Error: err.Error()})
}
