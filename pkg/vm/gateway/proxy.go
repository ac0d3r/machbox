package gateway

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
)

// ProxyHost resolves to the gateway, which serves the proxy on port 80.
const ProxyHost = "machbox.internal"

// credentialHeaders: most providers', Anthropic's and Gemini's.
var credentialHeaders = []string{"Authorization", "X-Api-Key", "X-Goog-Api-Key"}

// Proxy forwards the guest's requests to Upstream (request paths appended),
// with Key, if set, in place of the guest's credential.
type Proxy struct {
	Upstream *url.URL
	Key      string
}

// handler only ever connects to Upstream; redirects go back to the guest.
func (px *Proxy) handler() http.Handler {
	return &httputil.ReverseProxy{
		Rewrite:       px.rewrite,
		FlushInterval: -1, // SSE
		ModifyResponse: func(resp *http.Response) error {
			logrus.Debugf("ai proxy: %s %s: %s", resp.Request.Method, resp.Request.URL.Path, resp.Status)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Path only: the query may hold the key.
			if !errors.Is(err, context.Canceled) {
				logrus.Warnf("ai proxy: %s %s: %v", r.Method, r.URL.Path, err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// rewrite puts the key wherever the guest sent a credential, so each client
// keeps its provider's scheme; else in Authorization.
func (px *Proxy) rewrite(r *httputil.ProxyRequest) {
	r.SetURL(px.Upstream)
	if px.Key == "" {
		return
	}
	sent := false
	if q := r.Out.URL.Query(); q.Has("key") {
		sent = true
		q.Set("key", px.Key)
		r.Out.URL.RawQuery = q.Encode()
	}
	h := r.Out.Header
	for _, name := range credentialHeaders {
		if h.Get(name) == "" {
			continue
		}
		sent = true
		if name == "Authorization" {
			h.Set(name, "Bearer "+px.Key)
		} else {
			h.Set(name, px.Key)
		}
	}
	if !sent {
		h.Set("Authorization", "Bearer "+px.Key)
	}
}

func serveProxy(l net.Listener, px *Proxy) *http.Server {
	srv := &http.Server{
		Handler:           px.handler(),
		ReadHeaderTimeout: 30 * time.Second,
		// Not stderr: a session may own the terminal.
		ErrorLog: log.New(debugLog{}, "", 0),
	}
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Warnf("ai proxy: %v", err)
		}
	}()
	return srv
}

type debugLog struct{}

func (debugLog) Write(p []byte) (int, error) {
	logrus.Debugf("ai proxy: %s", bytes.TrimSpace(p))
	return len(p), nil
}
