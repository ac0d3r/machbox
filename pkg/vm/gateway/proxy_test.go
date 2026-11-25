package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
)

func TestProxyCredentials(t *testing.T) {
	var got *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL + "/api")

	tests := []struct {
		name   string
		key    string
		target string
		header map[string]string
		want   map[string]string
		query  string
	}{
		{"anthropic", "real", "/v1/messages", map[string]string{"X-Api-Key": "dummy"},
			map[string]string{"X-Api-Key": "real", "Authorization": ""}, ""},
		{"openai", "real", "/v1/chat/completions", map[string]string{"Authorization": "Bearer dummy"},
			map[string]string{"Authorization": "Bearer real", "X-Api-Key": ""}, ""},
		{"gemini", "real", "/v1beta/models?key=dummy&alt=sse", map[string]string{"X-Goog-Api-Key": "dummy"},
			map[string]string{"X-Goog-Api-Key": "real", "Authorization": ""}, "alt=sse&key=real"},
		{"gemini query", "real", "/v1beta/models?key=dummy", nil,
			map[string]string{"Authorization": ""}, "key=real"},
		{"none sent", "real", "/v1/models", nil, map[string]string{"Authorization": "Bearer real"}, ""},
		{"no key", "", "/v1/models", map[string]string{"X-Api-Key": "guest"},
			map[string]string{"X-Api-Key": "guest", "Authorization": ""}, ""},
	}
	for _, tt := range tests {
		px := &Proxy{Upstream: base, Key: tt.key}
		h := px.handler()
		req := httptest.NewRequest(http.MethodPost, "http://"+ProxyHost+tt.target, strings.NewReader("{}"))
		for k, v := range tt.header {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || got == nil {
			t.Fatalf("%s: status %d", tt.name, rec.Code)
		}
		if want := "/api" + strings.SplitN(tt.target, "?", 2)[0]; got.URL.Path != want {
			t.Errorf("%s: path %s, want %s", tt.name, got.URL.Path, want)
		}
		if got.Host != base.Host {
			t.Errorf("%s: host %s, want %s", tt.name, got.Host, base.Host)
		}
		for k, v := range tt.want {
			if got.Header.Get(k) != v {
				t.Errorf("%s: %s = %q, want %q", tt.name, k, got.Header.Get(k), v)
			}
		}
		if got.URL.RawQuery != tt.query {
			t.Errorf("%s: query %q, want %q", tt.name, got.URL.RawQuery, tt.query)
		}
		got = nil
	}
}

// The stack cannot dial itself: only start and close are checked.
func TestGatewayWithProxy(t *testing.T) {
	base, _ := url.Parse("https://api.example.com")
	g, err := Start(Options{Proxy: &Proxy{Upstream: base, Key: "k"}})
	if err != nil {
		t.Fatal(err)
	}
	if g.proxy == nil {
		t.Error("no proxy server")
	}
	if err := g.Close(); err != nil {
		t.Error(err)
	}
}

// A failed request's log does not show the key.
func TestProxyErrorHidesKey(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	base, _ := url.Parse(upstream.URL)
	upstream.Close() // refused

	logs := test.NewGlobal()
	rec := httptest.NewRecorder()
	(&Proxy{Upstream: base, Key: "secret"}).handler().ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "http://"+ProxyHost+"/v1beta/models?key=dummy", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status %d, want 502", rec.Code)
	}
	if len(logs.Entries) == 0 {
		t.Fatal("nothing logged")
	}
	for _, e := range logs.Entries {
		if strings.Contains(e.Message, "secret") {
			t.Errorf("log shows the key: %s", e.Message)
		}
	}
}
