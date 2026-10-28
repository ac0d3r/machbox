package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const manifest = `manifest_version: 1
name: demo
version: %s
workflows:
  info:
    steps:
      - id: info
        run: [tools/info]
`

type entry struct {
	name string
	body string
	mode int64
	typ  byte
}

func tarGz(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.body)), Typeflag: typ, Linkname: "/etc/passwd"}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func pluginArchive(t *testing.T, version string) []byte {
	return tarGz(t,
		entry{name: "machbox-demo/", typ: tar.TypeDir, mode: 0o755},
		entry{name: "machbox-demo/plugin.yml", body: strings.Replace(manifest, "%s", version, 1), mode: 0o644},
		entry{name: "machbox-demo/tools/info", body: "#!/bin/sh\n", mode: 0o755},
	)
}

// fakeGitHub serves releases of owner/machbox-demo; latest is the last one.
type fakeGitHub struct {
	srv      *httptest.Server
	tags     []string
	archives map[string][]byte
	sums     map[string]string // overrides the published .sha256
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{archives: map[string][]byte{}, sums: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) add(tag string, archive []byte) {
	f.tags = append(f.tags, tag)
	f.archives[tag] = archive
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	const prefix = "/repos/owner/machbox-demo/releases/"
	p := r.URL.Path
	switch {
	case p == prefix+"latest" && len(f.tags) > 0:
		f.writeRelease(w, f.tags[len(f.tags)-1])
	case strings.HasPrefix(p, prefix+"tags/"):
		tag := strings.TrimPrefix(p, prefix+"tags/")
		if _, ok := f.archives[tag]; !ok {
			http.NotFound(w, r)
			return
		}
		f.writeRelease(w, tag)
	case strings.HasPrefix(p, "/download/"):
		tag, name, _ := strings.Cut(strings.TrimPrefix(p, "/download/"), "/")
		data := f.archives[tag]
		if strings.HasSuffix(name, ".sha256") {
			sum := sha256.Sum256(data)
			s := hex.EncodeToString(sum[:])
			if o, ok := f.sums[tag]; ok {
				s = o
			}
			_, _ = w.Write([]byte(s + "  machbox-demo.tar.gz\n"))
			return
		}
		_, _ = w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGitHub) writeRelease(w http.ResponseWriter, tag string) {
	dl := f.srv.URL + "/download/" + tag + "/"
	_ = json.NewEncoder(w).Encode(release{Tag: tag, Assets: []asset{
		{Name: "machbox-demo.tar.gz", URL: dl + "machbox-demo.tar.gz"},
		{Name: "machbox-demo.tar.gz.sha256", URL: dl + "machbox-demo.tar.gz.sha256"},
	}})
}

func TestInstallUpdateRemove(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.add("v0.1.0", pluginArchive(t, "0.1.0"))
	gh.add("v0.2.0", pluginArchive(t, "0.2.0"))
	s := &Store{Dir: t.TempDir(), API: gh.srv.URL}
	ctx := context.Background()
	repo := "https://github.com/owner/machbox-demo.git"

	in, err := s.Install(ctx, repo, "0.1.0", false)
	if err != nil {
		t.Fatal(err)
	}
	if in.Name != "demo" || in.Version != "0.1.0" || in.Source != (Source{Repo: "owner/machbox-demo", Tag: "v0.1.0"}) {
		t.Fatalf("installed %+v from %+v", in.Plugin, in.Source)
	}
	if in.Dir != s.Path("owner/machbox-demo") {
		t.Fatalf("installed in %s", in.Dir)
	}
	if fi, err := os.Stat(filepath.Join(in.Dir, "tools", "info")); err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("tools/info: %v, %v", fi, err)
	}
	if _, err := s.Install(ctx, repo, "", false); err == nil {
		t.Fatal("installing over an installed plugin succeeded without replace")
	}

	in, changed, err := s.Update(ctx, "demo")
	if err != nil || !changed || in.Version != "0.2.0" {
		t.Fatalf("update: %+v, changed=%v, %v", in, changed, err)
	}
	if _, changed, err := s.Update(ctx, "demo"); err != nil || changed {
		t.Fatalf("second update: changed=%v, %v", changed, err)
	}
	if list, err := s.List(); err != nil || len(list) != 1 {
		t.Fatalf("list: %d plugins, %v", len(list), err)
	}

	if repo, err := s.Remove("demo"); err != nil || repo != "owner/machbox-demo" {
		t.Fatalf("remove: %s, %v", repo, err)
	}
	if _, err := s.Get("owner/machbox-demo"); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("get after remove: %v", err)
	}
	if entries, _ := os.ReadDir(s.Dir); len(entries) != 0 {
		t.Errorf("store left %d entries behind", len(entries))
	}
	for _, ref := range []string{"../demo", "owner/..", "./x", "a/b/c"} {
		if _, err := s.Remove(ref); err == nil || errors.Is(err, ErrNotInstalled) {
			t.Errorf("Remove(%q) = %v, want invalid", ref, err)
		}
	}
}

// Plugins from different repositories may share a manifest name: both are
// kept, and the name alone no longer picks one.
func TestSameNameFromTwoRepos(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.add("v1", pluginArchive(t, "1.0.0"))
	s := &Store{Dir: t.TempDir(), API: gh.srv.URL}
	ctx := context.Background()

	if _, err := s.Install(ctx, "github.com/owner/machbox-demo", "", false); err != nil {
		t.Fatal(err)
	}
	if in, err := s.Get("demo"); err != nil || in.Source.Repo != "owner/machbox-demo" {
		t.Fatalf("get by name: %v", err)
	}
	// Another repository's copy, as a fork would publish it.
	fork := s.Path("fork/machbox-demo")
	if err := os.MkdirAll(filepath.Dir(fork), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(fork, os.DirFS(s.Path("owner/machbox-demo"))); err != nil {
		t.Fatal(err)
	}

	if list, err := s.List(); err != nil || len(list) != 2 {
		t.Fatalf("list: %d plugins, %v", len(list), err)
	}
	if _, err := s.Get("demo"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("get by shared name: %v", err)
	}
	if in, err := s.Get("fork/machbox-demo"); err != nil || in.Source.Repo != "fork/machbox-demo" {
		t.Fatalf("get by repo: %+v, %v", in, err)
	}
}

func TestInstallRejects(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.add("v1", pluginArchive(t, "1.0.0"))
	gh.sums["v1"] = strings.Repeat("0", 64)
	gh.add("v2", tarGz(t, entry{name: "../evil", body: "x", mode: 0o644}))
	gh.add("v3", tarGz(t, entry{name: "plugin.yml", typ: tar.TypeSymlink}))
	s := &Store{Dir: t.TempDir(), API: gh.srv.URL}

	for _, tag := range []string{"v1", "v2", "v3", "v9"} {
		if _, err := s.Install(context.Background(), "github.com/owner/machbox-demo", tag, false); err == nil {
			t.Errorf("release %s installed", tag)
		}
	}
	if entries, _ := os.ReadDir(s.Dir); len(entries) != 0 {
		t.Errorf("store left %d entries behind", len(entries))
	}
}
