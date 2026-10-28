// Package store installs plugins from GitHub releases into
// ~/.machbox/plugins/<owner>/<repo>/.
//
// A plugin is identified by its repository: plugins from different
// repositories never replace each other, even if their manifests share a
// name. That name still works as a shorthand while it is unambiguous.
//
// A release must carry a .tar.gz asset holding plugin.yml and the built
// tools, at its root or in one top-level directory. If the release also has
// <asset>.sha256 (or GitHub reports a digest), the download is verified.
package store

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ac0d3r/machbox/internal/plugin"
)

const (
	// sourceFile records the release an installed plugin came from.
	sourceFile = ".machbox-source.json"

	maxArchiveSize   = 1 << 30
	maxExtractedSize = 4 << 30
)

// ErrNotInstalled is returned for a plugin reference with nothing installed.
var ErrNotInstalled = errors.New("plugin not installed")

// Source is where an installed plugin came from.
type Source struct {
	Repo string `json:"repo"` // owner/repo on GitHub
	Tag  string `json:"tag"`
}

// Installed is a plugin in the store.
type Installed struct {
	*plugin.Plugin
	Source Source
}

// Store manages the plugins in Dir.
type Store struct {
	Dir string
	// API is the GitHub API base URL; empty means https://api.github.com.
	API    string
	Client *http.Client
}

// Path returns the directory of the plugin from repo (owner/repo).
func (s *Store) Path(repo string) string { return filepath.Join(s.Dir, filepath.FromSlash(repo)) }

// Get returns the installed plugin ref names: owner/repo, or the name in
// its manifest if only one installed plugin has it.
func (s *Store) Get(ref string) (*Installed, error) {
	if !strings.Contains(ref, "/") {
		return s.byName(ref)
	}
	if !validRepo(ref) {
		return nil, fmt.Errorf("invalid plugin %q: want owner/repo or a plugin name", ref)
	}
	return s.load(ref)
}

func (s *Store) load(repo string) (*Installed, error) {
	dir := s.Path(repo)
	if _, err := os.Stat(filepath.Join(dir, plugin.ManifestName)); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotInstalled, repo)
	}
	p, err := plugin.Load(dir)
	if err != nil {
		return nil, err
	}
	in := &Installed{Plugin: p, Source: Source{Repo: repo}}
	if data, err := os.ReadFile(filepath.Join(dir, sourceFile)); err == nil {
		var src Source
		if json.Unmarshal(data, &src) == nil {
			in.Source.Tag = src.Tag
		}
	}
	return in, nil
}

func (s *Store) byName(name string) (*Installed, error) {
	list, err := s.List()
	if err != nil {
		return nil, err
	}
	var found []*Installed
	for _, in := range list {
		if in.Name == name {
			found = append(found, in)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: %s", ErrNotInstalled, name)
	case 1:
		return found[0], nil
	}
	repos := make([]string, len(found))
	for i, in := range found {
		repos[i] = in.Source.Repo
	}
	return nil, fmt.Errorf("plugin name %s is ambiguous; use one of: %s", name, strings.Join(repos, ", "))
}

// validRepo reports whether repo is owner/repo with no path tricks.
func validRepo(repo string) bool {
	owner, name, ok := strings.Cut(repo, "/")
	return ok && repoPartRe.MatchString(owner) && repoPartRe.MatchString(name)
}

// List returns the installed plugins, sorted by repository.
func (s *Store) List() ([]*Installed, error) {
	owners, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*Installed
	for _, o := range owners {
		if !o.IsDir() || !repoPartRe.MatchString(o.Name()) {
			continue
		}
		repos, err := os.ReadDir(filepath.Join(s.Dir, o.Name()))
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			if !r.IsDir() || !repoPartRe.MatchString(r.Name()) {
				continue
			}
			in, err := s.load(o.Name() + "/" + r.Name())
			if err != nil {
				continue
			}
			list = append(list, in)
		}
	}
	slices.SortFunc(list, func(a, b *Installed) int { return strings.Compare(a.Source.Repo, b.Source.Repo) })
	return list, nil
}

// Install downloads the release tagged version (the latest if empty) of the
// plugin repository at repoURL. A plugin already installed from that
// repository is replaced only if replace is set.
func (s *Store) Install(ctx context.Context, repoURL, version string, replace bool) (*Installed, error) {
	repo, err := ParseRepo(repoURL)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.Path(repo)); err == nil && !replace {
		return nil, fmt.Errorf("%s is already installed; run: machbox plugin update %s", repo, repo)
	}
	rel, err := s.release(ctx, repo, version)
	if err != nil {
		return nil, err
	}
	return s.install(ctx, repo, rel)
}

// Update installs the latest release of the plugin ref names if its tag
// changed. It reports whether anything changed.
func (s *Store) Update(ctx context.Context, ref string) (*Installed, bool, error) {
	cur, err := s.Get(ref)
	if err != nil {
		return nil, false, err
	}
	rel, err := s.release(ctx, cur.Source.Repo, "")
	if err != nil {
		return nil, false, err
	}
	if rel.Tag == cur.Source.Tag {
		return cur, false, nil
	}
	in, err := s.install(ctx, cur.Source.Repo, rel)
	if err != nil {
		return nil, false, err
	}
	return in, true, nil
}

// Remove deletes the plugin ref names and returns its repository.
func (s *Store) Remove(ref string) (string, error) {
	repo := ref
	if !strings.Contains(ref, "/") {
		in, err := s.byName(ref)
		if err != nil {
			return "", err
		}
		repo = in.Source.Repo
	} else if !validRepo(ref) {
		return "", fmt.Errorf("invalid plugin %q: want owner/repo or a plugin name", ref)
	}
	// A plugin whose manifest no longer loads can still be removed by repo.
	dir := s.Path(repo)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: %s", ErrNotInstalled, repo)
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	_ = os.Remove(filepath.Dir(dir)) // the owner directory, once empty
	return repo, nil
}

// repoPartRe matches a GitHub owner or repository name.
var repoPartRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)

var repoPathRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?/?$`)

// ParseRepo returns owner/name for a GitHub repository URL
// (https://github.com/owner/name, github.com/owner/name or
// git@github.com:owner/name.git).
func ParseRepo(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if rest, ok := strings.CutPrefix(s, "git@github.com:"); ok {
		s = rest
	} else {
		if !strings.Contains(s, "://") {
			s = "https://" + s
		}
		u, err := url.Parse(s)
		if err != nil || !strings.EqualFold(u.Host, "github.com") && !strings.EqualFold(u.Host, "www.github.com") {
			return "", fmt.Errorf("%q is not a GitHub repository URL", raw)
		}
		s = strings.TrimPrefix(u.Path, "/")
	}
	m := repoPathRe.FindStringSubmatch(s)
	if m == nil || !validRepo(m[1]+"/"+m[2]) {
		return "", fmt.Errorf("%q is not a GitHub repository URL", raw)
	}
	return m[1] + "/" + m[2], nil
}

type release struct {
	Tag    string  `json:"tag_name"`
	Assets []asset `json:"assets"`
}

type asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// release looks up the release tagged version, or the latest. A version
// without a leading "v" also matches the tag "v<version>".
func (s *Store) release(ctx context.Context, repo, version string) (*release, error) {
	if version == "" {
		return s.getRelease(ctx, repo, "releases/latest")
	}
	rel, err := s.getRelease(ctx, repo, "releases/tags/"+url.PathEscape(version))
	if errors.Is(err, errNoRelease) && !strings.HasPrefix(version, "v") {
		rel, err = s.getRelease(ctx, repo, "releases/tags/"+url.PathEscape("v"+version))
	}
	if errors.Is(err, errNoRelease) {
		return nil, fmt.Errorf("%s has no release %s", repo, version)
	}
	return rel, err
}

var errNoRelease = errors.New("no such release")

func (s *Store) getRelease(ctx context.Context, repo, rel string) (*release, error) {
	resp, err := s.get(ctx, strings.TrimSuffix(s.apiOrDefault(), "/")+"/repos/"+repo+"/"+rel, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		if rel == "releases/latest" {
			return nil, fmt.Errorf("%s has no release (or the repository does not exist)", repo)
		}
		return nil, errNoRelease
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub %s: %s", repo, resp.Status)
	}
	var r release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("GitHub %s: %w", repo, err)
	}
	return &r, nil
}

func (s *Store) get(ctx context.Context, u, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	// A token raises GitHub's rate limit for anonymous requests.
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" && strings.HasPrefix(u, s.apiOrDefault()) {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	c := s.Client
	if c == nil {
		c = http.DefaultClient
	}
	return c.Do(req)
}

func (s *Store) apiOrDefault() string {
	if s.API != "" {
		return s.API
	}
	return "https://api.github.com"
}

// pickAsset returns the release's plugin archive and its expected SHA-256
// (empty if the release publishes none).
func (s *Store) pickAsset(ctx context.Context, repo string, rel *release) (asset, string, error) {
	var archives []asset
	byName := map[string]asset{}
	for _, a := range rel.Assets {
		byName[a.Name] = a
		if strings.HasSuffix(a.Name, ".tar.gz") || strings.HasSuffix(a.Name, ".tgz") {
			archives = append(archives, a)
		}
	}
	var a asset
	switch {
	case len(archives) == 1:
		a = archives[0]
	case len(archives) > 1:
		want, ok := byName[path.Base(repo)+".tar.gz"]
		if !ok {
			return asset{}, "", fmt.Errorf("release %s of %s has several archives; expected one named %s.tar.gz",
				rel.Tag, repo, path.Base(repo))
		}
		a = want
	default:
		return asset{}, "", fmt.Errorf("release %s of %s has no .tar.gz asset", rel.Tag, repo)
	}

	if sum, ok := byName[a.Name+".sha256"]; ok {
		resp, err := s.get(ctx, sum.URL, "")
		if err != nil {
			return asset{}, "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return asset{}, "", fmt.Errorf("download %s: %s", sum.Name, resp.Status)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		if err != nil {
			return asset{}, "", fmt.Errorf("download %s: %w", sum.Name, err)
		}
		fields := strings.Fields(string(data))
		if len(fields) == 0 {
			return asset{}, "", fmt.Errorf("%s is empty", sum.Name)
		}
		return a, strings.ToLower(fields[0]), nil
	}
	if d, ok := strings.CutPrefix(a.Digest, "sha256:"); ok {
		return a, strings.ToLower(d), nil
	}
	return a, "", nil
}

func (s *Store) install(ctx context.Context, repo string, rel *release) (*Installed, error) {
	a, sum, err := s.pickAsset(ctx, repo, rel)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	// Staged next to the store so the final rename stays on one volume.
	tmp, err := os.MkdirTemp(s.Dir, ".install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	if err := s.download(ctx, a, sum, tmp); err != nil {
		return nil, err
	}
	root, err := pluginRoot(tmp)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.Name, err)
	}
	if _, err := plugin.Load(root); err != nil {
		return nil, fmt.Errorf("%s: %w", a.Name, err)
	}
	src := Source{Repo: repo, Tag: rel.Tag}
	data, _ := json.MarshalIndent(src, "", "  ")
	if err := os.WriteFile(filepath.Join(root, sourceFile), append(data, '\n'), 0o600); err != nil {
		return nil, err
	}

	dst := s.Path(repo)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(dst); err == nil {
		old := filepath.Join(tmp, "old")
		if err := os.Rename(dst, old); err != nil {
			return nil, err
		}
		if err := os.Rename(root, dst); err != nil {
			_ = os.Rename(old, dst)
			return nil, err
		}
	} else if err := os.Rename(root, dst); err != nil {
		return nil, err
	}
	return s.load(repo)
}

func (s *Store) download(ctx context.Context, a asset, sum, dir string) error {
	resp, err := s.get(ctx, a.URL, "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", a.Name, resp.Status)
	}

	f, err := os.CreateTemp(dir, "archive-")
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArchiveSize+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", a.Name, err)
	}
	if n > maxArchiveSize {
		return fmt.Errorf("download %s: larger than %d bytes", a.Name, maxArchiveSize)
	}
	if got := hex.EncodeToString(h.Sum(nil)); sum != "" && got != sum {
		return fmt.Errorf("download %s: sha256 %s, release says %s", a.Name, got, sum)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := extract(f, filepath.Join(dir, "plugin")); err != nil {
		return fmt.Errorf("extract %s: %w", a.Name, err)
	}
	return nil
}

// extract unpacks a .tar.gz into dir. Only regular files and directories
// are allowed, and nothing may land outside dir.
func extract(r io.Reader, dir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	var total int64
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if name == "." {
			continue
		}
		if !filepath.IsLocal(name) {
			return fmt.Errorf("unsafe path %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += hdr.Size
			if total > maxExtractedSize {
				return fmt.Errorf("larger than %d bytes extracted", maxExtractedSize)
			}
			if d := path.Dir(name); d != "." {
				if err := root.MkdirAll(d, 0o755); err != nil {
					return err
				}
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		case tar.TypeXGlobalHeader:
		default:
			return fmt.Errorf("%s: unsupported entry type %q", hdr.Name, hdr.Typeflag)
		}
	}
}

// pluginRoot finds plugin.yml in the extracted archive: at its root, or in
// its only top-level directory.
func pluginRoot(tmp string) (string, error) {
	dir := filepath.Join(tmp, "plugin")
	if _, err := os.Stat(filepath.Join(dir, plugin.ManifestName)); err == nil {
		return dir, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	if len(entries) == 1 && entries[0].IsDir() {
		sub := filepath.Join(dir, entries[0].Name())
		if _, err := os.Stat(filepath.Join(sub, plugin.ManifestName)); err == nil {
			return sub, nil
		}
	}
	return "", fmt.Errorf("no %s at the archive root or in its only directory", plugin.ManifestName)
}
