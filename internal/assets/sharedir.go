package assets

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type ShareDir struct {
	root string
}

func NewShareDir(sampleName, samplePath string, files ...string) (*ShareDir, error) {
	shares := filepath.Join(AppDir(), fmt.Sprintf("shares_%s", strconv.FormatInt(time.Now().UnixNano(), 36)))
	if err := os.MkdirAll(shares, 0o700); err != nil {
		_ = os.RemoveAll(shares)
		return nil, err
	}

	for i := range files {
		if err := copyAsset(files[i], shares, 0o500); err != nil {
			_ = os.RemoveAll(shares)
			return nil, fmt.Errorf("copy %s: %w", files[i], err)
		}
	}

	dst := filepath.Join(shares, sampleName)
	if err := copyPath(samplePath, dst); err != nil {
		_ = os.RemoveAll(shares)
		return nil, fmt.Errorf("copy sample: %w", err)
	}

	return &ShareDir{root: shares}, nil
}

func (d *ShareDir) Path() string { return d.root }

func (d *ShareDir) Clean() error {
	if d.root == "" {
		return nil
	}

	err := os.RemoveAll(d.root)
	d.root = ""
	return err
}

func copyAsset(name, dstDir string, mode os.FileMode) error {
	src, err := OpenFS(name)
	if err != nil {
		return err
	}
	defer src.Close()

	dstPath := filepath.Join(dstDir, name)
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o700); err != nil {
		return err
	}

	// #nosec G304 -- name is a hardcoded asset name, dstDir is a temp dir created by MkdirTemp.
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func copyPath(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst, info.Mode())
}

func copyFile(src, dst string, mode os.FileMode) error {
	// #nosec G304 -- src is the user-provided sample path that is intentionally copied into the shared dir.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// #nosec G304 -- dst is a path inside the temp shared dir constructed from MkdirTemp.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(out, info.Mode())
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		return copyFile(path, out, info.Mode())
	})
}
