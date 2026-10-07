package archive

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExtractDiskImage mounts a DMG, copies its contents into outputDir, then detaches.
// outputDir keeps a durable copy for later static/dynamic analysis (same as ZIP extract).
// Symlinks that resolve outside the mount are skipped (avoids host FS escapes).
func ExtractDiskImage(dmgPath, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return err
	}

	mountPoint, err := os.MkdirTemp("", "statictool-dmg-mount-*")
	if err != nil {
		return err
	}
	defer func() { _ = detachDiskImage(mountPoint) }()

	cmd := exec.Command(
		"hdiutil", "attach", dmgPath,
		"-mountpoint", mountPoint,
		"-noverify",
		"-nobrowse",
		"-quiet",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("hdiutil attach: %w: %s", err, strings.TrimSpace(string(out)))
	}

	if err := copyTreeWithinRoot(mountPoint, outputDir); err != nil {
		return fmt.Errorf("copy dmg contents: %w", err)
	}
	return nil
}

func detachDiskImage(mountPoint string) error {
	cmd := exec.Command("hdiutil", "detach", mountPoint, "-force", "-quiet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hdiutil detach: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = os.Remove(mountPoint)
	return nil
}

func copyTreeWithinRoot(srcRoot, dstRoot string) error {
	srcRoot = filepath.Clean(srcRoot)
	return filepath.WalkDir(srcRoot, func(src string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcRoot, src)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dst := filepath.Join(dstRoot, rel)

		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			resolved := target
			if !filepath.IsAbs(target) {
				resolved = filepath.Join(filepath.Dir(src), target)
			}
			if !pathWithinRoot(srcRoot, resolved) {
				return nil // skip host / out-of-volume links (e.g. Applications → /Applications)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
				return err
			}
			return os.Symlink(target, dst)
		}

		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}

		return copyFile(src, dst)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func pathWithinRoot(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	sep := string(os.PathSeparator)
	return path == root || strings.HasPrefix(path, root+sep)
}
