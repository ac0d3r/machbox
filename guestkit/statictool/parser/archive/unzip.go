package archive

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExtractZIP extracts a zip archive into outputDir.
// Password-protected archives fall back to the system unzip tool.
func ExtractZIP(zipPath, outputDir, password string) error {
	outputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return err
	}

	if password != "" {
		return extractZIPWithUnzip(zipPath, outputDir, password)
	}
	return extractZIPStd(zipPath, outputDir)
}

func extractZIPStd(zipPath, outputDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	root := filepath.Clean(outputDir) + string(os.PathSeparator)
	for _, f := range r.File {
		if err := extractZIPFile(f, outputDir, root); err != nil {
			return err
		}
	}
	return nil
}

func extractZIPFile(f *zip.File, outputDir, root string) error {
	name := filepath.Clean(f.Name)
	if name == "." || name == "" {
		return nil
	}
	// Disallow absolute paths and parent traversal (zip slip).
	if filepath.IsAbs(name) || strings.HasPrefix(name, ".."+string(os.PathSeparator)) || name == ".." {
		return fmt.Errorf("illegal zip path: %q", f.Name)
	}

	target := filepath.Join(outputDir, name)
	if !strings.HasPrefix(target+string(os.PathSeparator), root) && target != filepath.Clean(outputDir) {
		return fmt.Errorf("illegal zip path: %q", f.Name)
	}

	mode := f.Mode()
	if f.FileInfo().IsDir() {
		return os.MkdirAll(target, dirPerm(mode))
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open %q: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, filePerm(mode))
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, rc); err != nil {
		return fmt.Errorf("write %q: %w", f.Name, err)
	}
	return nil
}

func extractZIPWithUnzip(zipPath, outputDir, password string) error {
	if err := validateZIPListing(zipPath); err != nil {
		return err
	}
	cmd := exec.Command("unzip", "-o", "-q", "-P", password, zipPath, "-d", outputDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unzip: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return rejectEscapingSymlinks(outputDir)
}

// validateZIPListing rejects zip-slip / absolute paths before invoking unzip.
func validateZIPListing(zipPath string) error {
	cmd := exec.Command("unzip", "-Z1", zipPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unzip list: %w: %s", err, strings.TrimSpace(string(out)))
	}
	for _, name := range strings.Split(string(out), "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		cleaned := filepath.Clean(name)
		if filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("illegal zip path: %q", name)
		}
	}
	return nil
}

// rejectEscapingSymlinks removes symlinks whose targets escape outputDir
// (defense in depth: unzip may still create out-of-tree links).
func rejectEscapingSymlinks(outputDir string) error {
	root := filepath.Clean(outputDir)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		resolved := target
		if !filepath.IsAbs(target) {
			resolved = filepath.Join(filepath.Dir(path), target)
		}
		if !pathWithinRoot(root, resolved) {
			_ = os.Remove(path)
			return fmt.Errorf("illegal symlink after unzip: %q -> %q", path, target)
		}
		return nil
	})
}

func dirPerm(mode os.FileMode) os.FileMode {
	perm := mode.Perm()
	if perm == 0 {
		return 0o750
	}
	return perm
}

func filePerm(mode os.FileMode) os.FileMode {
	perm := mode.Perm()
	if perm == 0 {
		return 0o640
	}
	// Never extract setuid/setgid/sticky bits from untrusted archives.
	return perm & 0o777
}
