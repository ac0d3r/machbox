package archive

import (
	"archive/zip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExtractZIPStd(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "sample.zip")
	outDir := filepath.Join(dir, "out")

	if err := writeTestZip(zipPath, map[string]string{
		"hello.txt":      "hi",
		"sub/nested.bin": "xx",
	}); err != nil {
		t.Fatal(err)
	}

	if err := ExtractZIP(zipPath, outDir, ""); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(outDir, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hi" {
		t.Fatalf("content = %q", got)
	}
	if _, err := os.Stat(filepath.Join(outDir, "sub", "nested.bin")); err != nil {
		t.Fatal(err)
	}
}

func TestExtractZIPWithPassword(t *testing.T) {
	if _, err := exec.LookPath("zip"); err != nil {
		t.Skip("zip not available")
	}
	if _, err := exec.LookPath("unzip"); err != nil {
		t.Skip("unzip not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("top-secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	const password = "s3cret"
	zipPath := filepath.Join(dir, "locked.zip")
	cmd := exec.Command("zip", "-q", "-P", password, zipPath, "secret.txt")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zip -P: %v: %s", err, out)
	}

	outDir := filepath.Join(dir, "out")
	if err := ExtractZIP(zipPath, outDir, password); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "top-secret" {
		t.Fatalf("content = %q", got)
	}

	badDir := filepath.Join(dir, "bad")
	if err := ExtractZIP(zipPath, badDir, "wrong-password"); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestExtractZIPRejectsZipSlip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	outDir := filepath.Join(dir, "out")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("nope")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if err := ExtractZIP(zipPath, outDir, ""); err == nil {
		t.Fatal("expected zip-slip error")
	}
}

func TestExtractZIPWithPasswordRejectsZipSlip(t *testing.T) {
	if _, err := exec.LookPath("unzip"); err != nil {
		t.Skip("unzip not available")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	outDir := filepath.Join(dir, "out")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../../evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("nope")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// Password path uses system unzip; listing must reject slip before extract.
	if err := ExtractZIP(zipPath, outDir, "any"); err == nil {
		t.Fatal("expected zip-slip error via unzip path")
	}
}

func writeTestZip(path string, files map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(body)); err != nil {
			return err
		}
	}
	return zw.Close()
}
