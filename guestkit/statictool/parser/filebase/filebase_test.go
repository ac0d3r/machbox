package filebase

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenFromFileMachO(t *testing.T) {
	info, err := GenFromFile("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != TypeMachO {
		t.Fatalf("expected %q, got %q", TypeMachO, info.Type)
	}
	if info.Hash.SHA256 == "" || info.Hash.MD5 == "" || info.Hash.SHA1 == "" {
		t.Fatalf("expected hashes, got %+v", info.Hash)
	}
	if info.MIME != "application/x-mach-binary" {
		t.Fatalf("expected mach-o mime, got %q", info.MIME)
	}
}

func TestGenFromFileDylib(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "libdemo.dylib")
	// Thin LE Mach-O with filetype MH_DYLIB.
	buf := make([]byte, 32)
	buf[0], buf[1], buf[2], buf[3] = 0xCF, 0xFA, 0xED, 0xFE
	buf[12] = 0x06
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := GenFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != TypeDylib {
		t.Fatalf("expected %q, got %q", TypeDylib, info.Type)
	}
}

func TestGenFromFileZIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.zip")
	// Minimal local-file ZIP header (PK\x03\x04) is enough for magic sniff.
	if err := os.WriteFile(path, []byte{'P', 'K', 0x03, 0x04, 0x00, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := GenFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != TypeZIP {
		t.Fatalf("expected %q, got %q", TypeZIP, info.Type)
	}
}

func TestGenFromFileXARPkg(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.pkg")
	if err := os.WriteFile(path, []byte("xar!\x00\x00\x00\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := GenFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != TypePKG {
		t.Fatalf("expected %q, got %q", TypePKG, info.Type)
	}
}

func TestGenFromFilePkgDirectoryIsNotPKG(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "com.example.pkg")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := GenFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type == TypePKG {
		t.Fatal("expanded .pkg directory must not be classified as TypePKG")
	}
	if !info.IsDir {
		t.Fatal("expected directory")
	}
}

func TestGenFromFileDMGTrailer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.dmg")
	buf := make([]byte, 600)
	copy(buf[len(buf)-512:], []byte("koly"))
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := GenFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != TypeDMG {
		t.Fatalf("expected %q, got %q", TypeDMG, info.Type)
	}
}

func TestGenFromFileAppBundle(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Dummy.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := GenFromFile(app)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != TypeAppBundle {
		t.Fatalf("expected %q, got %q", TypeAppBundle, info.Type)
	}
	if !info.IsDir {
		t.Fatal("expected directory")
	}
	if info.Hash.SHA256 != "" {
		t.Fatalf("directories should not be hashed, got %+v", info.Hash)
	}
	if info.MIME != "" {
		t.Fatalf("directories should not have mime, got %q", info.MIME)
	}
}

func TestSniffHeaderMachO(t *testing.T) {
	// MH_CIGAM_64 (little-endian 64-bit) + filetype MH_EXECUTE at offset 12.
	header := make([]byte, 32)
	header[0], header[1], header[2], header[3] = 0xCF, 0xFA, 0xED, 0xFE
	header[12] = 0x02 // MH_EXECUTE
	sn := sniffHeader(header)
	if sn.Kind != kindMachO {
		t.Fatalf("expected kindMachO, got %v", sn.Kind)
	}

	header[12] = 0x06 // MH_DYLIB
	sn = sniffHeader(header)
	if sn.Kind != kindDylib {
		t.Fatalf("expected kindDylib, got %v", sn.Kind)
	}
}

func TestGenFromFileThinMachOWithoutFileCmd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	buf := make([]byte, 32)
	buf[0], buf[1], buf[2], buf[3] = 0xCF, 0xFA, 0xED, 0xFE
	buf[12] = 0x02
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := GenFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != TypeMachO {
		t.Fatalf("expected %q, got %q", TypeMachO, info.Type)
	}
}
