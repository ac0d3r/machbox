package appbundle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseInfo(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Dummy.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.dummy</string>
  <key>CFBundleExecutable</key><string>dummy</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "dummy"), []byte("not-a-macho"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := Parse(app)
	if err != nil {
		t.Fatal(err)
	}
	if got.Info.Identifier != "com.example.dummy" {
		t.Fatalf("identifier = %q", got.Info.Identifier)
	}
	if got.Info.Executable != "dummy" {
		t.Fatalf("executable = %q", got.Info.Executable)
	}
	if got.Hashes == nil || got.Hashes.SHA256 == "" {
		t.Fatalf("expected main executable hashes, got %+v", got.Hashes)
	}
}

func TestParseWithoutExecutable(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Bare.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.bare</string>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Parse(app)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hashes != nil {
		t.Fatalf("expected no hashes without executable, got %+v", got.Hashes)
	}
}
