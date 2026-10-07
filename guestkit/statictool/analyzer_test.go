package statictool

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"statictool/parser/filebase"
)

func TestAnalyzeMachO(t *testing.T) {
	report, err := Analyze("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	if report.Base.Type != filebase.TypeMachO {
		t.Fatalf("type = %q", report.Base.Type)
	}
	if report.Data == nil {
		t.Fatal("expected macho data")
	}
}

func TestAnalyzeAppBundle(t *testing.T) {
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
</dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	// Copy a real Mach-O so Children can pick it up as TypeMachO.
	src, err := os.ReadFile("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "dummy"), src, 0o755); err != nil {
		t.Fatal(err)
	}

	report, err := Analyze(app)
	if err != nil {
		t.Fatal(err)
	}
	if report.Base.Type != filebase.TypeAppBundle {
		t.Fatalf("type = %q", report.Base.Type)
	}
	if report.Data == nil {
		t.Fatal("expected appbundle data")
	}
	// Contents/ -> MacOS/ -> dummy should surface as an interested Mach-O child.
	if !hasMachODescendant(report.Children) {
		t.Fatalf("expected mach-o in children, got %+v", report.Children)
	}
}

func hasMachODescendant(children []Report) bool {
	for _, c := range children {
		if c.Base.Type == filebase.TypeMachO || c.Base.Type == filebase.TypeDylib {
			return true
		}
		if hasMachODescendant(c.Children) {
			return true
		}
	}
	return false
}

func TestAnalyzeZIP(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "sample.zip")
	if err := writeZip(zipPath, map[string]string{"readme.txt": "hi"}); err != nil {
		t.Fatal(err)
	}

	a := NewAnalyzer(AnalyzeOptions{ExtractDir: filepath.Join(dir, "extract")})
	report, err := a.Analyze(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if report.Base.Type != filebase.TypeZIP {
		t.Fatalf("type = %q", report.Base.Type)
	}
	// plain text inside zip is not an interested leaf; children may be empty
	if report.Children == nil {
		report.Children = []Report{}
	}
}

func TestAnalyzeZIPRequiresExtractDir(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "sample.zip")
	if err := writeZip(zipPath, map[string]string{"readme.txt": "hi"}); err != nil {
		t.Fatal(err)
	}
	_, err := Analyze(zipPath)
	if err == nil {
		t.Fatal("expected error without ExtractDir")
	}
}

func TestIsInterested(t *testing.T) {
	if !isInterested(Report{Base: filebase.BaseInfo{Type: filebase.TypeMachO}}) {
		t.Fatal("mach-o should be interested")
	}
	if !isInterested(Report{Base: filebase.BaseInfo{Type: filebase.TypePKG}}) {
		t.Fatal("pkg should be interested")
	}
	if isInterested(Report{Base: filebase.BaseInfo{Type: filebase.TypeUnknown, IsDir: true}}) {
		t.Fatal("empty dir should not be interested")
	}
	if !isInterested(Report{
		Base:     filebase.BaseInfo{Type: filebase.TypeUnknown, IsDir: true},
		Children: []Report{{}},
	}) {
		t.Fatal("dir with children should be interested")
	}
}

func writeZip(path string, files map[string]string) error {
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
