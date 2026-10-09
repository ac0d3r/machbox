package report

import (
	"testing"

	"github.com/ac0d3r/machbox/internal/agent"
)

func TestStaticResultPicksNestedAppFromArchive(t *testing.T) {
	const raw = `{
  "base": {"name": "sample.zip", "path": "/share/sample.zip", "type": "zip", "size": 10, "hash": {"sha256": "abc"}},
  "children": [
    {
      "base": {"name": "Dummy.app", "path": "/tmp/machbox_x/extract/sample/Dummy.app", "type": "appbundle", "is_dir": true},
      "data": {"info": {"identifier": "com.example.dummy"}},
      "children": [
        {"base": {"name": "dummy", "path": "/tmp/machbox_x/extract/sample/Dummy.app/Contents/MacOS/dummy", "type": "mach-o"}}
      ]
    }
  ]
}`

	p := New(agent.GuestInfo{})
	if err := p.StaticResult(raw, "/share/sample.zip"); err != nil {
		t.Fatal(err)
	}
	if p.data.FileType != "zip" || p.data.SHA256 != "abc" {
		t.Fatalf("meta: type=%q sha=%q", p.data.FileType, p.data.SHA256)
	}
	path, typ := p.GetPickFile()
	if typ != "appbundle" {
		t.Fatalf("pick typ = %q", typ)
	}
	if path != "/tmp/machbox_x/extract/sample/Dummy.app" {
		t.Fatalf("pick path = %q", path)
	}
}

func TestStaticResultMachOUsesOrigin(t *testing.T) {
	const raw = `{
  "base": {"name": "ls", "path": "/share/ls", "type": "mach-o", "size": 1, "hash": {"sha256": "d"}}
}`
	p := New(agent.GuestInfo{})
	if err := p.StaticResult(raw, "/share/ls"); err != nil {
		t.Fatal(err)
	}
	path, typ := p.GetPickFile()
	if path != "/share/ls" || typ != "mach-o" {
		t.Fatalf("pick = %q %q", path, typ)
	}
}

func TestStaticResultPrefersNameMatchedApp(t *testing.T) {
	const raw = `{
  "base": {"name": "Werkbit.zip", "path": "/share/Werkbit.zip", "type": "zip", "size": 10, "hash": {"sha256": "a"}},
  "children": [
    {"base": {"name": "A Helper.app", "path": "/tmp/x/extract/Werkbit/A Helper.app", "type": "appbundle"}},
    {"base": {"name": "Werkbit.app", "path": "/tmp/x/extract/Werkbit/Werkbit.app", "type": "appbundle"}}
  ]
}`
	p := New(agent.GuestInfo{})
	if err := p.StaticResult(raw, "/share/Werkbit.zip"); err != nil {
		t.Fatal(err)
	}
	path, typ := p.GetPickFile()
	if typ != "appbundle" || path != "/tmp/x/extract/Werkbit/Werkbit.app" {
		t.Fatalf("pick = %q %q", path, typ)
	}
}

func TestStaticResultSkipsNestedHelperApp(t *testing.T) {
	const raw = `{
  "base": {"name": "sample.dmg", "path": "/share/sample.dmg", "type": "dmg", "size": 10, "hash": {"sha256": "b"}},
  "children": [
    {
      "base": {"name": "Main.app", "path": "/tmp/x/extract/sample/Main.app", "type": "appbundle"},
      "children": [
        {"base": {"name": "Helper.app", "path": "/tmp/x/extract/sample/Main.app/Contents/Helpers/Helper.app", "type": "appbundle"}},
        {"base": {"name": "main", "path": "/tmp/x/extract/sample/Main.app/Contents/MacOS/main", "type": "mach-o"}}
      ]
    }
  ]
}`
	p := New(agent.GuestInfo{})
	if err := p.StaticResult(raw, "/share/sample.dmg"); err != nil {
		t.Fatal(err)
	}
	path, typ := p.GetPickFile()
	if typ != "appbundle" || path != "/tmp/x/extract/sample/Main.app" {
		t.Fatalf("pick = %q %q", path, typ)
	}
}

func TestStaticResultPrefersShallowerMachO(t *testing.T) {
	const raw = `{
  "base": {"name": "tools.zip", "path": "/share/tools.zip", "type": "zip", "size": 10, "hash": {"sha256": "c"}},
  "children": [
    {"base": {"name": "deep", "path": "/tmp/x/extract/tools/bin/nested/tool", "type": "mach-o"}},
    {"base": {"name": "tool", "path": "/tmp/x/extract/tools/tool", "type": "mach-o"}}
  ]
}`
	p := New(agent.GuestInfo{})
	if err := p.StaticResult(raw, "/share/tools.zip"); err != nil {
		t.Fatal(err)
	}
	path, typ := p.GetPickFile()
	if typ != "mach-o" || path != "/tmp/x/extract/tools/tool" {
		t.Fatalf("pick = %q %q", path, typ)
	}
}

func TestStaticResultSkipsDylibOnly(t *testing.T) {
	const raw = `{
  "base": {"name": "lib.zip", "path": "/share/lib.zip", "type": "zip", "size": 10, "hash": {"sha256": "e"}},
  "children": [
    {"base": {"name": "foo.dylib", "path": "/tmp/x/extract/lib/foo.dylib", "type": "dylib"}}
  ]
}`
	p := New(agent.GuestInfo{})
	if err := p.StaticResult(raw, "/share/lib.zip"); err != nil {
		t.Fatal(err)
	}
	path, typ := p.GetPickFile()
	if path != "" || typ != "" {
		t.Fatalf("expected empty pick, got %q %q", path, typ)
	}
}

func TestIsNestedAppBundle(t *testing.T) {
	if isNestedAppBundle("/tmp/x/Main.app") {
		t.Fatal("top-level app should not be nested")
	}
	if !isNestedAppBundle("/tmp/x/Main.app/Contents/Helpers/Helper.app") {
		t.Fatal("helper under .app should be nested")
	}
}

func TestArchiveStem(t *testing.T) {
	if got := archiveStem("Werkbit.zip"); got != "Werkbit" {
		t.Fatalf("got %q", got)
	}
	if got := archiveStem("sample.tar.gz"); got != "sample" {
		t.Fatalf("got %q", got)
	}
}
