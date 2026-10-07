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
