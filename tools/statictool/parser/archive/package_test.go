package archive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSignatureInfoNoSignature(t *testing.T) {
	out := "Status: no signature"
	info, err := parseSignatureInfo(out)
	if err != nil {
		t.Fatalf("parseSignatureInfo: %v", err)
	}
	if info.Status != "no signature" {
		t.Fatalf("status = %q", info.Status)
	}
	if info.Notarized {
		t.Fatal("expected notarized=false")
	}
}

func TestParseSignatureInfoTrusted(t *testing.T) {
	out := strings.Join([]string{
		"Status: signed by a developer certificate issued by Apple",
		"Notarization: trusted by the Apple notary service",
		"Signed with a trusted timestamp on: 2024-01-02 03:04:05 -0800",
	}, "\n")
	info, err := parseSignatureInfo(out)
	if err != nil {
		t.Fatalf("parseSignatureInfo: %v", err)
	}
	if !info.Notarized {
		t.Fatal("expected notarized=true")
	}
	if info.Timestamp.IsZero() {
		t.Fatal("expected timestamp")
	}
}

func TestBuildFileTree(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.bin"), []byte("xx"), 0o644); err != nil {
		t.Fatal(err)
	}

	node, err := buildFileTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !node.IsDir || len(node.Children) != 2 {
		t.Fatalf("unexpected tree: %+v", node)
	}
}

func TestReadScriptMissingIsEmpty(t *testing.T) {
	dir := t.TempDir()
	if got := readScript(dir, ""); got != "" {
		t.Fatalf("empty name should return empty, got %q", got)
	}
	if got := readScript(dir, "missing.sh"); got != "" {
		t.Fatalf("missing script should return empty, got %q", got)
	}
}
