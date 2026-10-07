package archive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSignatureInfoNoSignature(t *testing.T) {
	info, err := parseSignatureInfo("Status: no signature")
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
		"Package \"x\":",
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

func TestReadScriptMissingIsEmpty(t *testing.T) {
	dir := t.TempDir()
	if got := readScript(dir, ""); got != "" {
		t.Fatalf("empty name should return empty, got %q", got)
	}
	if got := readScript(dir, "missing.sh"); got != "" {
		t.Fatalf("missing script should return empty, got %q", got)
	}
}

func TestReadScriptRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(outside, []byte("leak"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	// Scripts/../../secret.txt escapes pkg root into TempDir's parent.
	escape := filepath.Join("..", "..", filepath.Base(outside))
	if got := readScript(dir, escape); got != "" {
		t.Fatalf("traversal should be rejected, got %q", got)
	}
	if got := readScript(dir, outside); got != "" {
		t.Fatalf("absolute path should be rejected, got %q", got)
	}
}

func TestDiscoverFlatPackage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PackageInfo"), []byte(`<pkg-info identifier="a.b" version="1"/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	components, primary, err := discoverPackageComponents(dir)
	if err != nil {
		t.Fatal(err)
	}
	if primary != dir || len(components) != 1 {
		t.Fatalf("primary=%q components=%+v", primary, components)
	}
}

func TestResolveComponentPath(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "com.example.pkg")
	if err := os.Mkdir(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	// id without suffix should still resolve id+".pkg"
	if got := resolveComponentPath(dir, "com.example"); got != pkg {
		t.Fatalf("got %q want %q", got, pkg)
	}
	if got := resolveComponentPath(dir, "missing"); got != "" {
		t.Fatalf("unexpected match: %q", got)
	}
}
