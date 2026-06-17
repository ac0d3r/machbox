package filebase

import (
	"testing"
)

func TestGenFromFile(t *testing.T) {
	info, err := GenFromFile("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != TypeMachO {
		t.Fatalf("expected %q, got %q", TypeMachO, info.Type)
	}
}
