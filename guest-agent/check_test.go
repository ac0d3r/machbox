package main

import "testing"

func TestDecodeKCPassword(t *testing.T) {
	// "secret" as sysadminctl writes it: NUL-terminated, padded to a
	// multiple of 12 bytes.
	plain := append([]byte("secret\x00"), make([]byte, 5)...)
	enc := make([]byte, len(plain))
	for i, b := range plain {
		enc[i] = b ^ kcpasswordKey[i%len(kcpasswordKey)]
	}
	if got := decodeKCPassword(enc); got != "secret" {
		t.Errorf("decoded %q", got)
	}
}

func TestSIPDisabled(t *testing.T) {
	if !sipDisabled("System Integrity Protection status: disabled.\n") {
		t.Error("disabled not parsed")
	}
	if sipDisabled("System Integrity Protection status: enabled.\n") {
		t.Error("enabled parsed as disabled")
	}
}
