package macho

import (
	"testing"
)

func TestParseMachO(t *testing.T) {
	path := "/usr/bin/python3"

	info, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%#v", info)
}
