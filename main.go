package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/ac0d3r/machbox/cmd"
)

// Version is the machbox release (injected via -X at build time).
var Version = "dev"

// AppKit / StartGraphicApplication must run on the process main thread;
// locking in init is what guarantees main() runs there.
func init() {
	runtime.LockOSThread()
}

func main() {
	if err := cmd.Execute(Version); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
