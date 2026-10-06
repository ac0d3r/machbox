package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/ac0d3r/machbox/cmd"
)

func main() {
	// AppKit / StartGraphicApplication must run on the process main thread.
	runtime.LockOSThread()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
