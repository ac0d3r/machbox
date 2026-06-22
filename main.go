package main

import (
	"fmt"
	"os"

	"github.com/ac0d3r/machbox/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
