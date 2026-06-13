package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	resp, err := http.Get("https://www.baidu.com")
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		os.Exit(1)
	}

	fmt.Printf("StatusCode: %d\n", resp.StatusCode)
	fmt.Printf("Body length: %d 字节\n", len(body))

	cmd := exec.Command("ls", "-la")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}
