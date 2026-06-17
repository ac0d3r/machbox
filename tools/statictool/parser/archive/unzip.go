package archive

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func ExtractZIP(zipPath, outputDir, password string) error {
	outputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	args := []string{"-o", "-q"} // overwrite existing files, quiet mode
	if password != "" {
		args = append(args, "-P", password)
	}
	args = append(args, zipPath, "-d", outputDir)

	cmd := exec.Command("unzip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unzip failed: %w\noutput: %s", err, string(out))
	}

	return nil
}
