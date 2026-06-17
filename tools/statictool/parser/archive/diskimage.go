package archive

import (
	"os/exec"
)

func ExtractDiskImage(dmgPath, outputDir string) error {
	if err := exec.Command("hdiutil", "attach", dmgPath, "-mountpoint", outputDir).Run(); err != nil {
		return err
	}
	return nil
}

func DetachDiskImage(outdir string) error {
	return exec.Command("hdiutil", "detach", outdir).Run()
}
