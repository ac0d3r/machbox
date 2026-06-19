package archive

import (
	"os"
	"os/exec"
)

func ExtractDiskImage(dmgPath, mountPoint string) error {
	if err := exec.Command("hdiutil", "attach", dmgPath, "-mountpoint", mountPoint, "-noverify", // Skip validation to reduce wait time
		"-nobrowse", // Do not show in Finder
		"-quiet").Run(); err != nil {
		return err
	}
	return nil
}

func DetachDiskImage(mountPoint string) error {
	if err := exec.Command("hdiutil", "detach", mountPoint, "-force", "-quiet").Run(); err != nil {
		return err
	}
	return os.Remove(mountPoint)
}
