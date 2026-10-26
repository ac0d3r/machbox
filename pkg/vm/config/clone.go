package config

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// CloneFile APFS-clones src (a file or directory) to dst copy-on-write. dst
// must not exist, and both must be on the same APFS volume.
func CloneFile(src, dst string) error {
	if err := unix.Clonefile(src, dst, 0); err != nil {
		return fmt.Errorf("APFS clonefile %s → %s: %w", src, dst, err)
	}
	return nil
}
