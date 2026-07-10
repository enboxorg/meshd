//go:build linux || darwin || freebsd

package daemon

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func secureSocketFile(path string, uid, gid int, changeOwner bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect control socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("control socket path was replaced before permissions were set: %s", path)
	}
	if changeOwner {
		if err := os.Lchown(path, uid, gid); err != nil {
			return fmt.Errorf("setting socket owner: %w", err)
		}
	}
	if err := unix.Fchmodat(unix.AT_FDCWD, path, 0o600, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("setting socket permissions: %w", err)
	}
	return nil
}
