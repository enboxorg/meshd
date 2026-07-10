//go:build !linux && !darwin && !freebsd

package daemon

import (
	"fmt"
	"os"
)

func secureSocketFile(path string, _, _ int, _ bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect control socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("control socket path was replaced before permissions were set: %s", path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("setting socket permissions: %w", err)
	}
	return nil
}
