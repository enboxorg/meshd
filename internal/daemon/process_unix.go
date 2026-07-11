//go:build linux || darwin || freebsd

package daemon

import (
	"errors"

	"golang.org/x/sys/unix"
)

func processAlivePlatform(pid int) (bool, error) {
	err := unix.Kill(pid, 0)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ESRCH):
		return false, nil
	case errors.Is(err, unix.EPERM):
		return true, nil
	default:
		return false, err
	}
}
