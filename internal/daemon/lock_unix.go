//go:build linux || darwin || freebsd

package daemon

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func acquirePlatformInstanceLock(path string) (func() error, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create lock file handle")
	}
	closeFile := func() { _ = file.Close() }

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		closeFile()
		return nil, fmt.Errorf("inspect lock file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		closeFile()
		return nil, fmt.Errorf("lock path is not a regular file")
	}
	if stat.Nlink != 1 {
		closeFile()
		return nil, fmt.Errorf("lock file must have exactly one link")
	}

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		closeFile()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errInstanceLockContended
		}
		return nil, err
	}
	locked := true
	cleanup := func() {
		if locked {
			_ = unix.Flock(fd, unix.LOCK_UN)
			locked = false
		}
		closeFile()
	}

	if err := unix.Fchmod(fd, 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("secure lock file permissions: %w", err)
	}
	if uid, gid, ok := sudoSocketOwner(os.Geteuid(), os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")); ok {
		if err := unix.Fchown(fd, uid, gid); err != nil {
			cleanup()
			return nil, fmt.Errorf("set lock file owner: %w", err)
		}
	}

	return func() error {
		unlockErr := unix.Flock(fd, unix.LOCK_UN)
		locked = false
		closeErr := file.Close()
		return errors.Join(unlockErr, closeErr)
	}, nil
}
