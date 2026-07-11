package daemon

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// ErrAlreadyRunning is returned when another meshd process holds the
// instance lock associated with a control socket.
var ErrAlreadyRunning = errors.New("another meshd instance is already running")

var errInstanceLockContended = errors.New("instance lock is held")

// InstanceLock is a process-scoped, kernel-released singleton lock. The lock
// file intentionally remains on disk after Close; only the kernel lock, not
// file existence, represents ownership.
type InstanceLock struct {
	path    string
	release func() error
	once    sync.Once
	err     error
}

// AcquireInstanceLock acquires the singleton lock associated with socketPath.
// The caller must keep the returned lock open for the daemon's entire
// lifetime. The kernel releases the lock if the process exits unexpectedly.
func AcquireInstanceLock(socketPath string) (*InstanceLock, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return nil, fmt.Errorf("instance lock: socket path is required")
	}
	socketPath = filepath.Clean(socketPath)
	if err := ensurePrivateSocketDirectory(filepath.Dir(socketPath)); err != nil {
		return nil, fmt.Errorf("instance lock directory: %w", err)
	}

	path := instanceLockPath(socketPath)
	release, err := acquirePlatformInstanceLock(path)
	if errors.Is(err, errInstanceLockContended) {
		return nil, fmt.Errorf("%w (lock: %s)", ErrAlreadyRunning, path)
	}
	if err != nil {
		return nil, fmt.Errorf("acquire instance lock %s: %w", path, err)
	}
	return &InstanceLock{path: path, release: release}, nil
}

func instanceLockPath(socketPath string) string {
	return socketPath + ".lock"
}

// Path returns the persistent lock-file path.
func (l *InstanceLock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Close releases the singleton lock. It is safe to call Close more than once.
func (l *InstanceLock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.release != nil {
			l.err = l.release()
			l.release = nil
		}
	})
	return l.err
}
