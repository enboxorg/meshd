package daemon

import (
	"context"
	"fmt"
	"time"
)

const defaultProcessPollInterval = 100 * time.Millisecond

// ProcessAlive reports whether pid still identifies a live process. Lack of
// permission to inspect an elevated process counts as alive.
func ProcessAlive(pid int) (bool, error) {
	if pid <= 0 {
		return false, fmt.Errorf("process PID must be positive")
	}
	return processAlivePlatform(pid)
}

// WaitForProcessExit waits until pid is no longer alive. It deliberately does
// not consult the control socket, which may disappear or be replaced while the
// original daemon is still shutting down.
func WaitForProcessExit(ctx context.Context, pid int, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = defaultProcessPollInterval
	}
	for {
		alive, err := ProcessAlive(pid)
		if err != nil {
			return fmt.Errorf("check process %d: %w", pid, err)
		}
		if !alive {
			return nil
		}

		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("wait for process %d exit: %w", pid, ctx.Err())
		case <-timer.C:
		}
	}
}
