package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestWaitForProcessExitTimesOutWhileExactPIDLives(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := WaitForProcessExit(ctx, os.Getpid(), time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForProcessExit error = %v, want deadline exceeded", err)
	}
}

func TestWaitForProcessExitReturnsAfterExit(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestExitedProcessHelper$")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := WaitForProcessExit(ctx, pid, time.Millisecond); err != nil {
		t.Fatalf("WaitForProcessExit: %v", err)
	}
}

func TestExitedProcessHelper(t *testing.T) {}

func TestProcessAliveRejectsInvalidPID(t *testing.T) {
	if _, err := ProcessAlive(0); err == nil {
		t.Fatal("ProcessAlive accepted PID 0")
	}
}
