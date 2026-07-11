package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	instanceLockHelperEnv    = "MESHD_TEST_INSTANCE_LOCK_HELPER"
	instanceLockHelperSocket = "MESHD_TEST_INSTANCE_LOCK_SOCKET"
)

func TestInstanceLockExclusiveAndReusable(t *testing.T) {
	socket := testSocketPath(t)
	first, err := AcquireInstanceLock(socket)
	if err != nil {
		t.Fatalf("AcquireInstanceLock first: %v", err)
	}
	if first.Path() != socket+".lock" {
		t.Fatalf("lock path = %q, want %q", first.Path(), socket+".lock")
	}

	second, err := AcquireInstanceLock(socket)
	if second != nil || !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second lock = %v, %v; want ErrAlreadyRunning", second, err)
	}
	if !strings.Contains(err.Error(), first.Path()) {
		t.Fatalf("contention error %q does not identify lock path", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close first lock: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	third, err := AcquireInstanceLock(socket)
	if err != nil {
		t.Fatalf("reacquire after Close: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("Close third lock: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(instanceLockPath(socket))
		if err != nil {
			t.Fatalf("Stat lock file: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("lock mode = %o, want 0600", info.Mode().Perm())
		}
	}
}

func TestInstanceLockReleasedWhenProcessExits(t *testing.T) {
	socket := testSocketPath(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestInstanceLockHelperProcess$")
	cmd.Env = append(os.Environ(),
		instanceLockHelperEnv+"=1",
		instanceLockHelperSocket+"="+socket,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "locked" {
		t.Fatalf("helper output = %q, error = %v", scanner.Text(), scanner.Err())
	}
	if lock, err := AcquireInstanceLock(socket); lock != nil || !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("lock while helper alive = %v, %v; want contention", lock, err)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed helper exited successfully")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		lock, err := AcquireInstanceLock(socket)
		if err == nil {
			if closeErr := lock.Close(); closeErr != nil {
				t.Fatalf("Close recovered lock: %v", closeErr)
			}
			break
		}
		if !errors.Is(err, ErrAlreadyRunning) || time.Now().After(deadline) {
			t.Fatalf("reacquire after helper exit: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestInstanceLockHelperProcess(t *testing.T) {
	if os.Getenv(instanceLockHelperEnv) != "1" {
		return
	}
	lock, err := AcquireInstanceLock(os.Getenv(instanceLockHelperSocket))
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper lock: %v\n", err)
		os.Exit(2)
	}
	defer lock.Close()
	fmt.Println("locked")
	select {}
}
