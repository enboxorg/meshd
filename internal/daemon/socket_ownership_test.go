package daemon

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestDetachedServerStopPreservesReplacementSocket(t *testing.T) {
	socket := testSocketPath(t)
	first := NewServer(socket, nil, nil)
	first.SetInstanceID("first")
	if err := first.Start(); err != nil {
		t.Fatalf("start first server: %v", err)
	}
	defer first.Stop()

	// Detach the first listener from the filesystem namespace, then bind a
	// replacement at the same textual path. ss still reports that path for the
	// detached listener, but only the replacement is reachable by new clients.
	if err := os.Remove(socket); err != nil {
		t.Fatalf("detach first socket: %v", err)
	}
	second := NewServer(socket, nil, nil)
	second.SetInstanceID("second")
	if err := second.Start(); err != nil {
		t.Fatalf("start replacement server: %v", err)
	}
	defer second.Stop()

	first.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	status, err := NewClient(socket).GetStatus(ctx)
	if err != nil {
		t.Fatalf("replacement socket was removed by first Stop: %v", err)
	}
	if status.InstanceID != "second" {
		t.Fatalf("reachable instance = %q, want second", status.InstanceID)
	}

	// A repeated Stop must not retain stale inode identity that could match a
	// future filesystem entry after inode reuse.
	first.Stop()
	if _, err := os.Lstat(socket); err != nil {
		t.Fatalf("repeated first Stop removed replacement: %v", err)
	}
}
