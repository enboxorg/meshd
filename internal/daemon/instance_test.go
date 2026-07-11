package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTargetedShutdownRejectsDifferentInstance(t *testing.T) {
	socket := testSocketPath(t)
	server := NewServer(socket, nil, nil)
	server.SetInstanceID("instance-a")
	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer server.Stop()

	client := NewClient(socket)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := client.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.InstanceID != "instance-a" {
		t.Fatalf("instance ID = %q, want instance-a", status.InstanceID)
	}

	err = client.Shutdown(ctx)
	if !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("headerless shutdown error = %v, want ErrInstanceMismatch", err)
	}
	select {
	case <-server.ShutdownCh():
		t.Fatal("headerless request signaled instance-bearing server")
	case <-time.After(100 * time.Millisecond):
	}

	err = client.ShutdownInstance(ctx, "instance-b")
	if !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("wrong-instance shutdown error = %v, want ErrInstanceMismatch", err)
	}
	select {
	case <-server.ShutdownCh():
		t.Fatal("wrong-instance request signaled shutdown")
	case <-time.After(100 * time.Millisecond):
	}

	if err := client.ShutdownInstance(ctx, "instance-a"); err != nil {
		t.Fatalf("matching shutdown: %v", err)
	}
	select {
	case <-server.ShutdownCh():
	case <-time.After(time.Second):
		t.Fatal("matching shutdown did not signal server")
	}
}

func TestNewInstanceID(t *testing.T) {
	first, err := NewInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || len(second) != 32 || first == second {
		t.Fatalf("instance IDs = %q, %q", first, second)
	}
}
