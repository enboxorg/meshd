package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "meshd.sock")
}

func TestServerStartStop(t *testing.T) {
	sock := testSocketPath(t)
	srv := NewServer(sock, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Socket file should exist.
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket file not found: %v", err)
	}

	srv.Stop()

	// Socket file should be removed.
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket file not removed after Stop()")
	}
}

func TestServerRejectsDoubleStart(t *testing.T) {
	sock := testSocketPath(t)
	srv1 := NewServer(sock, nil, nil)
	if err := srv1.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv1.Stop()

	// A second server on the same socket should fail.
	srv2 := NewServer(sock, nil, nil)
	if err := srv2.Start(); err == nil {
		srv2.Stop()
		t.Fatal("expected error starting second server on same socket")
	}
}

func TestStaleSocketCleanup(t *testing.T) {
	sock := testSocketPath(t)

	// Create a stale socket file (no listener).
	if err := os.MkdirAll(filepath.Dir(sock), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(sock, nil, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start() should clean up stale socket: %v", err)
	}
	defer srv.Stop()
}

func TestStatusEndpoint(t *testing.T) {
	sock := testSocketPath(t)
	srv := NewServer(sock, func() Status {
		return Status{
			TUNDevice: "meshd0",
			MeshIP:    "10.200.0.1",
			Network:   "test-net",
		}
	}, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	client := NewClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := client.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus() error: %v", err)
	}

	if !status.Running {
		t.Error("expected Running=true")
	}
	if status.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", status.PID, os.Getpid())
	}
	if status.TUNDevice != "meshd0" {
		t.Errorf("TUNDevice = %q, want %q", status.TUNDevice, "meshd0")
	}
	if status.MeshIP != "10.200.0.1" {
		t.Errorf("MeshIP = %q, want %q", status.MeshIP, "10.200.0.1")
	}
	if status.Network != "test-net" {
		t.Errorf("Network = %q, want %q", status.Network, "test-net")
	}
	if status.Uptime == "" {
		t.Error("expected non-empty Uptime")
	}
}

func TestStatusEndpointNoFunc(t *testing.T) {
	sock := testSocketPath(t)
	srv := NewServer(sock, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	client := NewClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, err := client.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus() error: %v", err)
	}

	if !status.Running {
		t.Error("expected Running=true")
	}
	if status.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", status.PID, os.Getpid())
	}
}

func TestShutdownEndpoint(t *testing.T) {
	sock := testSocketPath(t)
	srv := NewServer(sock, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	client := NewClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	// The shutdown channel should be signaled.
	select {
	case <-srv.ShutdownCh():
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownCh not signaled within timeout")
	}
}

func TestShutdownEndpointResponse(t *testing.T) {
	sock := testSocketPath(t)
	srv := NewServer(sock, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	// Use raw HTTP to check the response body.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Post("http://meshd/api/v0/shutdown", "", nil)
	if err != nil {
		t.Fatalf("POST /api/v0/shutdown error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "shutting down" {
		t.Errorf("body status = %q, want %q", body["status"], "shutting down")
	}
}

func TestClientIsRunning(t *testing.T) {
	sock := testSocketPath(t)
	client := NewClient(sock)

	// No server running — should return false.
	if client.IsRunning() {
		t.Fatal("expected IsRunning=false when no server")
	}

	srv := NewServer(sock, nil, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Server running — should return true.
	if !client.IsRunning() {
		t.Fatal("expected IsRunning=true when server running")
	}

	srv.Stop()

	// Server stopped — should return false.
	if client.IsRunning() {
		t.Fatal("expected IsRunning=false after Stop()")
	}
}

func TestClientShutdownNoServer(t *testing.T) {
	sock := testSocketPath(t)
	client := NewClient(sock)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := client.Shutdown(ctx)
	if err == nil {
		t.Fatal("expected error when no server running")
	}
}

func TestClientGetStatusNoServer(t *testing.T) {
	sock := testSocketPath(t)
	client := NewClient(sock)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.GetStatus(ctx)
	if err == nil {
		t.Fatal("expected error when no server running")
	}
}

func TestSocketPath(t *testing.T) {
	sock := testSocketPath(t)
	srv := NewServer(sock, nil, nil)
	if got := srv.SocketPath(); got != sock {
		t.Errorf("SocketPath() = %q, want %q", got, sock)
	}
}

func TestDefaultSocketPath(t *testing.T) {
	p := DefaultSocketPath()
	if p == "" {
		t.Fatal("DefaultSocketPath() returned empty string")
	}
}
