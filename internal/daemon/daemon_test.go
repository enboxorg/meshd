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
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "meshd.sock")
}

func TestDefaultSocketPathUsesEnboxHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENBOX_HOME", dir)

	got := DefaultSocketPath()
	want := filepath.Join(dir, "meshd.sock")
	if got != want {
		t.Fatalf("DefaultSocketPath() = %q, want %q", got, want)
	}
}

func TestServerStartStop(t *testing.T) {
	sockDir := filepath.Join(t.TempDir(), "socket")
	if err := os.Mkdir(sockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(sockDir, "meshd.sock")
	srv := NewServer(sock, nil, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Socket file should exist.
	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("socket file not found: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(sockDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory mode = %o, want 0700", dirInfo.Mode().Perm())
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

func TestServerRejectsSymlinkSocketDirectory(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(root, "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	srv := NewServer(filepath.Join(link, "meshd.sock"), nil, nil)
	if err := srv.Start(); err == nil {
		srv.Stop()
		t.Fatal("Start accepted a symlink socket directory")
	}
}

func TestDetectsIntermediateSymlinkSocketDirectory(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	nested := filepath.Join(target, "socket")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	hasSymlink, err := socketDirectoryPathHasSymlink(filepath.Join(link, "socket"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSymlink {
		t.Fatal("intermediate symlink was not detected")
	}
}

func TestServerRejectsPublicSocketDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(filepath.Join(dir, "meshd.sock"), nil, nil)
	if err := srv.Start(); err == nil {
		srv.Stop()
		t.Fatal("Start accepted a group/world-accessible socket directory")
	}
}

func TestSocketAuthorizationAllowsDaemonAndOriginalSudoUser(t *testing.T) {
	allowed := authorizedSocketUIDs(0, "501", "20")
	for _, uid := range []string{"0", "501"} {
		if _, ok := allowed[uid]; !ok {
			t.Fatalf("authorized UIDs %v missing %s", allowed, uid)
		}
	}
	if _, ok := allowed["502"]; ok {
		t.Fatalf("authorized UIDs unexpectedly include 502: %v", allowed)
	}
	if uid, gid, ok := sudoSocketOwner(0, "501", "20"); !ok || uid != 501 || gid != 20 {
		t.Fatalf("sudoSocketOwner = %d, %d, %v", uid, gid, ok)
	}
	if _, _, ok := sudoSocketOwner(1000, "501", "20"); ok {
		t.Fatal("non-root process trusted SUDO_UID")
	}
}

func TestPrivateModeEnforcementPlatforms(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "freebsd"} {
		if !enforcePrivateMode(goos) {
			t.Fatalf("private Unix mode not enforced on %s", goos)
		}
	}
	if enforcePrivateMode("windows") {
		t.Fatal("POSIX mode bits enforced on Windows")
	}
}

func TestSocketDirectoryCreationPolicy(t *testing.T) {
	if !mayCreateSocketDirectory(1000, "", "") {
		t.Fatal("unprivileged daemon cannot create its socket directory")
	}
	if !mayCreateSocketDirectory(0, "", "") {
		t.Fatal("direct root daemon cannot create its trusted socket directory")
	}
	if mayCreateSocketDirectory(0, "1", "501") || mayCreateSocketDirectory(0, "", "501") {
		t.Fatal("sudo handoff can create a caller-selected socket directory as root")
	}
	if !privilegedSocketHandoff(0, "1", "501") || privilegedSocketHandoff(0, "", "") {
		t.Fatal("privileged socket handoff detection is incorrect")
	}
}

func TestStatusEndpoint(t *testing.T) {
	sock := testSocketPath(t)
	srv := NewServer(sock, func() Status {
		return Status{
			TUNDevice:       "meshd0",
			MeshIP:          "10.200.0.1",
			Network:         "test-net",
			OwnerDID:        "did:example:owner",
			NetworkRecordID: "network-1",
			Peers:           []PeerStatus{{Name: "peer-a", MeshIP: "10.200.0.2", Online: true}},
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
	if status.OwnerDID != "did:example:owner" {
		t.Errorf("OwnerDID = %q, want %q", status.OwnerDID, "did:example:owner")
	}
	if status.NetworkRecordID != "network-1" {
		t.Errorf("NetworkRecordID = %q, want %q", status.NetworkRecordID, "network-1")
	}
	if len(status.Peers) != 1 || status.Peers[0].Name != "peer-a" || status.Peers[0].MeshIP != "10.200.0.2" || !status.Peers[0].Online {
		t.Fatalf("Peers = %+v, want peer-a online at 10.200.0.2", status.Peers)
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

func TestShutdownSignalPersistsUntilReceived(t *testing.T) {
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
		t.Fatalf("first Shutdown() error: %v", err)
	}
	if err := client.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown() error: %v", err)
	}

	// Wait until both asynchronous handlers have had a chance to signal before
	// beginning to receive. A lossy unbuffered send would drop this notification.
	time.Sleep(150 * time.Millisecond)
	select {
	case <-srv.ShutdownCh():
	case <-time.After(time.Second):
		t.Fatal("shutdown signal was not retained for a late receiver")
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
