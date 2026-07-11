package trayapp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/enboxorg/meshd/internal/daemon"
)

func TestServiceConnectRunsSelectedProfile(t *testing.T) {
	var gotExecutable string
	var gotArgs, gotEnv []string
	service := NewService("work")
	service.findMeshd = func() (string, error) { return "/opt/meshd", nil }
	service.launchConnect = func(_ context.Context, executable string, args, env []string) ([]byte, error) {
		gotExecutable, gotArgs, gotEnv = executable, args, env
		return nil, nil
	}

	if err := service.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if gotExecutable != "/opt/meshd" || !reflect.DeepEqual(gotArgs, []string{"up", "--profile", "work"}) {
		t.Fatalf("command = %q %v", gotExecutable, gotArgs)
	}
	if len(gotEnv) == 0 {
		t.Fatal("connect launcher received an empty environment")
	}
}

func TestServiceConnectReportsCommandOutput(t *testing.T) {
	service := NewService("")
	service.findMeshd = func() (string, error) { return "/opt/meshd", nil }
	service.launchConnect = func(context.Context, string, []string, []string) ([]byte, error) {
		return []byte("vault password required\nrun meshd vault remember"), errors.New("exit status 1")
	}
	err := service.Connect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "meshd vault remember") {
		t.Fatalf("Connect error = %v", err)
	}
}

func TestServiceDisconnectWaitsForExactProcess(t *testing.T) {
	socket := privateSocketPath(t)
	server := daemon.NewServer(socket, nil, nil)
	server.SetInstanceID("tray-instance")
	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer server.Stop()
	go func() {
		<-server.ShutdownCh()
		server.Stop()
	}()

	service := NewService("")
	service.socket = socket
	service.client = daemon.NewClient(socket)
	service.disconnectPoll = time.Millisecond
	var gotPID int
	var gotPoll time.Duration
	service.waitForExit = func(_ context.Context, pid int, poll time.Duration) error {
		gotPID = pid
		gotPoll = poll
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if gotPID != os.Getpid() || gotPoll != time.Millisecond {
		t.Fatalf("process wait = pid %d poll %s, want pid %d poll 1ms", gotPID, gotPoll, os.Getpid())
	}
}

func TestServiceStatusReusesDaemonConnection(t *testing.T) {
	socket := privateSocketPath(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	counted := &countingListener{Listener: listener}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(daemon.Status{Running: true})
	})}
	go func() { _ = server.Serve(counted) }()
	t.Cleanup(func() { _ = server.Close() })

	service := NewService("")
	service.socket = socket
	service.client = daemon.NewClient(socket)
	for i := 0; i < 2; i++ {
		status, err := service.Status(context.Background())
		if err != nil || status == nil || !status.Running {
			t.Fatalf("Status %d = %+v, %v", i, status, err)
		}
	}
	if got := counted.accepts.Load(); got != 1 {
		t.Fatalf("daemon connections = %d, want 1 reused connection", got)
	}
}

func TestServiceDisconnectDoesNotHideResponsiveServerError(t *testing.T) {
	socket := privateSocketPath(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v0/status" {
			_ = json.NewEncoder(w).Encode(daemon.Status{
				Running:    true,
				PID:        os.Getpid(),
				InstanceID: "responsive-instance",
			})
			return
		}
		http.Error(w, "shutdown rejected", http.StatusInternalServerError)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	service := NewService("")
	service.socket = socket
	service.client = daemon.NewClient(socket)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Disconnect(ctx); err == nil || !strings.Contains(err.Error(), "shutdown rejected") {
		t.Fatalf("Disconnect error = %v, want responsive server error", err)
	}
}

func TestServiceDisconnectAcceptsRequestRaceWhenCapturedProcessExited(t *testing.T) {
	socket := privateSocketPath(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v0/status" {
			_ = json.NewEncoder(w).Encode(daemon.Status{
				Running:    true,
				PID:        5151,
				InstanceID: "exited-instance",
			})
			return
		}
		http.Error(w, "socket closing", http.StatusInternalServerError)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	service := NewService("")
	service.socket = socket
	service.client = daemon.NewClient(socket)
	service.processAlive = func(pid int) (bool, error) {
		if pid != 5151 {
			t.Fatalf("process check PID = %d, want 5151", pid)
		}
		return false, nil
	}
	if err := service.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect request race: %v", err)
	}
}

func TestServiceDisconnectTargetsObservedInstance(t *testing.T) {
	socket := privateSocketPath(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	targets := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v0/status" {
			_ = json.NewEncoder(w).Encode(daemon.Status{
				Running:    true,
				PID:        4242,
				InstanceID: "observed-instance",
			})
			return
		}
		targets <- r.Header.Get("X-Meshd-Instance-ID")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "shutting down"})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	service := NewService("")
	service.socket = socket
	service.client = daemon.NewClient(socket)
	var gotPID int
	service.waitForExit = func(_ context.Context, pid int, _ time.Duration) error {
		gotPID = pid
		return nil
	}
	if err := service.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if got := <-targets; got != "observed-instance" {
		t.Fatalf("shutdown target = %q, want observed-instance", got)
	}
	if gotPID != 4242 {
		t.Fatalf("process wait PID = %d, want 4242", gotPID)
	}
}

func TestServiceDisconnectReportsProcessWaitFailure(t *testing.T) {
	socket := privateSocketPath(t)
	server := daemon.NewServer(socket, nil, nil)
	server.SetInstanceID("surviving-instance")
	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer server.Stop()

	service := NewService("")
	service.socket = socket
	service.client = daemon.NewClient(socket)
	service.waitForExit = func(context.Context, int, time.Duration) error {
		return context.DeadlineExceeded
	}
	err := service.Disconnect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "process "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("Disconnect wait error = %v", err)
	}
}

func TestServiceDisconnectAlreadyStopped(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "missing.sock")
	service := NewService("")
	service.socket = socket
	service.client = daemon.NewClient(socket)
	if err := service.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect absent daemon: %v", err)
	}
}

func TestServiceDashboardURLPrefersLiveDaemonContext(t *testing.T) {
	service := NewService("")
	got := service.DashboardURL(&daemon.Status{
		OwnerDID:        "did:example:owner",
		NetworkRecordID: "network-7",
	})
	if got != "https://admin.meshd.sh?network=network-7&owner=did%3Aexample%3Aowner" {
		t.Fatalf("DashboardURL = %q", got)
	}
}

func TestServiceOpenDashboardAndCopyText(t *testing.T) {
	service := NewService("")
	var opened, copied string
	service.openURL = func(rawURL string) error { opened = rawURL; return nil }
	service.writeClipboard = func(_ context.Context, text string) error { copied = text; return nil }
	status := &daemon.Status{OwnerDID: "did:example:owner"}
	if err := service.OpenDashboard(status); err != nil {
		t.Fatalf("OpenDashboard: %v", err)
	}
	if err := service.CopyText(context.Background(), "10.200.0.8"); err != nil {
		t.Fatalf("CopyText: %v", err)
	}
	if !strings.Contains(opened, "owner=did%3Aexample%3Aowner") || copied != "10.200.0.8" {
		t.Fatalf("opened = %q, copied = %q", opened, copied)
	}
}

func TestFindMeshdExecutableOrder(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	tray := filepath.Join(root, "release", "meshd-tray")
	sibling := filepath.Join(filepath.Dir(tray), "meshd")
	if err := os.MkdirAll(filepath.Dir(tray), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sibling, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findMeshdExecutable(tray, home, "darwin", func(string) (string, error) {
		return "/path/meshd", nil
	})
	if err != nil || got != sibling {
		t.Fatalf("findMeshdExecutable = %q, %v; want sibling %q", got, err, sibling)
	}
}

func TestFindMeshdExecutableBesideAppBundle(t *testing.T) {
	root := t.TempDir()
	tray := filepath.Join(root, "meshd-tray.app", "Contents", "MacOS", "meshd-tray")
	meshd := filepath.Join(root, "meshd")
	if err := os.WriteFile(meshd, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findMeshdExecutable(tray, "", "darwin", func(string) (string, error) {
		return "", errors.New("not found")
	})
	if err != nil || got != meshd {
		t.Fatalf("findMeshdExecutable = %q, %v; want %q", got, err, meshd)
	}
}

func TestCompactOutput(t *testing.T) {
	got := compactOutput([]byte(" one\n\n two\tthree "))
	if got != "one two three" {
		t.Fatalf("compactOutput = %q", got)
	}
}

func TestCompactOutputTruncatesUTF8ByRunes(t *testing.T) {
	got := compactOutput([]byte(strings.Repeat("界", 300)))
	if !utf8.ValidString(got) {
		t.Fatalf("compactOutput returned invalid UTF-8: %q", got)
	}
	if count := utf8.RuneCountInString(got); count != 240 {
		t.Fatalf("compactOutput rune count = %d, want 240", count)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("compactOutput = %q, want ellipsis suffix", got)
	}
}

func TestMacOSTerminalCommandKeepsPayloadOutOfScript(t *testing.T) {
	executable := "/Applications/meshd \"tools\"/meshd's\nmalicious"
	payload := "work; touch /tmp/not-safe\nend tell"
	command := connectShellCommand(executable, []string{
		"up", "--profile", payload,
	})
	for _, want := range []string{
		`'/Applications/meshd "tools"/meshd'\''s` + "\n" + `malicious'`,
		`'work; touch /tmp/not-safe` + "\n" + `end tell'`,
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("Terminal command missing %q:\n%s", want, command)
		}
	}
	for _, untrusted := range []string{executable, payload, "malicious", "not-safe"} {
		if strings.Contains(macOSTerminalScript, untrusted) {
			t.Fatalf("Terminal script contains untrusted payload %q:\n%s", untrusted, macOSTerminalScript)
		}
	}
	if strings.Contains(macOSTerminalScript, "with administrator privileges") {
		t.Fatalf("Terminal script requested direct elevation:\n%s", macOSTerminalScript)
	}
}

type countingListener struct {
	net.Listener
	accepts atomic.Int32
}

func privateSocketPath(t *testing.T) string {
	t.Helper()
	// Darwin limits sockaddr_un paths to 104 bytes. t.TempDir includes the
	// full test name and can exceed that limit on hosted macOS runners.
	dir, err := os.MkdirTemp("", "meshd-tray-")
	if err != nil {
		t.Fatalf("MkdirTemp socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod socket directory: %v", err)
	}
	return filepath.Join(dir, "m.sock")
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return conn, err
}
