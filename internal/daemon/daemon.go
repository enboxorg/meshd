// Package daemon provides a lightweight control socket for meshd.
//
// When meshd up starts, it opens a Unix socket and serves a minimal HTTP
// API. Other commands (meshd down, meshd status) connect to this socket
// to control or query the running daemon.
//
// Endpoints:
//
//	POST /api/v0/shutdown  — gracefully stop the daemon
//	GET  /api/v0/status    — return running state as JSON
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/tailscale/peercred"
)

// DefaultSocketPath returns the default Unix socket path for the daemon.
//
// ENBOX_HOME set: $ENBOX_HOME/meshd.sock
// Root: /var/run/meshd/meshd.sock
// User: ~/.enbox/meshd.sock
func DefaultSocketPath() string {
	if d := os.Getenv("ENBOX_HOME"); d != "" {
		return filepath.Join(d, "meshd.sock")
	}
	if os.Getuid() == 0 {
		return "/var/run/meshd/meshd.sock"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/meshd.sock"
	}
	return filepath.Join(home, ".enbox", "meshd.sock")
}

// Status is the JSON response from GET /api/v0/status.
type Status struct {
	Running         bool         `json:"running"`
	TUNDevice       string       `json:"tunDevice,omitempty"`
	MeshIP          string       `json:"meshIP,omitempty"`
	Network         string       `json:"network,omitempty"`
	OwnerDID        string       `json:"ownerDID,omitempty"`
	NetworkRecordID string       `json:"networkRecordID,omitempty"`
	Peers           []PeerStatus `json:"peers,omitempty"`
	Uptime          string       `json:"uptime,omitempty"`
	PID             int          `json:"pid"`
}

// PeerStatus is the status-facing view of a peer from the engine's latest
// network map.
type PeerStatus struct {
	Name   string `json:"name"`
	MeshIP string `json:"meshIP"`
	Online bool   `json:"online"`
}

type peerAuthorizedContextKey struct{}

// StatusFunc is called to obtain the current daemon status.
type StatusFunc func() Status

// Server is a lightweight HTTP control server over a Unix socket.
type Server struct {
	socketPath string
	logger     *slog.Logger
	statusFn   StatusFunc
	startTime  time.Time

	mu       sync.Mutex
	listener net.Listener
	srv      *http.Server

	// shutdownCh is closed once when a shutdown request is received.
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
}

// NewServer creates a new daemon control server.
//
// The statusFn callback is called to obtain current status for the
// /api/v0/status endpoint. The returned ShutdownCh() channel is
// signaled when a POST /api/v0/shutdown request is received.
func NewServer(socketPath string, statusFn StatusFunc, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		socketPath: socketPath,
		logger:     logger,
		statusFn:   statusFn,
		startTime:  time.Now(),
		shutdownCh: make(chan struct{}),
	}
}

// ShutdownCh returns a channel that is closed when a shutdown request
// is received via the control socket.
func (s *Server) ShutdownCh() <-chan struct{} {
	return s.shutdownCh
}

// SocketPath returns the path of the Unix socket.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// Start begins listening on the Unix socket and serving HTTP requests.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The daemon can run as root after a sudo TUN handoff, while the socket
	// remains in the invoking user's state directory. Refuse symlinked or
	// group/world-accessible directories instead of changing an
	// environment-selected path as root.
	sockDir := filepath.Dir(s.socketPath)
	if err := ensurePrivateSocketDirectory(sockDir); err != nil {
		return err
	}

	// Remove stale socket if no one is listening.
	if conn, err := net.Dial("unix", s.socketPath); err == nil {
		conn.Close()
		return fmt.Errorf("another meshd instance is already running (socket: %s)", s.socketPath)
	}
	_ = os.Remove(s.socketPath)

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.socketPath, err)
	}

	uid, gid, changeOwner := sudoSocketOwner(os.Geteuid(), os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"))
	if err := secureSocketFile(s.socketPath, uid, gid, changeOwner); err != nil {
		listener.Close()
		_ = os.Remove(s.socketPath)
		return err
	}

	s.listener = listener

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v0/shutdown", s.handleShutdown)
	mux.HandleFunc("GET /api/v0/status", s.handleStatus)

	allowedUIDs := authorizedSocketUIDs(os.Geteuid(), os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"))
	s.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authorized, _ := r.Context().Value(peerAuthorizedContextKey{}).(bool); !authorized {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			mux.ServeHTTP(w, r)
		}),
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, peerAuthorizedContextKey{}, socketPeerAuthorized(conn, allowedUIDs))
		},
	}

	go func() {
		if err := s.srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Warn("daemon server error", slog.Any("error", err))
		}
	}()

	s.logger.Info("daemon control socket listening", slog.String("path", s.socketPath))
	return nil
}

func ensurePrivateSocketDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if !mayCreateSocketDirectory(os.Geteuid(), os.Getenv("MESHD_SUDO_CHILD"), os.Getenv("SUDO_UID")) {
			return fmt.Errorf("socket directory must be created by the invoking user before privilege elevation: %s", dir)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating socket directory: %w", err)
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("inspect socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("socket directory must be a real directory, not a symlink: %s", dir)
	}
	if privilegedSocketHandoff(os.Geteuid(), os.Getenv("MESHD_SUDO_CHILD"), os.Getenv("SUDO_UID")) {
		hasSymlink, err := socketDirectoryPathHasSymlink(dir)
		if err != nil {
			return err
		}
		if hasSymlink {
			return fmt.Errorf("socket directory path must not contain symlinks during privilege handoff: %s", dir)
		}
	}
	if enforcePrivateMode(runtime.GOOS) && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("socket directory permissions must be 0700: %s", dir)
	}
	return nil
}

func mayCreateSocketDirectory(euid int, sudoChild, sudoUID string) bool {
	return !privilegedSocketHandoff(euid, sudoChild, sudoUID)
}

func privilegedSocketHandoff(euid int, sudoChild, sudoUID string) bool {
	return euid == 0 && (sudoChild != "" || sudoUID != "")
}

func socketDirectoryPathHasSymlink(dir string) (bool, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false, fmt.Errorf("resolve socket directory: %w", err)
	}
	resolvedDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return false, fmt.Errorf("resolve socket directory symlinks: %w", err)
	}
	return filepath.Clean(resolvedDir) != filepath.Clean(absDir), nil
}

func enforcePrivateMode(goos string) bool {
	switch goos {
	case "linux", "darwin", "freebsd":
		return true
	default:
		return false
	}
}

func sudoSocketOwner(euid int, sudoUID, sudoGID string) (uid, gid int, ok bool) {
	if euid != 0 {
		return 0, 0, false
	}
	uid64, uidErr := strconv.ParseInt(sudoUID, 10, 32)
	gid64, gidErr := strconv.ParseInt(sudoGID, 10, 32)
	if uidErr != nil || gidErr != nil || uid64 <= 0 || gid64 < 0 {
		return 0, 0, false
	}
	return int(uid64), int(gid64), true
}

func authorizedSocketUIDs(euid int, sudoUID, sudoGID string) map[string]struct{} {
	allowed := map[string]struct{}{strconv.Itoa(euid): {}}
	if uid, _, ok := sudoSocketOwner(euid, sudoUID, sudoGID); ok {
		allowed[strconv.Itoa(uid)] = struct{}{}
	}
	return allowed
}

func socketPeerAuthorized(conn net.Conn, allowedUIDs map[string]struct{}) bool {
	creds, err := peercred.Get(conn)
	if errors.Is(err, peercred.ErrNotImplemented) {
		// Platforms without peer credentials rely on the owner-only socket.
		return true
	}
	if err != nil {
		return false
	}
	uid, ok := creds.UserID()
	if !ok {
		return false
	}
	_, ok = allowedUIDs[uid]
	return ok
}

// Stop gracefully shuts down the HTTP server and removes the socket.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	_ = os.Remove(s.socketPath)
	s.logger.Info("daemon control socket closed")
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("shutdown requested via control socket")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "shutting down"})

	// Signal shutdown asynchronously so the HTTP response is sent first.
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.shutdownOnce.Do(func() { close(s.shutdownCh) })
	}()
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := Status{
		Running: true,
		PID:     os.Getpid(),
	}
	if s.statusFn != nil {
		status = s.statusFn()
		status.Running = true
		status.PID = os.Getpid()
	}
	status.Uptime = time.Since(s.startTime).Round(time.Second).String()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
