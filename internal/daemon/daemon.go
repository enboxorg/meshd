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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
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
	Running   bool   `json:"running"`
	TUNDevice string `json:"tunDevice,omitempty"`
	MeshIP    string `json:"meshIP,omitempty"`
	Network   string `json:"network,omitempty"`
	Uptime    string `json:"uptime,omitempty"`
	PID       int    `json:"pid"`
}

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

	// shutdownCh is signaled when a shutdown request is received.
	shutdownCh chan struct{}
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

	// Ensure socket directory exists.
	sockDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		return fmt.Errorf("creating socket directory: %w", err)
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

	// Set socket permissions: world-accessible on platforms with peer
	// creds (Linux, macOS), restricted otherwise.
	perm := os.FileMode(0600)
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd":
		perm = 0666
	}
	if err := os.Chmod(s.socketPath, perm); err != nil {
		s.logger.Warn("setting socket permissions", slog.Any("error", err))
	}

	s.listener = listener

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v0/shutdown", s.handleShutdown)
	mux.HandleFunc("GET /api/v0/status", s.handleStatus)

	s.srv = &http.Server{Handler: mux}

	go func() {
		if err := s.srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Warn("daemon server error", slog.Any("error", err))
		}
	}()

	s.logger.Info("daemon control socket listening", slog.String("path", s.socketPath))
	return nil
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
		select {
		case s.shutdownCh <- struct{}{}:
		default:
		}
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
