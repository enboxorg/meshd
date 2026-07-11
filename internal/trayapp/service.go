package trayapp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/enboxorg/meshd/internal/clipboard"
	"github.com/enboxorg/meshd/internal/daemon"
	"github.com/enboxorg/meshd/internal/dashboard"
	"github.com/enboxorg/meshd/internal/openurl"
)

const defaultDisconnectPoll = 150 * time.Millisecond

type commandRunner func(context.Context, string, []string, []string) ([]byte, error)
type processWaiter func(context.Context, int, time.Duration) error
type processChecker func(int) (bool, error)

// Service performs the side effects requested from the tray menu.
type Service struct {
	profile string
	socket  string
	client  *daemon.Client

	findMeshd      func() (string, error)
	launchConnect  commandRunner
	openURL        func(string) error
	writeClipboard func(context.Context, string) error
	waitForExit    processWaiter
	processAlive   processChecker
	disconnectPoll time.Duration
}

// NewService creates a tray service for profile. An empty profile follows the
// normal ENBOX_PROFILE/default-profile resolution.
func NewService(profile string) *Service {
	socket := daemon.DefaultSocketPath()
	return &Service{
		profile:        strings.TrimSpace(profile),
		socket:         socket,
		client:         daemon.NewClient(socket),
		findMeshd:      FindMeshdExecutable,
		launchConnect:  connectCommand,
		openURL:        openurl.Open,
		writeClipboard: clipboard.WriteText,
		waitForExit:    daemon.WaitForProcessExit,
		processAlive:   daemon.ProcessAlive,
		disconnectPoll: defaultDisconnectPoll,
	}
}

// Status returns the running daemon status. A connection or decoding error
// means the tray should render the daemon as disconnected.
func (s *Service) Status(ctx context.Context) (*daemon.Status, error) {
	return s.client.GetStatus(ctx)
}

// Connect starts meshd for the selected profile. macOS hands the command to a
// visible Terminal so the CLI can own any interactive sudo flow; other
// platforms wait for the CLI's normal background-start readiness check.
func (s *Service) Connect(ctx context.Context) error {
	executable, err := s.findMeshd()
	if err != nil {
		return err
	}
	args := []string{"up"}
	if s.profile != "" {
		args = append(args, "--profile", s.profile)
	}
	output, err := s.launchConnect(ctx, executable, args, os.Environ())
	if err != nil {
		detail := compactOutput(output)
		if detail != "" {
			return fmt.Errorf("meshd up: %w: %s", err, detail)
		}
		return fmt.Errorf("meshd up: %w", err)
	}
	return nil
}

// Disconnect requests a graceful shutdown of the observed daemon instance and
// waits for that exact process to exit.
func (s *Service) Disconnect(ctx context.Context) error {
	status, err := s.client.GetStatus(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("read meshd status: %w", ctx.Err())
		}
		if !s.client.IsRunning() {
			return nil
		}
		return fmt.Errorf("read meshd status: %w", err)
	}
	if status == nil || status.PID <= 0 {
		return fmt.Errorf("meshd status did not include a valid process ID; refusing an unverified disconnect")
	}

	if status.InstanceID != "" {
		err = s.client.ShutdownInstance(ctx, status.InstanceID)
	} else {
		// A daemon already running during an in-place upgrade may predate
		// instance IDs. The exact captured PID is still verified below.
		err = s.client.Shutdown(ctx)
	}
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("request shutdown: %w", ctx.Err())
		}
		processAlive := s.processAlive
		if processAlive == nil {
			processAlive = daemon.ProcessAlive
		}
		alive, aliveErr := processAlive(status.PID)
		if aliveErr == nil && !alive {
			return nil
		}
		if aliveErr != nil {
			return fmt.Errorf("request shutdown: %w (could not verify process %d: %v)", err, status.PID, aliveErr)
		}
		return fmt.Errorf("request shutdown: %w", err)
	}

	poll := s.disconnectPoll
	if poll <= 0 {
		poll = defaultDisconnectPoll
	}
	waitForExit := s.waitForExit
	if waitForExit == nil {
		waitForExit = daemon.WaitForProcessExit
	}
	if err := waitForExit(ctx, status.PID, poll); err != nil {
		return fmt.Errorf("wait for meshd process %d shutdown: %w", status.PID, err)
	}
	return nil
}

// DashboardURL builds the dashboard URL from live daemon context when
// connected, falling back to the selected local profile when disconnected.
func (s *Service) DashboardURL(status *daemon.Status) string {
	ctx := dashboard.ResolveContext(s.profile)
	if status != nil && (status.OwnerDID != "" || status.NetworkRecordID != "") {
		ctx = dashboard.Context{
			OwnerDID:        status.OwnerDID,
			NetworkRecordID: status.NetworkRecordID,
		}
	}
	return dashboard.BuildURL(dashboard.DefaultURL, ctx)
}

// OpenDashboard opens the dashboard in the default browser.
func (s *Service) OpenDashboard(status *daemon.Status) error {
	if err := s.openURL(s.DashboardURL(status)); err != nil {
		return fmt.Errorf("open dashboard: %w", err)
	}
	return nil
}

// CopyText writes a mesh IP to the system clipboard.
func (s *Service) CopyText(ctx context.Context, text string) error {
	if err := s.writeClipboard(ctx, text); err != nil {
		return fmt.Errorf("copy mesh IP: %w", err)
	}
	return nil
}

// FindMeshdExecutable finds the daemon CLI next to the tray executable, in
// the standard installer directory, or on PATH (in that order).
func FindMeshdExecutable() (string, error) {
	if override := strings.TrimSpace(os.Getenv("MESHD_BINARY")); override != "" {
		if regularFile(override) {
			return override, nil
		}
		return "", fmt.Errorf("MESHD_BINARY does not name a file: %s", override)
	}

	trayExecutable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve meshd-tray executable: %w", err)
	}
	home, _ := os.UserHomeDir()
	return findMeshdExecutable(trayExecutable, home, runtime.GOOS, exec.LookPath)
}

func findMeshdExecutable(trayExecutable, home, goos string, lookPath func(string) (string, error)) (string, error) {
	name := "meshd"
	if goos == "windows" {
		name += ".exe"
	}

	candidates := []string{filepath.Join(filepath.Dir(trayExecutable), name)}
	const appMarker = ".app" + string(filepath.Separator) + "Contents" + string(filepath.Separator) + "MacOS"
	if index := strings.LastIndex(trayExecutable, appMarker); index >= 0 {
		appRoot := trayExecutable[:index+len(".app")]
		candidates = append(candidates,
			filepath.Join(filepath.Dir(appRoot), name),
			filepath.Join(filepath.Dir(appRoot), "bin", name),
		)
	}
	if home != "" {
		candidates = append(candidates, filepath.Join(home, ".meshd", "bin", name))
	}
	for _, candidate := range candidates {
		if regularFile(candidate) {
			return candidate, nil
		}
	}
	if found, err := lookPath(name); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("cannot find %s; reinstall meshd or set MESHD_BINARY", name)
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func runCommand(ctx context.Context, executable string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

func compactOutput(output []byte) string {
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return ""
	}
	detail := strings.Join(fields, " ")
	return truncateRunes(detail, 240)
}
