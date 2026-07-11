package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client communicates with a running meshd daemon via Unix socket.
type Client struct {
	socketPath string
	httpClient *http.Client
}

// NewClient creates a new daemon client that connects to the given socket.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
			Timeout: 5 * time.Second,
		},
	}
}

// Shutdown sends a shutdown request to the running daemon.
func (c *Client) Shutdown(ctx context.Context) error {
	return c.shutdown(ctx, "")
}

// ShutdownInstance sends a shutdown request only to the daemon with the
// supplied instance ID. A different daemon at the same socket path rejects
// the request with ErrInstanceMismatch.
func (c *Client) ShutdownInstance(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return fmt.Errorf("shutdown instance: instance ID is required")
	}
	return c.shutdown(ctx, instanceID)
}

func (c *Client) shutdown(ctx context.Context, instanceID string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", "http://meshd/api/v0/shutdown", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	if instanceID != "" {
		req.Header.Set(instanceIDHeader, instanceID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusConflict {
			return fmt.Errorf("%w: %s", ErrInstanceMismatch, string(body))
		}
		return fmt.Errorf("daemon returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetStatus queries the running daemon for its current status.
func (c *Client) GetStatus(ctx context.Context) (*Status, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://meshd/api/v0/status", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("daemon returned %d: %s", resp.StatusCode, string(body))
	}

	var status Status
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("parsing status: %w", err)
	}

	return &status, nil
}

// IsRunning checks whether a daemon is listening on the socket.
func (c *Client) IsRunning() bool {
	conn, err := net.DialTimeout("unix", c.socketPath, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
