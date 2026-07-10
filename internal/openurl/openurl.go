// Package openurl opens URLs with the operating system's default browser.
package openurl

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const openTimeout = 5 * time.Second

// Command returns the platform browser-opening command for rawURL.
func Command(goos, rawURL string) (string, []string, bool) {
	switch goos {
	case "darwin":
		return "open", []string{rawURL}, true
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}, true
	default:
		return "xdg-open", []string{rawURL}, true
	}
}

// Open opens rawURL in the current platform's default browser.
func Open(rawURL string) error {
	if strings.TrimSpace(rawURL) == "" {
		return fmt.Errorf("URL is empty")
	}

	name, args, ok := Command(runtime.GOOS, rawURL)
	if !ok {
		return fmt.Errorf("opening URLs is unsupported on %s", runtime.GOOS)
	}
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s did not return within %s", name, openTimeout)
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("%s failed: %w: %s", name, err, detail)
		}
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}
