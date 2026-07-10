// Package clipboard writes text to the desktop clipboard without pulling a
// GUI toolkit into the meshd daemon.
package clipboard

import (
	"context"
	"fmt"
	"strings"
)

// WriteText replaces the desktop clipboard contents with text.
func WriteText(ctx context.Context, text string) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("clipboard text is empty")
	}
	return writeText(ctx, text)
}
