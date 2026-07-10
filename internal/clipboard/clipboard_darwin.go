//go:build darwin

package clipboard

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func writeText(ctx context.Context, text string) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/pbcopy")
	cmd.Stdin = strings.NewReader(text)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pbcopy: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
