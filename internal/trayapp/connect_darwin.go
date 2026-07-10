//go:build darwin

package trayapp

import (
	"context"
	"fmt"
	"os/exec"
)

func connectCommand(ctx context.Context, executable string, args, _ []string) ([]byte, error) {
	command := connectShellCommand(executable, args)
	output, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", macOSTerminalScript, command).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("launch meshd in Terminal: %w", err)
	}
	return output, nil
}
