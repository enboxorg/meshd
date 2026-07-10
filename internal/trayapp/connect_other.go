//go:build !darwin

package trayapp

import "context"

func connectCommand(ctx context.Context, executable string, args, env []string) ([]byte, error) {
	return runCommand(ctx, executable, args, env)
}
