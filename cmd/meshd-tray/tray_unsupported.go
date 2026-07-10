//go:build !darwin && !windows

package main

import "fmt"

func runTray(string) error {
	return fmt.Errorf("the tray app is currently supported on macOS and Windows")
}
