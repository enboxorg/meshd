//go:build !darwin && !windows

package main

import "fmt"

func installAutostart(string) (string, error) {
	return "", fmt.Errorf("autostart is currently supported on macOS and Windows")
}

func uninstallAutostart() (string, error) {
	return "", fmt.Errorf("autostart is currently supported on macOS and Windows")
}
