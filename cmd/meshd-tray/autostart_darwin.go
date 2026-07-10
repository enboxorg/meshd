//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/enboxorg/meshd/internal/trayapp"
)

func installAutostart(profile string) (string, error) {
	executable, err := executablePath()
	if err != nil {
		return "", err
	}
	if !strings.Contains(executable, ".app"+string(filepath.Separator)+"Contents"+string(filepath.Separator)+"MacOS") {
		return "", fmt.Errorf("install meshd-tray from its packaged .app bundle")
	}
	meshdBinary, _ := trayapp.FindMeshdExecutable()
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
	domain := "gui/" + strconv.Itoa(os.Getuid())
	runLaunchctl := func(args ...string) ([]byte, error) {
		return exec.Command("/bin/launchctl", args...).CombinedOutput()
	}
	if err := replaceLaunchAgent(plistPath, domain, []byte(launchAgentPlist(executable, profile, meshdBinary)), runLaunchctl); err != nil {
		return plistPath, err
	}
	return plistPath, nil
}

func uninstallAutostart() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_ = exec.Command("/bin/launchctl", "bootout", domain, plistPath).Run()
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return plistPath, fmt.Errorf("remove LaunchAgent: %w", err)
	}
	return plistPath, nil
}
