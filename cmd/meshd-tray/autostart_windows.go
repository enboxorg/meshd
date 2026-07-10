//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const createShortcutScript = `$shell = New-Object -ComObject WScript.Shell; $shortcut = $shell.CreateShortcut($env:MESHD_TRAY_AUTOSTART_LINK); $shortcut.TargetPath = $env:MESHD_TRAY_AUTOSTART_TARGET; $shortcut.WorkingDirectory = Split-Path $env:MESHD_TRAY_AUTOSTART_TARGET; $shortcut.Arguments = $env:MESHD_TRAY_AUTOSTART_ARGS; $shortcut.Description = 'meshd menu-bar companion'; $shortcut.Save()`

func installAutostart(profile string) (string, error) {
	executable, err := executablePath()
	if err != nil {
		return "", err
	}
	executable = installedTrayTarget(executable)
	shortcutPath, err := startupShortcutPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(shortcutPath), 0o755); err != nil {
		return "", fmt.Errorf("create Startup directory: %w", err)
	}
	args := startupArguments(profile)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", createShortcutScript)
	cmd.Env = append(os.Environ(),
		"MESHD_TRAY_AUTOSTART_LINK="+shortcutPath,
		"MESHD_TRAY_AUTOSTART_TARGET="+executable,
		"MESHD_TRAY_AUTOSTART_ARGS="+args,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return shortcutPath, fmt.Errorf("create Startup shortcut: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return shortcutPath, nil
}

func uninstallAutostart() (string, error) {
	shortcutPath, err := startupShortcutPath()
	if err != nil {
		return "", err
	}
	if err := os.Remove(shortcutPath); err != nil && !os.IsNotExist(err) {
		return shortcutPath, fmt.Errorf("remove Startup shortcut: %w", err)
	}
	return shortcutPath, nil
}

func startupShortcutPath() (string, error) {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		var err error
		appData, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve AppData directory: %w", err)
		}
	}
	return filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "meshd-tray.lnk"), nil
}
