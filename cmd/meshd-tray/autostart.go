package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	launchAgentLabel          = "org.enbox.meshd-tray"
	windowsTrayCurrentPointer = "meshd-tray.current"
)

type launchctlCommand func(args ...string) ([]byte, error)

func launchAgentPlist(executable, profile, meshdBinary string) string {
	args := []string{executable}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	var programArgs strings.Builder
	for _, arg := range args {
		programArgs.WriteString("\n      <string>")
		programArgs.WriteString(xmlText(arg))
		programArgs.WriteString("</string>")
	}

	environment := ""
	if meshdBinary != "" {
		environment = `
    <key>EnvironmentVariables</key>
    <dict>
      <key>MESHD_BINARY</key>
      <string>` + xmlText(meshdBinary) + `</string>
    </dict>`
	}

	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>` + launchAgentLabel + `</string>
    <key>ProgramArguments</key>
    <array>` + programArgs.String() + `
    </array>` + environment + `
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>AssociatedBundleIdentifiers</key>
    <array>
      <string>` + launchAgentLabel + `</string>
    </array>
  </dict>
</plist>
`
}

func xmlText(value string) string {
	var out bytes.Buffer
	_ = xml.EscapeText(&out, []byte(value))
	return out.String()
}

func startupArguments(profile string) string {
	if profile == "" {
		return ""
	}
	return "--profile " + strconv.Quote(profile)
}

// installedTrayTarget resolves the installer's versioned Windows tray image.
// A direct executable remains the safe fallback for development builds and
// older installations without the pointer file.
func installedTrayTarget(executable string) string {
	pointerPath := filepath.Join(filepath.Dir(executable), windowsTrayCurrentPointer)
	data, err := os.ReadFile(pointerPath)
	if err != nil {
		return executable
	}
	name := strings.TrimSpace(string(data))
	lower := strings.ToLower(name)
	if name == "" || filepath.Base(name) != name ||
		!strings.HasPrefix(lower, "meshd-tray-") || !strings.HasSuffix(lower, ".exe") {
		return executable
	}
	target := filepath.Join(filepath.Dir(executable), name)
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		return executable
	}
	return target
}

// replaceLaunchAgent swaps and registers a LaunchAgent transactionally. If
// launchctl rejects the replacement, the prior plist and loaded job are put
// back before the error is returned.
func replaceLaunchAgent(plistPath, domain string, data []byte, run launchctlCommand) error {
	previous, err := os.ReadFile(plistPath)
	previousExists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read existing LaunchAgent: %w", err)
	}

	service := domain + "/" + launchAgentLabel
	_, printErr := run("print", service)
	wasLoaded := printErr == nil
	if wasLoaded && !previousExists {
		return fmt.Errorf("loaded LaunchAgent has no managed plist at %s", plistPath)
	}

	if err := atomicWrite(plistPath, data, 0o644); err != nil {
		return fmt.Errorf("write LaunchAgent: %w", err)
	}
	if wasLoaded {
		if output, err := run("bootout", domain, plistPath); err != nil {
			restoreErr := restoreLaunchAgentFile(plistPath, previous, previousExists)
			return errors.Join(
				launchctlError("unregister existing LaunchAgent", err, output),
				wrapError("restore previous LaunchAgent plist", restoreErr),
			)
		}
	}
	if output, err := run("bootstrap", domain, plistPath); err != nil {
		restoreErr := restoreLaunchAgentFile(plistPath, previous, previousExists)
		var reloadErr error
		if wasLoaded && previousExists && restoreErr == nil {
			if reloadOutput, err := run("bootstrap", domain, plistPath); err != nil {
				reloadErr = launchctlError("reload previous LaunchAgent", err, reloadOutput)
			}
		}
		return errors.Join(
			launchctlError("register LaunchAgent", err, output),
			wrapError("restore previous LaunchAgent plist", restoreErr),
			reloadErr,
		)
	}
	return nil
}

func restoreLaunchAgentFile(path string, previous []byte, existed bool) error {
	if existed {
		return atomicWrite(path, previous, 0o644)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func launchctlError(action string, err error, output []byte) error {
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, detail)
}

func wrapError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func executablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
		path = resolved
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve absolute executable path: %w", err)
	}
	return path, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".meshd-tray-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
