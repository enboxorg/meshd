package main

import (
	"fmt"
	"os"
	"strings"

	profilecfg "github.com/enboxorg/meshd/internal/profile"
)

const usage = `meshd-tray - meshd menu-bar companion

Usage:
  meshd-tray [--profile <name>]
  meshd-tray install [--profile <name>]
  meshd-tray uninstall
  meshd-tray --version

Commands:
  install     Start meshd-tray at login for the current user
  uninstall   Remove meshd-tray from login startup

The tray icon reflects daemon connectivity. Its menu can connect or disconnect,
open the active network dashboard, and copy this device's or a peer's mesh IP.
`

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "meshd-tray: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	profile, args, err := extractProfile(args)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return runTray(profile)
	}
	if len(args) > 1 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(args[1:], " "))
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	case "-v", "--version", "version":
		fmt.Printf("meshd-tray %s\n", version)
		return nil
	case "install":
		path, err := installAutostart(profile)
		if err != nil {
			return err
		}
		fmt.Printf("meshd-tray will start at login.\n  %s\n", path)
		return nil
	case "uninstall":
		path, err := uninstallAutostart()
		if err != nil {
			return err
		}
		fmt.Printf("meshd-tray login startup removed.\n  %s\n", path)
		return nil
	default:
		return fmt.Errorf("unknown command %q; run 'meshd-tray --help'", args[0])
	}
}

func extractProfile(args []string) (string, []string, error) {
	var profile string
	remaining := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] != "--profile" {
			remaining = append(remaining, args[i])
			continue
		}
		if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
			return "", nil, fmt.Errorf("--profile requires a name")
		}
		if profile != "" {
			return "", nil, fmt.Errorf("--profile may only be specified once")
		}
		profile = strings.TrimSpace(args[i+1])
		if err := profilecfg.ValidateName(profile); err != nil {
			return "", nil, fmt.Errorf("invalid --profile: %w", err)
		}
		i++
	}
	return profile, remaining, nil
}
