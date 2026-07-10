package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInstalledTrayTarget(t *testing.T) {
	dir := t.TempDir()
	stable := filepath.Join(dir, "meshd-tray.exe")
	versioned := filepath.Join(dir, "meshd-tray-0.0.9.exe")
	if err := os.WriteFile(stable, []byte("stable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(versioned, []byte("versioned"), 0o755); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(dir, windowsTrayCurrentPointer)
	if err := os.WriteFile(pointer, []byte(filepath.Base(versioned)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := installedTrayTarget(stable); got != versioned {
		t.Fatalf("installedTrayTarget = %q, want %q", got, versioned)
	}

	for _, unsafe := range []string{"../outside.exe", "meshd.exe", "meshd-tray-missing.exe"} {
		if err := os.WriteFile(pointer, []byte(unsafe), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := installedTrayTarget(stable); got != stable {
			t.Fatalf("installedTrayTarget with %q = %q, want fallback %q", unsafe, got, stable)
		}
	}
}

func TestReplaceLaunchAgentRollsBackLoadedJob(t *testing.T) {
	dir := t.TempDir()
	plistPath := filepath.Join(dir, launchAgentLabel+".plist")
	previous := []byte("old plist")
	if err := os.WriteFile(plistPath, previous, 0o644); err != nil {
		t.Fatal(err)
	}

	var calls []string
	bootstrapCalls := 0
	run := func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "print", "bootout":
			return nil, nil
		case "bootstrap":
			bootstrapCalls++
			contents, err := os.ReadFile(plistPath)
			if err != nil {
				return nil, err
			}
			if bootstrapCalls == 1 {
				if string(contents) != "new plist" {
					t.Fatalf("first bootstrap saw %q", contents)
				}
				return []byte("replacement rejected"), errors.New("bootstrap failed")
			}
			if !reflect.DeepEqual(contents, previous) {
				t.Fatalf("rollback bootstrap saw %q, want %q", contents, previous)
			}
			return nil, nil
		default:
			t.Fatalf("unexpected launchctl command: %v", args)
			return nil, nil
		}
	}

	err := replaceLaunchAgent(plistPath, "gui/501", []byte("new plist"), run)
	if err == nil || !strings.Contains(err.Error(), "replacement rejected") {
		t.Fatalf("replaceLaunchAgent error = %v", err)
	}
	contents, readErr := os.ReadFile(plistPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(contents, previous) {
		t.Fatalf("plist after rollback = %q, want %q", contents, previous)
	}
	wantCalls := []string{
		"print gui/501/" + launchAgentLabel,
		"bootout gui/501 " + plistPath,
		"bootstrap gui/501 " + plistPath,
		"bootstrap gui/501 " + plistPath,
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("launchctl calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestReplaceLaunchAgentRemovesFailedFreshInstall(t *testing.T) {
	plistPath := filepath.Join(t.TempDir(), launchAgentLabel+".plist")
	run := func(args ...string) ([]byte, error) {
		if args[0] == "print" {
			return nil, errors.New("not loaded")
		}
		return []byte("rejected"), errors.New("bootstrap failed")
	}
	if err := replaceLaunchAgent(plistPath, "gui/501", []byte("new plist"), run); err == nil {
		t.Fatal("replaceLaunchAgent succeeded")
	}
	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Fatalf("fresh failed plist remains: %v", err)
	}
}
