package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestExtractProfile(t *testing.T) {
	profile, remaining, err := extractProfile([]string{"install", "--profile", "work"})
	if err != nil {
		t.Fatalf("extractProfile: %v", err)
	}
	if profile != "work" || !reflect.DeepEqual(remaining, []string{"install"}) {
		t.Fatalf("extractProfile = %q, %v", profile, remaining)
	}
}

func TestExtractProfileErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--profile"},
		{"--profile", "one", "--profile", "two"},
		{"--profile", "../work"},
		{"--profile", "work profile"},
	} {
		if _, _, err := extractProfile(args); err == nil {
			t.Fatalf("extractProfile(%v) succeeded", args)
		}
	}
}

func TestLaunchAgentPlist(t *testing.T) {
	plist := launchAgentPlist("/Users/alice/A&B/meshd-tray", "work<home>", "/Users/alice/.meshd/bin/meshd")
	for _, want := range []string{
		"<key>AssociatedBundleIdentifiers</key>",
		"/Users/alice/A&amp;B/meshd-tray",
		"work&lt;home&gt;",
		"MESHD_BINARY",
		"<key>RunAtLoad</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
	if strings.Contains(plist, "<key>KeepAlive</key>") {
		t.Fatal("LaunchAgent must not use KeepAlive; Quit would immediately relaunch")
	}
}

func TestStartupArguments(t *testing.T) {
	if got := startupArguments(""); got != "" {
		t.Fatalf("startupArguments(empty) = %q", got)
	}
	if got := startupArguments("work profile"); got != `--profile "work profile"` {
		t.Fatalf("startupArguments = %q", got)
	}
}
