//go:build darwin

package engine

import "testing"

func TestTrustedDarwinCommandUsesAbsoluteSystemPaths(t *testing.T) {
	for input, want := range map[string]string{
		"ifconfig": darwinIfconfigPath,
		"route":    darwinRoutePath,
	} {
		got, err := trustedDarwinCommand(input)
		if err != nil || got != want {
			t.Fatalf("trustedDarwinCommand(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := trustedDarwinCommand("/tmp/ifconfig"); err == nil {
		t.Fatal("trustedDarwinCommand accepted an arbitrary executable")
	}
}
