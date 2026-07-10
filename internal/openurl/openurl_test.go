package openurl

import "testing"

func TestCommand(t *testing.T) {
	for _, tc := range []struct {
		goos     string
		wantName string
		wantArgs []string
	}{
		{goos: "darwin", wantName: "open", wantArgs: []string{"https://example.com"}},
		{goos: "linux", wantName: "xdg-open", wantArgs: []string{"https://example.com"}},
		{goos: "freebsd", wantName: "xdg-open", wantArgs: []string{"https://example.com"}},
		{goos: "windows", wantName: "rundll32", wantArgs: []string{"url.dll,FileProtocolHandler", "https://example.com"}},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			name, args, ok := Command(tc.goos, "https://example.com")
			if !ok {
				t.Fatal("Command returned !ok")
			}
			if name != tc.wantName {
				t.Fatalf("name = %q, want %q", name, tc.wantName)
			}
			if len(args) != len(tc.wantArgs) {
				t.Fatalf("args = %q, want %q", args, tc.wantArgs)
			}
			for i := range args {
				if args[i] != tc.wantArgs[i] {
					t.Fatalf("args = %q, want %q", args, tc.wantArgs)
				}
			}
		})
	}
}

func TestOpenRejectsEmptyURL(t *testing.T) {
	if err := Open("  "); err == nil {
		t.Fatal("Open returned nil for an empty URL")
	}
}
