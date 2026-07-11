package engine

import (
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshnet/types/logger"
	"github.com/tailscale/wireguard-go/tun"
)

func TestNewEngineValidation(t *testing.T) {
	validSigner := &dwn.Signer{
		DID: "did:dht:test123",
	}

	tests := map[string]struct {
		cfg     Config
		wantErr string
	}{
		"missing endpoint": {
			cfg:     Config{},
			wantErr: "AnchorEndpoint is required",
		},
		"missing tenant": {
			cfg:     Config{AnchorEndpoint: "https://example.com"},
			wantErr: "AnchorTenant is required",
		},
		"missing network record": {
			cfg: Config{
				AnchorEndpoint: "https://example.com",
				AnchorTenant:   "did:dht:anchor",
			},
			wantErr: "NetworkRecordID is required",
		},
		"missing self DID": {
			cfg: Config{
				AnchorEndpoint:  "https://example.com",
				AnchorTenant:    "did:dht:anchor",
				NetworkRecordID: "record123",
			},
			wantErr: "SelfDID is required",
		},
		"missing signer": {
			cfg: Config{
				AnchorEndpoint:  "https://example.com",
				AnchorTenant:    "did:dht:anchor",
				NetworkRecordID: "record123",
				SelfDID:         "did:dht:self",
			},
			wantErr: "Signer is required",
		},
		"valid config": {
			cfg: Config{
				AnchorEndpoint:  "https://example.com",
				AnchorTenant:    "did:dht:anchor",
				NetworkRecordID: "record123",
				SelfDID:         "did:dht:self",
				Signer:          validSigner,
			},
			wantErr: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			eng, err := New(tc.cfg)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if got := err.Error(); got != tc.wantErr {
					t.Errorf("error = %q, want %q", got, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eng == nil {
				t.Fatal("engine is nil")
			}

			// Clean up.
			if eng.Backend() == nil {
				t.Error("backend is nil")
			}
			if eng.Running() {
				t.Error("engine should not be running before Start")
			}
			eng.Stop()
		})
	}
}

func TestEngineStartStop(t *testing.T) {
	cfg := Config{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		SelfDID:         "did:dht:self",
		Signer: &dwn.Signer{
			DID: "did:dht:self",
		},
	}

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Stop should be safe to call even before Start.
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
}

func TestNewEngineFailsWhenRequestedTUNUnavailable(t *testing.T) {
	originalNewTUNDevice := newTUNDevice
	t.Cleanup(func() {
		newTUNDevice = originalNewTUNDevice
	})

	newTUNDevice = func(logger.Logf, string) (tun.Device, string, error) {
		return nil, "", syscall.EBUSY
	}

	eng, err := New(Config{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
		TUNName:         "meshd0",
	})
	if eng != nil {
		t.Fatal("New returned an engine after requested TUN creation failed")
	}
	if !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("New error = %v, want wrapped EBUSY", err)
	}
	if !strings.Contains(err.Error(), `creating TUN device "meshd0"`) {
		t.Fatalf("New error = %q, want TUN device context", err)
	}
}

func TestTUNCreationErrorBusyGuidance(t *testing.T) {
	linuxErr := tunCreationError("linux", "meshd0", syscall.EBUSY)
	if !errors.Is(linuxErr, syscall.EBUSY) {
		t.Fatalf("Linux error = %v, want wrapped EBUSY", linuxErr)
	}
	if !strings.Contains(linuxErr.Error(), `"iff: meshd0" in /proc/*/fdinfo/*`) {
		t.Fatalf("Linux error = %q, want exact TUN owner guidance", linuxErr)
	}

	darwinErr := tunCreationError("darwin", "utun", syscall.EBUSY)
	if !errors.Is(darwinErr, syscall.EBUSY) {
		t.Fatalf("Darwin error = %v, want wrapped EBUSY", darwinErr)
	}
	if strings.Contains(darwinErr.Error(), "/proc/") {
		t.Fatalf("Darwin error contains Linux guidance: %q", darwinErr)
	}
}

func TestSlogToLogf(t *testing.T) {
	// Ensure the adapter doesn't panic.
	logf := slogToLogf(nil)
	if logf == nil {
		t.Fatal("logf is nil")
	}
	// slog.Default() should be used when nil is passed.
	// Just verify it doesn't panic.
}
