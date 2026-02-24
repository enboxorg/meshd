package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/enboxorg/dwn-mesh/internal/control"
	"github.com/enboxorg/dwn-mesh/internal/dwn"
)

// testSigner creates a Signer with a real Ed25519 key for testing.
func testSigner() *dwn.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &dwn.Signer{
		DID:        "did:dht:testself",
		PrivateKey: priv,
	}
}

// TestEngineRealLifecycle creates a real engine with UserspaceEngine + netstack,
// verifies it starts and stops cleanly. This exercises the full meshnet stack
// in userspace mode (no root required, no real TUN device).
func TestEngineRealLifecycle(t *testing.T) {
	cfg := Config{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "rec-123",
		SelfDID:         "did:dht:testself",
		Signer:          testSigner(),
		PollInterval:    5 * time.Second,
		ListenPort:      0, // auto-select
	}

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Verify initial state.
	if eng.Running() {
		t.Fatal("engine should not be running before Start")
	}
	if eng.Backend() == nil {
		t.Fatal("backend is nil")
	}
	if eng.ns == nil {
		t.Fatal("netstack is nil — real engine should have netstack")
	}
	if eng.netMon == nil {
		t.Fatal("network monitor is nil")
	}
	if eng.dialer == nil {
		t.Fatal("dialer is nil")
	}

	// Stop without starting should be safe.
	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
}

// TestEngineStartAndStop creates a real engine, starts it, and stops it.
// This verifies the full lifecycle including the LocalBackend.Start path.
func TestEngineStartAndStop(t *testing.T) {
	cfg := Config{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "rec-123",
		SelfDID:         "did:dht:testself",
		Signer:          testSigner(),
		PollInterval:    1 * time.Second,
		ListenPort:      0,
	}

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start the engine. The MapResponseFunc will try to hit example.com
	// and fail, but the engine itself should start without error (meshnet
	// handles control errors gracefully in the polling loop).
	err = eng.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if !eng.Running() {
		t.Fatal("engine should be running after Start")
	}

	// Double-start should error.
	if err := eng.Start(ctx); err == nil {
		t.Fatal("expected error on double Start")
	}

	// Give the polling loop a moment then stop.
	time.Sleep(100 * time.Millisecond)

	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if eng.Running() {
		t.Fatal("engine should not be running after Stop")
	}
}

// TestEngineWithStaticMapResponse verifies the engine converter works with
// a pre-built MapResponse (no DWN needed).
func TestEngineWithStaticMapResponse(t *testing.T) {
	converter := NewConverter("test-mesh")

	// Build a static response with self + one peer.
	resp := control.BuildStaticMapResponse(
		&control.Node{
			ID:     1,
			Name:   "self",
			DID:    "did:dht:self",
			Key:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Online: true,
		},
		[]*control.Node{
			{
				ID:     2,
				Name:   "peer1",
				DID:    "did:dht:peer1",
				Key:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				Online: true,
			},
		},
		nil,
	)

	nm, err := converter.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	if !nm.SelfNode.Valid() {
		t.Fatal("self node not valid")
	}
	if len(nm.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(nm.Peers))
	}
	if nm.Domain != "test-mesh" {
		t.Errorf("domain = %q, want %q", nm.Domain, "test-mesh")
	}
}

// TestEngineAutoKeyDeliveryIntegration verifies the auto key delivery
// is wired into the MapResponseFunc correctly.
func TestEngineAutoKeyDeliveryIntegration(t *testing.T) {
	// Create an auto key delivery tracker (without a real encryption manager
	// so it won't actually deliver, but we can test the tracking).
	akd := &AutoKeyDelivery{
		delivered: make(map[string]bool),
	}

	// Pre-mark some as delivered.
	akd.MarkDelivered("did:dht:alice")

	// Simulate what MapResponseFunc does internally.
	memberDIDs := []string{"did:dht:alice", "did:dht:bob"}
	pending := akd.PendingDelivery(memberDIDs)

	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	if pending[0] != "did:dht:bob" {
		t.Errorf("pending[0] = %q, want %q", pending[0], "did:dht:bob")
	}
}
