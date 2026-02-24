package engine

import (
	"testing"
)

func TestAutoKeyDelivery_NilSafe(t *testing.T) {
	// All methods should be safe to call on nil.
	var akd *AutoKeyDelivery

	akd.MarkDelivered("did:dht:test")
	if akd.DeliveredCount() != 0 {
		t.Error("DeliveredCount on nil should be 0")
	}
	if pending := akd.PendingDelivery([]string{"did:dht:test"}); pending != nil {
		t.Errorf("PendingDelivery on nil should be nil, got %v", pending)
	}
	if s := akd.String(); s != "AutoKeyDelivery: disabled (not anchor)" {
		t.Errorf("String on nil = %q", s)
	}
}

func TestAutoKeyDelivery_NewReturnsNilForNonOwner(t *testing.T) {
	// With nil encryption manager, should return nil.
	akd := NewAutoKeyDelivery(AutoKeyDeliveryConfig{
		Endpoint:             "https://example.com",
		AnchorDID:            "did:dht:anchor",
		NetworkRecordID:      "rec123",
		EncryptionKeyManager: nil,
	})
	if akd != nil {
		t.Error("expected nil for nil EncryptionKeyManager")
	}
}

func TestAutoKeyDelivery_MarkAndPending(t *testing.T) {
	// We can't use a real EncryptionKeyManager in unit tests without crypto
	// setup, so we test the tracking logic directly.
	akd := &AutoKeyDelivery{
		delivered: make(map[string]bool),
	}

	members := []string{"did:dht:alice", "did:dht:bob", "did:dht:carol"}

	// All should be pending initially.
	pending := akd.PendingDelivery(members)
	if len(pending) != 3 {
		t.Fatalf("pending = %d, want 3", len(pending))
	}

	// Mark alice as delivered.
	akd.MarkDelivered("did:dht:alice")
	if akd.DeliveredCount() != 1 {
		t.Errorf("DeliveredCount = %d, want 1", akd.DeliveredCount())
	}

	pending = akd.PendingDelivery(members)
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2", len(pending))
	}
	for _, p := range pending {
		if p == "did:dht:alice" {
			t.Error("alice should not be pending")
		}
	}

	// Mark all.
	akd.MarkDelivered("did:dht:bob")
	akd.MarkDelivered("did:dht:carol")

	pending = akd.PendingDelivery(members)
	if len(pending) != 0 {
		t.Fatalf("pending = %d, want 0", len(pending))
	}

	if akd.DeliveredCount() != 3 {
		t.Errorf("DeliveredCount = %d, want 3", akd.DeliveredCount())
	}
}

func TestAutoKeyDelivery_MarkIdempotent(t *testing.T) {
	akd := &AutoKeyDelivery{
		delivered: make(map[string]bool),
	}

	akd.MarkDelivered("did:dht:alice")
	akd.MarkDelivered("did:dht:alice")
	akd.MarkDelivered("did:dht:alice")

	if akd.DeliveredCount() != 1 {
		t.Errorf("DeliveredCount = %d, want 1 (idempotent)", akd.DeliveredCount())
	}
}

func TestAutoKeyDelivery_String(t *testing.T) {
	akd := &AutoKeyDelivery{
		delivered: make(map[string]bool),
	}
	akd.MarkDelivered("did:dht:alice")

	got := akd.String()
	want := "AutoKeyDelivery: 1 delivered"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
