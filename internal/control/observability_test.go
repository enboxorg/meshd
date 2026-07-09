package control

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

// captureHandler records the slog records emitted during a test so assertions
// can check both the level and the attributes of a specific log line.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler       { return h }

// warnFor reports whether a WARN record was emitted whose attributes include
// nodeDID/did == wantDID.
func (h *captureHandler) warnFor(wantDID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Level != slog.LevelWarn {
			continue
		}
		match := false
		r.Attrs(func(a slog.Attr) bool {
			if (a.Key == "nodeDID" || a.Key == "did") && a.Value.String() == wantDID {
				match = true
				return false
			}
			return true
		})
		if match {
			return true
		}
	}
	return false
}

// An undecryptable node record is the visible symptom of a missing
// role-audience key delivery (issue #187). loadNodeEntry must count it, warn
// with the peer's DID, and still track the DID so key delivery can retry.
func TestLoadNodeEntryCountsUndecryptablePeer(t *testing.T) {
	handler := &captureHandler{}
	c := &DWNClient{
		nodes:  map[string]*NodeRecord{},
		logger: slog.New(handler),
	}

	const peerDID = "did:jwk:peer-undecryptable"
	entry := json.RawMessage(`{"recordsWrite":{"recordId":"peer-record",` +
		`"descriptor":{"recipient":"` + peerDID + `"},` +
		`"encodedData":"AAAA","encryption":{}}}`)
	failing := func([]byte, *dwncrypto.Encryption) ([]byte, error) {
		return nil, errors.New("no key material")
	}

	c.loadNodeEntry(context.Background(), entry, failing, "member-1")

	if got := c.UndecryptablePeerCount(); got != 1 {
		t.Fatalf("UndecryptablePeerCount = %d, want 1", got)
	}
	if !handler.warnFor(peerDID) {
		t.Fatalf("expected a WARN log naming %q, got none", peerDID)
	}
	// The DID is still tracked (from the unencrypted recipient) so auto key
	// delivery can target it on the next pass.
	rec, ok := c.nodes[peerDID]
	if !ok {
		t.Fatalf("undecryptable peer %q was not tracked", peerDID)
	}
	if rec.RecordID != "peer-record" || rec.MemberRecordID != "member-1" {
		t.Fatalf("tracked record = %+v, want recordId/memberRecordId set", rec)
	}

	// The counter is cumulative across loads.
	c.loadNodeEntry(context.Background(), entry, failing, "member-1")
	if got := c.UndecryptablePeerCount(); got != 2 {
		t.Fatalf("UndecryptablePeerCount after second load = %d, want 2", got)
	}
}

// A peer with no readable/derivable mesh IP is dropped from the network map.
// buildMapResponse must count and warn instead of swallowing at Debug.
func TestBuildMapResponseCountsDroppedPeer(t *testing.T) {
	handler := &captureHandler{}
	const selfDID = "did:jwk:self"
	const peerDID = "did:jwk:ghost-peer"
	c := &DWNClient{
		selfDID: selfDID,
		logger:  slog.New(handler),
		// Empty MeshCIDR: no deterministic fallback IP can be derived, so a peer
		// without a decrypted MeshIP has no valid address and must be dropped.
		network: &NetworkConfig{Name: "test"},
		nodes: map[string]*NodeRecord{
			selfDID: {DID: selfDID, MeshIP: "10.200.0.2", RecordID: "self-record"},
			peerDID: {DID: peerDID, RecordID: "ghost-record"},
		},
	}

	resp := c.buildMapResponse()
	if resp == nil {
		t.Fatal("buildMapResponse returned nil")
	}
	if len(resp.Peers) != 0 {
		t.Fatalf("peers = %d, want 0 (ghost peer dropped)", len(resp.Peers))
	}
	if got := c.DroppedPeerCount(); got != 1 {
		t.Fatalf("DroppedPeerCount = %d, want 1", got)
	}
	if !handler.warnFor(peerDID) {
		t.Fatalf("expected a WARN log naming dropped peer %q, got none", peerDID)
	}
	if !strings.HasPrefix(resp.Node.DID, "did:jwk:self") {
		t.Fatalf("self node = %+v, want self retained", resp.Node)
	}
}
