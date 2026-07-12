package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
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
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

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

	// Reprojecting the same opaque record must not create a new episode.
	c.loadNodeEntry(context.Background(), entry, failing, "member-1")
	if got := c.UndecryptablePeerCount(); got != 1 {
		t.Fatalf("UndecryptablePeerCount after repeat = %d, want 1", got)
	}
	const warning = "node record could not be loaded; peer will be invisible until key delivery or record recovery"
	if got := handler.count(slog.LevelWarn, warning); got != 1 {
		t.Fatalf("repeat warning count = %d, want 1", got)
	}

	// A new failure class is a materially new diagnostic episode.
	parseFailure := func([]byte, *dwncrypto.Encryption) ([]byte, error) {
		return nil, errors.New("malformed ciphertext")
	}
	c.loadNodeEntry(context.Background(), entry, parseFailure, "member-1")
	if got := c.UndecryptablePeerCount(); got != 2 {
		t.Fatalf("UndecryptablePeerCount after class change = %d, want 2", got)
	}
	if got := handler.count(slog.LevelWarn, warning); got != 2 {
		t.Fatalf("class-change warning count = %d, want 2", got)
	}

	// A successful parse closes the episode; the next failure is counted again.
	recovering := func([]byte, *dwncrypto.Encryption) ([]byte, error) {
		return []byte(`{"meshIP":"10.200.1.9"}`), nil
	}
	if err := c.loadNodeEntry(context.Background(), entry, recovering, "member-1"); err != nil {
		t.Fatalf("recovering loadNodeEntry: %v", err)
	}
	if _, failed := c.nodeFailures["peer-record"]; failed {
		t.Fatal("successful parse retained node failure episode")
	}
	if got := handler.count(slog.LevelInfo, "node record is readable again"); got != 1 {
		t.Fatalf("recovery log count = %d, want 1", got)
	}

	c.loadNodeEntry(context.Background(), entry, failing, "member-1")
	if got := c.UndecryptablePeerCount(); got != 3 {
		t.Fatalf("UndecryptablePeerCount after relapse = %d, want 3", got)
	}
	if got := handler.count(slog.LevelWarn, warning); got != 3 {
		t.Fatalf("relapse warning count = %d, want 3", got)
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

func (h *captureHandler) count(level slog.Level, message string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	count := 0
	for _, record := range h.records {
		if record.Level == level && record.Message == message {
			count++
		}
	}
	return count
}

func TestLoadEndpointEntryWarnsOnceAndReportsRecovery(t *testing.T) {
	handler := &captureHandler{}
	const (
		peerDID      = "did:jwk:endpoint-peer"
		nodeRecordID = "node-record"
	)
	c := &DWNClient{
		logger: slog.New(handler),
		nodes: map[string]*NodeRecord{
			peerDID: {DID: peerDID, RecordID: nodeRecordID},
		},
	}

	entries := []json.RawMessage{
		json.RawMessage(`{"recordsWrite":{"recordId":"endpoint-record-a","descriptor":{"recipient":"` +
			peerDID + `","parentId":"` + nodeRecordID + `"},"encodedData":"AAAA","encryption":{}}}`),
		json.RawMessage(`{"recordsWrite":{"recordId":"endpoint-record-b","descriptor":{"recipient":"` +
			peerDID + `","parentId":"` + nodeRecordID + `"},"encodedData":"AAAA","encryption":{}}}`),
	}
	wantErr := errors.New("delivery query failed")
	failing := func([]byte, *dwncrypto.Encryption) ([]byte, error) {
		return nil, wantErr
	}

	for _, entry := range entries {
		if err := c.loadEndpointEntry(context.Background(), entry, failing); !errors.Is(err, wantErr) {
			t.Fatalf("loadEndpointEntry error = %v, want %v", err, wantErr)
		}
	}
	if got := c.UnreadableEndpointCount(); got != 2 {
		t.Fatalf("UnreadableEndpointCount = %d, want 2", got)
	}
	if !handler.warnFor(peerDID) {
		t.Fatalf("expected endpoint warning naming %q", peerDID)
	}
	if got := handler.count(slog.LevelWarn, "endpoint record could not be loaded; peer connectivity may be degraded"); got != 1 {
		t.Fatalf("endpoint warnings = %d, want 1 for repeated identical failure", got)
	}

	recovered := func([]byte, *dwncrypto.Encryption) ([]byte, error) {
		return []byte(`{"localEndpoints":["192.0.2.1:1234"],"discoKey":"disco","updatedAt":"2026-07-11T00:00:00Z"}`), nil
	}
	if err := c.loadEndpointEntry(context.Background(), entries[1], recovered); err != nil {
		t.Fatalf("recovered loadEndpointEntry: %v", err)
	}
	if got := len(c.nodes[peerDID].Endpoints); got != 1 {
		t.Fatalf("peer endpoints = %d, want 1 after recovery", got)
	}
	if got := handler.count(slog.LevelInfo, "endpoint record is readable again"); got != 1 {
		t.Fatalf("endpoint recovery logs = %d, want 1", got)
	}
	if _, failed := c.endpointFailures[nodeRecordID]; failed {
		t.Fatal("successful endpoint parse retained parent-slot failure episode")
	}
	if err := c.loadEndpointEntry(context.Background(), entries[0], failing); !errors.Is(err, wantErr) {
		t.Fatalf("post-recovery loadEndpointEntry error = %v, want %v", err, wantErr)
	}
	if got := handler.count(slog.LevelWarn, "endpoint record could not be loaded; peer connectivity may be degraded"); got != 2 {
		t.Fatalf("endpoint warnings after recovery = %d, want a new episode", got)
	}
}

func TestLoadChildRecordsPropagatesRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sealedMockReply(t, w, "query", dwn.Status{Code: http.StatusOK, Detail: "OK"}, []json.RawMessage{
			json.RawMessage(`{"recordId":"endpoint-record"}`),
		})
	}))
	defer server.Close()

	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("generate query signer: %v", err)
	}
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	client := NewDWNClient(
		server.URL,
		identity.URI,
		"network-record",
		identity.URI,
		signer,
	)
	wantErr := fmt.Errorf("delivery lookup: %w", dwn.ErrRateLimited)
	count, err := client.loadChildRecords(
		context.Background(),
		"network/node/endpoint",
		"network-record/node-record",
		"",
		func(context.Context, json.RawMessage, EntryDecryptor) error {
			return wantErr
		},
	)
	if !errors.Is(err, dwn.ErrRateLimited) {
		t.Fatalf("loadChildRecords error = %v, want ErrRateLimited", err)
	}
	if count != 0 {
		t.Fatalf("loadChildRecords count = %d, want 0 for incomplete snapshot", count)
	}
}
