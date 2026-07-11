package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

func TestLoadEndpointEntryWarnsWhenFailureClassChanges(t *testing.T) {
	handler := &captureHandler{}
	const (
		peerDID      = "did:jwk:endpoint-class-transition"
		nodeRecordID = "node-record"
	)
	client := &DWNClient{
		logger: slog.New(handler),
		nodes: map[string]*NodeRecord{
			peerDID: {DID: peerDID, RecordID: nodeRecordID},
		},
	}

	entry := json.RawMessage(`{"recordsWrite":{"recordId":"endpoint-record","descriptor":{"recipient":"` +
		peerDID + `","parentId":"` + nodeRecordID + `"},"encodedData":"AAAA","encryption":{}}}`)
	parseErr := errors.New("delivery query failed")
	parseFailure := func([]byte, *dwncrypto.Encryption) ([]byte, error) {
		return nil, parseErr
	}
	if err := client.loadEndpointEntry(context.Background(), entry, parseFailure); !errors.Is(err, parseErr) {
		t.Fatalf("loadEndpointEntry parse error = %v, want %v", err, parseErr)
	}

	keyErr := errors.New("no delivery record for keyId changed at network/member")
	keyFailure := func([]byte, *dwncrypto.Encryption) ([]byte, error) {
		return nil, keyErr
	}
	if err := client.loadEndpointEntry(context.Background(), entry, keyFailure); !errors.Is(err, keyErr) {
		t.Fatalf("loadEndpointEntry key error = %v, want %v", err, keyErr)
	}

	if got := client.UnreadableEndpointCount(); got != 2 {
		t.Fatalf("UnreadableEndpointCount = %d, want 2", got)
	}
	if got := handler.count(slog.LevelWarn, "endpoint record could not be loaded; peer connectivity may be degraded"); got != 2 {
		t.Fatalf("endpoint warnings = %d, want 2 after failure class changes", got)
	}

	recovered := func([]byte, *dwncrypto.Encryption) ([]byte, error) {
		return []byte(`{"localEndpoints":["192.0.2.1:1234"],"discoKey":"disco","updatedAt":"2026-07-11T00:00:00Z"}`), nil
	}
	if err := client.loadEndpointEntry(context.Background(), entry, recovered); err != nil {
		t.Fatalf("recovered loadEndpointEntry: %v", err)
	}
	if got := len(client.nodes[peerDID].Endpoints); got != 1 {
		t.Fatalf("peer endpoints = %d, want 1 after recovery", got)
	}
	if got := handler.count(slog.LevelInfo, "endpoint record is readable again"); got != 1 {
		t.Fatalf("endpoint recovery logs = %d, want 1", got)
	}
}

func TestLoadChildRecordsPropagatesContextAbort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sealedMockReply(t, w, "query", dwn.Status{Code: http.StatusOK, Detail: "OK"}, []json.RawMessage{
			json.RawMessage(`{"recordId":"endpoint-record"}`),
			json.RawMessage(`{"recordId":"second-endpoint-record"}`),
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

	t.Run("handler deadline", func(t *testing.T) {
		wantErr := fmt.Errorf("delivery lookup: %w", context.DeadlineExceeded)
		count, err := client.loadChildRecords(
			context.Background(),
			"network/node/endpoint",
			"network-record/node-record",
			"",
			func(context.Context, json.RawMessage, EntryDecryptor) error {
				return wantErr
			},
		)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("loadChildRecords error = %v, want context.DeadlineExceeded", err)
		}
		if count != 0 {
			t.Fatalf("loadChildRecords count = %d, want 0 for incomplete snapshot", count)
		}
	})

	t.Run("pre-canceled query context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		count, err := client.loadChildRecords(
			ctx,
			"network/node/endpoint",
			"network-record/node-record",
			"",
			func(context.Context, json.RawMessage, EntryDecryptor) error {
				t.Fatal("handler called for a pre-canceled query")
				return nil
			},
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("loadChildRecords error = %v, want context.Canceled", err)
		}
		if count != 0 {
			t.Fatalf("loadChildRecords count = %d, want 0 for canceled query", count)
		}
	})

	t.Run("ctx error aborts generic handler failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		genericErr := errors.New("generic parse failure")
		calls := 0
		count, err := client.loadChildRecords(
			ctx,
			"network/node/endpoint",
			"network-record/node-record",
			"",
			func(context.Context, json.RawMessage, EntryDecryptor) error {
				calls++
				cancel()
				return genericErr
			},
		)
		if !errors.Is(err, genericErr) {
			t.Fatalf("loadChildRecords error = %v, want %v", err, genericErr)
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("context error = %v, want context.Canceled", ctx.Err())
		}
		if calls != 1 {
			t.Fatalf("handler calls = %d, want 1 before cancellation aborts the remaining entry", calls)
		}
		if count != 0 {
			t.Fatalf("loadChildRecords count = %d, want 0 for incomplete snapshot", count)
		}
	})
}
