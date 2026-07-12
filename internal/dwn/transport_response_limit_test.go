package dwn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadBoundedResponseBody(t *testing.T) {
	t.Run("exact boundary", func(t *testing.T) {
		body, err := readBoundedResponseBody(strings.NewReader("12345"), 5)
		if err != nil {
			t.Fatalf("readBoundedResponseBody: %v", err)
		}
		if got := string(body); got != "12345" {
			t.Fatalf("body = %q, want exact boundary content", got)
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		body, err := readBoundedResponseBody(strings.NewReader("123456"), 5)
		if body != nil {
			t.Fatalf("body = %q, want nil on overflow", body)
		}
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("error = %v, want ErrTransport", err)
		}
		if err == nil || !strings.Contains(err.Error(), "exceeds 5-byte limit") {
			t.Fatalf("error = %v, want response-size detail", err)
		}
	})

	t.Run("reader error discards partial data", func(t *testing.T) {
		readFailure := errors.New("test reader failed")
		reader := io.MultiReader(
			strings.NewReader("partial"),
			iotest.ErrReader(readFailure),
		)
		body, err := readBoundedResponseBody(reader, 32)
		if body != nil {
			t.Fatalf("body = %q, want nil after reader error", body)
		}
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("error = %v, want ErrTransport", err)
		}
		if !errors.Is(err, readFailure) {
			t.Fatalf("error = %v, want wrapped reader failure", err)
		}
	})

	t.Run("limit plus one overflow is rejected", func(t *testing.T) {
		body, err := readBoundedResponseBody(strings.NewReader("unused"), math.MaxInt64)
		if body != nil {
			t.Fatalf("body = %q, want nil for invalid limit", body)
		}
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("error = %v, want ErrTransport", err)
		}
	})
}

func TestHTTPTransportRejectsOversizedResponseBodies(t *testing.T) {
	signer := newTestSigner(t)
	message, err := BuildRecordsQuery(signer, RecordsFilter{Protocol: "test"}, "", nil, "")
	if err != nil {
		t.Fatalf("BuildRecordsQuery: %v", err)
	}

	rpcResponse, err := json.Marshal(JsonRpcResponse{
		JSONRPC: "2.0",
		ID:      "response-limit-test",
		Result: &JsonRpcResult{Reply: &DwnReply{
			Status: Status{Code: http.StatusOK, Detail: "OK"},
		}},
	})
	if err != nil {
		t.Fatalf("marshal JSON-RPC response: %v", err)
	}

	tests := []struct {
		name       string
		body       []byte
		header     string
		limit      int64
		wantDetail string
	}{
		{
			name:       "normal JSON response",
			body:       rpcResponse,
			limit:      int64(len(rpcResponse) - 1),
			wantDetail: "reading response body",
		},
		{
			name:       "dwn-response header with binary data",
			body:       []byte("binary-record-data"),
			header:     string(rpcResponse),
			limit:      int64(len("binary-record-data") - 1),
			wantDetail: "reading response data",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.header != "" {
					w.Header().Set("dwn-response", tc.header)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()

			transport := NewHTTPTransport(server.URL)
			transport.maxResponseBodyBytes = tc.limit
			result, err := transport.Send(context.Background(), "did:dht:target", message, nil)
			if result != nil {
				t.Fatalf("result = %+v, want nil on oversized response", result)
			}
			if !errors.Is(err, ErrTransport) {
				t.Fatalf("error = %v, want ErrTransport", err)
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantDetail) {
				t.Fatalf("error = %v, want %q context", err, tc.wantDetail)
			}
		})
	}
}

func TestHTTPTransportTruncatesMalformedResponsePreview(t *testing.T) {
	const tailMarker = "tail-marker-must-not-appear"
	body := strings.Repeat("x", maxHTTPResponseErrorPreviewBytes) + tailMarker
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	signer := newTestSigner(t)
	message, err := BuildRecordsQuery(signer, RecordsFilter{Protocol: "test"}, "", nil, "")
	if err != nil {
		t.Fatalf("BuildRecordsQuery: %v", err)
	}
	transport := NewHTTPTransport(server.URL)
	transport.maxResponseBodyBytes = int64(len(body))
	result, err := transport.Send(context.Background(), "did:dht:target", message, nil)
	if result != nil {
		t.Fatalf("result = %+v, want nil for malformed response", result)
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport", err)
	}
	if strings.Contains(err.Error(), tailMarker) {
		t.Fatalf("error contains content beyond diagnostic preview: %v", err)
	}
	wantSize := fmt.Sprintf("(%d bytes total)", len(body))
	if !strings.Contains(err.Error(), wantSize) {
		t.Fatalf("error = %v, want size diagnostic %q", err, wantSize)
	}
}
