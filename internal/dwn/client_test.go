package dwn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRecordsQueryWithAuthRateLimitedReply(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(JsonRpcResponse{
			JSONRPC: "2.0",
			Result: &JsonRpcResult{
				Reply: &DwnReply{Status: Status{Code: http.StatusTooManyRequests, Detail: "RateLimitExceeded: retry after 2s"}},
			},
		}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, newTestSigner(t))
	_, err := client.RecordsQueryWithAuth(
		context.Background(), "did:example:target", RecordsFilter{Protocol: "test"},
		"", nil, MessageAuth{},
	)
	requireRateLimitError(t, err, 2*time.Second)
}

func TestQueryEntriesRateLimited(t *testing.T) {
	tests := []struct {
		name   string
		detail string
		want   time.Duration
	}{
		{name: "reported delay", detail: "RateLimitExceeded: tenant rate limit exceeded, retry after 3s", want: 3 * time.Second},
		{name: "default delay", detail: "Too Many Requests", want: time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := QueryEntries(&DwnReply{Status: Status{Code: 429, Detail: tc.detail}})
			requireRateLimitError(t, err, tc.want)
		})
	}
}

func TestQueryResultDelegatesRateLimited(t *testing.T) {
	reply := &Response{Status: Status{Code: 429, Detail: "RateLimitExceeded: retry after 1s"}}
	_, err := QueryResult(reply)
	requireRateLimitError(t, err, time.Second)
}

func requireRateLimitError(t *testing.T, err error, wantRetryAfter time.Duration) {
	t.Helper()
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("errors.Is(%v, ErrRateLimited) = false", err)
	}
	var rateErr *RateLimitError
	if !errors.As(err, &rateErr) {
		t.Fatalf("error = %T %v, want *RateLimitError", err, err)
	}
	if rateErr.RetryAfter != wantRetryAfter {
		t.Errorf("RetryAfter = %v, want %v", rateErr.RetryAfter, wantRetryAfter)
	}
}
