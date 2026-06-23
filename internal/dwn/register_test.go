package dwn

import (
	"net/http"
	"testing"
)

func TestRegistrationAlreadyExists(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{name: "conflict", status: http.StatusConflict, body: "anything", want: true},
		{name: "already registered", status: http.StatusBadRequest, body: `{"error":"tenant already registered"}`, want: true},
		{name: "already exists", status: http.StatusUnprocessableEntity, body: `{"error":"tenant already exists"}`, want: true},
		{name: "bad request", status: http.StatusBadRequest, body: `{"error":"invalid did"}`, want: false},
		{name: "rate limited", status: http.StatusTooManyRequests, body: `{"error":"rate limit exceeded"}`, want: false},
	}

	for _, tt := range tests {
		if got := registrationAlreadyExists(tt.status, []byte(tt.body)); got != tt.want {
			t.Fatalf("%s: registrationAlreadyExists() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
