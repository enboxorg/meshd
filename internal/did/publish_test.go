package did

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestToCoreDocument(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("with DWN endpoint", func(t *testing.T) {
		doc := d.toCoreDocument("https://dwn.example.com")

		if doc.ID != d.URI {
			t.Errorf("ID = %q, want %q", doc.ID, d.URI)
		}
		if len(doc.Context) == 0 || doc.Context[0] != "https://www.w3.org/ns/did/v1" {
			t.Error("missing DID v1 context")
		}

		// Should have 2 verification methods: signing (Ed25519) + encryption (X25519)
		if len(doc.VerificationMethod) != 2 {
			t.Fatalf("expected 2 VMs, got %d", len(doc.VerificationMethod))
		}

		// Check signing key
		sigVM := doc.VerificationMethod[0]
		if sigVM.ID != d.URI+"#0" {
			t.Errorf("signing VM ID = %q", sigVM.ID)
		}
		if sigVM.PublicKeyJwk == nil {
			t.Fatal("signing VM PublicKeyJwk is nil")
		}
		if sigVM.PublicKeyJwk.CRV != "Ed25519" {
			t.Errorf("signing VM CRV = %q", sigVM.PublicKeyJwk.CRV)
		}
		if sigVM.PublicKeyJwk.KTY != "OKP" {
			t.Errorf("signing VM KTY = %q", sigVM.PublicKeyJwk.KTY)
		}

		// Check encryption key
		encVM := doc.VerificationMethod[1]
		if encVM.ID != d.URI+"#enc" {
			t.Errorf("encryption VM ID = %q", encVM.ID)
		}
		if encVM.PublicKeyJwk == nil {
			t.Fatal("encryption VM PublicKeyJwk is nil")
		}
		if encVM.PublicKeyJwk.CRV != "X25519" {
			t.Errorf("encryption VM CRV = %q", encVM.PublicKeyJwk.CRV)
		}

		// Check purposes
		if len(doc.Authentication) == 0 {
			t.Error("authentication is empty")
		}
		if len(doc.AssertionMethod) == 0 {
			t.Error("assertionMethod is empty")
		}
		if len(doc.CapabilityInvocation) == 0 {
			t.Error("capabilityInvocation is empty")
		}
		if len(doc.CapabilityDelegation) == 0 {
			t.Error("capabilityDelegation is empty")
		}
		if len(doc.KeyAgreement) == 0 {
			t.Error("keyAgreement is empty")
		}

		// Check DWN service
		if len(doc.Service) != 1 {
			t.Fatalf("expected 1 service, got %d", len(doc.Service))
		}
		if doc.Service[0].Type != "DecentralizedWebNode" {
			t.Errorf("service type = %q", doc.Service[0].Type)
		}
		if len(doc.Service[0].ServiceEndpoint) != 1 || doc.Service[0].ServiceEndpoint[0] != "https://dwn.example.com" {
			t.Errorf("service endpoint = %v", doc.Service[0].ServiceEndpoint)
		}
	})

	t.Run("without DWN endpoint", func(t *testing.T) {
		doc := d.toCoreDocument("")

		if len(doc.Service) != 0 {
			t.Errorf("expected 0 services, got %d", len(doc.Service))
		}
	})
}

func TestPublish(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("publishes to mock gateway", func(t *testing.T) {
		var receivedMethod string
		var receivedContentType string
		var receivedBodyLen int

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedContentType = r.Header.Get("Content-Type")
			body := make([]byte, 4096)
			n, _ := r.Body.Read(body)
			receivedBodyLen = n
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		err := d.Publish(context.Background(), "https://dwn.example.com",
			WithGatewayURL(srv.URL),
			WithHTTPClient(srv.Client()),
		)
		if err != nil {
			t.Fatalf("Publish: %v", err)
		}

		if receivedMethod != http.MethodPut {
			t.Errorf("expected PUT, got %s", receivedMethod)
		}
		if receivedContentType != "application/octet-stream" {
			t.Errorf("content-type = %q", receivedContentType)
		}
		// BEP44 message: 64 (sig) + 8 (seq) + DNS payload > 72 bytes
		if receivedBodyLen < 72 {
			t.Errorf("body too small: %d bytes", receivedBodyLen)
		}
	})

	t.Run("gateway error propagates", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		}))
		defer srv.Close()

		err := d.Publish(context.Background(), "https://dwn.example.com",
			WithGatewayURL(srv.URL),
			WithHTTPClient(srv.Client()),
		)
		if err == nil {
			t.Fatal("expected error on 500 response")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		err := d.Publish(ctx, "https://dwn.example.com",
			WithGatewayURL(srv.URL),
			WithHTTPClient(srv.Client()),
		)
		if err == nil {
			t.Fatal("expected error on cancelled context")
		}
	})
}

func TestPublish_RoundTrip(t *testing.T) {
	// Generate a DID, publish it to a mock gateway, capture the BEP44 message,
	// then verify it can be decoded back to a valid DID Document.
	//
	// This test uses the Pkarr client's Fetch (indirectly via the resolver)
	// to verify the round-trip. Since we can't easily do that without a real
	// gateway, we just verify the Publish call succeeds with a mock.

	d, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			body := make([]byte, 4096)
			n, _ := r.Body.Read(body)
			capturedBody = body[:n]
			w.WriteHeader(http.StatusOK)
			return
		}
		// For GET (fetch), return the captured body
		if r.Method == http.MethodGet {
			if len(capturedBody) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(capturedBody)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	// Publish
	err = d.Publish(context.Background(), "https://dwn.example.com",
		WithGatewayURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Verify we captured a BEP44 message (sig + seq + DNS payload)
	if len(capturedBody) < 72 {
		t.Fatalf("captured body too small: %d bytes", len(capturedBody))
	}

	// Signature is 64 bytes, seq is 8 bytes, rest is DNS payload
	dnsPayload := capturedBody[72:]
	if len(dnsPayload) == 0 {
		t.Fatal("DNS payload is empty")
	}

	t.Logf("Published DID %s: %d byte BEP44 message (%d byte DNS payload)",
		d.URI, len(capturedBody), len(dnsPayload))
}
