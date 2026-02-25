// Copied from github.com/enboxorg/web5-go — will be replaced by a shared enbox Go library.
package diddht

import (
	"context"
	"fmt"
	"net/http"

	"github.com/enboxorg/meshd/pkg/dids/didcore"
	"github.com/enboxorg/meshd/pkg/dids/diddht/internal/bep44"
	"github.com/enboxorg/meshd/pkg/dids/diddht/internal/dns"
	"github.com/enboxorg/meshd/pkg/dids/diddht/internal/pkarr"
)

// Signer is a function that signs a payload with an Ed25519 private key
// and returns the 64-byte signature.
type Signer func(payload []byte) ([]byte, error)

// PublishOptions configures DID DHT publication.
type PublishOptions struct {
	// GatewayURL is the Pkarr relay URL. Default: https://diddht.tbddev.org
	GatewayURL string

	// HTTPClient is the HTTP client for gateway requests. Default: http.DefaultClient
	HTTPClient *http.Client
}

// PublishOption configures the Publish function.
type PublishOption func(*PublishOptions)

// WithPublishGateway sets the Pkarr gateway URL.
func WithPublishGateway(url string) PublishOption {
	return func(o *PublishOptions) {
		o.GatewayURL = url
	}
}

// WithPublishHTTPClient sets the HTTP client for the publish request.
func WithPublishHTTPClient(c *http.Client) PublishOption {
	return func(o *PublishOptions) {
		o.HTTPClient = c
	}
}

// Publish publishes a DID Document to the DHT via a Pkarr gateway.
//
// Parameters:
//   - ctx: context for cancellation
//   - didID: the z-base-32 identifier (method-specific ID, not the full URI)
//   - doc: the DID Document to publish
//   - seq: sequence number (typically Unix timestamp, must be monotonically increasing)
//   - publicKey: the Ed25519 public key bytes (32 bytes)
//   - signer: function that signs payloads with the Ed25519 private key
//   - opts: optional configuration (gateway URL, HTTP client)
//
// The function:
//  1. Marshals the DID Document into a DNS packet per the did:dht spec
//  2. Creates a BEP44 signed message from the DNS packet
//  3. PUTs the BEP44 message to the Pkarr relay
func Publish(ctx context.Context, didID string, doc *didcore.Document, seq int64, publicKey []byte, signer Signer, opts ...PublishOption) error {
	options := &PublishOptions{
		GatewayURL: defaultGatewayURL,
		HTTPClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Step 1: Marshal DID Document → DNS packet.
	dnsPayload, err := dns.MarshalDIDDocument(doc)
	if err != nil {
		return fmt.Errorf("marshaling DID document to DNS: %w", err)
	}

	// Step 2: Create BEP44 message.
	bep44Signer := bep44.Signer(signer)
	msg, err := bep44.NewMessage(dnsPayload, seq, publicKey, bep44Signer)
	if err != nil {
		return fmt.Errorf("creating BEP44 message: %w", err)
	}

	// Step 3: Publish to Pkarr gateway.
	client := pkarr.NewClient(options.GatewayURL, options.HTTPClient)
	if err := client.PutWithContext(ctx, didID, msg); err != nil {
		return fmt.Errorf("publishing to gateway %s: %w", options.GatewayURL, err)
	}

	return nil
}
