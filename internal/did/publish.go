package did

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/enboxorg/meshd/pkg/dids/didcore"
	"github.com/enboxorg/meshd/pkg/dids/diddht"
	"github.com/enboxorg/meshd/pkg/jwk"
)

// PublishOptions configures DID DHT publication.
type PublishOptions struct {
	// GatewayURL is the Pkarr relay URL. Default: https://diddht.tbddev.org
	GatewayURL string

	// HTTPClient is the HTTP client used for gateway requests. Default: http.DefaultClient
	HTTPClient *http.Client

	// Logger for structured logging. Default: slog.Default()
	Logger *slog.Logger
}

// PublishOption configures the publisher.
type PublishOption func(*PublishOptions)

// WithGatewayURL sets the Pkarr gateway URL for publication.
func WithGatewayURL(url string) PublishOption {
	return func(o *PublishOptions) {
		o.GatewayURL = url
	}
}

// WithHTTPClient sets the HTTP client for gateway requests.
func WithHTTPClient(c *http.Client) PublishOption {
	return func(o *PublishOptions) {
		o.HTTPClient = c
	}
}

// WithPublishLogger sets the logger for publication operations.
func WithPublishLogger(l *slog.Logger) PublishOption {
	return func(o *PublishOptions) {
		o.Logger = l
	}
}

// Publish publishes this DID's document to the DHT via a Pkarr gateway.
//
// The process:
//  1. Convert internal DID → didcore.Document (for DNS marshaling)
//  2. Marshal the DID Document into a DNS packet (did:dht spec)
//  3. Sign the DNS packet as a BEP44 message using the Identity Key
//  4. PUT the BEP44 message to the Pkarr relay
//
// dwnEndpoint should be the DWN server URL where this node's DWN is hosted.
// If empty, the DID Document will not include a DWN service endpoint.
func (d *DID) Publish(ctx context.Context, dwnEndpoint string, opts ...PublishOption) error {
	options := &PublishOptions{
		GatewayURL: "https://enbox-did-dht.fly.dev",
		HTTPClient: http.DefaultClient,
		Logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(options)
	}

	logger := options.Logger

	// Build the didcore.Document.
	coreDoc := d.toCoreDocument(dwnEndpoint)

	logger.DebugContext(ctx, "publishing DID document",
		slog.String("did", d.URI),
		slog.Int("verificationMethods", len(coreDoc.VerificationMethod)),
		slog.Int("services", len(coreDoc.Service)),
	)

	// Sequence number is Unix timestamp (monotonically increasing for updates).
	seq := time.Now().Unix()

	signer := func(payload []byte) ([]byte, error) {
		return d.Sign(payload)
	}

	// Publish options.
	publishOpts := []diddht.PublishOption{
		diddht.WithPublishGateway(options.GatewayURL),
	}
	if options.HTTPClient != nil {
		publishOpts = append(publishOpts, diddht.WithPublishHTTPClient(options.HTTPClient))
	}

	logger.InfoContext(ctx, "publishing DID to DHT",
		slog.String("did", d.URI),
		slog.String("gateway", options.GatewayURL),
		slog.Int64("seq", seq),
	)

	if err := diddht.Publish(ctx, d.Identifier(), &coreDoc, seq, d.SigningPublicKey, signer, publishOpts...); err != nil {
		return fmt.Errorf("publishing DID: %w", err)
	}

	logger.InfoContext(ctx, "DID published successfully",
		slog.String("did", d.URI),
	)

	return nil
}

// toCoreDocument converts the internal DID to a didcore.Document
// suitable for DNS marshaling and DHT publication.
func (d *DID) toCoreDocument(dwnEndpoint string) didcore.Document {
	doc := didcore.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      d.URI,
	}

	// Add signing key (Ed25519).
	signingVM := didcore.VerificationMethod{
		ID:         d.URI + "#0",
		Type:       "JsonWebKey",
		Controller: d.URI,
		PublicKeyJwk: &jwk.JWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(d.SigningPublicKey),
		},
	}
	doc.AddVerificationMethod(signingVM, didcore.Purposes(
		didcore.PurposeAuthentication,
		didcore.PurposeAssertion,
		didcore.PurposeCapabilityInvocation,
		didcore.PurposeCapabilityDelegation,
	))

	// Add encryption key (X25519).
	encVM := didcore.VerificationMethod{
		ID:         d.URI + "#enc",
		Type:       "JsonWebKey",
		Controller: d.URI,
		PublicKeyJwk: &jwk.JWK{
			KTY: "OKP",
			CRV: "X25519",
			X:   base64.RawURLEncoding.EncodeToString(d.EncryptionPublicKey),
		},
	}
	doc.AddVerificationMethod(encVM, didcore.Purposes(
		didcore.PurposeKeyAgreement,
	))

	// Add DWN service if endpoint provided.
	if dwnEndpoint != "" {
		doc.AddService(didcore.Service{
			ID:              d.URI + "#dwn",
			Type:            "DecentralizedWebNode",
			ServiceEndpoint: []string{dwnEndpoint},
		})
	}

	return doc
}
