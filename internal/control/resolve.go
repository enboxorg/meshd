package control

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/enboxorg/dwn-mesh/pkg/dids/did"
	"github.com/enboxorg/dwn-mesh/pkg/dids/didcore"
)

// Resolver resolves DIDs to DID Documents. This abstraction allows the control
// layer to discover peer DWN service endpoints and public keys from their DIDs.
type Resolver interface {
	ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error)
}

// PeerEndpointInfo holds the resolved information about a peer's DID,
// including their DWN service endpoint(s) and signing key(s).
type PeerEndpointInfo struct {
	// DID is the peer's DID URI.
	DID string

	// DWNEndpoints are the DWN service endpoints extracted from the DID Document.
	DWNEndpoints []string

	// SigningKeyID is the ID of the first authentication verification method.
	SigningKeyID string

	// Document is the full resolved DID Document.
	Document didcore.Document
}

// Service type constants for DID Document service entries.
const (
	ServiceTypeDWN = "DecentralizedWebNode"
)

// ResolvePeerEndpoints resolves a DID URI and extracts DWN service endpoints
// and signing key information from the resulting DID Document.
//
// Returns ErrNoDWNService if the DID Document contains no DecentralizedWebNode
// service entries.
func ResolvePeerEndpoints(ctx context.Context, resolver Resolver, uri string, logger *slog.Logger) (*PeerEndpointInfo, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Validate the DID URI before resolving.
	parsedDID, err := did.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing DID %q: %w", uri, err)
	}

	logger.DebugContext(ctx, "resolving peer DID",
		slog.String("did", parsedDID.URI),
		slog.String("method", parsedDID.Method),
	)

	result, err := resolver.ResolveWithContext(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("resolving DID %q: %w", uri, err)
	}

	if errCode := result.GetError(); errCode != "" {
		return nil, fmt.Errorf("DID resolution error for %q: %s", uri, errCode)
	}

	doc := result.Document
	info := &PeerEndpointInfo{
		DID:      uri,
		Document: doc,
	}

	// Extract DWN service endpoints.
	for _, svc := range doc.Service {
		if svc.Type == ServiceTypeDWN {
			info.DWNEndpoints = append(info.DWNEndpoints, svc.ServiceEndpoint...)
		}
	}

	// Extract signing key ID from authentication verification methods.
	if len(doc.Authentication) > 0 {
		info.SigningKeyID = doc.GetAbsoluteResourceID(doc.Authentication[0])
	}

	logger.DebugContext(ctx, "resolved peer DID",
		slog.String("did", uri),
		slog.Int("dwnEndpoints", len(info.DWNEndpoints)),
		slog.String("signingKey", info.SigningKeyID),
	)

	return info, nil
}

// Sentinel errors for resolution.
var (
	ErrNoDWNService = fmt.Errorf("no %s service in DID Document", ServiceTypeDWN)
)

// ResolvePeerDWNEndpoint resolves a DID and returns the first DWN service
// endpoint URL. This is a convenience wrapper around ResolvePeerEndpoints
// for the common case where only the endpoint URL is needed.
//
// Returns ErrNoDWNService if no DWN service endpoint is found.
func ResolvePeerDWNEndpoint(ctx context.Context, resolver Resolver, uri string, logger *slog.Logger) (string, error) {
	info, err := ResolvePeerEndpoints(ctx, resolver, uri, logger, )
	if err != nil {
		return "", err
	}

	if len(info.DWNEndpoints) == 0 {
		return "", fmt.Errorf("%w: %s", ErrNoDWNService, uri)
	}

	return info.DWNEndpoints[0], nil
}
