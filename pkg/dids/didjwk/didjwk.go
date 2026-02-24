// Copied from github.com/enboxorg/web5-go — will be replaced by a shared enbox Go library.
package didjwk

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/enboxorg/dwn-mesh/pkg/dids/did"
	"github.com/enboxorg/dwn-mesh/pkg/dids/didcore"
	"github.com/enboxorg/dwn-mesh/pkg/jwk"
)

// Resolver is a type to implement resolution
type Resolver struct{}

// ResolveWithContext the provided DID URI (must be a did:jwk) as per the wee bit of detail provided in the
// spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md
func (r Resolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {
	return r.Resolve(uri)
}

// Resolve the provided DID URI (must be a did:jwk) as per the wee bit of detail provided in the
// spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md
func (r Resolver) Resolve(uri string) (didcore.ResolutionResult, error) {
	did, err := did.Parse(uri)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if did.Method != "jwk" {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(did.ID)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	var jwk jwk.JWK
	err = json.Unmarshal(decodedID, &jwk)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	doc := createDocument(did, jwk)
	return didcore.ResolutionResultWithDocument(doc), nil
}

func createDocument(did did.DID, publicKey jwk.JWK) didcore.Document {
	doc := didcore.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      did.URI,
	}

	vm := didcore.VerificationMethod{
		ID:           did.URI + "#0",
		Type:         "JsonWebKey",
		Controller:   did.URI,
		PublicKeyJwk: &publicKey,
	}

	doc.AddVerificationMethod(
		vm,
		didcore.Purposes("assertionMethod", "authentication", "capabilityInvocation", "capabilityDelegation"),
	)

	return doc
}
