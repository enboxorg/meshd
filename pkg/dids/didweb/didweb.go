// Copied from github.com/enboxorg/web5-go — will be replaced by a shared enbox Go library.
package didweb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	liburl "net/url"
	"strings"

	_did "github.com/enboxorg/dwn-mesh/pkg/dids/did"
	"github.com/enboxorg/dwn-mesh/pkg/dids/didcore"
)

// TransformID takes a did:web's identifier (the third part, after the method) and returns the web URL per the [spec]
//
// [spec]: https://w3c-ccg.github.io/did-method-web/#read-resolve
func TransformID(id string) (string, error) {
	domain := strings.ReplaceAll(id, ":", "/")

	temp, err := liburl.PathUnescape("https://" + domain)
	if err != nil {
		return "", err
	}

	url, err := liburl.Parse(temp)
	if err != nil {
		return "", err
	}

	//! temporarily diverging from spec in order to make local development easier (Moe - 2024-05-13)
	//! set url scheme to http if hostname is localhost or an ipv4 address
	if url.Hostname() == "localhost" || net.ParseIP(url.Hostname()) != nil {
		url.Scheme = "http"
	}

	if url.Path == "" || url.Path == "/" {
		url.Path += "/.well-known"
	}
	url.Path += "/did.json"

	return url.String(), nil
}

// Resolver is a type to implement resolution
type Resolver struct{}

// ResolveWithContext the provided DID URI (must be a did:web) as per the [spec]
//
// [spec]: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (r Resolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {
	did, err := _did.Parse(uri)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if did.Method != "web" {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	url, err := TransformID(did.ID)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	// TODO item 6 from https://w3c-ccg.github.io/did-method-web/#read-resolve https://github.com/enboxorg/web5-go/issues/94
	// TODO item 7 from https://w3c-ccg.github.io/did-method-web/#read-resolve https://github.com/enboxorg/web5-go/issues/95

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return didcore.ResolutionResult{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return didcore.ResolutionResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return didcore.ResolutionResult{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var document didcore.Document
	err = json.Unmarshal(body, &document)
	if err != nil {
		return didcore.ResolutionResult{}, fmt.Errorf("failed to deserialize document: %w", err)
	}

	return didcore.ResolutionResultWithDocument(document), nil
}

// Resolve the provided DID URI (must be a did:web) as per the [spec]
//
// [spec]: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (r Resolver) Resolve(uri string) (didcore.ResolutionResult, error) {
	return r.ResolveWithContext(context.Background(), uri)
}
