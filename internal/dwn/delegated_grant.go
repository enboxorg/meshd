package dwn

import (
	"encoding/json"
	"fmt"
	"math"
)

// ComputeDelegatedGrantID computes the CID of a delegated grant message,
// matching dwn-sdk-js `Message.getCid()` exactly.
//
// WIRE-COMPAT CONSTRAINT (dwn-sdk-js packages/dwn-sdk-js/src/core/message.ts,
// Message.getCid): the SDK shallow-copies the message and deletes the
// TOP-LEVEL `encodedData` property when it is truthy (`if (rawMessage.encodedData)`,
// so an empty string is kept) before computing the DAG-CBOR CIDv1 (SHA-256)
// over the remaining object. Everything else — recordId, contextId, the full
// descriptor (whose dataCid/dataSize still reference the encoded data), and
// authorization — is included as-is. The server recomputes this CID from the
// embedded `authorization.authorDelegatedGrant` and rejects the message if it
// does not equal the `delegatedGrantId` in the signature payload
// (Records.validateDelegatedGrantReferentialIntegrity), so this rule must not
// drift from the SDK.
//
// meshd's ComputeCID performs no stripping of its own; the encodedData
// removal happens here. Its float64→int64 normalization matches the JS
// DAG-CBOR encoder's integer handling for JSON numbers like dataSize.
func ComputeDelegatedGrantID(grant json.RawMessage) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(grant, &m); err != nil {
		return "", fmt.Errorf("parsing delegated grant message: %w", err)
	}
	if v, ok := m["encodedData"]; ok && jsTruthy(v) {
		delete(m, "encodedData")
	}
	cid, err := ComputeCID(m)
	if err != nil {
		return "", fmt.Errorf("computing delegated grant CID: %w", err)
	}
	return cid, nil
}

// jsTruthy reports whether a JSON-decoded value is truthy under JavaScript
// semantics. Used to replicate the SDK's `if (rawMessage.encodedData)` check.
func jsTruthy(v any) bool {
	switch val := v.(type) {
	case nil:
		return false
	case bool:
		return val
	case string:
		return val != ""
	case float64:
		return val != 0 && !math.IsNaN(val)
	default:
		// Objects and arrays are always truthy.
		return true
	}
}

// delegatedGrantAuthor returns the DID of the grantor — the signer of the
// delegated grant message. When a message is signed with a delegated grant,
// the grantor becomes the logical author (dwn-sdk-js RecordsWrite.sign:
// authorDid = Jws.getSignerDid(delegatedGrant.authorization.signature.signatures[0])),
// which is what the entry ID (recordId) of initial writes is derived from.
func delegatedGrantAuthor(grant json.RawMessage) (string, error) {
	var msg struct {
		Authorization struct {
			Signature *GeneralJWS `json:"signature"`
		} `json:"authorization"`
	}
	if err := json.Unmarshal(grant, &msg); err != nil {
		return "", fmt.Errorf("parsing delegated grant message: %w", err)
	}
	author, err := signerDIDFromJWS(msg.Authorization.Signature)
	if err != nil {
		return "", fmt.Errorf("delegated grant: %w", err)
	}
	return author, nil
}
