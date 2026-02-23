// Package mesh - discovery.go handles DID-based peer endpoint resolution.
//
// Resolution chain:
//   DID -> DID Document -> #dwn service endpoint -> DWN URL
//
// For each peer DID:
//   1. Resolve the DID document (via did:dht DHT lookup, did:web HTTPS, etc.)
//   2. Extract the #dwn service endpoint (may be URL, URL array, or DID URI)
//   3. If DID URI, recursively resolve (max depth 3)
//   4. Connect to the DWN endpoint via HTTPS
//   5. Read nodeInfo and subscribe to endpoint changes
//
// Caching:
//   - DID documents are cached with TTL based on the DID method
//   - DWN URLs are cached until DID document changes
//   - nodeInfo is cached locally for offline resilience
package mesh
