package dwn

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	gocid "github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

const (
	codecDAGCBOR = 0x71 // DAG-CBOR multicodec
	codecDAGPB   = 0x70 // DAG-PB (UnixFS) multicodec
)

// dagCBOREncMode uses deterministic CBOR encoding (canonical key sorting)
// matching DAG-CBOR semantics: map keys sorted by byte length first,
// then lexicographically. This is critical for CID interoperability.
var dagCBOREncMode cbor.EncMode

func init() {
	opts := cbor.CanonicalEncOptions()
	var err error
	dagCBOREncMode, err = opts.EncMode()
	if err != nil {
		panic("cbor enc mode: " + err.Error())
	}
}

// ComputeCID computes a CIDv1 (DAG-CBOR codec, SHA-256) for the given value.
//
// IMPORTANT: The input should be a map[string]any with only the fields that
// should be included. Zero-value/absent fields must be omitted, matching the
// JS SDK's removeUndefinedProperties() behavior. Do NOT pass a Go struct
// directly — use buildCIDInput helpers to construct the map.
func ComputeCID(obj any) (string, error) {
	data, err := dagCBOREncMode.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("cbor marshal: %w", err)
	}

	mh, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("multihash: %w", err)
	}

	c := gocid.NewCidV1(codecDAGCBOR, mh)
	return c.String(), nil
}

// ComputeDataCID computes a CIDv1 (DAG-PB codec, SHA-256) for raw data bytes.
//
// NOTE: A full implementation should use UnixFS DAG-PB encoding (chunking).
// This simplified version hashes the raw bytes directly, which is correct
// for data ≤ 256KiB (single-chunk UnixFS).
func ComputeDataCID(data []byte) (string, error) {
	mh, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("multihash: %w", err)
	}

	c := gocid.NewCidV1(codecDAGPB, mh)
	return c.String(), nil
}
