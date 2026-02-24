package dwn

import (
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
	gocid "github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

const (
	codecDAGCBOR = 0x71 // DAG-CBOR multicodec
	codecRaw     = 0x55 // raw multicodec (UnixFS leaf blocks)
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
//
// Before encoding, float64 values that represent whole integers are normalized
// to int64. This is required because Go's json.Unmarshal decodes JSON numbers
// to float64, and CBOR encodes float64 as a float type. The JS DAG-CBOR
// encoder (cborg/@ipld/dag-cbor) encodes JavaScript integers as CBOR integers.
// Without normalization, the CBOR bytes differ and the CIDs won't match.
func ComputeCID(obj any) (string, error) {
	obj = normalizeForCBOR(obj)
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

// normalizeForCBOR recursively walks a value and converts float64 values that
// represent whole integers to int64. This ensures CBOR encodes them as integer
// types (major type 0/1) rather than float types (major type 7), matching the
// behavior of the JS DAG-CBOR encoder which treats Number.isInteger() values
// as CBOR integers.
func normalizeForCBOR(v any) any {
	switch val := v.(type) {
	case float64:
		if !math.IsInf(val, 0) && !math.IsNaN(val) && val == math.Trunc(val) &&
			val >= math.MinInt64 && val <= math.MaxInt64 {
			return int64(val)
		}
		return val
	case map[string]any:
		for k, elem := range val {
			val[k] = normalizeForCBOR(elem)
		}
		return val
	case []any:
		for i, elem := range val {
			val[i] = normalizeForCBOR(elem)
		}
		return val
	default:
		return val
	}
}

// ComputeDataCID computes a CIDv1 (raw codec, SHA-256) for data bytes.
//
// UnixFS uses raw codec (0x55) for leaf blocks. For single-chunk data
// (≤ 256KiB), the root CID is the leaf CID itself. This matches the
// JS SDK's `Cid.computeDagPbCidFromBytes` which uses the UnixFS importer
// and produces a raw-codec CID for single-block data.
func ComputeDataCID(data []byte) (string, error) {
	mh, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("multihash: %w", err)
	}

	c := gocid.NewCidV1(codecRaw, mh)
	return c.String(), nil
}
