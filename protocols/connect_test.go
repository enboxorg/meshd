package protocols

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMeshProtocolDefinitionForConnect(t *testing.T) {
	stripped, err := MeshProtocolDefinitionForConnect()
	if err != nil {
		t.Fatalf("MeshProtocolDefinitionForConnect: %v", err)
	}
	if strings.Contains(string(stripped), "$keyAgreement") {
		t.Fatalf("stripped definition still contains $keyAgreement nodes")
	}

	var def struct {
		Protocol  string         `json:"protocol"`
		Published bool           `json:"published"`
		Types     map[string]any `json:"types"`
		Structure map[string]any `json:"structure"`
	}
	if err := json.Unmarshal(stripped, &def); err != nil {
		t.Fatalf("parsing stripped definition: %v", err)
	}
	if def.Protocol != MeshProtocolURI {
		t.Errorf("protocol = %q, want %q", def.Protocol, MeshProtocolURI)
	}
	if !def.Published {
		t.Errorf("published flag lost in stripping")
	}
	if len(def.Types) == 0 || len(def.Structure) == 0 {
		t.Fatalf("stripping dropped types or structure")
	}

	// The structure must otherwise be intact: same rule-set tree as the
	// embedded definition, minus only $keyAgreement nodes.
	var original struct {
		Structure map[string]any `json:"structure"`
	}
	if err := json.Unmarshal(MeshProtocolJSON, &original); err != nil {
		t.Fatalf("parsing embedded definition: %v", err)
	}
	assertSameTreeMinusKeyAgreement(t, "structure", original.Structure, def.Structure)
}

func assertSameTreeMinusKeyAgreement(t *testing.T, path string, original, stripped map[string]any) {
	t.Helper()
	for name, child := range original {
		if name == "$keyAgreement" {
			if _, present := stripped[name]; present {
				t.Errorf("%s: $keyAgreement not stripped", path)
			}
			continue
		}
		strippedChild, present := stripped[name]
		if !present {
			t.Errorf("%s: key %q lost in stripping", path, name)
			continue
		}
		origSet, origIsSet := child.(map[string]any)
		strippedSet, strippedIsSet := strippedChild.(map[string]any)
		if origIsSet && strippedIsSet {
			assertSameTreeMinusKeyAgreement(t, path+"/"+name, origSet, strippedSet)
		}
	}
}
