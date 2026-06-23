package protocols

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestProtocolDeleteActionsIncludeCreate(t *testing.T) {
	for name, data := range map[string][]byte{
		"wireguard-mesh": MeshProtocolJSON,
		"key-delivery":   KeyDeliveryProtocolJSON,
	} {
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: unmarshal protocol JSON: %v", name, err)
		}
		assertDeleteActionsIncludeCreate(t, name, doc)
	}
}

func assertDeleteActionsIncludeCreate(t *testing.T, path string, value any) {
	t.Helper()

	switch v := value.(type) {
	case map[string]any:
		if actions, ok := v["$actions"].([]any); ok {
			for i, action := range actions {
				actionMap, ok := action.(map[string]any)
				if !ok {
					continue
				}
				can, ok := actionMap["can"].([]any)
				if !ok {
					continue
				}
				if containsAction(can, "delete") && !containsAction(can, "create") {
					t.Fatalf("%s.$actions[%d] grants delete without create: %v", path, i, can)
				}
			}
		}
		for key, child := range v {
			assertDeleteActionsIncludeCreate(t, fmt.Sprintf("%s.%s", path, key), child)
		}
	case []any:
		for i, child := range v {
			assertDeleteActionsIncludeCreate(t, fmt.Sprintf("%s[%d]", path, i), child)
		}
	}
}

func containsAction(actions []any, want string) bool {
	for _, action := range actions {
		if action == want {
			return true
		}
	}
	return false
}
