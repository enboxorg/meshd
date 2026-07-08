package enboxconnect

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBuildConnectPermissionRequest(t *testing.T) {
	cpr, err := BuildConnectPermissionRequest(PermissionRequest{
		ProtocolDefinition: testProtocolDefinition,
		Permissions:        []string{"read", "write", "delete"},
	})
	if err != nil {
		t.Fatalf("BuildConnectPermissionRequest: %v", err)
	}

	want := []PermissionScope{
		{Interface: "Protocols", Method: "Query", Protocol: testProtocolURI},
		{Interface: "Messages", Method: "Read", Protocol: testProtocolURI},
		{Interface: "Records", Method: "Read", Protocol: testProtocolURI},
		{Interface: "Records", Method: "Write", Protocol: testProtocolURI},
		{Interface: "Records", Method: "Delete", Protocol: testProtocolURI},
	}
	if !reflect.DeepEqual(cpr.PermissionScopes, want) {
		t.Errorf("scopes = %+v, want %+v", cpr.PermissionScopes, want)
	}
	if string(cpr.ProtocolDefinition) != string(testProtocolDefinition) {
		t.Error("protocol definition was not passed through unchanged")
	}
}

func TestBuildConnectPermissionRequestNoPermissions(t *testing.T) {
	cpr, err := BuildConnectPermissionRequest(PermissionRequest{
		ProtocolDefinition: testProtocolDefinition,
	})
	if err != nil {
		t.Fatalf("BuildConnectPermissionRequest: %v", err)
	}
	want := []PermissionScope{
		{Interface: "Protocols", Method: "Query", Protocol: testProtocolURI},
		{Interface: "Messages", Method: "Read", Protocol: testProtocolURI},
	}
	if !reflect.DeepEqual(cpr.PermissionScopes, want) {
		t.Errorf("scopes = %+v, want %+v", cpr.PermissionScopes, want)
	}
}

func TestBuildConnectPermissionRequestErrors(t *testing.T) {
	if _, err := BuildConnectPermissionRequest(PermissionRequest{
		ProtocolDefinition: testProtocolDefinition,
		Permissions:        []string{"subscribe"},
	}); err == nil || !strings.Contains(err.Error(), "unsupported connect permission") {
		t.Errorf("error = %v, want unsupported permission", err)
	}

	if _, err := BuildConnectPermissionRequest(PermissionRequest{
		ProtocolDefinition: json.RawMessage(`{"structure":{}}`),
		Permissions:        []string{"read"},
	}); err == nil || !strings.Contains(err.Error(), "missing the protocol URI") {
		t.Errorf("error = %v, want missing protocol URI", err)
	}

	if _, err := BuildConnectPermissionRequest(PermissionRequest{
		ProtocolDefinition: json.RawMessage(`not-json`),
		Permissions:        []string{"read"},
	}); err == nil {
		t.Error("expected error for malformed protocol definition")
	}
}

func TestPermissionScopeWireNames(t *testing.T) {
	scope := PermissionScope{
		Interface: "Records", Method: "Write",
		Protocol: "https://p.example", ContextID: "ctx", ProtocolPath: "a/b",
	}
	got, err := json.Marshal(scope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"interface":"Records","method":"Write","protocol":"https://p.example","contextId":"ctx","protocolPath":"a/b"}`
	if string(got) != want {
		t.Errorf("wire form = %s, want %s", got, want)
	}
}
