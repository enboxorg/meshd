package enboxconnect

import (
	"encoding/json"
	"fmt"
)

// PermissionRequest is the meshd-level input for one protocol's permission
// request: the full protocol definition JSON plus the record-level
// permissions ("read", "write", "delete") being requested.
type PermissionRequest struct {
	ProtocolDefinition json.RawMessage
	Permissions        []string
}

// BuildConnectPermissionRequest expands a PermissionRequest into the wire
// ConnectPermissionRequest, mirroring createPermissionRequestForProtocol in
// packages/auth/src/wallet-connect-client.ts: a Protocols/Query scope and a
// Messages/Read scope are always included, followed by one Records/<Method>
// scope per requested permission. Every scope carries the protocol URI from
// the definition.
func BuildConnectPermissionRequest(pr PermissionRequest) (ConnectPermissionRequest, error) {
	var def struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(pr.ProtocolDefinition, &def); err != nil {
		return ConnectPermissionRequest{}, fmt.Errorf("parsing protocol definition: %w", err)
	}
	if def.Protocol == "" {
		return ConnectPermissionRequest{}, fmt.Errorf("protocol definition is missing the protocol URI")
	}

	scopes := []PermissionScope{
		{Interface: "Protocols", Method: "Query", Protocol: def.Protocol},
		{Interface: "Messages", Method: "Read", Protocol: def.Protocol},
	}

	for _, permission := range pr.Permissions {
		var method string
		switch permission {
		case "read":
			method = "Read"
		case "write":
			method = "Write"
		case "delete":
			method = "Delete"
		default:
			return ConnectPermissionRequest{}, fmt.Errorf(
				"unsupported connect permission %q (supported: read, write, delete)", permission)
		}
		scopes = append(scopes, PermissionScope{Interface: "Records", Method: method, Protocol: def.Protocol})
	}

	return ConnectPermissionRequest{
		ProtocolDefinition: pr.ProtocolDefinition,
		PermissionScopes:   scopes,
	}, nil
}

// buildConnectPermissionRequests expands every PermissionRequest.
func buildConnectPermissionRequests(prs []PermissionRequest) ([]ConnectPermissionRequest, error) {
	out := make([]ConnectPermissionRequest, 0, len(prs))
	for i, pr := range prs {
		cpr, err := BuildConnectPermissionRequest(pr)
		if err != nil {
			return nil, fmt.Errorf("permission request %d: %w", i, err)
		}
		out = append(out, cpr)
	}
	return out, nil
}
