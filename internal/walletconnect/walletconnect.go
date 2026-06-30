// Package walletconnect defines the CLI-to-wallet handoff format used by
// meshd wallet-connected profiles.
package walletconnect

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/protocols"
)

const (
	SchemePrefix = "meshd://connect/"

	RequestType  = "meshd-cli-connect-request"
	ResponseType = "meshd-cli-connect-response"

	NetworkCreateSchemePrefix = "meshd://network-create/"
	NetworkCreateRequestType  = "meshd-network-create-request"
	NetworkCreateResponseType = "meshd-network-create-response"

	ResponseEnvelopeType = "meshd-wallet-response-envelope"

	currentVersion = 1
	challengeBytes = 32
)

type Request struct {
	Version          int      `json:"version"`
	Type             string   `json:"type"`
	AppName          string   `json:"appName"`
	ProfileName      string   `json:"profileName,omitempty"`
	NodeDID          string   `json:"nodeDid"`
	DelegateDID      string   `json:"delegateDid,omitempty"`
	NodeProof        string   `json:"nodeProof"`
	Challenge        string   `json:"challenge"`
	CallbackURL      string   `json:"callbackUrl,omitempty"`
	ResponseEndpoint string   `json:"responseEndpoint,omitempty"`
	ResponseToken    string   `json:"responseToken,omitempty"`
	Protocol         string   `json:"protocol"`
	Permissions      []string `json:"permissions"`
	CreatedAt        string   `json:"createdAt"`
}

type Response struct {
	Version                     int               `json:"version"`
	Type                        string            `json:"type"`
	ProfileName                 string            `json:"profileName,omitempty"`
	OwnerDID                    string            `json:"ownerDID,omitempty"`
	ConnectedDID                string            `json:"connectedDid,omitempty"`
	DelegateDID                 string            `json:"delegateDid,omitempty"`
	NodeDID                     string            `json:"nodeDid"`
	WalletOrigin                string            `json:"walletOrigin,omitempty"`
	ExpiresAt                   string            `json:"expiresAt,omitempty"`
	Grants                      []json.RawMessage `json:"grants,omitempty"`
	NodeMultiPartyProtocols     []string          `json:"nodeMultiPartyProtocols,omitempty"`
	DelegateDecryptionKeys      []json.RawMessage `json:"delegateDecryptionKeys,omitempty"`
	DelegateMultiPartyProtocols []string          `json:"delegateMultiPartyProtocols,omitempty"`
}

type NetworkCreateRequest struct {
	Version           int    `json:"version"`
	Type              string `json:"type"`
	AppName           string `json:"appName"`
	ProfileName       string `json:"profileName,omitempty"`
	NodeDID           string `json:"nodeDid"`
	DelegateDID       string `json:"delegateDid,omitempty"`
	NodeProof         string `json:"nodeProof"`
	Challenge         string `json:"challenge"`
	CallbackURL       string `json:"callbackUrl,omitempty"`
	ResponseEndpoint  string `json:"responseEndpoint,omitempty"`
	ResponseToken     string `json:"responseToken,omitempty"`
	Protocol          string `json:"protocol"`
	NetworkName       string `json:"networkName"`
	MeshCIDR          string `json:"meshCIDR"`
	RequestedEndpoint string `json:"requestedEndpoint,omitempty"`
	CreatedAt         string `json:"createdAt"`
}

type NetworkCreateResponse struct {
	Version                     int               `json:"version"`
	Type                        string            `json:"type"`
	ProfileName                 string            `json:"profileName,omitempty"`
	OwnerDID                    string            `json:"ownerDID,omitempty"`
	ConnectedDID                string            `json:"connectedDid,omitempty"`
	DelegateDID                 string            `json:"delegateDid,omitempty"`
	NodeDID                     string            `json:"nodeDid"`
	WalletOrigin                string            `json:"walletOrigin,omitempty"`
	ExpiresAt                   string            `json:"expiresAt,omitempty"`
	AnchorEndpoint              string            `json:"anchorEndpoint"`
	NetworkRecordID             string            `json:"networkRecordId"`
	NetworkName                 string            `json:"networkName"`
	MeshCIDR                    string            `json:"meshCIDR"`
	MeshIP                      string            `json:"meshIP"`
	MemberRecordID              string            `json:"memberRecordId,omitempty"`
	MemberDateCreated           string            `json:"memberDateCreated,omitempty"`
	NodeRecordID                string            `json:"nodeRecordId,omitempty"`
	NodeDateCreated             string            `json:"nodeDateCreated,omitempty"`
	Grants                      []json.RawMessage `json:"grants,omitempty"`
	NodeMultiPartyProtocols     []string          `json:"nodeMultiPartyProtocols,omitempty"`
	DelegateMultiPartyProtocols []string          `json:"delegateMultiPartyProtocols,omitempty"`
}

type ResponseEnvelope struct {
	Version       int             `json:"version"`
	Type          string          `json:"type"`
	ResponseToken string          `json:"responseToken"`
	ResponseType  string          `json:"responseType"`
	Response      json.RawMessage `json:"response"`
}

func (r Response) EffectiveNodeMultiPartyProtocols() []string {
	if len(r.NodeMultiPartyProtocols) > 0 {
		return r.NodeMultiPartyProtocols
	}
	return r.DelegateMultiPartyProtocols
}

func (r *Response) NormalizeOwnerDID() {
	if r == nil {
		return
	}
	if r.OwnerDID == "" {
		r.OwnerDID = r.ConnectedDID
	}
	if r.ConnectedDID == "" {
		r.ConnectedDID = r.OwnerDID
	}
}

func (r Response) EffectiveOwnerDID() string {
	if r.OwnerDID != "" {
		return r.OwnerDID
	}
	return r.ConnectedDID
}

func (r NetworkCreateResponse) EffectiveNodeMultiPartyProtocols() []string {
	if len(r.NodeMultiPartyProtocols) > 0 {
		return r.NodeMultiPartyProtocols
	}
	return r.DelegateMultiPartyProtocols
}

func (r *NetworkCreateResponse) NormalizeOwnerDID() {
	if r == nil {
		return
	}
	if r.OwnerDID == "" {
		r.OwnerDID = r.ConnectedDID
	}
	if r.ConnectedDID == "" {
		r.ConnectedDID = r.OwnerDID
	}
}

func (r NetworkCreateResponse) EffectiveOwnerDID() string {
	if r.OwnerDID != "" {
		return r.OwnerDID
	}
	return r.ConnectedDID
}

func NewRequest(profileName string, identity *did.DID, delegateIdentities ...*did.DID) (Request, error) {
	if identity == nil {
		return Request{}, fmt.Errorf("node identity is required")
	}
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	if signer == nil || signer.DID == "" || len(signer.PrivateKey) != ed25519.PrivateKeySize {
		return Request{}, fmt.Errorf("node signer is required")
	}
	challenge, err := GenerateChallenge()
	if err != nil {
		return Request{}, err
	}
	delegateDID := ""
	if len(delegateIdentities) > 0 && delegateIdentities[0] != nil {
		delegateDID = strings.TrimSpace(delegateIdentities[0].URI)
	}
	req := Request{
		Version:     currentVersion,
		Type:        RequestType,
		AppName:     "meshd CLI",
		ProfileName: strings.TrimSpace(profileName),
		NodeDID:     strings.TrimSpace(signer.DID),
		DelegateDID: delegateDID,
		Challenge:   challenge,
		Protocol:    protocols.MeshProtocolURI,
		Permissions: []string{"mesh-node"},
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	req.NodeProof = SignNodeProof(signer, req.Challenge, req.NodeDID, req.DelegateDID, "", "", "", permissionsProofValue(req.Permissions))
	return req, nil
}

func NewNetworkCreateRequest(profileName string, identity *did.DID, networkName string, endpoint string, meshCIDR string, delegateIdentities ...*did.DID) (NetworkCreateRequest, error) {
	if identity == nil {
		return NetworkCreateRequest{}, fmt.Errorf("node identity is required")
	}
	networkName = strings.TrimSpace(networkName)
	if networkName == "" {
		return NetworkCreateRequest{}, fmt.Errorf("network name is required")
	}
	meshCIDR = strings.TrimSpace(meshCIDR)
	if meshCIDR == "" {
		meshCIDR = "10.200.0.0/16"
	}
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	challenge, err := GenerateChallenge()
	if err != nil {
		return NetworkCreateRequest{}, err
	}
	delegateDID := ""
	if len(delegateIdentities) > 0 && delegateIdentities[0] != nil {
		delegateDID = strings.TrimSpace(delegateIdentities[0].URI)
	}
	req := NetworkCreateRequest{
		Version:           currentVersion,
		Type:              NetworkCreateRequestType,
		AppName:           "meshd CLI",
		ProfileName:       strings.TrimSpace(profileName),
		NodeDID:           strings.TrimSpace(identity.URI),
		DelegateDID:       delegateDID,
		Challenge:         challenge,
		Protocol:          protocols.MeshProtocolURI,
		NetworkName:       networkName,
		MeshCIDR:          meshCIDR,
		RequestedEndpoint: strings.TrimSpace(endpoint),
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
	}
	req.NodeProof = SignNetworkCreateProof(signer, req.Challenge, req.NodeDID, req.NetworkName, req.RequestedEndpoint, req.MeshCIDR, req.DelegateDID, "", "", "")
	return req, nil
}

func SignRequest(identity *did.DID, req *Request) error {
	if identity == nil {
		return fmt.Errorf("node identity is required")
	}
	if req == nil {
		return fmt.Errorf("wallet connect request is required")
	}
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	req.NodeProof = SignNodeProof(signer, req.Challenge, req.NodeDID, req.DelegateDID, req.CallbackURL, req.ResponseEndpoint, req.ResponseToken, permissionsProofValue(req.Permissions))
	return nil
}

func SignNetworkCreateRequest(identity *did.DID, req *NetworkCreateRequest) error {
	if identity == nil {
		return fmt.Errorf("node identity is required")
	}
	if req == nil {
		return fmt.Errorf("network create request is required")
	}
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	req.NodeProof = SignNetworkCreateProof(signer, req.Challenge, req.NodeDID, req.NetworkName, req.RequestedEndpoint, req.MeshCIDR, req.DelegateDID, req.CallbackURL, req.ResponseEndpoint, req.ResponseToken)
	return nil
}

func EncodeRequest(req Request) (string, error) {
	if req.Version == 0 {
		req.Version = currentVersion
	}
	if err := req.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal wallet connect request: %w", err)
	}
	return SchemePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func DecodeRequest(raw string) (Request, error) {
	payload := strings.TrimSpace(raw)
	if strings.HasPrefix(payload, SchemePrefix) {
		payload = strings.TrimPrefix(payload, SchemePrefix)
	}
	if payload == "" {
		return Request{}, fmt.Errorf("empty wallet connect request")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Request{}, fmt.Errorf("decode wallet connect request: %w", err)
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return Request{}, fmt.Errorf("parse wallet connect request: %w", err)
	}
	if err := req.Validate(); err != nil {
		return Request{}, err
	}
	return req, nil
}

func EncodeNetworkCreateRequest(req NetworkCreateRequest) (string, error) {
	if req.Version == 0 {
		req.Version = currentVersion
	}
	if err := req.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal network create request: %w", err)
	}
	return NetworkCreateSchemePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func DecodeNetworkCreateRequest(raw string) (NetworkCreateRequest, error) {
	payload := strings.TrimSpace(raw)
	if strings.HasPrefix(payload, NetworkCreateSchemePrefix) {
		payload = strings.TrimPrefix(payload, NetworkCreateSchemePrefix)
	}
	if payload == "" {
		return NetworkCreateRequest{}, fmt.Errorf("empty network create request")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return NetworkCreateRequest{}, fmt.Errorf("decode network create request: %w", err)
	}
	var req NetworkCreateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return NetworkCreateRequest{}, fmt.Errorf("parse network create request: %w", err)
	}
	if err := req.Validate(); err != nil {
		return NetworkCreateRequest{}, err
	}
	return req, nil
}

func (r Request) Validate() error {
	if r.Version != currentVersion {
		return fmt.Errorf("unsupported wallet connect request version %d", r.Version)
	}
	if r.Type != RequestType {
		return fmt.Errorf("unsupported wallet connect request type %q", r.Type)
	}
	if r.NodeDID == "" {
		return fmt.Errorf("wallet connect request missing node DID")
	}
	if r.Challenge == "" {
		return fmt.Errorf("wallet connect request missing challenge")
	}
	if r.NodeProof == "" {
		return fmt.Errorf("wallet connect request missing node proof")
	}
	if !VerifyNodeProof(r.NodeDID, r.NodeProof, r.Challenge, r.DelegateDID, r.CallbackURL, r.ResponseEndpoint, r.ResponseToken, permissionsProofValue(r.Permissions)) {
		return fmt.Errorf("wallet connect request node proof is invalid")
	}
	return nil
}

func (r Response) Validate() error {
	if r.Version != currentVersion {
		return fmt.Errorf("unsupported wallet connect response version %d", r.Version)
	}
	if r.Type != ResponseType {
		return fmt.Errorf("unsupported wallet connect response type %q", r.Type)
	}
	if strings.TrimSpace(r.EffectiveOwnerDID()) == "" {
		return fmt.Errorf("wallet connect response missing owner DID")
	}
	if strings.TrimSpace(r.NodeDID) == "" {
		return fmt.Errorf("wallet connect response missing node DID")
	}
	return nil
}

func (r NetworkCreateRequest) Validate() error {
	if r.Version != currentVersion {
		return fmt.Errorf("unsupported network create request version %d", r.Version)
	}
	if r.Type != NetworkCreateRequestType {
		return fmt.Errorf("unsupported network create request type %q", r.Type)
	}
	if strings.TrimSpace(r.NodeDID) == "" {
		return fmt.Errorf("network create request missing node DID")
	}
	if strings.TrimSpace(r.NetworkName) == "" {
		return fmt.Errorf("network create request missing network name")
	}
	if strings.TrimSpace(r.MeshCIDR) == "" {
		return fmt.Errorf("network create request missing mesh CIDR")
	}
	if strings.TrimSpace(r.Protocol) != protocols.MeshProtocolURI {
		return fmt.Errorf("unsupported network create protocol %q", r.Protocol)
	}
	if strings.TrimSpace(r.Challenge) == "" {
		return fmt.Errorf("network create request missing challenge")
	}
	if strings.TrimSpace(r.NodeProof) == "" {
		return fmt.Errorf("network create request missing node proof")
	}
	if !VerifyNetworkCreateProof(r.NodeDID, r.NodeProof, r.Challenge, r.NetworkName, r.RequestedEndpoint, r.MeshCIDR, r.DelegateDID, r.CallbackURL, r.ResponseEndpoint, r.ResponseToken) {
		return fmt.Errorf("network create request node proof is invalid")
	}
	return nil
}

func (r NetworkCreateResponse) Validate() error {
	if r.Version != currentVersion {
		return fmt.Errorf("unsupported network create response version %d", r.Version)
	}
	if r.Type != NetworkCreateResponseType {
		return fmt.Errorf("unsupported network create response type %q", r.Type)
	}
	if strings.TrimSpace(r.EffectiveOwnerDID()) == "" {
		return fmt.Errorf("network create response missing owner DID")
	}
	if strings.TrimSpace(r.NodeDID) == "" {
		return fmt.Errorf("network create response missing node DID")
	}
	if strings.TrimSpace(r.AnchorEndpoint) == "" {
		return fmt.Errorf("network create response missing anchor endpoint")
	}
	if strings.TrimSpace(r.NetworkRecordID) == "" {
		return fmt.Errorf("network create response missing network record ID")
	}
	if strings.TrimSpace(r.NetworkName) == "" {
		return fmt.Errorf("network create response missing network name")
	}
	if strings.TrimSpace(r.MeshCIDR) == "" {
		return fmt.Errorf("network create response missing mesh CIDR")
	}
	if strings.TrimSpace(r.MeshIP) == "" {
		return fmt.Errorf("network create response missing mesh IP")
	}
	return nil
}

func NewResponseEnvelope(responseToken string, response json.RawMessage) (*ResponseEnvelope, error) {
	responseToken = strings.TrimSpace(responseToken)
	if responseToken == "" {
		return nil, fmt.Errorf("response token is required")
	}
	var header struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(response, &header); err != nil {
		return nil, fmt.Errorf("parse wallet response for envelope: %w", err)
	}
	if strings.TrimSpace(header.Type) == "" {
		return nil, fmt.Errorf("wallet response missing type")
	}
	env := &ResponseEnvelope{
		Version:       currentVersion,
		Type:          ResponseEnvelopeType,
		ResponseToken: responseToken,
		ResponseType:  header.Type,
		Response:      append(json.RawMessage(nil), response...),
	}
	return env, nil
}

func DecodeResponseEnvelope(data []byte, expectedToken string) (json.RawMessage, error) {
	var env ResponseEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse wallet response envelope: %w", err)
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(expectedToken) != "" && env.ResponseToken != strings.TrimSpace(expectedToken) {
		return nil, fmt.Errorf("wallet response envelope token mismatch")
	}
	return append(json.RawMessage(nil), env.Response...), nil
}

func (e ResponseEnvelope) Validate() error {
	if e.Version != currentVersion {
		return fmt.Errorf("unsupported wallet response envelope version %d", e.Version)
	}
	if e.Type != ResponseEnvelopeType {
		return fmt.Errorf("unsupported wallet response envelope type %q", e.Type)
	}
	if strings.TrimSpace(e.ResponseToken) == "" {
		return fmt.Errorf("wallet response envelope missing response token")
	}
	if strings.TrimSpace(e.ResponseType) == "" {
		return fmt.Errorf("wallet response envelope missing response type")
	}
	if len(e.Response) == 0 {
		return fmt.Errorf("wallet response envelope missing response")
	}
	return nil
}

func GenerateChallenge() (string, error) {
	var b [challengeBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate wallet connect challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func NodeProofMessage(challenge, nodeDID string, delivery ...string) []byte {
	delegateDID, callbackURL, responseEndpoint, responseToken, permissions := nodeProofFields(delivery)
	msg := "meshd wallet connect v1\n" +
		"challenge=" + challenge + "\n" +
		"node=" + nodeDID + "\n"
	if delegateDID != "" {
		msg += "delegate=" + delegateDID + "\n"
	}
	msg += "callback=" + callbackURL + "\n" +
		"responseEndpoint=" + responseEndpoint + "\n" +
		"responseToken=" + responseToken + "\n" +
		"permissions=" + permissions + "\n"
	return []byte(msg)
}

func NetworkCreateProofMessage(challenge, nodeDID, networkName, endpoint, meshCIDR string, delivery ...string) []byte {
	delegateDID, callbackURL, responseEndpoint, responseToken := networkCreateProofFields(delivery)
	msg := "meshd network create v1\n" +
		"challenge=" + challenge + "\n" +
		"node=" + nodeDID + "\n"
	if delegateDID != "" {
		msg += "delegate=" + delegateDID + "\n"
	}
	msg += "name=" + networkName + "\n" +
		"endpoint=" + endpoint + "\n" +
		"cidr=" + meshCIDR + "\n" +
		"callback=" + callbackURL + "\n" +
		"responseEndpoint=" + responseEndpoint + "\n" +
		"responseToken=" + responseToken + "\n"
	return []byte(msg)
}

func SignNodeProof(signer *dwn.Signer, challenge, nodeDID string, delivery ...string) string {
	if signer == nil || signer.DID != nodeDID || len(signer.PrivateKey) != ed25519.PrivateKeySize {
		return ""
	}
	sig := ed25519.Sign(signer.PrivateKey, NodeProofMessage(challenge, nodeDID, delivery...))
	return base64.RawURLEncoding.EncodeToString(sig)
}

func VerifyNodeProof(nodeDID, proof, challenge string, delivery ...string) bool {
	pub, err := did.ParseURI(nodeDID)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil {
		return false
	}
	return did.VerifyWith(pub, NodeProofMessage(challenge, nodeDID, delivery...), sig)
}

func SignNetworkCreateProof(signer *dwn.Signer, challenge, nodeDID, networkName, endpoint, meshCIDR string, delivery ...string) string {
	if signer == nil || signer.DID != nodeDID || len(signer.PrivateKey) != ed25519.PrivateKeySize {
		return ""
	}
	sig := ed25519.Sign(signer.PrivateKey, NetworkCreateProofMessage(challenge, nodeDID, networkName, endpoint, meshCIDR, delivery...))
	return base64.RawURLEncoding.EncodeToString(sig)
}

func VerifyNetworkCreateProof(nodeDID, proof, challenge, networkName, endpoint, meshCIDR string, delivery ...string) bool {
	pub, err := did.ParseURI(nodeDID)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil {
		return false
	}
	return did.VerifyWith(pub, NetworkCreateProofMessage(challenge, nodeDID, networkName, endpoint, meshCIDR, delivery...), sig)
}

func nodeProofFields(values []string) (delegateDID, callbackURL, responseEndpoint, responseToken, permissions string) {
	if len(values) >= 5 {
		return strings.TrimSpace(values[0]),
			strings.TrimSpace(values[1]),
			strings.TrimSpace(values[2]),
			strings.TrimSpace(values[3]),
			strings.TrimSpace(values[4])
	}
	if len(values) > 0 {
		callbackURL = strings.TrimSpace(values[0])
	}
	if len(values) > 1 {
		responseEndpoint = strings.TrimSpace(values[1])
	}
	if len(values) > 2 {
		responseToken = strings.TrimSpace(values[2])
	}
	if len(values) > 3 {
		permissions = strings.TrimSpace(values[3])
	}
	return "", callbackURL, responseEndpoint, responseToken, permissions
}

func networkCreateProofFields(values []string) (delegateDID, callbackURL, responseEndpoint, responseToken string) {
	if len(values) >= 4 {
		return strings.TrimSpace(values[0]),
			strings.TrimSpace(values[1]),
			strings.TrimSpace(values[2]),
			strings.TrimSpace(values[3])
	}
	if len(values) > 0 {
		callbackURL = strings.TrimSpace(values[0])
	}
	if len(values) > 1 {
		responseEndpoint = strings.TrimSpace(values[1])
	}
	if len(values) > 2 {
		responseToken = strings.TrimSpace(values[2])
	}
	return "", callbackURL, responseEndpoint, responseToken
}

func permissionsProofValue(permissions []string) string {
	if len(permissions) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(permissions))
	values := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		permission = strings.TrimSpace(permission)
		if permission == "" {
			continue
		}
		if _, ok := seen[permission]; ok {
			continue
		}
		seen[permission] = struct{}{}
		values = append(values, permission)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}
