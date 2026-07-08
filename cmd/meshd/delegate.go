package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/protocols"
)

// walletSessionHasDelegatedMeshGrants reports whether the wallet session is
// an enbox connect session: it holds delegated read and write grants for the
// mesh protocol, issued to the session grantee (the local delegate).
func walletSessionHasDelegatedMeshGrants(session *state.WalletSession, meta identityMetadata) bool {
	if session == nil {
		return false
	}
	granteeDID, _ := walletSessionGrantGranteeDID(session, meta)
	now := time.Now().UTC()
	for _, messageType := range []dwn.DwnInterface{dwn.InterfaceRecordsRead, dwn.InterfaceRecordsWrite} {
		grant, _, err := dwn.FindDelegatedGrant(session.Grants, dwn.PermissionGrantMatch{
			Grantor:     firstNonEmpty(session.EffectiveOwnerDID(), meta.OwnerDID),
			Grantee:     granteeDID,
			MessageType: messageType,
			Protocol:    protocols.MeshProtocolURI,
			Now:         now,
		})
		if err != nil || len(grant) == 0 {
			return false
		}
	}
	return true
}

// newDelegateSessionForCLI builds the full wallet delegate session for the
// active network: it resolves the session's delegated grants, fetches the
// installed protocol definition from the owner tenant, unwraps the delivered
// grant keys, and builds the sealed audience source.
func newDelegateSessionForCLI(ctx context.Context, stateDir string, meta identityMetadata, ns *state.NetworkState, delegateIdentity *did.DID, logger *slog.Logger) (*mesh.DelegateSession, error) {
	if ns == nil {
		return nil, fmt.Errorf("network state is required")
	}
	if delegateIdentity == nil {
		return nil, fmt.Errorf("delegate identity is required")
	}
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return nil, err
	}
	session, err := state.LoadWalletSession(stateDir, password)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("wallet session is missing; run 'meshd auth connect'")
	}
	ownerDID := firstNonEmpty(session.EffectiveOwnerDID(), meta.OwnerDID, ns.AnchorDID)
	if ns.AnchorDID != "" && ownerDID != ns.AnchorDID {
		return nil, fmt.Errorf("wallet session owner %s does not match network anchor %s", ownerDID, ns.AnchorDID)
	}
	return mesh.NewDelegateSession(ctx, mesh.DelegateSessionParams{
		Endpoint:           ns.AnchorEndpoint,
		OwnerDID:           ownerDID,
		DelegateSigner:     dwnSigner(delegateIdentity),
		DelegateX25519Priv: delegateIdentity.EncryptionPrivateKey,
		Grants:             session.Grants,
		Logger:             logger,
	})
}

// delegateSessionForCLIBestEffort resolves the delegate session for read-only
// CLI commands (peer list, doctor). Failures degrade to plain delegated-grant
// reads: queries still work, but role-audience records stay encrypted.
func delegateSessionForCLIBestEffort(ctx context.Context, stateDir string, meta identityMetadata, ns *state.NetworkState, delegateIdentity *did.DID, readAuth dwn.MessageAuth) *mesh.DelegateSession {
	if len(readAuth.DelegatedGrant) == 0 {
		return nil
	}
	sess, err := newDelegateSessionForCLI(ctx, stateDir, meta, ns, delegateIdentity, nil)
	if err != nil {
		fmt.Printf("  Warning: wallet delegate session unavailable: %v\n", err)
		return nil
	}
	return sess
}

// delegateNetworkState maps a delegate create/join result onto the persisted
// network state, mirroring the legacy wallet-response import: the wallet
// owner is both anchor and member, and the node keeps its device DID.
func delegateNetworkState(result *mesh.DelegateNetworkResult, ownerDID, endpoint, nodeDID, delegateDID string) *state.NetworkState {
	if result == nil {
		return nil
	}
	return &state.NetworkState{
		NetworkRecordID: result.NetworkRecordID,
		AnchorDID:       ownerDID,
		AnchorEndpoint:  endpoint,
		NetworkName:     result.NetworkName,
		MeshCIDR:        result.MeshCIDR,
		MeshIP:          result.MeshIP,
		NodeDID:         nodeDID,
		OwnerDID:        ownerDID,
		MemberDID:       ownerDID,
		DelegateDID:     delegateDID,
		NodeRecordID:    result.NodeRecordID,
		NodeDateCreated: result.NodeDateCreated,
	}
}

// delegateOwnerEndpoint resolves the owner tenant's DWN endpoint for delegate
// operations. did:jwk owners do not publish DWN endpoints in their DID
// documents, so the endpoint comes from the --endpoint flag, DWN_ENDPOINT, or
// the MESHD_WALLET_RESPONSE_ENDPOINT default chain rather than DID resolution.
func delegateOwnerEndpoint(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return walletResponseEndpoint("")
}

// createNetworkAsDelegateCLI creates a wallet-owned network directly through
// the profile's enbox connect delegate session. handled is false when the
// wallet session is not a delegated (enbox connect) session, so the caller
// falls back to the legacy wallet-page request flow.
func createNetworkAsDelegateCLI(ctx context.Context, stateDir string, identity *did.DID, meta identityMetadata, name, endpoint string, opts networkCreateOptions) (bool, error) {
	if !state.WalletSessionExists(stateDir) {
		return false, nil
	}
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return false, err
	}
	session, err := state.LoadWalletSession(stateDir, password)
	if err != nil {
		return false, err
	}
	if session == nil || !walletSessionHasDelegatedMeshGrants(session, meta) {
		return false, nil
	}
	if state.HasNetwork(stateDir) {
		return true, fmt.Errorf("already in a network. Use 'meshd network leave' first.")
	}

	endpoint = delegateOwnerEndpoint(endpoint)
	ownerDID := firstNonEmpty(session.EffectiveOwnerDID(), meta.OwnerDID)
	nodeDID := firstNonEmpty(meta.NodeDID, identity.URI)
	delegateIdentity, err := verifyWalletDelegateIdentity(stateDir, firstNonEmpty(session.DelegateDID, meta.DelegateDID))
	if err != nil {
		return true, err
	}
	if delegateIdentity == nil {
		return true, fmt.Errorf("wallet session has no delegate identity; run 'meshd auth connect' again")
	}

	fmt.Printf("Creating wallet-owned network %q on %s...\n", name, endpoint)
	sess, err := mesh.NewDelegateSession(ctx, mesh.DelegateSessionParams{
		Endpoint:           endpoint,
		OwnerDID:           ownerDID,
		DelegateSigner:     dwnSigner(delegateIdentity),
		DelegateX25519Priv: delegateIdentity.EncryptionPrivateKey,
		Grants:             session.Grants,
	})
	if err != nil {
		return true, fmt.Errorf("initializing wallet delegate session: %w", err)
	}
	hostname, _ := os.Hostname()
	result, err := mesh.CreateNetworkAsDelegate(ctx, mesh.CreateNetworkParams{
		Session:     sess,
		NetworkName: name,
		MeshCIDR:    opts.meshCIDR,
		NodeDID:     nodeDID,
		Hostname:    hostname,
	})
	if err != nil {
		return true, err
	}

	ns := delegateNetworkState(result, ownerDID, endpoint, nodeDID, delegateIdentity.URI)
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return true, fmt.Errorf("saving network state: %w", err)
	}

	fmt.Printf("Network created.\n")
	fmt.Printf("  Name: %s\n", result.NetworkName)
	fmt.Printf("  CIDR: %s\n", result.MeshCIDR)
	fmt.Printf("  Mesh IP: %s\n", result.MeshIP)
	fmt.Printf("  Wallet Owner DID: %s\n", ownerDID)
	fmt.Printf("  Delegate DID: %s\n", delegateIdentity.URI)
	fmt.Printf("  Node DID: %s\n", nodeDID)
	fmt.Printf("  Network Record: %s\n", result.NetworkRecordID)
	fmt.Printf("  Node Record: %s\n", result.NodeRecordID)
	fmt.Printf("  Anchor Endpoint: %s\n", endpoint)
	fmt.Printf("\nRun 'meshd up' to start the mesh.\n")
	return true, nil
}

// setupDelegateJoin joins a wallet-owned network directly through the
// profile's enbox connect delegate session: the delegated write grant
// registers this device's node record immediately, with no dashboard
// approval round-trip. handled is false when the profile does not carry a
// delegated wallet session (or a different owner was requested), letting
// legacy flows keep their existing paths.
func setupDelegateJoin(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string) (*state.NetworkState, bool, error) {
	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	if meta.AuthType != profile.AuthTypeWalletAuthorizedNode {
		return nil, false, nil
	}
	if !state.WalletSessionExists(stateDir) {
		return nil, false, nil
	}
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return nil, false, err
	}
	session, err := state.LoadWalletSession(stateDir, password)
	if err != nil {
		return nil, false, err
	}
	if session == nil || !walletSessionHasDelegatedMeshGrants(session, meta) {
		return nil, false, nil
	}
	ownerDID := firstNonEmpty(session.EffectiveOwnerDID(), meta.OwnerDID)
	if f.ownerDID != "" && f.ownerDID != ownerDID {
		// A different owner was requested; use the legacy approval flow.
		return nil, false, nil
	}

	endpoint := delegateOwnerEndpoint(f.endpoint)
	nodeDID := firstNonEmpty(meta.NodeDID, identity.URI)
	delegateIdentity, err := verifyWalletDelegateIdentity(stateDir, firstNonEmpty(session.DelegateDID, meta.DelegateDID))
	if err != nil {
		return nil, true, err
	}
	if delegateIdentity == nil {
		return nil, true, fmt.Errorf("wallet session has no delegate identity; run 'meshd auth connect' again")
	}

	fmt.Printf("Joining %s's network on %s...\n", ownerDID, endpoint)
	sess, err := mesh.NewDelegateSession(ctx, mesh.DelegateSessionParams{
		Endpoint:           endpoint,
		OwnerDID:           ownerDID,
		DelegateSigner:     dwnSigner(delegateIdentity),
		DelegateX25519Priv: delegateIdentity.EncryptionPrivateKey,
		Grants:             session.Grants,
	})
	if err != nil {
		return nil, true, fmt.Errorf("initializing wallet delegate session: %w", err)
	}
	hostname, _ := os.Hostname()
	result, err := mesh.JoinNetworkAsDelegate(ctx, mesh.JoinNetworkParams{
		Session:         sess,
		NetworkRecordID: f.networkID,
		NodeDID:         nodeDID,
		Hostname:        hostname,
	})
	if err != nil {
		return nil, true, err
	}

	ns := delegateNetworkState(result, ownerDID, endpoint, nodeDID, delegateIdentity.URI)
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return nil, true, fmt.Errorf("saving network state: %w", err)
	}

	fmt.Printf("Joined network %q.\n", result.NetworkName)
	fmt.Printf("  CIDR: %s\n", result.MeshCIDR)
	fmt.Printf("  Mesh IP: %s\n", result.MeshIP)
	fmt.Printf("  Node Record: %s\n", result.NodeRecordID)
	return ns, true, nil
}
