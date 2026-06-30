package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/enboxorg/meshd/internal/vault"
)

const walletSessionFile = "session.vault.json"

type WalletSession struct {
	Version int `json:"version"`
	// OwnerDID is the wallet/member DID that issued the grants.
	OwnerDID string `json:"ownerDID,omitempty"`
	// ConnectedDID is the pre-beta name for OwnerDID. Keep writing and reading
	// it while wallet-connected profiles transition.
	ConnectedDID string `json:"connectedDid,omitempty"`
	// DelegateDID is the local control/session DID that receives wallet-issued
	// grants for this node. Older sessions may omit it and grant directly to
	// NodeDID instead.
	DelegateDID string `json:"delegateDid,omitempty"`
	// NodeDID is the local device DID used for mesh identity and node records.
	NodeDID                     string            `json:"nodeDid"`
	WalletOrigin                string            `json:"walletOrigin,omitempty"`
	ExpiresAt                   string            `json:"expiresAt,omitempty"`
	Grants                      []json.RawMessage `json:"grants,omitempty"`
	NodeMultiPartyProtocols     []string          `json:"nodeMultiPartyProtocols,omitempty"`
	DelegateDecryptionKeys      []json.RawMessage `json:"delegateDecryptionKeys,omitempty"`
	DelegateMultiPartyProtocols []string          `json:"delegateMultiPartyProtocols,omitempty"`
}

func (s *WalletSession) NormalizeOwnerDID() {
	if s == nil {
		return
	}
	if s.OwnerDID == "" {
		s.OwnerDID = s.ConnectedDID
	}
	if s.ConnectedDID == "" {
		s.ConnectedDID = s.OwnerDID
	}
}

func (s *WalletSession) EffectiveOwnerDID() string {
	if s == nil {
		return ""
	}
	if s.OwnerDID != "" {
		return s.OwnerDID
	}
	return s.ConnectedDID
}

func (s *WalletSession) EffectiveNodeMultiPartyProtocols() []string {
	if s == nil {
		return nil
	}
	if len(s.NodeMultiPartyProtocols) > 0 {
		return s.NodeMultiPartyProtocols
	}
	return s.DelegateMultiPartyProtocols
}

func StoreWalletSession(stateDir string, password string, session *WalletSession) error {
	if session == nil {
		return fmt.Errorf("wallet session is required")
	}
	if session.Version == 0 {
		session.Version = 1
	}
	session.NormalizeOwnerDID()
	if session.EffectiveOwnerDID() == "" {
		return fmt.Errorf("owner DID is required")
	}
	if session.NodeDID == "" {
		return fmt.Errorf("node DID is required")
	}
	if len(session.NodeMultiPartyProtocols) == 0 && len(session.DelegateMultiPartyProtocols) > 0 {
		session.NodeMultiPartyProtocols = append([]string(nil), session.DelegateMultiPartyProtocols...)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	plaintext, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal wallet session: %w", err)
	}
	sealed, err := vault.Seal(plaintext, password)
	if err != nil {
		return err
	}

	target := filepath.Join(stateDir, walletSessionFile)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0600); err != nil {
		return fmt.Errorf("write encrypted wallet session: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename encrypted wallet session: %w", err)
	}
	return nil
}

func LoadWalletSession(stateDir string, password string) (*WalletSession, error) {
	target := filepath.Join(stateDir, walletSessionFile)
	data, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read encrypted wallet session: %w", err)
	}
	plaintext, err := vault.Open(data, password)
	if err != nil {
		return nil, fmt.Errorf("open encrypted wallet session: %w", err)
	}
	var session WalletSession
	if err := json.Unmarshal(plaintext, &session); err != nil {
		return nil, fmt.Errorf("unmarshal wallet session: %w", err)
	}
	session.NormalizeOwnerDID()
	return &session, nil
}

func WalletSessionExists(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, walletSessionFile))
	return err == nil
}
