// Package vaultkey stores vault unlock keys in the operating system keyring.
package vaultkey

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const (
	// ServiceName is the stable service identifier used for meshd vault keys.
	ServiceName   = "org.enbox.meshd.vault"
	accountPrefix = "state-"
)

// ErrNotFound reports that no vault key exists for a state directory.
var ErrNotFound = errors.New("vault key not found")

// Backend is the subset of a system keyring needed by Store.
type Backend interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}

// Store maps meshd state directories to entries in a keyring backend.
type Store struct {
	backend Backend
}

var defaultStore = New(systemBackend{})

// New creates a Store backed by backend. Backend must not be nil.
func New(backend Backend) *Store {
	if backend == nil {
		panic("vaultkey: nil backend")
	}
	return &Store{backend: backend}
}

// Get returns the vault key stored for stateDir in the system keyring.
func Get(stateDir string) (string, error) {
	return defaultStore.Get(stateDir)
}

// Set stores the vault key for stateDir in the system keyring.
func Set(stateDir, key string) error {
	return defaultStore.Set(stateDir, key)
}

// Delete removes the vault key for stateDir from the system keyring.
func Delete(stateDir string) error {
	return defaultStore.Delete(stateDir)
}

// Get returns the vault key stored for stateDir.
func (s *Store) Get(stateDir string) (string, error) {
	account, err := accountForStateDir(stateDir)
	if err != nil {
		return "", err
	}

	secret, err := s.backend.Get(ServiceName, account)
	if err != nil {
		if isNotFound(err) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("get vault key: %w", err)
	}
	return secret, nil
}

// Set stores the vault key for stateDir.
func (s *Store) Set(stateDir, key string) error {
	account, err := accountForStateDir(stateDir)
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("vault key is required")
	}

	if err := s.backend.Set(ServiceName, account, key); err != nil {
		return fmt.Errorf("set vault key: %w", err)
	}
	return nil
}

// Delete removes the vault key for stateDir.
func (s *Store) Delete(stateDir string) error {
	account, err := accountForStateDir(stateDir)
	if err != nil {
		return err
	}

	if err := s.backend.Delete(ServiceName, account); err != nil {
		if isNotFound(err) {
			return ErrNotFound
		}
		return fmt.Errorf("delete vault key: %w", err)
	}
	return nil
}

func accountForStateDir(stateDir string) (string, error) {
	if stateDir == "" {
		return "", fmt.Errorf("state directory is required")
	}

	normalized, err := filepath.Abs(stateDir)
	if err != nil {
		return "", fmt.Errorf("resolve state directory: %w", err)
	}
	normalized = filepath.Clean(normalized)

	digest := sha256.Sum256([]byte(normalized))
	return accountPrefix + hex.EncodeToString(digest[:]), nil
}

func isNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, keyring.ErrNotFound)
}

type systemBackend struct{}

func (systemBackend) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (systemBackend) Set(service, account, secret string) error {
	return keyring.Set(service, account, secret)
}

func (systemBackend) Delete(service, account string) error {
	return keyring.Delete(service, account)
}
