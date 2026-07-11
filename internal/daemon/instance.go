package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

const instanceIDHeader = "X-Meshd-Instance-ID"

// ErrInstanceMismatch indicates that a request reached a different daemon
// instance than the caller intended to control.
var ErrInstanceMismatch = errors.New("daemon instance does not match")

// NewInstanceID returns a random identifier suitable for matching a launched
// daemon child with status and shutdown requests.
func NewInstanceID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate daemon instance ID: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}
