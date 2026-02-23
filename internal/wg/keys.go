// Package wg - keys.go handles WireGuard key generation and management.
//
// WireGuard uses Curve25519 keypairs:
//   - Private key: 32 random bytes, clamped per Curve25519 spec
//   - Public key: Curve25519 base point multiplication of private key
//
// Key storage:
//   - Private keys are stored locally only (never written to DWN)
//   - Public keys are written to the nodeInfo DWN record (encrypted)
//   - Key rotation generates a new keypair and updates the nodeInfo record
//
// Key expiry:
//   - Optional keyExpiry field in nodeInfo triggers rotation reminders
//   - Expired keys are flagged; the agent generates and publishes new keys
package wg
