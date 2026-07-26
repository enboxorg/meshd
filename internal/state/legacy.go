package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckNoLegacyVault fails when a retired password-encrypted vault file sits
// where the named plaintext state file is read or written (identity.json →
// identity.vault.json). meshd removed encrypted vaults: the local OS account
// is the trust boundary and the network owner can revoke any device from the
// admin dashboard. Failing here — instead of treating the profile as
// uninitialized — prevents silently minting a fresh identity next to an
// orphaned network.json.
func CheckNoLegacyVault(stateDir, filename string) error {
	legacy := filepath.Join(stateDir, strings.TrimSuffix(filename, ".json")+".vault.json")
	if _, err := os.Stat(legacy); err == nil {
		return fmt.Errorf("encrypted vaults were removed; delete %s and re-join the network (the owner can re-approve this device)", legacy)
	}
	return nil
}
