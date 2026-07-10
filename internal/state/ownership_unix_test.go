//go:build unix

package state

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestSaveNetworkStateChownsToDirOwner exercises the actual chown. It runs only
// as root (the exact privilege the daemon holds after the sudo TUN re-exec);
// non-root CI skips it. It creates a dir owned by nobody, saves state as root,
// and asserts the file was handed to the dir's owner.
func TestSaveNetworkStateChownsToDirOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown to another uid")
	}
	const wantUID, wantGID = 65534, 65534 // nobody/nogroup on most systems
	dir := t.TempDir()
	if err := os.Chown(dir, wantUID, wantGID); err != nil {
		t.Fatalf("chown dir: %v", err)
	}
	if err := SaveNetworkState(dir, &NetworkState{NetworkRecordID: "n1"}); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, networkFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if int(st.Uid) != wantUID || int(st.Gid) != wantGID {
		t.Fatalf("owner = %d:%d, want %d:%d", st.Uid, st.Gid, wantUID, wantGID)
	}
}
