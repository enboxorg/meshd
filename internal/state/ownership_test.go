package state

import "testing"

func TestFileOwnerForDir(t *testing.T) {
	cases := []struct {
		name                     string
		procEUID, dirUID, dirGID int
		statOK                   bool
		wantUID, wantGID         int
		wantChown                bool
	}{
		{"root process, user-owned dir", 0, 1000, 1000, true, 1000, 1000, true},
		{"root process, distinct uid and gid", 0, 1000, 2000, true, 1000, 2000, true},
		{"root process, root-owned dir", 0, 0, 0, true, 0, 0, false},
		{"non-root process, user-owned dir", 1000, 1000, 1000, true, 0, 0, false},
		{"non-root process, root-owned dir", 1000, 0, 0, true, 0, 0, false},
		{"stat failed", 0, 1000, 1000, false, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid, chown := fileOwnerForDir(tc.procEUID, tc.dirUID, tc.dirGID, tc.statOK)
			if uid != tc.wantUID || gid != tc.wantGID || chown != tc.wantChown {
				t.Fatalf("fileOwnerForDir(%d,%d,%d,%v)=(%d,%d,%v) want (%d,%d,%v)",
					tc.procEUID, tc.dirUID, tc.dirGID, tc.statOK, uid, gid, chown, tc.wantUID, tc.wantGID, tc.wantChown)
			}
		})
	}
}

// TestSaveNetworkStatePreservesOwnerWhenNotRoot guards the common path: a normal
// user must still be able to save and re-read state, and the ownership
// realignment must be a no-op that never errors.
func TestSaveNetworkStatePreservesOwnerWhenNotRoot(t *testing.T) {
	dir := t.TempDir()
	if err := SaveNetworkState(dir, &NetworkState{NetworkRecordID: "n1"}); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}
	if _, err := LoadNetworkState(dir); err != nil {
		t.Fatalf("LoadNetworkState: %v", err)
	}
}
