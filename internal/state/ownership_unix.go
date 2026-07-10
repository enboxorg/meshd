//go:build unix

package state

import (
	"os"
	"syscall"
)

// alignOwnerToDir best-effort chowns path to the owner of dir so that a state
// file written by the root daemon (after the sudo TUN re-exec) stays readable
// by the non-root user who owns the profile directory. The decision is made by
// fileOwnerForDir.
//
// It uses Lchown (not Chown) so it never follows a symlink: in a deployment
// where the state directory is writable by an unprivileged user, that user
// could otherwise unlink the root-written tmp file and plant a symlink between
// the write and the chown, tricking root into chowning an attacker-chosen path
// (a race-based local privilege escalation). Lchown on the regular tmp file we
// just wrote behaves identically to Chown, and matches restoreSudoUserOwnership
// in cmd/meshd. Any chown error is intentionally ignored: failing to realign
// ownership must never block state persistence.
func alignOwnerToDir(dir, path string) {
	info, err := os.Stat(dir)
	if err != nil {
		return
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	uid, gid, chown := fileOwnerForDir(os.Geteuid(), int(st.Uid), int(st.Gid), true)
	if !chown {
		return
	}
	_ = os.Lchown(path, uid, gid)
}
