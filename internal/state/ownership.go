package state

// fileOwnerForDir decides whether a freshly written state file should be
// chowned to the uid/gid that owns its state directory, and to which ids.
//
// Background: when `meshd up` re-execs under sudo to open the TUN device, the
// root daemon persists network.json as root:root 0600. A later non-root
// `meshd status` / `meshd peer list` then fails to read it with EACCES.
// Aligning each freshly written state file to the directory owner keeps it
// readable by the invoking user for the whole lifetime of a running daemon,
// survives crashes (no deferred cleanup), and needs no SUDO_UID plumbing.
//
// Rules, in order:
//   - dirStatOK false (owner unknown / unsupported platform): do nothing.
//   - procEUID != 0: only root may hand a file to another uid, so a non-root
//     process never chowns.
//   - dirUID == 0: the directory is root-owned (e.g. a system service under
//     /var/lib, or a direct `sudo meshd up` fresh install where the profile
//     directory is created by root). A root-owned file is then expected; leave
//     it. The exit-time restoreSudoUserOwnership safety net in cmd/meshd covers
//     the direct-sudo fresh-install case for those who need the CLI afterwards.
//   - otherwise: chown the file to the directory's uid/gid.
func fileOwnerForDir(procEUID, dirUID, dirGID int, dirStatOK bool) (uid, gid int, chown bool) {
	if !dirStatOK {
		return 0, 0, false
	}
	if procEUID != 0 {
		return 0, 0, false
	}
	if dirUID == 0 {
		return 0, 0, false
	}
	return dirUID, dirGID, true
}
