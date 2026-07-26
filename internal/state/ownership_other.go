//go:build !unix

package state

// AlignOwnerToDir is a no-op on platforms without POSIX file ownership
// (notably Windows, where os.Chown is unsupported and syscall.Stat_t exposes no
// Uid/Gid). State files simply inherit the writing process's ownership there.
func AlignOwnerToDir(dir, path string) {}
