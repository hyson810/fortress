//go:build !linux

package stealth

// DropPrivileges is a no-op on non-Linux platforms.
func DropPrivileges(uid, gid int) error {
	return nil
}
