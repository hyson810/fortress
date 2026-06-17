//go:build linux

package stealth

import (
	"fmt"
	"log"

	"golang.org/x/sys/unix"
)

// DropPrivileges drops the process privileges to the given UID and GID.
// This should be called after all privileged operations (e.g., raw socket
// creation) are complete. On Linux, this uses setgid/setuid syscalls.
// The caller should first complete any operations requiring elevated
// privileges (CAP_NET_RAW, etc.) before invoking this function.
func DropPrivileges(uid, gid int) error {
	if uid < 0 || gid < 0 {
		return fmt.Errorf("stealth: invalid uid=%d or gid=%d", uid, gid)
	}

	// Drop group first, then user.
	if err := unix.Setgid(gid); err != nil {
		return fmt.Errorf("stealth: setgid(%d): %w", gid, err)
	}
	if err := unix.Setuid(uid); err != nil {
		return fmt.Errorf("stealth: setuid(%d): %w", uid, err)
	}

	log.Printf("[stealth] privileges dropped to uid=%d gid=%d", uid, gid)
	return nil
}
