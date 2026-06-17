//go:build !windows

package stealth

import "syscall"

// unixProcAttr returns a SysProcAttr that detaches the child process from
// the parent's terminal session via Setpgid and Setsid, preventing signal
// propagation.
func unixProcAttr() syscall.SysProcAttr {
	return syscall.SysProcAttr{
		Setpgid: true,
		Setsid:  true,
	}
}
