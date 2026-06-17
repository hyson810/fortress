//go:build windows

package stealth

import "syscall"

// unixProcAttr is a no-op stub for Windows builds. Process detachment on
// Windows uses different mechanisms (CREATE_NEW_PROCESS_GROUP, etc.) that
// are not needed for the watchdog's testing / development path.
func unixProcAttr() syscall.SysProcAttr {
	return syscall.SysProcAttr{}
}
