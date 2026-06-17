//go:build !linux || !cgo
// +build !linux !cgo

package engine

import "fmt"

// InitFFI is a stub for non-Linux platforms.
func InitFFI(iface string) error {
	return fmt.Errorf("FFI bridge requires Linux")
}

// PollFFI is a stub for non-Linux platforms.
func PollFFI() int { return 0 }

// ReadFFI is a stub for non-Linux platforms.
func ReadFFI() (PacketContext, bool) {
	return PacketContext{}, false
}

// InjectFFI is a stub for non-Linux platforms.
func InjectFFI(srcIP, dstIP string, srcPort, dstPort uint16, protocol, tcpFlags string, payloadSize uint16) error {
	return fmt.Errorf("FFI bridge requires Linux")
}

// FortressStats is a stub for non-Linux platforms.
func FortressStats() (received, passed, dropped, rateLimited, writes, overflows uint64) {
	return 0, 0, 0, 0, 0, 0
}

// BlockIPFFI is a stub for non-Linux platforms.
func BlockIPFFI(ip uint32) error {
	return fmt.Errorf("FFI bridge requires Linux")
}

// CloseFFI is a stub for non-Linux platforms.
func CloseFFI() error { return nil }
