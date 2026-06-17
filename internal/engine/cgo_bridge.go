//go:build linux && cgo
// +build linux,cgo

package engine

/*
#cgo LDFLAGS: -L${SRCDIR}/../../muscle/target/release -lfortress_ffi -ldl -lpthread -lm
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	int64_t  timestamp;
	uint8_t  src_ip[16];
	uint8_t  dst_ip[16];
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  protocol[8];
	uint8_t  tcp_flags[8];
	uint16_t payload_size;
	uint64_t payload_hash;
	uint8_t  direction[8];
	uint8_t  _pad[6];
} ffi_packet_t;

typedef struct {
	uint64_t packets_received;
	uint64_t packets_passed;
	uint64_t packets_dropped;
	uint64_t packets_rate_limited;
	uint64_t ringbuf_writes;
	uint64_t ringbuf_overflows;
} ffi_stats_t;

extern int fortress_init(const char* iface);
extern int fortress_poll();
extern int fortress_read(uint8_t* buf, int max);
extern int fortress_inject_packet(const char* src_ip, const char* dst_ip, uint16_t src_port, uint16_t dst_port, const char* protocol, const char* tcp_flags, uint16_t payload_size);
extern ffi_stats_t fortress_stats();
extern int fortress_block_ip(uint32_t ip);
extern int fortress_close();
*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"
)

var ffiInitialized bool

// InitFFI loads the Rust muscle library and initializes the engine.
func InitFFI(iface string) error {
	if ffiInitialized {
		return fmt.Errorf("FFI already initialized")
	}
	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(cIface))

	ret := C.fortress_init(cIface)
	if ret != 0 {
		return fmt.Errorf("fortress_init failed with code %d", ret)
	}
	ffiInitialized = true
	return nil
}

// PollFFI checks the Rust ring buffer for available packets.
func PollFFI() int {
	return int(C.fortress_poll())
}

// ReadFFI reads one PacketContext from the Rust ring buffer.
// Returns the converted Go PacketContext and true on success.
func ReadFFI() (PacketContext, bool) {
	var raw C.ffi_packet_t
	n := C.fortress_read((*C.uint8_t)(unsafe.Pointer(&raw)), C.int(unsafe.Sizeof(raw)))
	if n != C.int(unsafe.Sizeof(raw)) {
		return PacketContext{}, false
	}

	pkt := PacketContext{
		Timestamp:   time.Unix(0, int64(raw.timestamp)),
		SrcIP:       ipBytesToString(&raw.src_ip[0]),
		DstIP:       ipBytesToString(&raw.dst_ip[0]),
		SrcPort:     uint16(raw.src_port),
		DstPort:     uint16(raw.dst_port),
		Protocol:    c8ToString(&raw.protocol[0]),
		TCPFlags:    c8ToString(&raw.tcp_flags[0]),
		PayloadSize: uint16(raw.payload_size),
	}
	return pkt, true
}

// InjectFFI pushes a test packet into the Rust ring buffer.
func InjectFFI(srcIP, dstIP string, srcPort, dstPort uint16, protocol, tcpFlags string, payloadSize uint16) error {
	cSrc := C.CString(srcIP)
	cDst := C.CString(dstIP)
	cProto := C.CString(protocol)
	cFlags := C.CString(tcpFlags)
	defer C.free(unsafe.Pointer(cSrc))
	defer C.free(unsafe.Pointer(cDst))
	defer C.free(unsafe.Pointer(cProto))
	defer C.free(unsafe.Pointer(cFlags))

	ret := C.fortress_inject_packet(cSrc, cDst, C.uint16_t(srcPort), C.uint16_t(dstPort), cProto, cFlags, C.uint16_t(payloadSize))
	if ret != 0 {
		return fmt.Errorf("fortress_inject_packet failed with code %d", ret)
	}
	return nil
}

// FortressStats returns the Rust engine statistics.
func FortressStats() (received, passed, dropped, rateLimited, writes, overflows uint64) {
	stats := C.fortress_stats()
	return uint64(stats.packets_received), uint64(stats.packets_passed),
		uint64(stats.packets_dropped), uint64(stats.packets_rate_limited),
		uint64(stats.ringbuf_writes), uint64(stats.ringbuf_overflows)
}

// BlockIPFFI blocks an IPv4 address at the XDP level.
func BlockIPFFI(ip uint32) error {
	ret := C.fortress_block_ip(C.uint32_t(ip))
	if ret != 0 {
		return fmt.Errorf("fortress_block_ip failed with code %d", ret)
	}
	return nil
}

// CloseFFI shuts down the Rust engine.
func CloseFFI() error {
	if !ffiInitialized {
		return nil
	}
	C.fortress_close()
	ffiInitialized = false
	return nil
}

// ipBytesToString converts a 16-byte IP array to dotted-quad or
// colon-hex string. IPv4 addresses are stored in the last 4 bytes.
func ipBytesToString(p *C.uint8_t) string {
	b := unsafe.Slice((*uint8)(unsafe.Pointer(p)), 16)
	// Check for IPv4-mapped or native IPv4 (last 4 bytes non-zero, first 12 zero)
	isV4 := true
	for i := 0; i < 12; i++ {
		if b[i] != 0 {
			isV4 = false
			break
		}
	}
	if isV4 {
		return fmt.Sprintf("%d.%d.%d.%d", b[12], b[13], b[14], b[15])
	}
	// IPv6: 8 groups of 2 bytes
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// c8ToString converts a null-terminated 8-byte C string to a Go string.
func c8ToString(p *C.uint8_t) string {
	b := unsafe.Slice((*uint8)(unsafe.Pointer(p)), 8)
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}
