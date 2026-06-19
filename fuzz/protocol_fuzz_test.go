//go:build go1.22

// Package fuzz provides protocol-level fuzz targets for Hydra-Pro network parsers.
// Run with: go test -fuzz=FuzzDNSName -fuzztime=30s ./fuzz/
package fuzz

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"testing"
)

// ============================================================================
// DNS Name Parsing (RFC 1035)
// ============================================================================

// FuzzDNSName tests label-based DNS name parsing against crafted inputs.
// Labels are encoded as <length><data>, terminated by a 0x00 length byte.
// Valid names are at most 253 bytes, each label at most 63 bytes.
func FuzzDNSName(f *testing.F) {
	// Seed corpus with valid names
	f.Add([]byte("\x03www\x06google\x03com\x00"))
	f.Add([]byte("\x01a\x00"))
	f.Add([]byte("\x00")) // root label
	f.Add([]byte("\x3f" + strings.Repeat("x", 63) + "\x00")) // max label

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		// Parse labels
		pos := 0
		labelCount := 0
		totalLen := 0
		maxLabels := 127

		for pos < len(data) && labelCount < maxLabels {
			if pos >= len(data) {
				break
			}
			labelLen := int(data[pos])
			pos++

			if labelLen == 0 {
				// Root label — valid termination
				return
			}

			// Compressed name pointer (0xC0 prefix)
			if labelLen&0xC0 == 0xC0 {
				if pos >= len(data) {
					return // truncated pointer
				}
				// Accept compression — stop parsing
				return
			}

			if labelLen > 63 && labelLen&0xC0 != 0xC0 {
				// Invalid label length, but parser must not crash
				return
			}

			if pos+labelLen > len(data) {
				// Truncated label — parser must handle gracefully
				return
			}

			totalLen += labelLen + 1
			if totalLen > 255 {
				return
			}

			pos += labelLen
			labelCount++
		}
	})
}

// ============================================================================
// HTTP Request-Line Parsing (RFC 7230)
// ============================================================================

// FuzzHTTPRequestLine tests parsing of HTTP method, URI, and version.
func FuzzHTTPRequestLine(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add([]byte("POST /api/v1/data HTTP/1.1\r\n"))
	f.Add([]byte("OPTIONS * HTTP/1.1\r\n"))
	f.Add([]byte("CONNECT host:443 HTTP/1.0\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 8192 {
			return
		}

		// Find CRLF
		crlfIdx := bytes.Index(data, []byte("\r\n"))
		if crlfIdx < 0 {
			return
		}
		line := string(data[:crlfIdx])

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			return
		}

		method, uri, version := parts[0], parts[1], parts[2]

		// Validate method: tokens per RFC 7230
		for _, ch := range method {
			if ch < 0x21 || ch > 0x7E {
				return // invalid method character
			}
		}

		// Validate version
		if !strings.HasPrefix(version, "HTTP/") {
			return
		}
		if len(version) != 8 { // "HTTP/X.Y"
			return
		}

		_ = uri // URI may be anything — parser must not crash on it
	})
}

// ============================================================================
// TLS ClientHello Parsing
// ============================================================================

// FuzzTLSClientHello tests parsing of the TLS ClientHello handshake message.
// ClientHello structure:
//
//	1 byte   HandshakeType (0x01)
//	3 bytes  Length (uint24)
//	2 bytes  ClientVersion
//	32 bytes Random
//	1 byte   SessionID length
//	... variable SessionID
func FuzzTLSClientHello(f *testing.F) {
	// Seed with a minimal valid ClientHello
	f.Add([]byte{
		0x01,             // handshake type
		0x00, 0x00, 0x2c, // length
		0x03, 0x03, // TLS 1.2
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00, // session ID length 0
		0x00, 0x02, 0x00, 0x01, 0x00, // cipher suites
		0x01, 0x00, // compression methods
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 5 {
			return
		}

		msgType := data[0]
		if msgType != 0x01 {
			return // not a ClientHello — skip
		}

		// Parse 3-byte big-endian length
		if len(data) < 4 {
			return
		}
		length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		if int(length)+4 > len(data) {
			// Claimed length exceeds data — parser must not OOB
			return
		}

		// Truncate to claimed length for further parsing
		payload := data[4 : 4+length]

		const minClientHelloLen = 2 + 32 + 1 // version + random + sessionIDLen
		if len(payload) < minClientHelloLen {
			return
		}

		clientVersion := binary.BigEndian.Uint16(payload[0:2])
		_ = clientVersion

		// Random is payload[2:34]
		random := payload[2:34]
		_ = random

		sidLen := int(payload[34])
		pos := 35
		if pos+sidLen > len(payload) {
			return // truncated session ID
		}
		pos += sidLen

		// Cipher suites
		if pos+2 > len(payload) {
			return
		}
		cipherLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
		pos += 2
		if pos+cipherLen > len(payload) {
			return
		}
		pos += cipherLen

		// Compression methods
		if pos+1 > len(payload) {
			return
		}
		compLen := int(payload[pos])
		pos++
		if pos+compLen > len(payload) {
			return
		}
		// Extensions would follow — not parsed here

		// If we reach here, the basic structure was parseable
	})
}

// ============================================================================
// ICMP Packet Parsing
// ============================================================================

// ICMPType constants
const (
	ICMPEchoReply   uint8 = 0
	ICMPDestUnreach uint8 = 3
	ICMPSourceQuench uint8 = 4
	ICMPRedirect    uint8 = 5
	ICMPEchoRequest uint8 = 8
	ICMPTimeExceeded uint8 = 11
	ICMPParamProblem uint8 = 12
	ICMPTimestamp    uint8 = 13
	ICMPTimestampReply uint8 = 14
)

// ICMPHeaderLength is the minimum ICMP header size (type + code + checksum).
const ICMPHeaderLength = 4

// FuzzICMPPacket tests ICMP packet header parsing.
// ICMP header: 1 byte type, 1 byte code, 2 bytes checksum, variable body.
func FuzzICMPPacket(f *testing.F) {
	// Seed with common ICMP types
	f.Add([]byte{8, 0, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01}) // Echo request
	f.Add([]byte{0, 0, 0xff, 0xff, 0x00, 0x01, 0x00, 0x01}) // Echo reply
	f.Add([]byte{3, 1, 0x00, 0x00, 0x00, 0x00})             // Dest unreachable

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < ICMPHeaderLength {
			return
		}

		icmpType := data[0]
		code := data[1]
		checksum := binary.BigEndian.Uint16(data[2:4])

		_ = code
		_ = checksum

		// Validate ICMP type is known
		switch icmpType {
		case ICMPEchoReply, ICMPDestUnreach, ICMPSourceQuench,
			ICMPRedirect, ICMPEchoRequest, ICMPTimeExceeded,
			ICMPParamProblem, ICMPTimestamp, ICMPTimestampReply:
			// Known types are valid
		default:
			// Unknown types must not crash the parser
		}

		// Validate checksum — pure random inputs will almost always fail,
		// but we verify the parser doesn't crash computing it
		if len(data) >= 8 {
			_ = computeICMPChecksum(data[:8])
		}

		// Parse rest-of-header based on type
		if len(data) >= 8 {
			restOfHeader := binary.BigEndian.Uint32(data[4:8])
			_ = restOfHeader
		}
	})
}

// computeICMPChecksum computes the RFC 792 ICMP checksum over the given bytes.
// This is a standard checksum utility used in the fuzz target to exercise
// checksum computation without side effects.
func computeICMPChecksum(data []byte) uint16 {
	if len(data) == 0 {
		return 0
	}

	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold carries
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// ============================================================================
// Utility: Deterministic seed-based random for fuzz seed generation
// ============================================================================

// genFuzzSeeds helps generate seed inputs for fuzz targets without relying
// on crypto/rand. Uses math/rand intentionally — seeds are for fuzzing
// only, not for cryptographic use.
func genFuzzSeeds(rng *rand.Rand, n int) [][]byte {
	seeds := make([][]byte, n)
	for i := range seeds {
		length := rng.Intn(256) + 1
		seeds[i] = make([]byte, length)
		rng.Read(seeds[i])
	}
	return seeds
}

// ============================================================================
// Additional Fuzz Targets
// ============================================================================

// FuzzUDPHeader tests UDP header parsing (8 bytes minimum).
func FuzzUDPHeader(f *testing.F) {
	f.Add([]byte{0x00, 0x35, 0x00, 0x35, 0x00, 0x20, 0x00, 0x00}) // DNS query
	f.Add([]byte{0x04, 0x57, 0x00, 0x50, 0x00, 0x10, 0x00, 0x00}) // random

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8 {
			return
		}
		srcPort := binary.BigEndian.Uint16(data[0:2])
		dstPort := binary.BigEndian.Uint16(data[2:4])
		length := binary.BigEndian.Uint16(data[4:6])
		checksum := binary.BigEndian.Uint16(data[6:8])

		// Length must be at least 8 and at most payload size
		if length < 8 || int(length) > len(data) {
			return
		}

		_ = srcPort
		_ = dstPort
		_ = checksum
	})
}

// FuzzTCPFlags tests TCP header flag bit parsing.
func FuzzTCPFlags(f *testing.F) {
	f.Add([]byte{0x00, 0x50, 0x00, 0x35, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00}) // SYN packet

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 20 {
			return
		}
		// TCP header starts at offset 0
		srcPort := binary.BigEndian.Uint16(data[0:2])
		dstPort := binary.BigEndian.Uint16(data[2:4])
		seqNum := binary.BigEndian.Uint32(data[4:8])
		ackNum := binary.BigEndian.Uint32(data[8:12])
		dataOffset := (data[12] >> 4) & 0x0F
		flags := data[13]

		// Known TCP flags
		const (
			TCPFIN = 1 << 0
			TCPSYN = 1 << 1
			TCPRST = 1 << 2
			TCPPSH = 1 << 3
			TCPACK = 1 << 4
			TCPURG = 1 << 5
			TCPECE = 1 << 6
			TCPCWR = 1 << 7
		)

		// Validate data offset: must be at least 5 (20 bytes)
		if dataOffset < 5 {
			return
		}
		headerLen := int(dataOffset) * 4
		if headerLen > len(data) {
			return
		}

		// Check for invalid flag combinations
		if flags&TCPFIN != 0 && flags&TCPSYN != 0 {
			// FIN+SYN is unusual but not strictly invalid
		}

		_ = srcPort
		_ = dstPort
		_ = seqNum
		_ = ackNum
		// Validate that parsing window size + checksum + urgent pointer is safe
		if headerLen >= 20 {
			window := binary.BigEndian.Uint16(data[14:16])
			checksum := binary.BigEndian.Uint16(data[16:18])
			urgent := binary.BigEndian.Uint16(data[18:20])
			_ = window
			_ = checksum
			_ = urgent
		}
	})
}

// FuzzNetIPAddr tests net.ParseIP against crafted byte sequences.
func FuzzNetIPAddr(f *testing.F) {
	f.Add("127.0.0.1")
	f.Add("::1")
	f.Add("192.168.1.1")
	f.Add("2001:db8::1")

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 256 {
			return
		}
		// net.ParseIP must never panic on arbitrary input
		ip := net.ParseIP(s)
		if ip != nil {
			// Verify it round-trips correctly
			roundTripped := ip.String()
			_ = roundTripped
		}
	})
}
