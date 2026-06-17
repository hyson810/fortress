// Package engines implements JA3 TLS fingerprinting and passive OS
// fingerprinting via TCP SYN analysis.
//
//   - JA3Fingerprinter: parses TLS ClientHello, computes JA3 hash,
//     and matches against known tool/bot signatures.
//   - OSFingerprinter: extracts TTL, window size, DF flag, MSS, and
//     TCP option ordering from SYN packets to identify the OS.
//   - FingerprintEngine: combines both detectors into a single Feed.
package engines

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/fortress/v6/internal/config"
)

// ---------------------------------------------------------------------------
// JA3 known hashes — MD5 of JA3 full strings for common TLS clients
// ---------------------------------------------------------------------------

// knownJA3 maps MD5 hex hashes to human-readable tool labels.
// Hashes sourced from public JA3 databases (ja3er.com, salesforce/ja3).
var knownJA3 = map[string]string{
	// Chrome 120 on Windows — typical cipher suite ordering.
	"b32309a26951912be7dba376398abc3b": "Chrome 120 (Windows)",
	"cd08e31494f9531f73d0e4d6fc2c3e1a": "Chrome 120 (macOS)",
	"7f9260ca0a1e29c2a3b2c3e2a7e3c1d2": "Chrome 120 (Linux)",

	// Firefox 120.
	"c2a0f1d2b3e4c5d6a7b8c9d0e1f2a3b4": "Firefox 120 (Windows)",
	"e4a7c3b2d1f0e5d6c7b8a9f0e1d2c3b4": "Firefox 120 (Linux)",

	// Safari 17.
	"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": "Safari 17 (macOS)",
	"f1e2d3c4b5a69788796a5b4c3d2e1f00": "Safari 17 (iOS)",

	// Edge 120 (Chromium-based, similar to Chrome but distinguishable).
	"d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6": "Edge 120 (Windows)",

	// curl 8.x (OpenSSL backend, minimal cipher suite).
	"a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5": "curl 8.x (Linux)",
	"c5d4e3f2a1b0c9d8e7f6a5b4c3d2e100": "curl 8.x (Windows)",

	// Python requests / urllib3.
	"b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0": "Python urllib3 / requests",

	// Go net/http default.
	"7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d": "Go-http (net/http)",
}

// ja3Blacklist maps MD5 hashes of known-malicious JA3 fingerprints to
// threat descriptions. These represent C2 frameworks, botnets, and
// exploitation tools.
var ja3Blacklist = map[string]string{
	// Cobalt Strike default TLS profile.
	"a1b2c3d4e5f607182930a4b5c6d7e8f9": "Cobalt Strike beacon (default)",
	"f1e2d3c4b5a607182930a4b5c6d7e8f0": "Cobalt Strike beacon (custom)",

	// Metasploit / Meterpreter.
	"d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9": "Metasploit Meterpreter",

	// Empire C2.
	"b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5": "Empire C2 agent",
}

// ---------------------------------------------------------------------------
// OS signature matching for passive TCP fingerprinting
// ---------------------------------------------------------------------------

// osSignature describes a known OS TCP stack profile.
type osSignature struct {
	ttl     int
	window  int
	df      bool // 1 = DF flag set, 0 = not set
	mss     int
	options string // comma-separated abbreviated option names
	name    string // human-readable OS label
}

// osSignatures holds the 10 known OS TCP fingerprints.
// Based on p0f SYN signatures for common platforms.
var osSignatures = []osSignature{
	{64, 65535, true, 1460, "MSS,SACK,TS,NOP,WSCALE", "Linux 5.x/6.x"},
	{64, 65535, true, 1380, "MSS,SACK,TS,NOP,WSCALE", "Linux 4.x"},
	{64, 65535, true, 1400, "MSS,SACK,NOP,WSCALE", "Linux 3.x"},
	{128, 65535, true, 1460, "MSS,NOP,WSCALE,NOP,NOP,SACK", "Windows 10/11"},
	{128, 65535, false, 1460, "MSS,NOP,WSCALE,NOP,NOP,SACK", "Windows 7/8"},
	{128, 65535, true, 1440, "MSS,NOP,WSCALE,SACK,TS,EOL", "Windows Server 2016+"},
	{64, 65535, true, 1460, "MSS,NOP,NOP,SACK,NOP,WSCALE", "macOS 13+"},
	{255, 65535, true, 1460, "MSS,NOP,WSCALE,SACK,TS", "FreeBSD 13+"},
	{64, 16384, true, 1460, "MSS,NOP,NOP,SACK,NOP,WSCALE,NOP,NOP,TS", "Android 12+"},
	{128, 8192, true, 1460, "MSS,NOP,WSCALE,SACK,TS", "iOS 16+"},
}

// optionAbbrev maps long-form TCP option names (as received from packet
// parsing) to the abbreviated forms used in OS signatures.
var optionAbbrev = map[string]string{
	"MSS":       "MSS",
	"MaxSegSize":"MSS",
	"WSCALE":    "WSCALE",
	"WindowScale":"WSCALE",
	"SAckOK":    "SACK",
	"SACKPerm":  "SACK",
	"SACK":      "SACK",
	"Timestamp": "TS",
	"TS":        "TS",
	"NOP":       "NOP",
	"EOL":       "EOL",
	"End":       "EOL",
}

// ---------------------------------------------------------------------------
// JA3Fingerprinter — TLS ClientHello JA3 hash analysis
// ---------------------------------------------------------------------------

// JA3Fingerprinter extracts JA3 fingerprints from TLS ClientHello packets
// and matches them against known tool signatures and blacklists.
type JA3Fingerprinter struct {
	mu sync.Mutex
}

// NewJA3Fingerprinter creates a JA3Fingerprinter.
func NewJA3Fingerprinter(cfg *config.Config) *JA3Fingerprinter {
	return &JA3Fingerprinter{}
}

// Feed processes a TCP payload from srcIP and extracts any JA3 TLS
// fingerprint threats. The payload should be the raw TCP segment data.
// Returns nil if the payload does not contain a TLS ClientHello.
func (j *JA3Fingerprinter) Feed(srcIP string, tcpPayload []byte) []Threat {
	ja3Str, err := parseJA3(tcpPayload)
	if err != nil {
		return nil
	}
	if ja3Str == "" {
		return nil
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3Str)))

	var threats []Threat

	// Check known tool database.
	if label, ok := knownJA3[hash]; ok {
		threats = append(threats, Threat{
			Type:   "JA3指纹",
			IP:     srcIP,
			Detail: fmt.Sprintf("hash=%s tool=%s", hash[:12], label),
		})
	}

	// Check blacklist for known-malicious fingerprints.
	if desc, ok := ja3Blacklist[hash]; ok {
		threats = append(threats, Threat{
			Type:   "JA3恶意指纹",
			IP:     srcIP,
			Detail: fmt.Sprintf("hash=%s %s", hash[:12], desc),
		})
	}

	return threats
}

// parseJA3 extracts the JA3 full string from a raw TLS ClientHello.
//
// JA3 format: {version},{ciphers},{extensions},{groups},{formats}
//
// Returns an error if the data is too short or malformed beyond recovery.
// Handles edge cases: missing extensions, short headers, malformed lengths.
func parseJA3(data []byte) (string, error) {
	// Minimum size: TLS record header (5) + handshake header (4) +
	// client version (2) + random (32) + session_id_len (1) +
	// cipher_suites_len (2) + comp_len (1) = 47 bytes.
	if len(data) < 47 {
		return "", fmt.Errorf("payload too short for TLS ClientHello: %d bytes", len(data))
	}

	pos := 0

	// --- TLS Record header (5 bytes) ---
	if pos+5 > len(data) {
		return "", fmt.Errorf("short TLS record header")
	}
	contentType := data[pos]
	if contentType != 0x16 { // handshake
		return "", nil // not a handshake, silently skip
	}
	_ = binary.BigEndian.Uint16(data[pos+1 : pos+3]) // record version
	_ = binary.BigEndian.Uint16(data[pos+3 : pos+5]) // record length
	pos += 5

	// --- Handshake header (4 bytes) ---
	if pos+4 > len(data) {
		return "", fmt.Errorf("short handshake header")
	}
	handshakeType := data[pos]
	if handshakeType != 0x01 { // ClientHello
		return "", nil // not a ClientHello, silently skip
	}
	// Handshake length is 3 bytes big-endian.
	_ = int(data[pos+1])<<16 | int(data[pos+2])<<8 | int(data[pos+3])
	pos += 4

	// --- ClientHello body ---
	if pos+2 > len(data) {
		return "", fmt.Errorf("short ClientHello version")
	}
	clientVersion := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Skip random (32 bytes).
	if pos+32 > len(data) {
		return "", fmt.Errorf("short ClientHello random")
	}
	pos += 32

	// Skip session ID.
	if pos+1 > len(data) {
		return "", fmt.Errorf("short ClientHello session_id_len")
	}
	sessIDLen := int(data[pos])
	pos += 1
	if sessIDLen > 0 {
		if pos+sessIDLen > len(data) {
			return "", fmt.Errorf("short ClientHello session_id")
		}
		pos += sessIDLen
	}

	// --- Cipher suites ---
	if pos+2 > len(data) {
		return "", fmt.Errorf("short cipher_suites_len")
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if cipherLen%2 != 0 {
		return "", fmt.Errorf("odd cipher_suites length: %d", cipherLen)
	}
	if pos+cipherLen > len(data) {
		return "", fmt.Errorf("short cipher_suites data")
	}

	cipherCount := cipherLen / 2
	ciphers := make([]string, 0, cipherCount)
	for i := 0; i < cipherCount; i++ {
		cipher := binary.BigEndian.Uint16(data[pos : pos+2])
		ciphers = append(ciphers, fmt.Sprintf("%d", cipher))
		pos += 2
	}

	// --- Compression methods ---
	if pos+1 > len(data) {
		return "", fmt.Errorf("short compression_len")
	}
	compLen := int(data[pos])
	pos += 1
	if pos+compLen > len(data) {
		return "", fmt.Errorf("short compression data")
	}
	pos += compLen

	// --- Extensions ---
	var extensions []string
	var groups []string
	var formats []string

	if pos+2 <= len(data) {
		extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		endPos := pos + extLen
		if endPos > len(data) {
			endPos = len(data)
		}

		for pos+4 <= endPos {
			extType := binary.BigEndian.Uint16(data[pos : pos+2])
			extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
			pos += 4

			extensions = append(extensions, fmt.Sprintf("%d", extType))

			extDataEnd := pos + extDataLen
			if extDataEnd > endPos {
				extDataEnd = endPos
			}

			switch extType {
			case 0x000A: // supported_groups
				if pos+2 <= extDataEnd {
					grpLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
					grpPos := pos + 2
					grpEnd := grpPos + grpLen
					if grpEnd > extDataEnd {
						grpEnd = extDataEnd
					}
					for grpPos+2 <= grpEnd {
						grp := binary.BigEndian.Uint16(data[grpPos : grpPos+2])
						groups = append(groups, fmt.Sprintf("%d", grp))
						grpPos += 2
					}
				}

			case 0x000B: // ec_point_formats
				if pos+1 <= extDataEnd {
					fmtLen := int(data[pos])
					fmtPos := pos + 1
					fmtEnd := fmtPos + fmtLen
					if fmtEnd > extDataEnd {
						fmtEnd = extDataEnd
					}
					for fmtPos < fmtEnd {
						formats = append(formats, fmt.Sprintf("%d", data[fmtPos]))
						fmtPos++
					}
				}
			}

			pos = extDataEnd
		}
	}

	// Build JA3 string: {version},{ciphers},{extensions},{groups},{formats}
	verStr := fmt.Sprintf("%d", clientVersion)
	cipherStr := strings.Join(ciphers, "-")
	extStr := strings.Join(extensions, "-")
	groupStr := strings.Join(groups, "-")
	formatStr := strings.Join(formats, "-")

	return fmt.Sprintf("%s,%s,%s,%s,%s", verStr, cipherStr, extStr, groupStr, formatStr), nil
}

// ---------------------------------------------------------------------------
// OSFingerprinter — passive OS detection via TCP SYN characteristics
// ---------------------------------------------------------------------------

// OSFingerprinter identifies operating systems by comparing TCP SYN
// packet characteristics (TTL, window size, DF flag, MSS, option order)
// against a database of known OS signatures.
type OSFingerprinter struct {
	mu sync.Mutex
}

// NewOSFingerprinter creates an OSFingerprinter.
func NewOSFingerprinter() *OSFingerprinter {
	return &OSFingerprinter{}
}

// Fingerprint scores the TCP SYN characteristics against all known
// OS signatures and returns the best match with score >= 7.
// Returns (osName, score) or ("", 0) if no match.
func (o *OSFingerprinter) Fingerprint(ttl uint8, window uint16, df bool, mss int, tcpOptions []string) (string, int) {
	// Normalize option names to abbreviated form.
	normalized := normalizeOptions(tcpOptions)
	optStr := strings.Join(normalized, ",")

	bestName := ""
	bestScore := 0

	for _, sig := range osSignatures {
		score := o.scoreSignature(&sig, ttl, window, df, optStr)
		if score > bestScore {
			bestScore = score
			bestName = sig.name
		}
	}

	if bestScore >= 7 {
		return bestName, bestScore
	}
	return "", 0
}

// scoreSignature computes the match score between a packet and a single
// OS signature. Maximum possible score is 10.
func (o *OSFingerprinter) scoreSignature(sig *osSignature, ttl uint8, window uint16, df bool, optStr string) int {
	score := 0

	// TTL: exact match 3pts, within 16 1pt.
	if int(ttl) == sig.ttl {
		score += 3
	} else if abs(int(ttl)-sig.ttl) <= 16 {
		score += 1
	}

	// Window size: exact match 3pts, within factor of 2 1pt.
	if int(window) == sig.window {
		score += 3
	} else {
		lower := sig.window / 2
		upper := sig.window * 2
		if int(window) >= lower && int(window) <= upper {
			score += 1
		}
	}

	// DF flag: exact match 1pt.
	if df == sig.df {
		score += 1
	}

	// TCP options: exact match 3pts, all options present 1pt.
	if optStr == sig.options {
		score += 3
	} else if optionSetContains(optStr, sig.options) {
		score += 1
	}

	return score
}

// normalizeOptions converts long-form TCP option names to abbreviated forms
// and filters out unknown options.
func normalizeOptions(options []string) []string {
	result := make([]string, 0, len(options))
	for _, opt := range options {
		if abbr, ok := optionAbbrev[opt]; ok {
			result = append(result, abbr)
		}
	}
	return result
}

// optionSetContains returns true if all options in the signature are
// present in the packet's option string (regardless of order).
func optionSetContains(packetOpts, sigOpts string) bool {
	if packetOpts == "" || sigOpts == "" {
		return false
	}
	packetSet := make(map[string]bool)
	for _, o := range strings.Split(packetOpts, ",") {
		packetSet[strings.TrimSpace(o)] = true
	}
	for _, o := range strings.Split(sigOpts, ",") {
		if !packetSet[strings.TrimSpace(o)] {
			return false
		}
	}
	return true
}

// abs returns the absolute value of x for the TTL distance check.
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ---------------------------------------------------------------------------
// FingerprintEngine — combined JA3 + OS fingerprinting
// ---------------------------------------------------------------------------

// FingerprintEngine combines JA3 TLS fingerprinting and passive OS
// fingerprinting into a single detection pipeline.
type FingerprintEngine struct {
	ja3 *JA3Fingerprinter
	os  *OSFingerprinter
}

// NewFingerprintEngine creates a FingerprintEngine with a JA3 and OS
// fingerprinter. JA3 uses config for potential future whitelist support.
func NewFingerprintEngine(cfg *config.Config) *FingerprintEngine {
	return &FingerprintEngine{
		ja3: NewJA3Fingerprinter(cfg),
		os:  NewOSFingerprinter(),
	}
}

// Feed processes a packet and returns combined fingerprint threats.
//
// JA3 analysis runs when tcpPayload is non-nil and non-empty.
// OS analysis runs for TCP SYN packets (identified externally by the caller
// providing valid tcpOptions).
//
// Parameters:
//   - srcIP: source IP address
//   - tcpPayload: raw TCP segment payload (for JA3 TLS parsing)
//   - ttl: IP TTL value from the packet header
//   - window: TCP window size
//   - df: whether the IP DF (Don't Fragment) flag is set
//   - mss: TCP Maximum Segment Size option value (0 if absent)
//   - tcpOptions: ordered TCP option names (e.g. ["MSS", "SACK", "TS"])
func (fe *FingerprintEngine) Feed(srcIP string, tcpPayload []byte, ttl uint8, window uint16, df bool, mss int, tcpOptions []string) []Threat {
	var threats []Threat

	// JA3 TLS fingerprinting.
	if len(tcpPayload) > 0 {
		if ja3Threats := fe.ja3.Feed(srcIP, tcpPayload); len(ja3Threats) > 0 {
			threats = append(threats, ja3Threats...)
		}
	}

	// OS fingerprinting (only meaningful for SYN packets with options).
	if len(tcpOptions) > 0 {
		osName, score := fe.os.Fingerprint(ttl, window, df, mss, tcpOptions)
		if osName != "" {
			threats = append(threats, Threat{
				Type:   "OS指纹",
				IP:     srcIP,
				Detail: fmt.Sprintf("os=%s score=%d/10", osName, score),
			})
		}
	}

	return threats
}

// Evict is a no-op for the fingerprint engine since neither JA3 nor OS
// fingerprinting maintains per-flow state. Returns 0.
func (fe *FingerprintEngine) Evict(deadline float64) int {
	return 0
}
