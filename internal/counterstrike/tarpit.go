// Package counterstrike implements active counter-measures against attackers.
//
// Tarpit implements a TCP Tarpit that keeps attacker connections alive
// indefinitely by replying to SYN with SYN-ACK window=0. The attacker's
// TCP stack enters zero-window probe state (probes every 30-60s), and
// each probe is answered with ACK window=0 — wasting attacker resources
// (sockets, memory, connection-table slots) while producing zero useful work.
package counterstrike

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/fortress/v6/internal/stealth"
)

// TarpitConn tracks a single connection being held in the tarpit.
type TarpitConn struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	CreatedAt time.Time
}

// Tarpit holds active tarpit connections, pinning attacker resources.
type Tarpit struct {
	mu          sync.Mutex
	connections map[string]*TarpitConn // key: "srcIP:srcPort"
	enableScapy bool                   // reserved for future Scapy integration
	dropOnce    sync.Once              // ensures privileges are dropped only once
	dropUID     int                    // UID to drop to after raw socket
	dropGID     int                    // GID to drop to after raw socket
}

// NewTarpit creates a new TCP tarpit.
func NewTarpit(enableScapy bool) *Tarpit {
	return &Tarpit{
		connections: make(map[string]*TarpitConn),
		enableScapy: enableScapy,
	}
}

// SetDropCredentials configures the UID/GID that the tarpit will drop
// privileges to after the first successful raw socket operation.
// Call this before any Tarpit calls. If not set, privilege dropping is
// skipped (the process retains its current privileges).
func (t *Tarpit) SetDropCredentials(uid, gid int) {
	t.dropUID = uid
	t.dropGID = gid
}

// Tarpit sends a SYN-ACK window=0 packet to the attacker, establishing a
// zero-window connection that keeps the attacker's socket pinned forever.
// Each subsequent zero-window probe from the attacker is answered with
// another ACK window=0, preventing the connection from ever closing.
func (t *Tarpit) Tarpit(srcIP, dstIP string, srcPort, dstPort uint16) error {
	t.mu.Lock()
	key := connKey(srcIP, srcPort)
	t.connections[key] = &TarpitConn{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		CreatedAt: time.Now(),
	}
	t.mu.Unlock()

	// Build and send the raw SYN-ACK packet with window=0.
	if err := sendSynAckWindowZero(srcIP, dstIP, srcPort, dstPort); err != nil {
		return err
	}

	// Drop privileges after the first successful raw socket operation.
	// Raw sockets require CAP_NET_RAW (or root); once created, we drop
	// to an unprivileged user to enforce least privilege.
	t.dropOnce.Do(func() {
		if t.dropUID > 0 && t.dropGID > 0 {
			if err := stealth.DropPrivileges(t.dropUID, t.dropGID); err != nil {
				log.Printf("[tarpit] privilege drop failed: %v", err)
			}
		}
	})

	return nil
}

// CheckConnection reports whether the given IP has any active tarpit connections.
func (t *Tarpit) CheckConnection(srcIP string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key := range t.connections {
		if len(key) >= len(srcIP) && key[:len(srcIP)] == srcIP {
			return true
		}
	}
	return false
}

// Cleanup removes connections older than one hour.
func (t *Tarpit) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-time.Hour)
	for key, conn := range t.connections {
		if conn.CreatedAt.Before(cutoff) {
			delete(t.connections, key)
		}
	}
}

// connKey builds a lookup key from IP:port.
func connKey(ip string, port uint16) string {
	return ip + ":" + formatPortU16(port)
}

// ---------------------------------------------------------------------------
// Raw packet construction and sending
// ---------------------------------------------------------------------------

// sendSynAckWindowZero builds and sends a raw TCP SYN-ACK packet with
// a zero receive window via a raw socket.
func sendSynAckWindowZero(srcIP, dstIP string, srcPort, dstPort uint16) error {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return &net.ParseError{Type: "IP address", Text: srcIP + " or " + dstIP}
	}

	// Sequence number: random (we are the server, responding to their SYN).
	// Our seq is arbitrary — we just need to ACK their SYN with seq+1.
	ourSeq := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	// Build TCP header (20 bytes, no options).
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)   // source port (our fake server port)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)   // dest port (attacker's source port)
	binary.BigEndian.PutUint32(tcpHeader[4:8], ourSeq)    // sequence number
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)        // ack number (0 — we claim we've seen nothing)
	tcpHeader[12] = 0x50                                   // data offset = 5 (20 bytes), upper nibble
	tcpHeader[13] = tcpSYN | tcpACK                        // flags: SYN + ACK
	binary.BigEndian.PutUint16(tcpHeader[14:16], 0)       // window = 0 (this is the tarpit!)
	binary.BigEndian.PutUint16(tcpHeader[16:18], 0)       // checksum (computed below)
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0)       // urgent pointer

	// Compute TCP checksum with pseudo-header.
	tcpChecksum := tcpChecksumWithPseudo(src, dst, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum)

	// Build IP header (20 bytes, no options).
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                                                            // version=4, IHL=5
	ipHeader[1] = 0x00                                                            // DSCP/ECN
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(20+len(tcpHeader)))          // total length
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(time.Now().UnixNano()&0xFFFF)) // ID
	ipHeader[6] = 0x40                                                            // flags: DF
	ipHeader[7] = 0x00                                                            // fragment offset
	ipHeader[8] = 64                                                               // TTL
	ipHeader[9] = syscall.IPPROTO_TCP                                              // protocol
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)                                // checksum (computed below)
	copy(ipHeader[12:16], src)                                                     // source IP
	copy(ipHeader[16:20], dst)                                                     // dest IP

	// Compute IP header checksum.
	ipChecksum := ipChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum)

	// Assemble full packet.
	packet := append(ipHeader, tcpHeader...)

	// Send via raw socket.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// Set IP_HDRINCL so the kernel uses our IP header as-is.
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return err
	}

	addr := &syscall.SockaddrInet4{
		Port: int(dstPort),
	}
	copy(addr.Addr[:], dst)

	return syscall.Sendto(fd, packet, 0, addr)
}

// TCP flags
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
	tcpURG = 0x20
)

// ipChecksum computes the 16-bit one's complement of the one's complement
// sum of all 16-bit words in the header.
func ipChecksum(header []byte) uint16 {
	return onesComplementSum(header)
}

// tcpChecksumWithPseudo computes the TCP checksum including the IPv4
// pseudo-header: source IP, dest IP, protocol, and TCP segment length.
func tcpChecksumWithPseudo(src, dst net.IP, tcpSegment []byte) uint16 {
	tcpLen := len(tcpSegment)

	// Build pseudo-header + TCP segment for checksum calculation.
	buf := make([]byte, 12+tcpLen)

	// Pseudo-header: source IP (4), dest IP (4), zero (1), protocol (1), TCP length (2).
	copy(buf[0:4], src)
	copy(buf[4:8], dst)
	buf[8] = 0
	buf[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(buf[10:12], uint16(tcpLen))

	// Copy TCP segment (with checksum field zeroed).
	copy(buf[12:], tcpSegment)

	return onesComplementSum(buf)
}

// onesComplementSum computes the 16-bit ones' complement sum over the buffer.
// The result is the ones' complement checksum suitable for IP and TCP.
func onesComplementSum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	// Add carry.
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// formatPortU16 formats a port number as a string without importing fmt.
func formatPortU16(port uint16) string {
	buf := make([]byte, 0, 5)
	if port >= 10000 {
		buf = append(buf, byte('0'+port/10000))
		port %= 10000
	}
	if port >= 1000 || len(buf) > 0 {
		buf = append(buf, byte('0'+port/1000))
		port %= 1000
	}
	if port >= 100 || len(buf) > 0 {
		buf = append(buf, byte('0'+port/100))
		port %= 100
	}
	if port >= 10 || len(buf) > 0 {
		buf = append(buf, byte('0'+port/10))
		port %= 10
	}
	buf = append(buf, byte('0'+port))
	return string(buf)
}
