// Hydra-Pro Parser Fuzz Targets (cargo-fuzz / libfuzzer)
//
// Usage:
//   cargo fuzz run fuzz_ethernet_frame
//   cargo fuzz run fuzz_ipv4_header
//   cargo fuzz run fuzz_tcp_segment
//   cargo fuzz run fuzz_dns_message
//
// Requires Cargo.toml with:
//   [dependencies]
//   libfuzzer-sys = "0.4"
//   arbitrary = { version = "1", features = ["derive"] }

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::convert::TryFrom;

// ============================================================================
// Ethernet Frame Constants (IEEE 802.3)
// ============================================================================

const ETHERNET_HEADER_LEN: usize = 14; // 6 dst + 6 src + 2 ethertype
const ETHERNET_MIN_PAYLOAD: usize = 46; // minimum payload for 802.3
const ETHERNET_MAX_FRAME: usize = 1522; // 1518 + VLAN tag
const ETHERNET_MIN_FRAME: usize = 64;

/// Ethernet frame types recognized by the parser.
#[derive(Debug, PartialEq)]
enum EtherType {
    IPv4,
    ARP,
    IPv6,
    VLAN,
    WakeOnLAN,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x86DD => EtherType::IPv6,
            0x8100 => EtherType::VLAN,
            0x0842 => EtherType::WakeOnLAN,
            other => EtherType::Unknown(other),
        }
    }
}

// ============================================================================
// Fuzz Target: Ethernet Frame Parsing
// ============================================================================

/// Parses an Ethernet II frame from raw bytes.
/// Returns None if the frame is malformed, otherwise Some(ethertype, payload).
fn parse_ethernet_frame(data: &[u8]) -> Option<(EtherType, &[u8])> {
    if data.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    // Validate frame size constraints
    if data.len() < ETHERNET_MIN_FRAME || data.len() > ETHERNET_MAX_FRAME {
        return None;
    }
    // Destination MAC: data[0..6]
    // Source MAC: data[6..12]
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let payload = &data[ETHERNET_HEADER_LEN..];

    // Reject frames where payload is too small
    if payload.len() < ETHERNET_MIN_PAYLOAD && ethertype != 0x8100 {
        return None;
    }

    Some((EtherType::from(ethertype), payload))
}

fuzz_target!(|data: &[u8]| {
    // fuzz_target: Ethernet frame parsing
    if let Some((ethertype, payload)) = parse_ethernet_frame(data) {
        // Exercise the parsed result without crashing
        let _ = match &ethertype {
            EtherType::IPv4 => "IPv4 packet",
            EtherType::ARP => "ARP packet",
            EtherType::IPv6 => "IPv6 packet",
            EtherType::VLAN => "VLAN tagged frame",
            EtherType::WakeOnLAN => "Wake-on-LAN magic packet",
            EtherType::Unknown(_) => "Unknown ethertype",
        };
        let _ = payload;
    }
});

// ============================================================================
// Fuzz Target: IPv4 Header Parsing
// ============================================================================

const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV4_HEADER_MAX_LEN: usize = 60; // maximum with options
const IPV4_TOTAL_LEN_MAX: u16 = 65535;

/// Parsed IPv4 header fields.
#[derive(Debug)]
struct IPv4Header {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    source: [u8; 4],
    destination: [u8; 4],
}

fn parse_ipv4_header(data: &[u8]) -> Option<IPv4Header> {
    use std::convert::TryFrom;

    if data.len() < IPV4_HEADER_MIN_LEN {
        return None;
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0F;

    // Must be IPv4
    if version != 4 {
        return None;
    }

    // IHL must be at least 5 (20 bytes) and at most 15 (60 bytes)
    if ihl < 5 || ihl > 15 {
        return None;
    }

    let header_len = usize::try_from(ihl).ok()? * 4;
    if data.len() < header_len {
        return None;
    }

    let dscp_ecn = data[1];
    let dscp = dscp_ecn >> 2;
    let ecn = dscp_ecn & 0x03;

    let total_length = u16::from_be_bytes([data[2], data[3]]);

    // Total length must be at least the header length
    if total_length < (header_len as u16) || total_length > IPV4_TOTAL_LEN_MAX {
        return None;
    }

    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    let flags = ((flags_frag >> 13) & 0x07) as u8;
    let fragment_offset = flags_frag & 0x1FFF;

    let ttl = data[8];
    let protocol = data[9];
    let header_checksum = u16::from_be_bytes([data[10], data[11]]);

    let mut source = [0u8; 4];
    source.copy_from_slice(&data[12..16]);
    let mut destination = [0u8; 4];
    destination.copy_from_slice(&data[16..20]);

    // Validate header checksum
    let computed = ipv4_checksum(&data[..header_len]);
    if computed != 0 && header_checksum != 0 {
        // Checksum mismatch — but we still return the header for fuzzing
        // (real parsers might log a warning but not crash)
    }
    let _ = computed;

    Some(IPv4Header {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        source,
        destination,
    })
}

/// Computes the IPv4 header checksum (RFC 791).
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        i += 2;
    }
    if i < header.len() {
        sum += u32::from(header[i]) << 8;
    }
    // Fold 32-bit sum to 16 bits with carry
    loop {
        let carry = sum >> 16;
        if carry == 0 {
            break;
        }
        sum = (sum & 0xFFFF) + carry;
    }
    !(sum as u16)
}

fuzz_target!(|data: &[u8]| {
    // fuzz_target: IPv4 header parsing
    if let Some(header) = parse_ipv4_header(data) {
        // Exercise parsed fields
        let _ = header.version;
        let _ = header.ihl;
        let _ = header.protocol;
        let _ = header.ttl;
        let _ = header.source;
        let _ = header.destination;
        let _ = header.total_length;
    }
});

// ============================================================================
// Fuzz Target: TCP Segment Parsing
// ============================================================================

const TCP_HEADER_MIN_LEN: usize = 20;
const TCP_DATA_OFFSET_MIN: u8 = 5;
const TCP_DATA_OFFSET_MAX: u8 = 15;

#[derive(Debug)]
struct TCPHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
}

fn parse_tcp_header(data: &[u8]) -> Option<TCPHeader> {
    if data.len() < TCP_HEADER_MIN_LEN {
        return None;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let data_offset = (data[12] >> 4) & 0x0F;

    // Data offset must be 5-15 (20-60 bytes)
    if data_offset < TCP_DATA_OFFSET_MIN || data_offset > TCP_DATA_OFFSET_MAX {
        return None;
    }

    let header_len = usize::try_from(data_offset).ok()? * 4;
    if data.len() < header_len {
        return None;
    }

    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent = u16::from_be_bytes([data[18], data[19]]);

    Some(TCPHeader {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        flags,
        window,
        checksum,
        urgent,
    })
}

fuzz_target!(|data: &[u8]| {
    // fuzz_target: TCP segment parsing
    if let Some(header) = parse_tcp_header(data) {
        // Validate flag combinations: SYN+FIN is unusual
        const TCP_FIN: u8 = 0x01;
        const TCP_SYN: u8 = 0x02;
        const TCP_RST: u8 = 0x04;
        if header.flags & TCP_FIN != 0 && header.flags & TCP_SYN != 0 {
            // FIN+SYN — unusual but parser must not crash
        }
        if header.flags & TCP_RST != 0 && header.flags & TCP_SYN != 0 {
            // RST+SYN — unusual but parser must not crash
        }
        let _ = header.seq_num;
        let _ = header.ack_num;
        let _ = header.src_port;
        let _ = header.dst_port;
    }
});

// ============================================================================
// Fuzz Target: DNS Message Parsing (RFC 1035)
// ============================================================================

const DNS_HEADER_LEN: usize = 12;

#[derive(Debug)]
struct DNSHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

fn parse_dns_header(data: &[u8]) -> Option<DNSHeader> {
    if data.len() < DNS_HEADER_LEN {
        return None;
    }

    let id = u16::from_be_bytes([data[0], data[1]]);

    let flags_hi = data[2];
    let flags_lo = data[3];

    let qr = (flags_hi & 0x80) != 0;
    let opcode = (flags_hi >> 3) & 0x0F;
    let aa = (flags_hi & 0x04) != 0;
    let tc = (flags_hi & 0x02) != 0;
    let rd = (flags_hi & 0x01) != 0;

    let ra = (flags_lo & 0x80) != 0;
    let z = (flags_lo >> 4) & 0x07;
    let rcode = flags_lo & 0x0F;

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);

    // Validate opcode range (0-5 are defined, 6-15 reserved)
    if opcode > 5 {
        // Reserved opcode — parser must handle gracefully
    }

    // Validate rcode range
    if rcode > 10 {
        // Reserved rcode — parser must handle gracefully
    }

    Some(DNSHeader {
        id,
        qr,
        opcode,
        aa,
        tc,
        rd,
        ra,
        z,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    })
}

/// Parse a DNS name label sequence from `data` starting at `offset`.
/// Returns (name_string, new_offset) or None if truncated.
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let max_jumps = 16; // prevent compression pointer loops
    let mut jumps = 0;

    loop {
        if offset >= data.len() {
            return None;
        }

        let label_len = data[offset];
        offset += 1;

        if label_len == 0 {
            // Root label — end of name
            break;
        }

        // Check for compression pointer (top two bits set)
        if label_len & 0xC0 == 0xC0 {
            if offset >= data.len() {
                return None;
            }
            if jumps >= max_jumps {
                // Pointer loop detected — bail
                return None;
            }
            let pointer = u16::from_be_bytes([label_len & 0x3F, data[offset]]) as usize;
            offset = pointer; // jump follows the pointer
            jumps += 1;
            continue;
        }

        // Regular label
        let len = label_len as usize;
        if len > 63 {
            return None; // label too long per RFC
        }
        if offset + len > data.len() {
            return None; // truncated
        }

        let label = match std::str::from_utf8(&data[offset..offset + len]) {
            Ok(s) => s.to_string(),
            Err(_) => return None, // non-UTF-8 label
        };
        labels.push(label);
        offset += len;
    }

    let name = labels.join(".");
    // Total name length must not exceed 253 chars
    if name.len() > 253 {
        return None;
    }

    Some((name, offset))
}

fuzz_target!(|data: &[u8]| {
    // fuzz_target: DNS message parsing
    if let Some(header) = parse_dns_header(data) {
        let mut pos: usize = DNS_HEADER_LEN;

        // Skip over question section
        for _ in 0..header.qdcount {
            match parse_dns_name(data, pos) {
                Some((name, new_pos)) => {
                    let _ = name;
                    pos = new_pos;
                }
                None => return, // truncated
            }
            // QTYPE + QCLASS = 4 bytes
            if pos + 4 > data.len() {
                return;
            }
            pos += 4;
        }

        let _ = header.ancount;
        let _ = header.nscount;
        let _ = header.arcount;
        let _ = header.opcode;
    }
});

// ============================================================================
// Fuzz Target: UTF-8 boundary testing (general input robustness)
// ============================================================================

fuzz_target!(|data: &[u8]| {
    // fuzz_target: UTF-8 boundary testing on byte sequences
    // This target ensures that text parsing never panics on arbitrary bytes.

    // Try to interpret as UTF-8 string
    match std::str::from_utf8(data) {
        Ok(valid) => {
            // Valid UTF-8: exercise string operations
            let lower = valid.to_lowercase();
            let _ = lower.len();
            if let Some(first) = valid.chars().next() {
                let _ = first.is_alphabetic();
                let _ = first.is_numeric();
                let _ = first.len_utf8();
            }
        }
        Err(_) => {
            // Invalid UTF-8: lossy conversion must not crash
            let lossy = String::from_utf8_lossy(data);
            let _ = lossy.len();
        }
    }
});
