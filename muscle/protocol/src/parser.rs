/// Protocol parsing error types for fortress muscle layer.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    TooShort,
    NotIPv4,
    NotIPv6,
    NotTCP,
    NotUDP,
    NotICMP,
    NotHTTP,
    NotTLS,
    Truncated,
    BadLength,
    UnknownProtocol(u8),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "packet too short"),
            ParseError::NotIPv4 => write!(f, "not an IPv4 packet"),
            ParseError::NotIPv6 => write!(f, "not an IPv6 packet"),
            ParseError::NotTCP => write!(f, "not a TCP segment"),
            ParseError::NotUDP => write!(f, "not a UDP datagram"),
            ParseError::NotICMP => write!(f, "not an ICMP packet"),
            ParseError::NotHTTP => write!(f, "not an HTTP message"),
            ParseError::NotTLS => write!(f, "not a TLS record"),
            ParseError::Truncated => write!(f, "truncated packet"),
            ParseError::BadLength => write!(f, "bad length field"),
            ParseError::UnknownProtocol(p) => write!(f, "unknown layer-4 protocol: {}", p),
        }
    }
}

impl std::error::Error for ParseError {}

// ── IPv4 ────────────────────────────────────────────────────────

/// Parsed IPv4 header fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4Header {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub protocol: u8,  // 6=TCP, 17=UDP, 1=ICMP
    pub ttl: u8,
    pub total_length: u16,
    pub ihl: u8,       // header length in 32-bit words
}

/// Parsed TCP header fields.
#[derive(Debug, Clone, PartialEq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,     // bitmask: FIN(1),SYN(2),RST(4),PSH(8),ACK(16),URG(32)
    pub window: u16,
    pub data_offset: u8, // header length in 32-bit words
}

// ── IPv6 ────────────────────────────────────────────────────────

/// Parsed IPv6 header fields — fixed 40-byte header only.
#[derive(Debug, Clone, PartialEq)]
pub struct Ipv6Header {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub flow_label: u32,
}

// ── UDP ─────────────────────────────────────────────────────────

/// Parsed UDP header fields.
#[derive(Debug, Clone, PartialEq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

// ── ICMP ────────────────────────────────────────────────────────

/// Parsed ICMP header fields (first 4 bytes common to all ICMP types).
#[derive(Debug, Clone, PartialEq)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
}

// ── Packet classification ───────────────────────────────────────

/// High-level packet classification for the muscle fast path.
#[derive(Debug, Clone, PartialEq)]
pub enum PacketClass {
    TcpIpv4 {
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
        payload_offset: usize,
    },
    UdpIpv4 {
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        payload_offset: usize,
    },
    IcmpIpv4 {
        src: [u8; 4],
        dst: [u8; 4],
        itype: u8,
        icode: u8,
    },
    TcpIpv6 {
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
        flags: u8,
        payload_offset: usize,
    },
    UdpIpv6 {
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
        payload_offset: usize,
    },
    Other,
}

// ═══════════════════════════════════════════════════════════════
// PARSING FUNCTIONS
// ═══════════════════════════════════════════════════════════════

/// Parse an Ethernet frame. Returns (ethertype, payload_offset, payload_len).
pub fn parse_ethernet(data: &[u8]) -> Option<(u16, usize, usize)> {
    if data.len() < 14 { return None; }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype == 0x8100 { // VLAN tag
        if data.len() < 18 { return None; }
        let ethertype = u16::from_be_bytes([data[16], data[17]]);
        return Some((ethertype, 18, data.len() - 18));
    }
    Some((ethertype, 14, data.len() - 14))
}

/// Parse an IPv4 header. Returns None if not IPv4 or malformed.
pub fn parse_ipv4(data: &[u8]) -> Option<Ipv4Header> {
    if data.len() < 20 { return None; }
    let version_ihl = data[0];
    if (version_ihl >> 4) != 4 { return None; }
    let ihl = version_ihl & 0x0F;
    let header_len = (ihl as usize) * 4;
    if data.len() < header_len { return None; }

    Some(Ipv4Header {
        src_ip: [data[12], data[13], data[14], data[15]],
        dst_ip: [data[16], data[17], data[18], data[19]],
        protocol: data[9],
        ttl: data[8],
        total_length: u16::from_be_bytes([data[2], data[3]]),
        ihl,
    })
}

/// Parse an IPv4 header with error discrimination.
pub fn parse_ipv4_err(data: &[u8]) -> Result<Ipv4Header, ParseError> {
    if data.len() < 20 { return Err(ParseError::TooShort); }
    let version_ihl = data[0];
    if (version_ihl >> 4) != 4 { return Err(ParseError::NotIPv4); }
    let ihl = version_ihl & 0x0F;
    let header_len = (ihl as usize) * 4;
    if data.len() < header_len { return Err(ParseError::Truncated); }

    Ok(Ipv4Header {
        src_ip: [data[12], data[13], data[14], data[15]],
        dst_ip: [data[16], data[17], data[18], data[19]],
        protocol: data[9],
        ttl: data[8],
        total_length: u16::from_be_bytes([data[2], data[3]]),
        ihl,
    })
}

/// Parse an IPv6 header — fixed 40 bytes.
pub fn parse_ipv6(data: &[u8]) -> Result<Ipv6Header, ParseError> {
    if data.len() < 40 {
        return Err(ParseError::TooShort);
    }
    let version = data[0] >> 4;
    if version != 6 {
        return Err(ParseError::NotIPv6);
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);

    let flow_label = u32::from_be_bytes([0, data[1], data[2], data[3]]) & 0x000F_FFFF;
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    Ok(Ipv6Header {
        src_ip: src,
        dst_ip: dst,
        payload_length,
        next_header,
        hop_limit,
        flow_label,
    })
}

/// Parse a TCP header. Returns None if malformed.
pub fn parse_tcp(data: &[u8]) -> Option<TcpHeader> {
    if data.len() < 20 { return None; }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let data_offset = (data[12] >> 4) & 0x0F;
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len { return None; }

    Some(TcpHeader {
        src_port, dst_port, flags: data[13],
        window: u16::from_be_bytes([data[14], data[15]]),
        data_offset,
    })
}

/// Parse a TCP header with error discrimination.
pub fn parse_tcp_err(data: &[u8]) -> Result<TcpHeader, ParseError> {
    if data.len() < 20 { return Err(ParseError::TooShort); }
    let data_offset = (data[12] >> 4) & 0x0F;
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len { return Err(ParseError::Truncated); }

    Ok(TcpHeader {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        flags: data[13],
        window: u16::from_be_bytes([data[14], data[15]]),
        data_offset,
    })
}

/// Parse a UDP header — 8 bytes.
pub fn parse_udp(data: &[u8]) -> Result<UdpHeader, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::TooShort);
    }
    Ok(UdpHeader {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        length: u16::from_be_bytes([data[4], data[5]]),
        checksum: u16::from_be_bytes([data[6], data[7]]),
    })
}

/// Parse an ICMP header — first 4 bytes after IP.
pub fn parse_icmp(data: &[u8]) -> Result<IcmpHeader, ParseError> {
    if data.len() < 4 {
        return Err(ParseError::TooShort);
    }
    Ok(IcmpHeader {
        icmp_type: data[0],
        icmp_code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
    })
}

/// Convert TCP flags bitmask to sorted flag string like "S", "AS", "FPU".
pub fn tcp_flags_string(flags: u8) -> String {
    let mut s = String::with_capacity(6);
    if flags & 0x01 != 0 { s.push('F'); }  // FIN
    if flags & 0x02 != 0 { s.push('S'); }  // SYN
    if flags & 0x04 != 0 { s.push('R'); }  // RST
    if flags & 0x08 != 0 { s.push('P'); }  // PSH
    if flags & 0x10 != 0 { s.push('A'); }  // ACK
    if flags & 0x20 != 0 { s.push('U'); }  // URG
    s
}

// ── Full packet classifier ─────────────────────────────────────

/// Classify a complete Ethernet frame.
/// Returns `(PacketClass, payload_offset_into_original_buffer)`.
pub fn classify(data: &[u8]) -> Result<(PacketClass, usize), ParseError> {
    if data.len() < 14 {
        return Err(ParseError::TooShort);
    }

    let (ethertype, l3_offset, _) = parse_ethernet(data)
        .ok_or(ParseError::TooShort)?;

    match ethertype {
        0x0800 => {
            // IPv4
            let l4_data = data.get(l3_offset..).ok_or(ParseError::Truncated)?;
            let ip = parse_ipv4(l4_data).ok_or(ParseError::Truncated)?;
            let ip_hdr_len = (ip.ihl as usize) * 4;
            let l4_offset = l3_offset + ip_hdr_len;
            let l4_payload = data.get(l4_offset..).ok_or(ParseError::Truncated)?;

            match ip.protocol {
                6 => {
                    let tcp = parse_tcp(l4_payload).ok_or(ParseError::TooShort)?;
                    let tcp_hdr_len = (tcp.data_offset as usize) * 4;
                    Ok((PacketClass::TcpIpv4 {
                        src: ip.src_ip,
                        dst: ip.dst_ip,
                        sport: tcp.src_port,
                        dport: tcp.dst_port,
                        flags: tcp.flags,
                        payload_offset: l4_offset + tcp_hdr_len,
                    }, l4_offset + tcp_hdr_len))
                }
                17 => {
                    let udp = parse_udp(l4_payload)?;
                    Ok((PacketClass::UdpIpv4 {
                        src: ip.src_ip,
                        dst: ip.dst_ip,
                        sport: udp.src_port,
                        dport: udp.dst_port,
                        payload_offset: l4_offset + 8,
                    }, l4_offset + 8))
                }
                1 => {
                    let icmp = parse_icmp(l4_payload)?;
                    Ok((PacketClass::IcmpIpv4 {
                        src: ip.src_ip,
                        dst: ip.dst_ip,
                        itype: icmp.icmp_type,
                        icode: icmp.icmp_code,
                    }, l4_offset + 4))
                }
                _ => Ok((PacketClass::Other, l4_offset)),
            }
        }
        0x86DD => {
            // IPv6
            let l4_data = data.get(l3_offset..).ok_or(ParseError::Truncated)?;
            let ip6 = parse_ipv6(l4_data)?;
            let l4_offset = l3_offset + 40;
            let l4_payload = data.get(l4_offset..).ok_or(ParseError::Truncated)?;

            match ip6.next_header {
                6 => {
                    let tcp = parse_tcp(l4_payload).ok_or(ParseError::TooShort)?;
                    let tcp_hdr_len = (tcp.data_offset as usize) * 4;
                    Ok((PacketClass::TcpIpv6 {
                        src: ip6.src_ip,
                        dst: ip6.dst_ip,
                        sport: tcp.src_port,
                        dport: tcp.dst_port,
                        flags: tcp.flags,
                        payload_offset: l4_offset + tcp_hdr_len,
                    }, l4_offset + tcp_hdr_len))
                }
                17 => {
                    let udp = parse_udp(l4_payload)?;
                    Ok((PacketClass::UdpIpv6 {
                        src: ip6.src_ip,
                        dst: ip6.dst_ip,
                        sport: udp.src_port,
                        dport: udp.dst_port,
                        payload_offset: l4_offset + 8,
                    }, l4_offset + 8))
                }
                _ => Ok((PacketClass::Other, l4_offset)),
            }
        }
        0x0806 => Ok((PacketClass::Other, l3_offset)), // ARP
        _ => Ok((PacketClass::Other, l3_offset)),
    }
}

/// Convenience: classify a raw IP-level buffer (no Ethernet header).
pub fn classify_ip(data: &[u8]) -> Result<(PacketClass, usize), ParseError> {
    if data.is_empty() {
        return Err(ParseError::TooShort);
    }
    let version = data[0] >> 4;
    match version {
        4 => {
            let ip = parse_ipv4_err(data)?;
            let ip_hdr_len = (ip.ihl as usize) * 4;
            let l4 = data.get(ip_hdr_len..).ok_or(ParseError::Truncated)?;
            match ip.protocol {
                6 => {
                    let tcp = parse_tcp_err(l4)?;
                    let tcp_hdr_len = (tcp.data_offset as usize) * 4;
                    Ok((PacketClass::TcpIpv4 {
                        src: ip.src_ip,
                        dst: ip.dst_ip,
                        sport: tcp.src_port,
                        dport: tcp.dst_port,
                        flags: tcp.flags,
                        payload_offset: ip_hdr_len + tcp_hdr_len,
                    }, ip_hdr_len + tcp_hdr_len))
                }
                17 => {
                    let udp = parse_udp(l4)?;
                    Ok((PacketClass::UdpIpv4 {
                        src: ip.src_ip,
                        dst: ip.dst_ip,
                        sport: udp.src_port,
                        dport: udp.dst_port,
                        payload_offset: ip_hdr_len + 8,
                    }, ip_hdr_len + 8))
                }
                1 => {
                    let icmp = parse_icmp(l4)?;
                    Ok((PacketClass::IcmpIpv4 {
                        src: ip.src_ip,
                        dst: ip.dst_ip,
                        itype: icmp.icmp_type,
                        icode: icmp.icmp_code,
                    }, ip_hdr_len + 4))
                }
                _ => Ok((PacketClass::Other, ip_hdr_len)),
            }
        }
        6 => {
            let ip6 = parse_ipv6(data)?;
            let l4 = data.get(40..).ok_or(ParseError::Truncated)?;
            match ip6.next_header {
                6 => {
                    let tcp = parse_tcp_err(l4)?;
                    let tcp_hdr_len = (tcp.data_offset as usize) * 4;
                    Ok((PacketClass::TcpIpv6 {
                        src: ip6.src_ip,
                        dst: ip6.dst_ip,
                        sport: tcp.src_port,
                        dport: tcp.dst_port,
                        flags: tcp.flags,
                        payload_offset: 40 + tcp_hdr_len,
                    }, 40 + tcp_hdr_len))
                }
                17 => {
                    parse_udp(l4)?;
                    Ok((PacketClass::UdpIpv6 {
                        src: ip6.src_ip,
                        dst: ip6.dst_ip,
                        sport: u16::from_be_bytes([l4[0], l4[1]]),
                        dport: u16::from_be_bytes([l4[2], l4[3]]),
                        payload_offset: 40 + 8,
                    }, 40 + 8))
                }
                _ => Ok((PacketClass::Other, 40)),
            }
        }
        _ => Err(ParseError::NotIPv4),
    }
}

// ═══════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing parser tests ─────────────────────────────────

    #[test]
    fn test_parse_ethernet_ipv4() {
        let frame: [u8; 34] = [
            0x00,0x00,0x00,0x00,0x00,0x00, // dst MAC
            0x00,0x00,0x00,0x00,0x00,0x00, // src MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, // IP header start
            0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // src/dst IP
        ];
        let (ethertype, offset, _) = parse_ethernet(&frame).unwrap();
        assert_eq!(ethertype, 0x0800); // IPv4
        let ip = parse_ipv4(&frame[offset..]).unwrap();
        assert_eq!(ip.src_ip, [192, 168, 1, 1]);
        assert_eq!(ip.dst_ip, [192, 168, 1, 2]);
        assert_eq!(ip.protocol, 6); // TCP
        assert_eq!(ip.ttl, 64);
    }

    #[test]
    fn test_tcp_flags_syn() {
        assert_eq!(tcp_flags_string(0x02), "S");
    }

    #[test]
    fn test_tcp_flags_synack() {
        assert_eq!(tcp_flags_string(0x12), "SA");
    }

    // ── ParseError tests ──────────────────────────────────────

    #[test]
    fn test_parse_error_display() {
        assert_eq!(ParseError::TooShort.to_string(), "packet too short");
        assert_eq!(ParseError::NotIPv4.to_string(), "not an IPv4 packet");
        assert_eq!(ParseError::NotIPv6.to_string(), "not an IPv6 packet");
        assert_eq!(ParseError::NotTCP.to_string(), "not a TCP segment");
        assert_eq!(ParseError::NotUDP.to_string(), "not a UDP datagram");
    }

    #[test]
    fn test_parse_error_unknown_protocol() {
        assert_eq!(
            ParseError::UnknownProtocol(99).to_string(),
            "unknown layer-4 protocol: 99"
        );
    }

    // ── IPv4 error-path tests ─────────────────────────────────

    #[test]
    fn test_ipv4_err_too_short() {
        let data = [0u8; 10];
        assert_eq!(parse_ipv4_err(&data), Err(ParseError::TooShort));
    }

    #[test]
    fn test_ipv4_err_not_ipv4() {
        // Version = 6
        let mut data = [0u8; 20];
        data[0] = 0x60;
        assert_eq!(parse_ipv4_err(&data), Err(ParseError::NotIPv4));
    }

    #[test]
    fn test_ipv4_err_truncated() {
        // IHL = 15 → 60 byte header, but only 20 bytes provided
        let mut data = [0u8; 30];
        data[0] = 0x4F;
        // Need at least 60, have 30
        assert_eq!(parse_ipv4_err(&data), Err(ParseError::Truncated));
    }

    #[test]
    fn test_ipv4_ip_options() {
        // IHL = 6 → 24 byte header (8 bytes of options)
        let mut data = [0u8; 40];
        data[0] = 0x46;      // version=4, ihl=6
        data[2] = 0x00; data[3] = 0x28; // total_length = 40
        data[8] = 64;        // TTL
        data[9] = 6;         // TCP
        // src IP: 10.0.0.1
        data[12] = 10; data[13] = 0; data[14] = 0; data[15] = 1;
        // dst IP: 10.0.0.2
        data[16] = 10; data[17] = 0; data[18] = 0; data[19] = 2;

        let ip = parse_ipv4_err(&data).unwrap();
        assert_eq!(ip.ihl, 6);
        assert_eq!(ip.src_ip, [10, 0, 0, 1]);
        assert_eq!(ip.dst_ip, [10, 0, 0, 2]);
    }

    // ── IPv6 tests ────────────────────────────────────────────

    #[test]
    fn test_ipv6_parse() {
        let mut data = [0u8; 60];
        data[0] = 0x60;          // version=6
        // flow label = 0xABCDE
        data[1] = 0x0A;
        data[2] = 0xBC;
        data[3] = 0xDE;
        data[4] = 0x00; data[5] = 0x14; // payload_length = 20
        data[6] = 6;             // next header = TCP
        data[7] = 64;            // hop limit
        // src: 2001:db8::1
        data[8]  = 0x20; data[9]  = 0x01;
        data[10] = 0x0d; data[11] = 0xb8;
        data[22] = 0x00; data[23] = 0x01;
        // dst: 2001:db8::2
        data[24] = 0x20; data[25] = 0x01;
        data[26] = 0x0d; data[27] = 0xb8;
        data[38] = 0x00; data[39] = 0x02;

        let ip6 = parse_ipv6(&data).unwrap();
        assert_eq!(ip6.next_header, 6);
        assert_eq!(ip6.hop_limit, 64);
        assert_eq!(ip6.payload_length, 20);
        assert_eq!(ip6.flow_label, 0xABCDE);
        assert_eq!(ip6.src_ip[0..2], [0x20, 0x01]);
        assert_eq!(ip6.dst_ip[15], 0x02);
    }

    #[test]
    fn test_ipv6_too_short() {
        let data = [0u8; 20];
        assert_eq!(parse_ipv6(&data), Err(ParseError::TooShort));
    }

    #[test]
    fn test_ipv6_not_ipv6() {
        let mut data = [0u8; 40];
        data[0] = 0x40; // version=4
        assert_eq!(parse_ipv6(&data), Err(ParseError::NotIPv6));
    }

    // ── UDP tests ─────────────────────────────────────────────

    #[test]
    fn test_udp_parse() {
        let mut data = [0u8; 8];
        data[0] = 0x13; data[1] = 0x89; // src_port = 5001
        data[2] = 0x00; data[3] = 0x35; // dst_port = 53 (DNS)
        data[4] = 0x00; data[5] = 0x20; // length = 32
        data[6] = 0x00; data[7] = 0x00; // checksum

        let udp = parse_udp(&data).unwrap();
        assert_eq!(udp.src_port, 5001);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(udp.length, 32);
    }

    #[test]
    fn test_udp_too_short() {
        let data = [0u8; 4];
        assert_eq!(parse_udp(&data), Err(ParseError::TooShort));
    }

    // ── ICMP tests ────────────────────────────────────────────

    #[test]
    fn test_icmp_echo_request() {
        let mut data = [0u8; 8];
        data[0] = 8;  // echo request
        data[1] = 0;  // code
        let icmp = parse_icmp(&data).unwrap();
        assert_eq!(icmp.icmp_type, 8);
        assert_eq!(icmp.icmp_code, 0);
    }

    #[test]
    fn test_icmp_echo_reply() {
        let mut data = [0u8; 8];
        data[0] = 0;  // echo reply
        data[1] = 0;
        let icmp = parse_icmp(&data).unwrap();
        assert_eq!(icmp.icmp_type, 0);
    }

    #[test]
    fn test_icmp_dest_unreachable() {
        let mut data = [0u8; 8];
        data[0] = 3;  // destination unreachable
        data[1] = 1;  // host unreachable
        let icmp = parse_icmp(&data).unwrap();
        assert_eq!(icmp.icmp_type, 3);
        assert_eq!(icmp.icmp_code, 1);
    }

    #[test]
    fn test_icmp_too_short() {
        assert_eq!(parse_icmp(&[0u8; 2]), Err(ParseError::TooShort));
    }

    // ── TCP error-path tests ──────────────────────────────────

    #[test]
    fn test_tcp_err_too_short() {
        assert_eq!(parse_tcp_err(&[0u8; 10]), Err(ParseError::TooShort));
    }

    #[test]
    fn test_tcp_err_truncated() {
        // data_offset = 15 → 60 bytes, but only 30
        let mut data = [0u8; 30];
        data[12] = 0xF0;
        assert_eq!(parse_tcp_err(&data), Err(ParseError::Truncated));
    }

    // ── Classify tests ────────────────────────────────────────

    #[test]
    fn test_classify_tcp_ipv4() {
        // Build a minimal Ethernet + IPv4 + TCP SYN packet
        let mut pkt = vec![0u8; 14 + 20 + 20]; // Eth + IP + TCP
        // Ethernet
        pkt[12] = 0x08; pkt[13] = 0x00; // IPv4
        // IPv4
        pkt[14] = 0x45; // version=4, ihl=5
        pkt[15] = 0x00; // DSCP+ECN
        pkt[16] = 0x00; pkt[17] = 0x28; // total_length=40
        pkt[23] = 6;    // protocol=TCP
        pkt[26] = 0xc0; pkt[27] = 0xa8; pkt[28] = 0x01; pkt[29] = 0x01; // src 192.168.1.1
        pkt[30] = 0xc0; pkt[31] = 0xa8; pkt[32] = 0x01; pkt[33] = 0x02; // dst 192.168.1.2
        // TCP
        pkt[34] = 0x04; pkt[35] = 0x57; // src_port=1111
        pkt[36] = 0x00; pkt[37] = 0x50; // dst_port=80
        // SEQ, ACK (8 bytes)
        pkt[46] = 0x50; // data_offset=5
        pkt[47] = 0x02; // flags=SYN

        match classify(&pkt) {
            Ok((PacketClass::TcpIpv4 { src, dst, sport, dport, flags, .. }, _)) => {
                assert_eq!(src, [192, 168, 1, 1]);
                assert_eq!(dst, [192, 168, 1, 2]);
                assert_eq!(sport, 1111);
                assert_eq!(dport, 80);
                assert_eq!(flags, 0x02);
            }
            other => panic!("expected TcpIpv4, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_udp_ipv4() {
        let mut pkt = vec![0u8; 14 + 20 + 8]; // Eth + IP + UDP
        pkt[12] = 0x08; pkt[13] = 0x00; // IPv4
        // IPv4
        pkt[14] = 0x45;
        pkt[16] = 0x00; pkt[17] = 0x1C; // total_length=28
        pkt[23] = 17;   // protocol=UDP
        pkt[26] = 10; pkt[27] = 0; pkt[28] = 0; pkt[29] = 1;
        pkt[30] = 10; pkt[31] = 0; pkt[32] = 0; pkt[33] = 2;
        // UDP
        pkt[34] = 0xC0; pkt[35] = 0x00; // src_port=49152
        pkt[36] = 0x00; pkt[37] = 0x35; // dst_port=53

        match classify(&pkt) {
            Ok((PacketClass::UdpIpv4 { sport, dport, .. }, _)) => {
                assert_eq!(sport, 49152);
                assert_eq!(dport, 53);
            }
            other => panic!("expected UdpIpv4, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_icmp_ipv4() {
        let mut pkt = vec![0u8; 14 + 20 + 4]; // Eth + IP + ICMP
        pkt[12] = 0x08; pkt[13] = 0x00; // IPv4
        pkt[14] = 0x45;
        pkt[16] = 0x00; pkt[17] = 0x18;
        pkt[23] = 1;    // protocol=ICMP
        pkt[26] = 10; pkt[27] = 0; pkt[28] = 0; pkt[29] = 1;
        pkt[30] = 10; pkt[31] = 0; pkt[32] = 0; pkt[33] = 2;
        // ICMP echo request
        pkt[34] = 8; pkt[35] = 0;

        match classify(&pkt) {
            Ok((PacketClass::IcmpIpv4 { itype, icode, .. }, _)) => {
                assert_eq!(itype, 8);
                assert_eq!(icode, 0);
            }
            other => panic!("expected IcmpIpv4, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_ipv6_tcp() {
        let mut pkt = vec![0u8; 14 + 40 + 20]; // Eth + IPv6 + TCP
        pkt[12] = 0x86; pkt[13] = 0xDD; // IPv6
        pkt[14] = 0x60; // version=6
        pkt[18] = 0x00; pkt[19] = 0x14; // payload_length=20
        pkt[20] = 6;    // next_header=TCP
        pkt[21] = 64;   // hop_limit
        // src IP: 2001::1
        pkt[22] = 0x20; pkt[23] = 0x01;
        pkt[37] = 0x01;
        // dst IP: 2001::2
        pkt[38] = 0x20; pkt[39] = 0x01;
        pkt[53] = 0x02;
        // TCP header
        pkt[54] = 0xC0; pkt[55] = 0x15; // dport=443
        pkt[56] = 0x01; pkt[57] = 0xBB; // sport=443
        pkt[66] = 0x50; // data_offset=5
        pkt[67] = 0x12; // flags=SYN+ACK

        match classify(&pkt) {
            Ok((PacketClass::TcpIpv6 { dport, flags, .. }, _)) => {
                assert_eq!(dport, 443);
                assert_eq!(flags, 0x12);
            }
            other => panic!("expected TcpIpv6, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_ipv6_udp() {
        let mut pkt = vec![0u8; 14 + 40 + 8]; // Eth + IPv6 + UDP
        pkt[12] = 0x86; pkt[13] = 0xDD; // IPv6
        pkt[14] = 0x60;
        pkt[18] = 0x00; pkt[19] = 0x08; // payload_length=8
        pkt[20] = 17;   // next_header=UDP
        pkt[21] = 255;  // hop_limit
        pkt[22] = 0x20; pkt[23] = 0x01;
        pkt[54] = 0x13; pkt[55] = 0x89; // src_port=5001
        pkt[56] = 0x00; pkt[57] = 0x35; // dst_port=53

        match classify(&pkt) {
            Ok((PacketClass::UdpIpv6 { sport, dport, .. }, _)) => {
                assert_eq!(sport, 5001);
                assert_eq!(dport, 53);
            }
            other => panic!("expected UdpIpv6, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_too_short() {
        assert_eq!(classify(&[0u8; 5]), Err(ParseError::TooShort));
    }

    #[test]
    fn test_classify_arp() {
        let mut arp = [0u8; 42];
        arp[12] = 0x08; arp[13] = 0x06; // ARP
        match classify(&arp) {
            Ok((PacketClass::Other, _)) => {} // OK
            other => panic!("expected Other for ARP, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_ip_raw() {
        // IPv4 TCP SYN to port 443
        let mut ip = [0u8; 40]; // 20 IP + 20 TCP
        ip[0] = 0x45;
        ip[2] = 0x00; ip[3] = 0x28; // total_length=40
        ip[9] = 6; // TCP
        ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 1;
        ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 2;
        // TCP
        ip[20] = 0x10; ip[21] = 0x92; // src_port=4242
        ip[22] = 0x01; ip[23] = 0xBB; // dst_port=443
        ip[32] = 0x50; // data_offset=5
        ip[33] = 0x02; // SYN

        match classify_ip(&ip) {
            Ok((PacketClass::TcpIpv4 { sport, dport, flags, .. }, _)) => {
                assert_eq!(sport, 4242);
                assert_eq!(dport, 443);
                assert_eq!(flags, 0x02);
            }
            other => panic!("expected TcpIpv4, got {:?}", other),
        }
    }

    #[test]
    fn test_tcp_flags_all() {
        assert_eq!(tcp_flags_string(0x01), "F");
        assert_eq!(tcp_flags_string(0x04), "R");
        assert_eq!(tcp_flags_string(0x08), "P");
        assert_eq!(tcp_flags_string(0x10), "A");
        assert_eq!(tcp_flags_string(0x20), "U");
        assert_eq!(tcp_flags_string(0x0A), "SP"); // SYN+PSH
        assert_eq!(tcp_flags_string(0x39), "FPAU"); // FIN+PSH+ACK+URG
    }

    #[test]
    fn test_parse_ethernet_vlan() {
        let mut frame = [0u8; 22];
        frame[12] = 0x81; frame[13] = 0x00; // VLAN tag
        frame[14] = 0x00; frame[15] = 0x01; // VLAN ID 1
        frame[16] = 0x08; frame[17] = 0x00; // Inner EtherType IPv4
        frame[18] = 0x45; // IP

        let (ethertype, offset, _) = parse_ethernet(&frame).unwrap();
        assert_eq!(ethertype, 0x0800);
        assert_eq!(offset, 18);
    }

    #[test]
    fn test_parse_ethernet_too_short() {
        assert!(parse_ethernet(&[0u8; 10]).is_none());
        // VLAN needs 18 bytes
        let mut vlan = [0u8; 17];
        vlan[12] = 0x81; vlan[13] = 0x00;
        assert!(parse_ethernet(&vlan).is_none());
    }

    #[test]
    fn test_classify_ip_v6_udp() {
        // IPv6 UDP
        let mut data = [0u8; 48]; // 40 IPv6 + 8 UDP
        data[0] = 0x60; // version=6
        data[4] = 0x00; data[5] = 0x08; // payload_length=8
        data[6] = 17;   // next_header=UDP
        // UDP header at offset 40
        data[40] = 0x00; data[41] = 0x35; // src_port=53
        data[42] = 0x08; data[43] = 0xAE; // dst_port=2222

        match classify_ip(&data) {
            Ok((PacketClass::UdpIpv6 { sport, dport, .. }, _)) => {
                assert_eq!(sport, 53);
                assert_eq!(dport, 2222);
            }
            other => panic!("expected UdpIpv6, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_ip_empty() {
        assert_eq!(classify_ip(&[]), Err(ParseError::TooShort));
    }

    #[test]
    fn test_classify_ip_not_ip() {
        // Version=0
        let data = [0u8; 20];
        assert_eq!(classify_ip(&data), Err(ParseError::NotIPv4));
    }
}
