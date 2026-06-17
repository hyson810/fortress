/// Parsed IPv4 header fields.
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub protocol: u8,  // 6=TCP, 17=UDP, 1=ICMP
    pub ttl: u8,
    pub total_length: u16,
    pub ihl: u8,       // header length in 32-bit words
}

/// Parsed TCP header fields.
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,     // bitmask: FIN(1),SYN(2),RST(4),PSH(8),ACK(16),URG(32)
    pub window: u16,
    pub data_offset: u8, // header length in 32-bit words
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
