/// Parse a DNS query name from wire format.
/// Returns (query_name, next_offset).
pub fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        if offset >= data.len() { return None; }
        let len = data[offset] as usize;
        if len == 0 { offset += 1; break; }
        if len & 0xC0 == 0xC0 { // pointer
            if offset + 1 >= data.len() { return None; }
            offset += 2;
            break;
        }
        if !name.is_empty() { name.push('.'); }
        offset += 1;
        if offset + len > data.len() { return None; }
        name.push_str(&String::from_utf8_lossy(&data[offset..offset + len]));
        offset += len;
    }
    Some((name, offset))
}

/// Check if data is a DNS packet and extract the first query.
pub fn parse_dns_query(data: &[u8]) -> Option<String> {
    if data.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 { return None; }
    parse_dns_name(data, 12).map(|(name, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        // google.com DNS query
        let dns: [u8; 28] = [
            0x00,0x01, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
            0x06, b'g',b'o',b'o',b'g',b'l',b'e',
            0x03, b'c',b'o',b'm',
            0x00,
            0x00,0x01, 0x00,0x01,
        ];
        let name = parse_dns_query(&dns).unwrap();
        assert_eq!(name, "google.com");
    }
}
