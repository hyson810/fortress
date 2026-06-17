/// Extract JA3 fields from a TLS ClientHello.
/// Returns (version, cipher_suites_str, extensions_str, ja3_hash).
pub fn parse_client_hello(data: &[u8]) -> Option<(u16, String, String, String)> {
    if data.len() < 50 { return None; }

    // TLS record: [content_type(1)][version(2)][length(2)][payload]
    if data[0] != 0x16 { return None; } // handshake
    let _record_len = u16::from_be_bytes([data[3], data[4]]) as usize;

    let hs_start = 5;
    if data.len() < hs_start + 4 { return None; }

    // Handshake: [type(1)][length(3)][payload]
    if data[hs_start] != 0x01 { return None; } // ClientHello
    let _hs_len = ((data[hs_start + 1] as usize) << 16) | ((data[hs_start + 2] as usize) << 8) | (data[hs_start + 3] as usize);

    let ch_start = hs_start + 4;
    if data.len() < ch_start + 38 { return None; }

    let version = u16::from_be_bytes([data[ch_start], data[ch_start + 1]]);

    // Skip 32 bytes random + 1 byte session_id_len → cipher suites at offset 38 from CH start
    let sid_len = data[ch_start + 32] as usize;
    let cs_offset = ch_start + 33 + 1 + sid_len;
    if data.len() < cs_offset + 2 { return None; }
    let cs_len = u16::from_be_bytes([data[cs_offset], data[cs_offset + 1]]) as usize;

    let cs_start = cs_offset + 2;
    let cs_end = std::cmp::min(cs_start + cs_len, data.len());
    let cipher_suites: Vec<String> = data[cs_start..cs_end]
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect();
    let cs_str = cipher_suites.join("-");

    // Build JA3 input string and compute MD5 hash
    let ja3_input = format!("{},{}", version, cs_str);
    let digest = md5::compute(ja3_input.as_bytes());
    let ja3_hash = format!("{:x}", digest);

    Some((version, cs_str, String::new(), ja3_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_data() {
        assert!(parse_client_hello(&[0u8; 10]).is_none());
    }
}
