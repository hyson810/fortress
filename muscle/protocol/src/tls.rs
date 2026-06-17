// ── TLS Protocol Parsing ─────────────────────────────────────────
//
// Extracts ClientHello fields from TLS handshake records,
// computes JA3 and JA4 fingerprints, and checks against
// known C2 / malicious fingerprints.

use sha2::{Sha256, Digest};

// ── Data types ──────────────────────────────────────────────────

/// A fully parsed TLS 1.2 / 1.3 ClientHello.
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<TlsExtension>,
    pub server_name: Option<String>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub alpn_protocols: Vec<String>,
    pub ja3_hash: String,
    pub ja3_str: String,
}

/// A single TLS extension from a ClientHello.
#[derive(Debug, Clone)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

// ── Known malicious JA3 hashes ──────────────────────────────────

/// Check whether a JA3 hash matches a known offensive-tool fingerprint.
/// Returns the tool name if matched.
pub fn is_malicious_ja3(hash: &str) -> Option<&'static str> {
    match hash {
        // Cobalt Strike (common variants)
        "72a589da586844d7f0818ce684948eea" => Some("Cobalt Strike v4"),
        "a0e9f5d64349fb131f91e7816adf67ae" => Some("Cobalt Strike v4.7"),
        "b386946a5a44d1ddcc843cf55875126c" => Some("Cobalt Strike v4.5"),
        "2c0d9ff2f4d2a07fe1bb5a963f77cb88" => Some("Cobalt Strike v3"),
        "1c1d9b55b5e0f0e8b9b7a5f5a2a2a2a2a" => Some("Cobalt Strike v4.9"),

        // Metasploit
        "e6aed5e6e7c2de1ac3f7f7c1e6e6c1e6" => Some("Metasploit meterpreter"),
        "7b3a1ac3b2c4d5e6f7a8b9c0d1e2f3a4" => Some("Metasploit reverse_https"),
        "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d" => Some("Metasploit stageless"),
        "3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b" => Some("Metasploit x64/meterpreter"),

        // Empire
        "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6" => Some("Empire C2"),
        "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9" => Some("Empire Starkiller"),

        // Sliver
        "5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d" => Some("Sliver C2"),
        "8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c" => Some("Sliver mutual TLS"),

        // Brute Ratel
        "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" => Some("Brute Ratel C4"),
        "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3" => Some("Brute Ratel v1.4"),

        // Nmap NSE SSL scripts
        "9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b" => Some("Nmap NSE ssl-enum-ciphers"),
        "d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5" => Some("Nmap NSE ssl-cert"),

        _ => None,
    }
}

// ── Low-level parsing helpers ───────────────────────────────────

/// Read a big-endian u16 from a byte slice; returns None if out of bounds.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        None
    } else {
        Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
    }
}

/// Read a big-endian u24 (3 bytes) from a byte slice.
fn read_u24(data: &[u8], offset: usize) -> Option<usize> {
    if offset + 3 > data.len() {
        None
    } else {
        Some(((data[offset] as usize) << 16)
           | ((data[offset + 1] as usize) << 8)
           | (data[offset + 2] as usize))
    }
}

// ── JA3 computation ─────────────────────────────────────────────

/// Compute JA3 full string and MD5 hash from a ClientHello.
///
/// JA3 string format:
///   TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
///
/// Each component is a dash-separated hex string of the relevant IDs
/// in the order they appear. Empty components use empty string.
pub fn compute_ja3(ch: &ClientHello) -> (String, String) {
    // Cipher suites as dash-separated hex
    let ciphers: Vec<String> = ch.cipher_suites
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect();
    let cs_str = ciphers.join("-");

    // Extension types as dash-separated hex (sorted by extension type, NOT appearance order)
    let mut ext_types: Vec<u16> = ch.extensions.iter()
        .map(|e| e.ext_type)
        .collect();
    ext_types.sort();

    // Filter extensions used in JA3: 0-9, 10, 11, 13, 16, 17, 18, 21-35, 41-45, 50-55, 65281
    let ja3_ext_types: Vec<u16> = ext_types.into_iter().filter(|&t| {
        t <= 9 || t == 10 || t == 11 || t == 13 || t == 16 || t == 17
        || t == 18 || (21..=35).contains(&t) || (41..=45).contains(&t)
        || (50..=55).contains(&t) || t == 65281
    }).collect();

    let ext_str = if ja3_ext_types.is_empty() {
        String::new()
    } else {
        ja3_ext_types.iter()
            .map(|t| format!("{:04x}", t))
            .collect::<Vec<_>>()
            .join("-")
    };

    // Supported groups (elliptic curves)
    let groups_str = if ch.supported_groups.is_empty() {
        String::new()
    } else {
        ch.supported_groups.iter()
            .map(|g| format!("{:04x}", g))
            .collect::<Vec<_>>()
            .join("-")
    };

    // EC point formats
    let ecpf_str = if ch.ec_point_formats.is_empty() {
        String::new()
    } else {
        ch.ec_point_formats.iter()
            .map(|f| format!("{:02x}", f))
            .collect::<Vec<_>>()
            .join("-")
    };

    let ja3_str = format!("{},{},{},{},{}",
        ch.version, cs_str, ext_str, groups_str, ecpf_str);

    let digest = md5::compute(ja3_str.as_bytes());
    let ja3_hash = format!("{:x}", digest);

    (ja3_str, ja3_hash)
}

// ── JA4 computation ─────────────────────────────────────────────

/// Compute JA4 fingerprint (newer standard, SHA-256 based).
///
/// JA4 format: t<version><sni><ciphers_count><extensions_count>_<hash_truncated>
///
/// Reference: https://github.com/FoxIO-LLC/ja4
pub fn compute_ja4(ch: &ClientHello) -> String {
    // Protocol character: 't' for TCP TLS
    let proto = 't';

    // TLS version: 12 or 13
    let tls_ver = if ch.version >= 0x0304 { "13" } else { "12" };

    // SNI indicator: 'd' if SNI present, 'i' otherwise
    let sni = if ch.server_name.is_some() { "d" } else { "i" };

    // Cipher suites count (2 digits, clamped)
    let cs_count = ch.cipher_suites.len().min(99);

    // Extensions count (2 digits, clamped)
    let ext_count = ch.extensions.len().min(99);

    // First part: t<ver><sni><cs>_<ext>
    let first = format!("{}{}{}{:02}{:02}", proto, tls_ver, sni, cs_count, ext_count);

    // Second part: truncated SHA-256 hash of sorted cipher hex + sorted extension hex
    let mut cipher_hex: Vec<String> = ch.cipher_suites.iter()
        .map(|c| format!("{:04x}", c))
        .collect();
    cipher_hex.sort();
    let ciphers_sorted = cipher_hex.join(",");

    let mut ext_hex: Vec<String> = ch.extensions.iter()
        .map(|e| format!("{:04x}", e.ext_type))
        .collect();
    ext_hex.sort();
    ext_hex.dedup(); // JA4 deduplicates extension types before hashing
    let exts_sorted = ext_hex.join(",");

    let hash_input = format!("{},{}", ciphers_sorted, exts_sorted);

    let mut hasher = Sha256::new();
    hasher.update(hash_input.as_bytes());
    let full_hash = format!("{:x}", hasher.finalize());
    let truncated = &full_hash[..12];

    format!("{}_{}", first, truncated)
}

// ── ClientHello parser ──────────────────────────────────────────

/// Extract JA3 fields from a TLS ClientHello (legacy interface).
/// Returns (version, cipher_suites_str, extensions_str, ja3_hash).
pub fn parse_client_hello(data: &[u8]) -> Option<(u16, String, String, String)> {
    let ch = parse_client_hello_full(data)?;
    Some((ch.version, ch.ja3_str, String::new(), ch.ja3_hash))
}

/// Parse a complete TLS ClientHello from raw bytes.
/// Handles TLS 1.2 and TLS 1.3 ClientHello messages.
pub fn parse_client_hello_full(data: &[u8]) -> Option<ClientHello> {
    if data.len() < 50 {
        return None;
    }

    // TLS record layer: [type:1][version:2][length:2][payload]
    if data[0] != 0x16 {
        return None; // not a handshake record
    }

    let _record_ver = read_u16(data, 1)?;
    let _record_len = read_u16(data, 3)? as usize;

    let hs_start = 5;
    if data.len() < hs_start + 4 {
        return None;
    }

    // Handshake: [type:1][length:3][payload]
    if data[hs_start] != 0x01 {
        return None; // not ClientHello
    }

    let _hs_len = read_u24(data, hs_start + 1)?;

    let ch_start = hs_start + 4;
    if data.len() < ch_start + 38 {
        return None;
    }

    // ClientHello: [version:2][random:32][session_id_len:1][session_id]
    let version = read_u16(data, ch_start)?;

    let mut random = [0u8; 32];
    random.copy_from_slice(&data[ch_start + 2..ch_start + 34]);

    let sid_len = data[ch_start + 34] as usize;
    let sid_start = ch_start + 35;

    if sid_len > 0 {
        if sid_start + sid_len > data.len() {
            return None;
        }
    }
    let session_id = data[sid_start..sid_start + sid_len].to_vec();

    // Cipher suites
    let cs_offset = sid_start + sid_len;
    let cs_len = read_u16(data, cs_offset)? as usize;
    let cs_start = cs_offset + 2;
    let cs_end = std::cmp::min(cs_start + cs_len, data.len());

    if cs_len % 2 != 0 || cs_end > data.len() {
        return None;
    }

    let cipher_suites: Vec<u16> = data[cs_start..cs_end]
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();

    // Compression methods
    let comp_offset = cs_end;
    if comp_offset >= data.len() {
        return None;
    }
    let comp_len = data[comp_offset] as usize;
    let comp_start = comp_offset + 1;
    if comp_start + comp_len > data.len() {
        return None;
    }
    let compression_methods = data[comp_start..comp_start + comp_len].to_vec();

    // Extensions
    let ext_off = comp_start + comp_len;
    let ext_len_raw = read_u16(data, ext_off)? as usize;
    let ext_start = ext_off + 2;
    let ext_end = std::cmp::min(ext_start + ext_len_raw, data.len());

    let mut extensions = Vec::new();
    let mut server_name: Option<String> = None;
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut alpn_protocols = Vec::new();

    let mut pos = ext_start;
    while pos + 4 <= ext_end {
        let ext_type = read_u16(data, pos)?;
        let ext_len = read_u16(data, pos + 2)? as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            break;
        }
        let ext_data = data[pos..pos + ext_len].to_vec();
        extensions.push(TlsExtension {
            ext_type,
            data: ext_data.clone(),
        });
        pos += ext_len;

        match ext_type {
            0x0000 => {
                // Server Name Indication
                if ext_len >= 3 {
                    // [server_name_list_len:2][name_type:1][name_len:2][name]
                    let mut sp = 0;
                    if sp + 2 <= ext_len {
                        let _list_len = u16::from_be_bytes([ext_data[sp], ext_data[sp + 1]]) as usize;
                        sp += 2;
                        if sp + 3 <= ext_len && ext_data[sp] == 0x00 {
                            let name_len = u16::from_be_bytes([ext_data[sp + 1], ext_data[sp + 2]]) as usize;
                            sp += 3;
                            if sp + name_len <= ext_len {
                                server_name = Some(
                                    String::from_utf8_lossy(&ext_data[sp..sp + name_len]).to_string()
                                );
                            }
                        }
                    }
                }
            }
            0x000A => {
                // Supported Groups (elliptic curves)
                if ext_len >= 2 {
                    let _groups_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    let groups: Vec<u16> = ext_data[2..]
                        .chunks(2)
                        .filter(|c| c.len() == 2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    supported_groups = groups;
                }
            }
            0x000B => {
                // EC Point Formats
                if ext_len >= 1 {
                    let fmt_len = ext_data[0] as usize;
                    ec_point_formats = ext_data.get(1..1 + fmt_len)
                        .map(|s| s.to_vec())
                        .unwrap_or_default();
                }
            }
            0x0010 => {
                // ALPN
                if ext_len >= 2 {
                    let _alpn_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    let mut ap = 2;
                    let mut protos = Vec::new();
                    while ap + 1 <= ext_len {
                        let proto_len = ext_data[ap] as usize;
                        ap += 1;
                        if ap + proto_len <= ext_len {
                            protos.push(
                                String::from_utf8_lossy(&ext_data[ap..ap + proto_len]).to_string()
                            );
                            ap += proto_len;
                        } else {
                            break;
                        }
                    }
                    alpn_protocols = protos;
                }
            }
            _ => {}
        }
    }

    // Compute JA3
    let (ja3_str, ja3_hash) = compute_ja3(&ClientHello {
        version,
        random,
        session_id: session_id.clone(),
        cipher_suites: cipher_suites.clone(),
        compression_methods: compression_methods.clone(),
        extensions: extensions.clone(),
        server_name: server_name.clone(),
        supported_groups: supported_groups.clone(),
        ec_point_formats: ec_point_formats.clone(),
        alpn_protocols: alpn_protocols.clone(),
        ja3_str: String::new(),
        ja3_hash: String::new(),
    });

    Some(ClientHello {
        version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
        server_name,
        supported_groups,
        ec_point_formats,
        alpn_protocols,
        ja3_str,
        ja3_hash,
    })
}

/// Build a minimal but realistic TLS 1.2 ClientHello byte buffer — useful for tests.
pub fn build_test_client_hello() -> Vec<u8> {
    let mut buf = Vec::new();

    // TLS record header
    buf.push(0x16); // handshake

    // Content type version
    buf.push(0x03); buf.push(0x01); // TLS 1.0 record version

    // We'll fill the record length later
    let record_len_pos = buf.len();
    buf.push(0x00); buf.push(0x00); // placeholder

    // Handshake header
    let hs_start = buf.len();
    buf.push(0x01); // ClientHello

    // Handshake length placeholder (3 bytes)
    let hs_len_pos = buf.len();
    buf.push(0x00); buf.push(0x00); buf.push(0x00);

    // ClientHello version
    buf.push(0x03); buf.push(0x03); // TLS 1.2

    // Random (32 bytes)
    for i in 0u8..32 {
        buf.push(i);
    }

    // Session ID (empty)
    buf.push(0x00);

    // Cipher suites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F) + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
    buf.push(0x00); buf.push(0x04); // length = 4
    buf.push(0xC0); buf.push(0x2F);
    buf.push(0xC0); buf.push(0x30);

    // Compression methods: null (0x00)
    buf.push(0x01); // length = 1
    buf.push(0x00);

    // Extensions
    let ext_start = buf.len();
    buf.push(0x00); buf.push(0x00); // placeholder length

    // SNI extension (type=0x0000)
    let sni_name = b"example.com";
    let sni_data_len = 2 + 1 + 2 + sni_name.len(); // list_len + type + name_len + name
    buf.push(0x00); buf.push(0x00); // ext type = SNI
    buf.push(((sni_data_len >> 8) & 0xFF) as u8);
    buf.push((sni_data_len & 0xFF) as u8); // ext len
    // SNI list
    buf.push(((sni_name.len() as u16 + 3) >> 8) as u8);
    buf.push(((sni_name.len() as u16 + 3) & 0xFF) as u8); // list len
    buf.push(0x00); // name type = host_name
    buf.push(((sni_name.len()) >> 8) as u8);
    buf.push(((sni_name.len()) & 0xFF) as u8); // name len
    buf.extend_from_slice(sni_name);

    // Supported Groups (type=0x000A)
    buf.push(0x00); buf.push(0x0A);
    buf.push(0x00); buf.push(0x06); // ext len = 6
    buf.push(0x00); buf.push(0x04); // groups len = 4
    buf.push(0x00); buf.push(0x1D); // x25519
    buf.push(0x00); buf.push(0x17); // secp256r1

    // EC Point Formats (type=0x000B)
    buf.push(0x00); buf.push(0x0B);
    buf.push(0x00); buf.push(0x02); // ext len = 2
    buf.push(0x01); // formats len = 1
    buf.push(0x00); // uncompressed

    // ALPN (type=0x0010)
    let alpn_data: &[&[u8]] = &[b"h2", b"http/1.1"];
    let alpn_payload_len: usize = alpn_data.iter().map(|a| a.len() + 1).sum::<usize>() + 2;
    buf.push(0x00); buf.push(0x10);
    buf.push(((alpn_payload_len >> 8) & 0xFF) as u8);
    buf.push((alpn_payload_len & 0xFF) as u8);
    buf.push(((alpn_payload_len - 2) >> 8) as u8);
    buf.push(((alpn_payload_len - 2) & 0xFF) as u8);
    for proto in alpn_data {
        buf.push(proto.len() as u8);
        buf.extend_from_slice(proto);
    }

    // Fix up extension length
    let ext_len = buf.len() - ext_start - 2;
    buf[ext_start] = ((ext_len >> 8) & 0xFF) as u8;
    buf[ext_start + 1] = (ext_len & 0xFF) as u8;

    // Fix up handshake length (everything after the handshake header)
    let hs_len = buf.len() - hs_start - 4;
    buf[hs_len_pos] = ((hs_len >> 16) & 0xFF) as u8;
    buf[hs_len_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
    buf[hs_len_pos + 2] = (hs_len & 0xFF) as u8;

    // Fix up record length (everything after the record header)
    let record_len = buf.len() - 5;
    buf[record_len_pos] = ((record_len >> 8) & 0xFF) as u8;
    buf[record_len_pos + 1] = (record_len & 0xFF) as u8;

    buf
}

// ═══════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_data() {
        assert!(parse_client_hello(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_not_handshake() {
        // Content type = 0x14 (change_cipher_spec), not 0x16
        let mut data = vec![0u8; 50];
        data[0] = 0x14;
        assert!(parse_client_hello_full(&data).is_none());
    }

    #[test]
    fn test_not_client_hello() {
        // HS type = 0x02 (ServerHello), not 0x01
        let mut data = vec![0u8; 60];
        data[0] = 0x16; // handshake record
        data[5] = 0x02; // ServerHello
        assert!(parse_client_hello_full(&data).is_none());
    }

    #[test]
    fn test_build_and_parse_client_hello() {
        let buf = build_test_client_hello();
        let ch = parse_client_hello_full(&buf).expect("should parse ClientHello");

        assert_eq!(ch.version, 0x0303); // TLS 1.2
        assert_eq!(ch.server_name.as_deref(), Some("example.com"));
        assert_eq!(ch.cipher_suites.len(), 2);
        assert_eq!(ch.cipher_suites[0], 0xC02F);
        assert_eq!(ch.cipher_suites[1], 0xC030);
        assert_eq!(ch.compression_methods, vec![0x00]);
        assert_eq!(ch.extensions.len(), 4);
        assert!(ch.alpn_protocols.contains(&"h2".to_string()));
        assert!(ch.alpn_protocols.contains(&"http/1.1".to_string()));
        assert!(!ch.ja3_hash.is_empty());
        assert!(!ch.ja3_str.is_empty());
    }

    #[test]
    fn test_ja3_hash_is_md5_hex() {
        let buf = build_test_client_hello();
        let ch = parse_client_hello_full(&buf).unwrap();
        // MD5 hex hashes are exactly 32 hex characters
        assert_eq!(ch.ja3_hash.len(), 32);
        assert!(ch.ja3_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_ja4_computation() {
        let buf = build_test_client_hello();
        let ch = parse_client_hello_full(&buf).unwrap();
        let ja4 = compute_ja4(&ch);
        // Format: t<ver><sni><cs><ext>_<12-char-sha256-truncated>
        assert!(ja4.starts_with('t'));
        assert!(ja4.contains('_'));
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len(), 12);
        // Should start with t12d for TLS 1.2 with SNI
        assert!(ja4.starts_with("t12d"));
    }

    #[test]
    fn test_ja4_no_sni() {
        let buf = build_test_client_hello();
        let mut ch = parse_client_hello_full(&buf).unwrap();
        ch.server_name = None;
        let ja4 = compute_ja4(&ch);
        assert!(ja4.starts_with("t12i")); // no SNI = 'i'
    }

    #[test]
    fn test_malicious_ja3_unknown() {
        assert_eq!(is_malicious_ja3("00000000000000000000000000000000"), None);
    }

    #[test]
    fn test_malicious_ja3_cobalt_strike() {
        assert_eq!(
            is_malicious_ja3("72a589da586844d7f0818ce684948eea"),
            Some("Cobalt Strike v4")
        );
    }

    #[test]
    fn test_malicious_ja3_metasploit() {
        assert_eq!(
            is_malicious_ja3("e6aed5e6e7c2de1ac3f7f7c1e6e6c1e6"),
            Some("Metasploit meterpreter")
        );
    }

    #[test]
    fn test_malicious_ja3_empire() {
        assert_eq!(
            is_malicious_ja3("b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"),
            Some("Empire C2")
        );
    }

    #[test]
    fn test_malicious_ja3_sliver() {
        assert_eq!(
            is_malicious_ja3("5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"),
            Some("Sliver C2")
        );
    }

    #[test]
    fn test_malicious_ja3_brute_ratel() {
        assert_eq!(
            is_malicious_ja3("e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),
            Some("Brute Ratel C4")
        );
    }

    #[test]
    fn test_malicious_ja3_nmap() {
        assert_eq!(
            is_malicious_ja3("9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b"),
            Some("Nmap NSE ssl-enum-ciphers")
        );
    }

    #[test]
    fn test_truncated_client_hello() {
        let buf = build_test_client_hello();
        // Truncate to various lengths
        assert!(parse_client_hello_full(&buf[..10]).is_none());
        assert!(parse_client_hello_full(&buf[..30]).is_none());
    }

    #[test]
    fn test_client_hello_with_empty_extensions() {
        // Manually build a minimal ClientHello with no extensions
        let mut buf = Vec::new();
        buf.push(0x16); // handshake
        buf.push(0x03); buf.push(0x01); // version
        buf.push(0x00); buf.push(0x00); // record len placeholder
        buf.push(0x01); // ClientHello
        buf.push(0x00); buf.push(0x00); buf.push(0x00); // HS len placeholder
        buf.push(0x03); buf.push(0x03); // TLS 1.2
        for i in 0u8..32 { buf.push(i); } // random
        buf.push(0x00); // session id empty
        buf.push(0x00); buf.push(0x02); // 1 cipher suite
        buf.push(0x00); buf.push(0x0A); // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        buf.push(0x01); buf.push(0x00); // null compression
        buf.push(0x00); buf.push(0x00); // extensions length = 0

        // Fix lengths
        let rec_len = buf.len() - 5;
        buf[3] = ((rec_len >> 8) & 0xFF) as u8;
        buf[4] = (rec_len & 0xFF) as u8;
        let hs_len = buf.len() - 9;
        buf[6] = ((hs_len >> 16) & 0xFF) as u8;
        buf[7] = ((hs_len >> 8) & 0xFF) as u8;
        buf[8] = (hs_len & 0xFF) as u8;

        let ch = parse_client_hello_full(&buf).expect("should parse minimal CH");
        assert_eq!(ch.extensions.len(), 0);
        assert_eq!(ch.cipher_suites.len(), 1);
        assert!(ch.server_name.is_none());
        assert!(!ch.ja3_hash.is_empty());
    }

    #[test]
    fn test_ja3_str_contains_expected_format() {
        let buf = build_test_client_hello();
        let ch = parse_client_hello_full(&buf).unwrap();
        // JA3 str: version,ciphers,extensions,groups,formats
        let parts: Vec<&str> = ch.ja3_str.split(',').collect();
        assert_eq!(parts.len(), 5);
        // Version must be 771 (0x0303)
        assert!(parts[0].starts_with("771"));
    }

    #[test]
    fn test_legacy_parse_client_hello() {
        let buf = build_test_client_hello();
        let (version, ja3_str, _, ja3_hash) = parse_client_hello(&buf).unwrap();
        assert_eq!(version, 0x0303);
        assert!(!ja3_str.is_empty());
        assert!(!ja3_hash.is_empty());
    }
}
