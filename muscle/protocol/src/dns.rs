// ── DNS Protocol Parsing ─────────────────────────────────────────
//
// Full DNS message parser with compression-pointer resolution,
// record-type constants, and DNS-tunnel detection heuristics
// that run in Rust before Go sees the data.

// ── DNS record type constants ────────────────────────────────────

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_ANY: u16 = 255;

// ── DNS class constants ────────────────────────────────────────

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_CH: u16 = 3;

// ── Data types ──────────────────────────────────────────────────

/// A fully parsed DNS message.
#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

/// A single DNS question section entry.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A single DNS resource record.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

// ── Low-level helpers ────────────────────────────────────────────

/// Convert a u16 DNS record type to a human-readable string.
pub fn dns_type_name(t: u16) -> &'static str {
    match t {
        DNS_TYPE_A => "A",
        DNS_TYPE_NS => "NS",
        DNS_TYPE_CNAME => "CNAME",
        DNS_TYPE_SOA => "SOA",
        DNS_TYPE_PTR => "PTR",
        DNS_TYPE_MX => "MX",
        DNS_TYPE_TXT => "TXT",
        DNS_TYPE_AAAA => "AAAA",
        DNS_TYPE_SRV => "SRV",
        DNS_TYPE_OPT => "OPT",
        DNS_TYPE_ANY => "ANY",
        _ => "UNKNOWN",
    }
}

/// Parse a DNS name with full compression-pointer resolution.
///
/// Returns (resolved_name, bytes_consumed).
/// Handles nested compression pointers (pointer → pointer → label).
#[allow(unused_assignments)]
fn parse_dns_name_full(data: &[u8], offset: usize, max_hops: usize) -> Option<(String, usize)> {
    if offset >= data.len() || max_hops == 0 {
        return None;
    }

    let mut name = String::new();
    let mut pos = offset;
    // Initialized in every branch that reaches the return
    let mut final_pos = 0usize;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len = data[pos] as usize;

        if len == 0 {
            // End of name — advance past the zero-length octet
            final_pos = pos + 1;
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes, then resolve via recursion
            if pos + 1 >= data.len() {
                return None;
            }
            let pointer = (((len & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            if pointer >= data.len() {
                return None;
            }
            // final_pos stays at the 2-byte pointer boundary
            final_pos = pos + 2;
            let (rest, _) = parse_dns_name_full(data, pointer, max_hops - 1)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&rest);
            break;
        }

        if len > 63 {
            // Invalid label length
            return None;
        }

        if pos + 1 + len > data.len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }

        name.push_str(&String::from_utf8_lossy(
            &data[pos + 1..pos + 1 + len]
        ));

        pos += 1 + len;
    }

    Some((name, final_pos))
}

/// Parse a DNS name from wire format (legacy / simple interface).
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

/// Parse a single DNS question at offset.
/// Returns (question, next_offset).
fn parse_dns_question(data: &[u8], offset: usize) -> Option<(DnsQuestion, usize)> {
    let (name, pos) = parse_dns_name_full(data, offset, 10)?;
    if pos + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    Some((DnsQuestion { name, qtype, qclass }, pos + 4))
}

/// Parse a single DNS resource record at offset.
/// Returns (record, next_offset).
fn parse_dns_record(data: &[u8], offset: usize) -> Option<(DnsRecord, usize)> {
    let (name, pos) = parse_dns_name_full(data, offset, 10)?;
    if pos + 10 > data.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
    let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]);
    let rd_start = pos + 10;
    let rd_end = rd_start + rdlength as usize;
    if rd_end > data.len() {
        return None;
    }
    let rdata = data[rd_start..rd_end].to_vec();
    Some((DnsRecord { name, rtype, rclass, ttl, rdlength, rdata }, rd_end))
}

// ── Public parse functions ──────────────────────────────────────

/// Check if data is a DNS packet and extract the first query.
pub fn parse_dns_query(data: &[u8]) -> Option<String> {
    if data.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 { return None; }
    parse_dns_name(data, 12).map(|(name, _)| name)
}

/// Parse a complete DNS message with all sections.
pub fn parse_dns_message(data: &[u8]) -> Option<DnsMessage> {
    if data.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;
    let mut questions = Vec::with_capacity(qdcount);
    let mut answers = Vec::with_capacity(ancount);
    let mut authorities = Vec::with_capacity(nscount);
    let mut additionals = Vec::with_capacity(arcount);

    // Questions
    for _ in 0..qdcount {
        let (q, next) = parse_dns_question(data, pos)?;
        questions.push(q);
        pos = next;
    }

    // Answers
    for _ in 0..ancount {
        let (r, next) = parse_dns_record(data, pos)?;
        answers.push(r);
        pos = next;
    }

    // Authorities
    for _ in 0..nscount {
        let (r, next) = parse_dns_record(data, pos)?;
        authorities.push(r);
        pos = next;
    }

    // Additionals
    for _ in 0..arcount {
        let (r, next) = parse_dns_record(data, pos)?;
        additionals.push(r);
        pos = next;
    }

    Some(DnsMessage {
        transaction_id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
}

/// Extract the QR (query/response) bit from DNS flags.
pub fn dns_is_response(flags: u16) -> bool {
    (flags & 0x8000) != 0
}

/// Extract the RCODE from DNS flags.
pub fn dns_rcode(flags: u16) -> u8 {
    (flags & 0x000F) as u8
}

// ── DNS tunnel detection ─────────────────────────────────────────

/// Check whether a DNS query name looks suspicious (potential DNS tunneling).
///
/// Heuristics:
/// - Very long labels (> 40 chars in a single label)
/// - Overall query length > 120 chars
/// - High ratio of hex characters (encoded data)
/// - Labels that look like base32/base64/noise
/// - Very high label count (> 10 labels)
pub fn is_suspicious_query(name: &str) -> bool {
    let name = name.to_lowercase();

    // Skip known safe domains (reverse lookups, local, etc.)
    if name.ends_with(".arpa") || name.ends_with(".local") || name.ends_with(".localhost") {
        return false;
    }

    let labels: Vec<&str> = name.split('.').collect();

    // Too many labels
    if labels.len() > 10 {
        return true;
    }

    // Very long overall
    if name.len() > 120 {
        return true;
    }

    // Check each label
    for label in &labels {
        let ll = label.len();

        // Individual label too long
        if ll > 40 {
            return true;
        }

        // Long labels with high hex character ratio
        if ll > 15 {
            let hex_count = label.chars().filter(|c| c.is_ascii_hexdigit()).count();
            if hex_count as f64 / ll as f64 > 0.85 {
                return true;
            }
        }

        // Labels with high unique character entropy in a long label
        if ll > 25 {
            let unique: std::collections::BTreeSet<char> = label.chars().collect();
            if unique.len() as f64 / ll as f64 > 0.45 {
                return true;
            }
        }
    }

    false
}

/// Compute Shannon entropy of a DNS query name (bits per character).
/// High entropy suggests encrypted / encoded data.
pub fn query_entropy(name: &str) -> f64 {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Convenience: check both suspicion and entropy.
/// Returns (is_suspicious, entropy).
pub fn analyze_query(name: &str) -> (bool, f64) {
    (is_suspicious_query(name), query_entropy(name))
}

// ── DNS rdata helpers ────────────────────────────────────────────

/// Extract an IPv4 address from an A-record rdata.
pub fn rdata_to_ipv4(rdata: &[u8]) -> Option<[u8; 4]> {
    if rdata.len() == 4 {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(rdata);
        Some(ip)
    } else {
        None
    }
}

/// Extract an IPv6 address from an AAAA-record rdata.
pub fn rdata_to_ipv6(rdata: &[u8]) -> Option<[u8; 16]> {
    if rdata.len() == 16 {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(rdata);
        Some(ip)
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════

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

    #[test]
    fn test_parse_dns_message_simple() {
        let dns: [u8; 28] = [
            0x12, 0x34, // tx id = 0x1234
            0x01, 0x00, // flags (standard query)
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount = 0
            0x00, 0x00, // nscount = 0
            0x00, 0x00, // arcount = 0
            0x06, b'g',b'o',b'o',b'g',b'l',b'e',
            0x03, b'c',b'o',b'm',
            0x00,
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
        ];
        let msg = parse_dns_message(&dns).unwrap();
        assert_eq!(msg.transaction_id, 0x1234);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "google.com");
        assert_eq!(msg.questions[0].qtype, DNS_TYPE_A);
        assert_eq!(msg.answers.len(), 0);
        assert_eq!(msg.authorities.len(), 0);
        assert_eq!(msg.additionals.len(), 0);
    }

    #[test]
    fn test_parse_dns_message_with_answers() {
        // Query response for A record with one answer
        let mut dns = Vec::new();
        // Header
        dns.extend_from_slice(&0x00u16.to_be_bytes()); // tx id
        dns.extend_from_slice(&0x8000u16.to_be_bytes()); // flags (QR=1)
        dns.extend_from_slice(&1u16.to_be_bytes());     // qdcount = 1
        dns.extend_from_slice(&1u16.to_be_bytes());     // ancount = 1
        dns.extend_from_slice(&0u16.to_be_bytes());     // nscount = 0
        dns.extend_from_slice(&0u16.to_be_bytes());     // arcount = 0
        // Question: example.com A
        dns.push(7); dns.extend_from_slice(b"example");
        dns.push(3); dns.extend_from_slice(b"com");
        dns.push(0); // end of name
        dns.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        dns.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // Answer: compressed name pointer to question
        dns.push(0xC0); dns.push(0x0C); // pointer to offset 12
        dns.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        dns.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        dns.extend_from_slice(&300u32.to_be_bytes()); // TTL
        dns.extend_from_slice(&4u16.to_be_bytes());   // rdlength = 4
        dns.extend_from_slice(&[93, 184, 216, 34]);   // 93.184.216.34

        let msg = parse_dns_message(&dns).unwrap();
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "example.com");
        assert_eq!(msg.answers[0].ttl, 300);
        assert_eq!(msg.answers[0].rdata, vec![93, 184, 216, 34]);
        assert!(dns_is_response(msg.flags));
    }

    #[test]
    fn test_dns_compression_pointer_resolution() {
        // Build a DNS message with compressed name pointer in answer
        let mut dns = Vec::new();
        // Header
        dns.extend_from_slice(&0xABu16.to_be_bytes());
        dns.extend_from_slice(&0x80u16.to_be_bytes()); // response
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&0u16.to_be_bytes());
        dns.extend_from_slice(&0u16.to_be_bytes());
        // Question: test.example.com A IN
        let name_start = dns.len();
        dns.push(4); dns.extend_from_slice(b"test");
        dns.push(7); dns.extend_from_slice(b"example");
        dns.push(3); dns.extend_from_slice(b"com");
        dns.push(0);
        dns.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        dns.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // Answer: pointer back to question name
        let name_ptr = name_start;
        dns.push(0xC0 | ((name_ptr >> 8) & 0x3F) as u8);
        dns.push((name_ptr & 0xFF) as u8);
        dns.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        dns.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        dns.extend_from_slice(&3600u32.to_be_bytes());
        dns.extend_from_slice(&4u16.to_be_bytes());
        dns.extend_from_slice(&[1, 2, 3, 4]);

        let msg = parse_dns_message(&dns).unwrap();
        assert_eq!(msg.answers[0].name, "test.example.com");
        assert_eq!(rdata_to_ipv4(&msg.answers[0].rdata), Some([1, 2, 3, 4]));
    }

    #[test]
    fn test_dns_truncated() {
        assert!(parse_dns_message(&[0u8; 5]).is_none());
        assert!(parse_dns_query(&[0u8; 5]).is_none());
    }

    #[test]
    fn test_dns_no_questions() {
        let header = [0u8; 12]; // all zero → qdcount = 0
        assert!(parse_dns_query(&header).is_none());
    }

    #[test]
    fn test_dns_type_names() {
        assert_eq!(dns_type_name(DNS_TYPE_A), "A");
        assert_eq!(dns_type_name(DNS_TYPE_AAAA), "AAAA");
        assert_eq!(dns_type_name(DNS_TYPE_CNAME), "CNAME");
        assert_eq!(dns_type_name(DNS_TYPE_MX), "MX");
        assert_eq!(dns_type_name(DNS_TYPE_TXT), "TXT");
        assert_eq!(dns_type_name(DNS_TYPE_SOA), "SOA");
        assert_eq!(dns_type_name(DNS_TYPE_SRV), "SRV");
        assert_eq!(dns_type_name(999), "UNKNOWN");
    }

    #[test]
    fn test_dns_is_response() {
        assert!(dns_is_response(0x8000));
        assert!(!dns_is_response(0x0000));
    }

    #[test]
    fn test_dns_rcode() {
        assert_eq!(dns_rcode(0x0000), 0); // NOERROR
        assert_eq!(dns_rcode(0x0001), 1); // FORMERR
        assert_eq!(dns_rcode(0x0003), 3); // NXDOMAIN
        assert_eq!(dns_rcode(0x0005), 5); // REFUSED
    }

    // ── Tunnel detection tests ─────────────────────────────────

    #[test]
    fn test_suspicious_long_label() {
        // A 50-character hex label
        let name: String = std::iter::repeat("a").take(50).collect::<String>() + ".example.com";
        assert!(is_suspicious_query(&name));
    }

    #[test]
    fn test_suspicious_hex_heavy() {
        let name = "deadbeefcafebabef00ddeadbeefcafe.example.com";
        assert!(is_suspicious_query(&name));
    }

    #[test]
    fn test_suspicious_high_entropy_label() {
        // High unique character ratio
        let name = "abcdefghijklmnopqrstuvwxyz0123456789.test.com";
        assert!(is_suspicious_query(&name));
    }

    #[test]
    fn test_not_suspicious_normal() {
        assert!(!is_suspicious_query("google.com"));
        assert!(!is_suspicious_query("www.example.org"));
        assert!(!is_suspicious_query("api.github.com"));
    }

    #[test]
    fn test_not_suspicious_arpa() {
        assert!(!is_suspicious_query("1.0.0.127.in-addr.arpa"));
        assert!(!is_suspicious_query("8.8.8.8.in-addr.arpa"));
    }

    #[test]
    fn test_not_suspicious_local() {
        assert!(!is_suspicious_query("myhost.local"));
        assert!(!is_suspicious_query("printer.localhost"));
    }

    #[test]
    fn test_query_entropy_low() {
        let entropy = query_entropy("google.com");
        assert!(entropy < 4.0); // Low entropy for normal domains
    }

    #[test]
    fn test_query_entropy_high() {
        let entropy = query_entropy("dGhpcyBpcyBhIHR1bm5lbGVkIHN0cmluZw==");
        assert!(entropy > 4.0); // High entropy for base64-like data
    }

    #[test]
    fn test_query_entropy_empty() {
        assert_eq!(query_entropy(""), 0.0);
    }

    #[test]
    fn test_analyze_query_normal() {
        let (suspicious, entropy) = analyze_query("api.github.com");
        assert!(!suspicious);
        assert!(entropy < 4.0);
    }

    #[test]
    fn test_rdata_to_ipv4() {
        assert_eq!(rdata_to_ipv4(&[192, 168, 1, 1]), Some([192, 168, 1, 1]));
        assert_eq!(rdata_to_ipv4(&[1, 2, 3]), None); // too short
        assert_eq!(rdata_to_ipv4(&[1, 2, 3, 4, 5]), None); // too long
    }

    #[test]
    fn test_rdata_to_ipv6() {
        let ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(rdata_to_ipv6(&ip), Some(ip));
        assert_eq!(rdata_to_ipv6(&[1, 2, 3]), None);
    }

    #[test]
    fn test_parse_dns_message_multi_question() {
        // Two questions
        let mut dns = Vec::new();
        dns.extend_from_slice(&0u16.to_be_bytes()); // tx id
        dns.extend_from_slice(&0u16.to_be_bytes()); // flags
        dns.extend_from_slice(&2u16.to_be_bytes()); // qdcount = 2
        dns.extend_from_slice(&0u16.to_be_bytes()); // ancount
        dns.extend_from_slice(&0u16.to_be_bytes()); // nscount
        dns.extend_from_slice(&0u16.to_be_bytes()); // arcount
        // Q1: foo.com A
        dns.push(3); dns.extend_from_slice(b"foo");
        dns.push(3); dns.extend_from_slice(b"com");
        dns.push(0);
        dns.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        dns.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // Q2: bar.org AAAA
        dns.push(3); dns.extend_from_slice(b"bar");
        dns.push(3); dns.extend_from_slice(b"org");
        dns.push(0);
        dns.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        dns.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let msg = parse_dns_message(&dns).unwrap();
        assert_eq!(msg.questions.len(), 2);
        assert_eq!(msg.questions[0].name, "foo.com");
        assert_eq!(msg.questions[0].qtype, DNS_TYPE_A);
        assert_eq!(msg.questions[1].name, "bar.org");
        assert_eq!(msg.questions[1].qtype, DNS_TYPE_AAAA);
    }
}
