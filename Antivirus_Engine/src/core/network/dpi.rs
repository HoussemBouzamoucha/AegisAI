// File: src/core/network/dpi.rs
//
// Selective Deep Packet Inspection engine.
//
// The DPI engine is NOT called on every connection — only when the heuristics
// score exceeds a threshold OR the ML model flags the flow as suspicious.
// This matches how production IDS/NGFW systems control cost:
//
//   heuristics score > threshold  →  trigger DPI
//   ml_score > threshold          →  trigger DPI
//   otherwise                     →  skip payload inspection entirely
//
// Each check is self-contained and returns an Option<DpiSignal>.  The engine
// accumulates all triggered signals and returns them to the scanner, which
// folds them into the connection's detection_signals and updates threat_level.
//
// ┌──────────────────────────────────────────────────────────────────┐
// │  DPI checks implemented                                          │
// │  1. Protocol mismatch  — payload doesn't match port's protocol  │
// │  2. Shellcode patterns — NOP sled, x86/x64 opcode sequences     │
// │  3. Crypto mining      — Stratum JSON (mining.subscribe etc.)   │
// │  4. Cleartext creds    — FTP PASS, HTTP Basic Auth              │
// │  5. DNS tunneling      — unusually long DNS labels on port 53   │
// │  6. HTTP command inj.  — shell commands embedded in HTTP body   │
// └──────────────────────────────────────────────────────────────────┘

use crate::core::network::types::NetworkConnection;

// ─── DpiSignal ────────────────────────────────────────────────────────────────

/// A single finding from the DPI engine.
///
/// The scanner converts each `DpiSignal` into a `DetectionSignal` with
/// `source = "dpi"` and adds `score_delta` to the connection's `threat_score`.
#[derive(Debug, Clone)]
pub struct DpiSignal {
    /// Human-readable description, shown in the UI and incident reports.
    pub description: String,
    /// Points added to the heuristic threat score.
    pub score_delta: i32,
}

impl DpiSignal {
    fn new(description: impl Into<String>, score_delta: i32) -> Self {
        Self { description: description.into(), score_delta }
    }
}

// ─── DpiEngine ────────────────────────────────────────────────────────────────

/// Stateless DPI engine.  Zero heap allocation at construction; all state is
/// local to each `inspect` call.
pub struct DpiEngine;

impl DpiEngine {
    pub fn new() -> Self { Self }

    /// Inspect captured payload bytes for a single connection.
    ///
    /// * `src_payload` — first bytes captured in the canonical-src direction
    /// * `dst_payload` — first bytes captured in the canonical-dst direction
    /// * `conn`        — the connection being inspected (supplies port/proto)
    ///
    /// Returns a (possibly empty) list of `DpiSignal`s.  An empty list means
    /// "nothing suspicious found in the payload".
    pub fn inspect(
        &self,
        src_payload: &[u8],
        dst_payload: &[u8],
        conn: &NetworkConnection,
    ) -> Vec<DpiSignal> {
        let mut signals: Vec<DpiSignal> = Vec::new();

        let remote_port = port_from_addr(&conn.remote_address).unwrap_or(0);
        let local_port  = port_from_addr(&conn.local_address).unwrap_or(0);

        // Use the canonical source payload for most outbound-traffic checks.
        // Some checks (mining, mismatch) also look at the response side.
        let all_payload: Vec<u8> = src_payload
            .iter()
            .chain(dst_payload.iter())
            .copied()
            .collect();

        if let Some(s) = Self::check_protocol_mismatch(src_payload, dst_payload, remote_port) {
            signals.push(s);
        }
        if let Some(s) = Self::check_shellcode_patterns(src_payload) {
            signals.push(s);
        }
        // Also check the response direction for injected payloads.
        if signals.is_empty() {
            if let Some(s) = Self::check_shellcode_patterns(dst_payload) {
                signals.push(s);
            }
        }
        if let Some(s) = Self::check_crypto_mining(&all_payload) {
            signals.push(s);
        }
        if let Some(s) = Self::check_cleartext_credentials(src_payload) {
            signals.push(s);
        }
        if let Some(s) = Self::check_dns_tunneling(src_payload, local_port, remote_port) {
            signals.push(s);
        }
        if let Some(s) = Self::check_http_command_injection(src_payload, remote_port) {
            signals.push(s);
        }

        signals
    }

    // ── Check 1: Protocol mismatch ────────────────────────────────────────────
    //
    // Malware frequently tunnels C2 traffic through HTTP or HTTPS ports to blend
    // in with legitimate web traffic.  If a connection lands on port 80/443 but
    // the payload doesn't resemble HTTP or TLS, that's a strong signal.

    fn check_protocol_mismatch(
        src: &[u8],
        dst: &[u8],
        remote_port: u16,
    ) -> Option<DpiSignal> {
        if src.is_empty() && dst.is_empty() { return None; }

        match remote_port {
            // HTTP ports: first bytes should be an HTTP method or "HTTP/" response.
            80 | 8080 | 8000 | 8888 => {
                let looks_http = is_http_request(src) || is_http_response(src)
                    || is_http_request(dst) || is_http_response(dst);
                if !looks_http && !src.is_empty() {
                    return Some(DpiSignal::new(
                        "Non-HTTP payload on HTTP port (possible C2 tunneling)",
                        20,
                    ));
                }
            }

            // HTTPS ports: first bytes should be a TLS ClientHello (0x16 0x03 xx).
            443 | 8443 | 4443 => {
                let looks_tls = starts_with_tls(src) || starts_with_tls(dst);
                if !looks_tls && !src.is_empty() {
                    return Some(DpiSignal::new(
                        "Cleartext payload on TLS port (masquerading as HTTPS)",
                        25,
                    ));
                }
            }

            // SSH: banner must start with "SSH-".
            22 => {
                let looks_ssh = src.starts_with(b"SSH-") || dst.starts_with(b"SSH-");
                if !looks_ssh && !src.is_empty() {
                    return Some(DpiSignal::new(
                        "Non-SSH payload on SSH port (possible backdoor or tunneling)",
                        18,
                    ));
                }
            }

            _ => {}
        }
        None
    }

    // ── Check 2: Shellcode patterns ───────────────────────────────────────────
    //
    // NOP sleds (0x90 sequences ≥ 8) are the clearest signal; they're placed
    // before shellcode to ensure control lands somewhere in the sled.
    // x86 "jmp-to-register" gadgets are also checked (0xff e4/e8/e3).

    fn check_shellcode_patterns(payload: &[u8]) -> Option<DpiSignal> {
        if payload.len() < 16 { return None; }

        // NOP sled: 8+ consecutive 0x90 bytes.
        if payload.windows(8).any(|w| w.iter().all(|&b| b == 0x90)) {
            return Some(DpiSignal::new(
                "NOP sled in payload (x86 shellcode pre-jump padding)",
                35,
            ));
        }

        // x86 jump-to-register gadgets often used to pivot to shellcode:
        //   ff e4 = JMP ESP    ff e8 = JMP ECX (unusual)
        //   ff e3 = JMP EBX    ff d0 = CALL EAX
        let jmp_gadgets: &[&[u8]] = &[b"\xff\xe4", b"\xff\xe8", b"\xff\xe3", b"\xff\xd0"];
        let gadget_count = jmp_gadgets
            .iter()
            .map(|g| payload.windows(2).filter(|w| w == g).count())
            .sum::<usize>();
        if gadget_count >= 3 {
            return Some(DpiSignal::new(
                "Repeated JMP/CALL register gadgets in payload (heap-spray pattern)",
                28,
            ));
        }

        // INT 3 spray (0xcc bytes): used in shellcode debugging / spray exploitation.
        let int3_count = payload.iter().filter(|&&b| b == 0xcc).count();
        if int3_count >= 16 && payload.len() >= 32 && int3_count * 2 > payload.len() {
            return Some(DpiSignal::new(
                "INT3 spray in payload (debugger breakpoint exploitation pattern)",
                22,
            ));
        }

        None
    }

    // ── Check 3: Crypto mining ────────────────────────────────────────────────
    //
    // The Stratum mining protocol sends JSON blobs with well-known method names.
    // Mining traffic through unexpected ports is a clear signal.

    fn check_crypto_mining(payload: &[u8]) -> Option<DpiSignal> {
        let s = std::str::from_utf8(payload).unwrap_or("");
        let mining_markers = [
            "mining.subscribe",
            "mining.authorize",
            "mining.notify",
            "mining.submit",
            "stratum+tcp",
            "stratum+ssl",
            "\"method\":\"eth_",     // Ethereum mining RPC
            "\"method\":\"getwork\"",
        ];
        if mining_markers.iter().any(|m| s.contains(m)) {
            return Some(DpiSignal::new(
                "Crypto mining Stratum protocol detected in payload",
                35,
            ));
        }
        None
    }

    // ── Check 4: Cleartext credentials ───────────────────────────────────────
    //
    // FTP sends passwords in cleartext (PASS command).
    // HTTP Basic Auth base64-encodes credentials but still transmits them
    // unencrypted — detectable from the Authorization header.

    fn check_cleartext_credentials(payload: &[u8]) -> Option<DpiSignal> {
        // Attempt UTF-8; fall back silently if binary.
        let s = match std::str::from_utf8(payload) {
            Ok(s)  => s,
            Err(_) => return None,
        };

        // FTP PASS command.
        if s.to_uppercase().starts_with("PASS ") && s.len() > 6 {
            return Some(DpiSignal::new(
                "Cleartext FTP password in payload (PASS command)",
                14,
            ));
        }

        // HTTP Basic Authentication header.
        if s.contains("Authorization: Basic ") {
            return Some(DpiSignal::new(
                "HTTP Basic Auth credentials transmitted in cleartext",
                10,
            ));
        }

        // HTTP form data containing 'password=' or 'passwd='.
        let lower = s.to_lowercase();
        if lower.contains("password=") || lower.contains("passwd=") {
            return Some(DpiSignal::new(
                "Cleartext password field in HTTP form data",
                8,
            ));
        }

        None
    }

    // ── Check 5: DNS tunneling ────────────────────────────────────────────────
    //
    // DNS labels are at most 63 bytes by spec.  Tunneling tools (iodine, dnscat2)
    // max out labels to encode binary data, producing labels far longer than
    // any legitimate hostname component.
    //
    // We scan the question section (after the 12-byte DNS header) looking for
    // suspiciously long label runs.

    fn check_dns_tunneling(payload: &[u8], local_port: u16, remote_port: u16) -> Option<DpiSignal> {
        // Only apply to DNS traffic.
        if local_port != 53 && remote_port != 53 { return None; }
        if payload.len() < 20 { return None; }

        // Skip the 12-byte DNS header.
        let question = &payload[12.min(payload.len())..];
        let mut max_label_len = 0usize;
        let mut current_label = 0usize;

        for &byte in question {
            if byte == 0 {
                // Null terminator — end of QNAME.
                break;
            } else if byte < 0x20 || byte > 0x7e {
                // Length octet or non-ASCII: end of current label run.
                max_label_len = max_label_len.max(current_label);
                current_label = 0;
            } else {
                current_label += 1;
            }
        }
        max_label_len = max_label_len.max(current_label);

        if max_label_len > 50 {
            return Some(DpiSignal::new(
                format!(
                    "DNS label length {} bytes exceeds normal hostnames (possible DNS tunneling)",
                    max_label_len
                ),
                20,
            ));
        }

        None
    }

    // ── Check 6: HTTP command injection ──────────────────────────────────────
    //
    // Shell commands embedded in HTTP request paths or bodies indicate
    // web-shell traffic, command injection, or C2 using HTTP as a carrier.

    fn check_http_command_injection(payload: &[u8], remote_port: u16) -> Option<DpiSignal> {
        // Only inspect HTTP ports.
        if !matches!(remote_port, 80 | 8080 | 8000 | 8888) { return None; }
        if payload.len() < 4 { return None; }

        let s = match std::str::from_utf8(payload) {
            Ok(s)  => s,
            Err(_) => return None,
        };

        // Shell invocations in HTTP paths or POST bodies.
        let shell_markers = [
            "/bin/sh", "/bin/bash", "cmd.exe", "cmd /c",
            "powershell", "powershell.exe",
            "wget http", "curl http", "curl -",
            "nc -e", "netcat",
            "; cat /", "&& cat /",        // command chaining
            "| base64", "base64 -d",      // decode+exec pattern
        ];

        // URL-encoded variants of common injection chars.
        let encoded_markers = ["%2Fbin%2Fsh", "%2Fbin%2Fbash", "cmd%20%2Fc"];

        let lower = s.to_lowercase();
        let hit = shell_markers.iter().any(|m| lower.contains(m))
            || encoded_markers.iter().any(|m| lower.contains(&m.to_lowercase()));

        if hit {
            return Some(DpiSignal::new(
                "Shell command embedded in HTTP payload (possible web-shell or command injection)",
                25,
            ));
        }

        None
    }
}

impl Default for DpiEngine {
    fn default() -> Self { Self }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Extract the port number from an IP:port address string.
/// Handles IPv4 ("1.2.3.4:80"), IPv6 ("[::1]:443"), and listener form ("0.0.0.0:*").
fn port_from_addr(addr: &str) -> Option<u16> {
    if addr.ends_with(":*") { return None; }
    if addr.starts_with('[') {
        if let Some(i) = addr.rfind(']') {
            return addr[i + 1..].trim_start_matches(':').parse().ok();
        }
    }
    addr.rfind(':').and_then(|c| addr[c + 1..].parse().ok())
}

fn is_http_request(payload: &[u8]) -> bool {
    let methods: &[&[u8]] = &[
        b"GET ", b"POST ", b"PUT ", b"DELETE ",
        b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    ];
    methods.iter().any(|m| payload.starts_with(m))
}

fn is_http_response(payload: &[u8]) -> bool {
    payload.starts_with(b"HTTP/1") || payload.starts_with(b"HTTP/2")
}

fn starts_with_tls(payload: &[u8]) -> bool {
    // TLS record layer: content-type (0x16 = Handshake) + version (0x03 xx)
    payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_conn(local: &str, remote: &str, proto: &str) -> NetworkConnection {
        NetworkConnection::new(proto, local, remote, "ESTABLISHED", None, None)
    }

    // ── Protocol mismatch ─────────────────────────────────────────────────────

    #[test]
    fn test_http_port_binary_payload_flagged() {
        let engine = DpiEngine::new();
        // 16 random-looking bytes on port 80 — not HTTP.
        let src = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
                       0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let conn = dummy_conn("192.168.1.1:54321", "1.2.3.4:80", "TCP");
        let signals = engine.inspect(&src, &[], &conn);
        assert!(
            signals.iter().any(|s| s.description.contains("HTTP port")),
            "Expected protocol-mismatch signal; got: {:?}", signals
        );
    }

    #[test]
    fn test_valid_http_on_port_80_not_flagged() {
        let engine = DpiEngine::new();
        let src = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let conn = dummy_conn("192.168.1.1:54321", "1.2.3.4:80", "TCP");
        let signals = engine.inspect(&src, &[], &conn);
        assert!(
            !signals.iter().any(|s| s.description.contains("HTTP port")),
            "Legitimate HTTP should not trigger mismatch"
        );
    }

    #[test]
    fn test_cleartext_on_tls_port_flagged() {
        let engine = DpiEngine::new();
        let src = b"GET /secret HTTP/1.1\r\n".to_vec(); // cleartext on 443
        let conn = dummy_conn("10.0.0.1:55555", "1.2.3.4:443", "TCP");
        let signals = engine.inspect(&src, &[], &conn);
        assert!(
            signals.iter().any(|s| s.description.contains("TLS port")),
            "Cleartext on port 443 should be flagged"
        );
    }

    #[test]
    fn test_valid_tls_on_port_443_not_flagged() {
        let engine = DpiEngine::new();
        // TLS ClientHello header: content-type=0x16, version=0x03 0x03
        let src = vec![0x16, 0x03, 0x03, 0x00, 0x80, 0x01, 0x00, 0x00, 0x7c];
        let conn = dummy_conn("10.0.0.1:55555", "1.2.3.4:443", "TCP");
        let signals = engine.inspect(&src, &[], &conn);
        assert!(
            !signals.iter().any(|s| s.description.contains("TLS port")),
            "Valid TLS handshake on 443 should not be flagged"
        );
    }

    // ── Shellcode ─────────────────────────────────────────────────────────────

    #[test]
    fn test_nop_sled_detected() {
        let engine = DpiEngine::new();
        let mut payload = vec![0x90u8; 32]; // 32-byte NOP sled
        payload.extend_from_slice(b"\x31\xc0\x50\x68");
        let conn = dummy_conn("10.0.0.1:4444", "1.2.3.4:4444", "TCP");
        let signals = engine.inspect(&payload, &[], &conn);
        assert!(
            signals.iter().any(|s| s.description.contains("NOP sled")),
            "NOP sled should be detected"
        );
        assert!(
            signals.iter().filter(|s| s.description.contains("NOP sled"))
                   .map(|s| s.score_delta).sum::<i32>() >= 30,
            "NOP sled score delta should be >= 30"
        );
    }

    #[test]
    fn test_clean_payload_no_shellcode() {
        let engine = DpiEngine::new();
        let payload = b"Hello, world! This is normal text.".to_vec();
        let conn = dummy_conn("10.0.0.1:5555", "1.2.3.4:80", "TCP");
        let signals = engine.inspect(&payload, &[], &conn);
        assert!(
            !signals.iter().any(|s| s.description.contains("shellcode") || s.description.contains("NOP")),
            "Clean text should not trigger shellcode detection"
        );
    }

    // ── Crypto mining ─────────────────────────────────────────────────────────

    #[test]
    fn test_stratum_mining_detected() {
        let engine = DpiEngine::new();
        let payload = br#"{"id":1,"method":"mining.subscribe","params":["cpuminer/2.5.1"]}"#.to_vec();
        let conn = dummy_conn("10.0.0.1:3333", "pool.example.com:3333", "TCP");
        let signals = engine.inspect(&payload, &[], &conn);
        assert!(
            signals.iter().any(|s| s.description.contains("mining")),
            "Stratum mining payload should be detected"
        );
    }

    // ── Cleartext credentials ─────────────────────────────────────────────────

    #[test]
    fn test_ftp_pass_flagged() {
        let engine = DpiEngine::new();
        let payload = b"PASS s3cr3tpassword\r\n".to_vec();
        let conn = dummy_conn("10.0.0.1:12345", "1.2.3.4:21", "TCP");
        let signals = engine.inspect(&payload, &[], &conn);
        assert!(
            signals.iter().any(|s| s.description.contains("FTP")),
            "FTP PASS command should be flagged"
        );
    }

    #[test]
    fn test_http_basic_auth_flagged() {
        let engine = DpiEngine::new();
        let payload = b"GET /admin HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n".to_vec();
        let conn = dummy_conn("10.0.0.1:54321", "1.2.3.4:80", "TCP");
        let signals = engine.inspect(&payload, &[], &conn);
        assert!(
            signals.iter().any(|s| s.description.contains("Basic Auth")),
            "HTTP Basic Auth should be flagged"
        );
    }

    // ── DNS tunneling ─────────────────────────────────────────────────────────

    #[test]
    fn test_long_dns_label_flagged() {
        let engine = DpiEngine::new();
        // 12 bytes DNS header + a long label (60 ASCII chars) + null terminator
        let mut payload = vec![0u8; 12]; // DNS header
        payload.extend_from_slice(&b"aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ01234567"[..]);
        payload.push(0x00); // null terminator
        let conn = dummy_conn("192.168.1.1:12345", "8.8.8.8:53", "UDP");
        let signals = engine.inspect(&payload, &[], &conn);
        assert!(
            signals.iter().any(|s| s.description.contains("DNS")),
            "Long DNS label should trigger tunneling detection"
        );
    }

    // ── HTTP command injection ─────────────────────────────────────────────────

    #[test]
    fn test_webshell_in_http_detected() {
        let engine = DpiEngine::new();
        let payload = b"POST /upload.php HTTP/1.1\r\n\r\ncmd=powershell -enc YQBiAGMA".to_vec();
        let conn = dummy_conn("10.0.0.1:54321", "1.2.3.4:80", "TCP");
        let signals = engine.inspect(&payload, &[], &conn);
        assert!(
            signals.iter().any(|s| s.description.contains("command injection") || s.description.contains("shell")),
            "Powershell in HTTP body should be flagged"
        );
    }

    // ── Score accumulation ────────────────────────────────────────────────────

    #[test]
    fn test_multiple_signals_accumulate() {
        let engine = DpiEngine::new();
        // NOP sled + mining on same payload
        let mut payload = vec![0x90u8; 20];
        payload.extend_from_slice(br#"{"method":"mining.subscribe"}"#);
        let conn = dummy_conn("10.0.0.1:4444", "1.2.3.4:4444", "TCP");
        let signals = engine.inspect(&payload, &[], &conn);
        let total_delta: i32 = signals.iter().map(|s| s.score_delta).sum();
        assert!(total_delta >= 35, "Combined payload should accumulate high delta: got {}", total_delta);
    }
}
