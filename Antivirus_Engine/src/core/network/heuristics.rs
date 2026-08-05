// File: src/core/network/heuristics.rs
//
// Top-tier network heuristics engine.
//
// Scoring tiers
// ─────────────
//  0 – 14  → Clean      (skip ML pipeline entirely)
// 15 – 34  → Suspicious (feed to OnePace.csv → ML model for confirmation)
// 35+      → Malicious  (high-confidence rule hit — report directly, skip ML)
//
// Design philosophy
// ─────────────────
// • A single high-confidence indicator can push a connection to Malicious.
// • Multiple medium signals accumulate into Suspicious.
// • Legitimate system processes and browsers on standard ports are whitelisted
//   early to prevent false positives from dominating.

use crate::core::network::types::NetworkConnection;
use crate::core::types::DetectionSignal;

// ─────────────────────────────────────────────────────────────────────────────
// Score thresholds
// ─────────────────────────────────────────────────────────────────────────────

const THRESHOLD_MALICIOUS:  i32 = 35;
const THRESHOLD_SUSPICIOUS: i32 = 15;

// ─────────────────────────────────────────────────────────────────────────────
// Known-clean process whitelist
// Connections from these processes on standard ports are scored very leniently.
// ─────────────────────────────────────────────────────────────────────────────

const CLEAN_SYSTEM_PROCESSES: &[&str] = &[
    "svchost", "lsass", "services", "winlogon", "csrss", "smss",
    "wininit", "ntoskrnl", "system", "registry", "memory compression",
    "searchindexer", "searchhost", "mpdefendercoreservice",
    "msmpeng", "nissrv", "securityhealthservice",
    "onedrive", "sihost", "taskhostw", "runtimebroker",
    "fontdrvhost", "dwm", "audiodg",
    "windows defender", "antimalware service executable",
    "spoolsv", "wuauclt", "trustedinstaller", "tiworker",
    "dashost", "wpnservice", "cryptsvc",
];

const CLEAN_BROWSER_PROCESSES: &[&str] = &[
    "chrome", "firefox", "msedge", "iexplore", "opera",
    "brave", "vivaldi", "safari", "waterfox", "tor browser",
];

// ─────────────────────────────────────────────────────────────────────────────
// Malicious indicators — single hit pushes score to ≥ 35
// ─────────────────────────────────────────────────────────────────────────────

/// Classic RAT / C2 / backdoor ports. A connection to these from an external
/// remote is almost always malicious.
const C2_REMOTE_PORTS: &[u16] = &[
    1337, 4444, 5554, 6969, 7777, 8899, 9999, 31337, 54321,
    65000, 65535,
];

/// Processes that are offensive security tools. Any network activity is
/// an immediate Malicious flag.
const MALWARE_TOOL_PROCESS_PATTERNS: &[&str] = &[
    "meterpreter", "cobalt", "mimikatz", "metasploit",
    "empire", "pupy", "covenant", "havoc", "sliver",
    "brute ratel", "nighthawk", "poshc2", "silenttrinity",
    "wce.exe", "lsassy", "procdump",
];

/// Dangerous listener ports — listening here with no known service is
/// almost certainly a backdoor.
const BACKDOOR_LISTENER_PORTS: &[u16] = &[
    1337, 4444, 5554, 6969, 7777, 8899, 31337, 54321,
];

/// Tor / anonymizer hostname substrings.
const TOR_PATTERNS: &[&str] = &[
    ".onion", "tor2web", "tor2io", ".exit", "torhiddensvc",
];

/// Known Tor SOCKS ports used by the Tor client.
const TOR_PORTS: &[u16] = &[9050, 9051, 9150, 9151];

// ─────────────────────────────────────────────────────────────────────────────
// High-suspicion indicators — accumulate toward Suspicious / Malicious
// ─────────────────────────────────────────────────────────────────────────────

/// Tunneling / reverse-proxy tools. Traffic through these can bypass firewalls.
const TUNNEL_PROCESS_PATTERNS: &[&str] = &[
    "ngrok", "frp", "chisel", "nps", "rathole", "bore",
    "serveo", "cloudflared", "pagekite", "ligolo",
    "rpivot", "iox", "gost",
];

/// Remote-access / lateral-movement tools.
const RAT_PROCESS_PATTERNS: &[&str] = &[
    "nc.exe", "ncat", "netcat", "nmap", "masscan",
    "psexec", "wmiexec", "dcomexec", "smbexec",
    "crackmapexec", "bloodhound", "sharphound",
    "rubeus", "kekeo",
];

/// Living-off-the-land binaries commonly abused for C2.
const LOLBIN_PROCESS_PATTERNS: &[&str] = &[
    "powershell", "pwsh", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin",
    "wmic", "msiexec", "installutil", "regasm", "regsvcs",
    "msbuild", "cmstp", "odbcconf", "ieexec", "forfiles",
    "syncappvpublishingserver", "appsyncpublishingserver",
    "pcalua", "appvlp",
];

/// Dynamic DNS / tunneling services — frequently used for C2 callbacks.
const DYNAMIC_DNS_PATTERNS: &[&str] = &[
    ".dyndns.", ".no-ip.", ".ngrok.io", ".ngrok-free.app",
    ".serveo.net", ".bore.pub", ".loca.lt",
    ".pagekite.me", ".trycloudflare.com",
    ".telebit.io", ".localhost.run",
    ".nip.io", ".xip.io", ".sslip.io",
];

/// High-risk TLDs frequently used for malware infrastructure.
const SUSPICIOUS_TLDS: &[&str] = &[
    ".pw", ".tk", ".ml", ".ga", ".cf",
    ".top", ".cc", ".to", ".ru", ".su",
    ".xyz", ".icu", ".club", ".cyou",
];

/// C2 / botnet hostname substrings.
const C2_HOST_PATTERNS: &[&str] = &[
    "c2.", "c&c.", "cnc.", "cmd.", "control.",
    "beacon.", "payload.", "stage.", "dropper.",
    "malware", "virus", "exploit", "hack",
];

/// IRC ports — heavily abused by botnets for C2 channels.
const IRC_PORTS: &[u16] = &[6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697];

/// Ports that should only be used by specific system services. Outbound
/// connections from non-matching processes are suspicious.
const RESTRICTED_OUTBOUND_PORTS: &[u16] = &[
    445,  // SMB
    135,  // RPC/DCOM
    139,  // NetBIOS
    389,  // LDAP
    636,  // LDAPS
    88,   // Kerberos
];

// ─────────────────────────────────────────────────────────────────────────────
// Heuristics engine
// ─────────────────────────────────────────────────────────────────────────────

pub struct NetworkHeuristics;

impl NetworkHeuristics {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, connection: &mut NetworkConnection) {
        let mut score:   i32 = 0;
        let mut signals: Vec<DetectionSignal> = Vec::new();

        let remote = connection.remote_address.to_lowercase();
        let _local  = connection.local_address.to_lowercase();
        let proc   = connection.process_name.as_deref().unwrap_or("").to_lowercase();
        let state  = connection.state.to_uppercase();
        let proto  = connection.protocol.to_lowercase();

        let remote_port = parse_port(&connection.remote_address);
        let local_port  = parse_port(&connection.local_address);
        let is_external = remote_port.is_some() && !is_local_or_private(&connection.remote_address);
        let is_listener = connection.is_listener();
        let is_system   = is_clean_system_process(&proc);
        let is_browser  = is_browser_process(&proc);
        let established = state.contains("ESTABLISHED");

        // ── 1. Malware tool process ───────────────────────────────────────────
        for pattern in MALWARE_TOOL_PROCESS_PATTERNS {
            if proc.contains(pattern) {
                score += 40;
                signals.push(sig("process", format!("Known offensive tool: '{}'", proc), 40));
                break;
            }
        }

        // ── 2. C2 / backdoor remote port (external connection) ────────────────
        if is_external {
            if let Some(port) = remote_port {
                if C2_REMOTE_PORTS.contains(&port) {
                    score += 38;
                    signals.push(sig("network", format!("Connection to known C2/backdoor port {port}"), 38));
                }
                // Tor SOCKS ports
                if TOR_PORTS.contains(&port) {
                    score += 38;
                    signals.push(sig("network", format!("Connection to Tor SOCKS port {port}"), 38));
                }
                // IRC / botnet ports
                if IRC_PORTS.contains(&port) {
                    score += 25;
                    signals.push(sig("network", format!("IRC port {port} — common botnet C2 channel"), 25));
                }
            }
        }

        // ── 3. Backdoor listener ──────────────────────────────────────────────
        if is_listener {
            if let Some(port) = local_port {
                if BACKDOOR_LISTENER_PORTS.contains(&port) {
                    score += 35;
                    signals.push(sig("network", format!("Listener on known backdoor port {port}"), 35));
                }
            }
        }

        // ── 4. Tor / anonymizer hostname ──────────────────────────────────────
        for pattern in TOR_PATTERNS {
            if remote.contains(pattern) {
                score += 38;
                signals.push(sig("network", format!("Tor/anonymizer indicator in remote address: '{pattern}'"), 38));
                break;
            }
        }

        // ── 5. Dynamic DNS / tunneling service ────────────────────────────────
        for pattern in DYNAMIC_DNS_PATTERNS {
            if remote.contains(pattern) {
                score += 22;
                signals.push(sig("network", format!("Dynamic DNS / tunneling service detected: '{pattern}'"), 22));
                break;
            }
        }

        // ── 6. Tunneling process ──────────────────────────────────────────────
        if !proc.is_empty() {
            for pattern in TUNNEL_PROCESS_PATTERNS {
                if proc.contains(pattern) {
                    score += 22;
                    signals.push(sig("process", format!("Tunneling tool '{proc}' making network connection"), 22));
                    break;
                }
            }
        }

        // ── 7. RAT / lateral-movement process ─────────────────────────────────
        if !proc.is_empty() {
            for pattern in RAT_PROCESS_PATTERNS {
                if proc.contains(pattern) {
                    score += 20;
                    signals.push(sig("process", format!("Remote-access/exploitation tool: '{proc}'"), 20));
                    break;
                }
            }
        }

        // ── 8. LOLBin making external connection ──────────────────────────────
        // Skip browsers and known-clean system processes.
        if is_external && !is_browser && !is_system && !proc.is_empty() {
            for pattern in LOLBIN_PROCESS_PATTERNS {
                if proc.contains(pattern) {
                    score += 18;
                    signals.push(sig("process", format!("LOLBin '{proc}' making outbound connection — common abuse technique"), 18));
                    break;
                }
            }
        }

        // ── 9. C2 hostname pattern ────────────────────────────────────────────
        for pattern in C2_HOST_PATTERNS {
            if remote.contains(pattern) {
                score += 20;
                signals.push(sig("network", format!("C2 hostname pattern '{pattern}' in remote address"), 20));
                break;
            }
        }

        // ── 10. Suspicious TLD ────────────────────────────────────────────────
        for tld in SUSPICIOUS_TLDS {
            // Match only at domain boundary (e.g., avoid ".top" inside "laptop")
            if remote.contains(&format!("{tld}:")) || remote.ends_with(tld) {
                score += 12;
                signals.push(sig("network", format!("High-risk TLD '{tld}' in remote address"), 12));
                break;
            }
        }

        // ── 11. RDP outbound to external ──────────────────────────────────────
        if is_external && !is_system {
            if let Some(port) = remote_port {
                if port == 3389 && proto == "tcp" {
                    score += 15;
                    signals.push(sig("network", "Outbound RDP (port 3389) to external host".to_string(), 15));
                }
                // VNC outbound
                if (port == 5900 || port == 5901) && is_external {
                    score += 15;
                    signals.push(sig("network", format!("Outbound VNC (port {port}) to external host"), 15));
                }
            }
        }

        // ── 12. Restricted outbound ports from non-system processes ───────────
        if is_external && !is_system && !proc.is_empty() {
            if let Some(port) = remote_port {
                if RESTRICTED_OUTBOUND_PORTS.contains(&port) {
                    score += 18;
                    signals.push(sig("network", format!("Non-system process '{proc}' connecting to restricted port {port} (SMB/RDP/LDAP/Kerberos)"), 18));
                }
            }
        }

        // ── 13. DNS from unexpected process / port ────────────────────────────
        // DNS should only use port 53 and only from known resolvers.
        if is_external && !is_system {
            if let Some(port) = remote_port {
                if port == 53 && proto == "tcp" {
                    // DNS over TCP from non-system process can indicate DNS tunneling.
                    score += 16;
                    signals.push(sig("network", format!("DNS over TCP from non-system process '{proc}' — possible DNS tunneling"), 16));
                }
                // Non-DNS traffic on port 53 (other protocol).
                if port == 53 && proto != "udp" && proto != "tcp" {
                    score += 14;
                    signals.push(sig("network", "Non-DNS protocol on port 53".to_string(), 14));
                }
            }
        }

        // ── 14. High-entropy / non-standard port external connection ──────────
        // Browsers and system processes excluded.
        if is_external && !is_browser && !is_system && established {
            if let Some(port) = remote_port {
                let is_standard = matches!(port, 80 | 443 | 8080 | 8443 | 21 | 22 | 25 |
                    53 | 110 | 143 | 465 | 587 | 993 | 995 | 123 | 3306 | 5432 | 27017);
                if !is_standard && port > 1024 && port < 49152 {
                    score += 8;
                    signals.push(sig("network", format!("External connection to uncommon port {port}"), 8));
                }
            }
        }

        // ── 15. ESTABLISHED external with no process info ─────────────────────
        if is_external && established && connection.pid.is_none() && !is_listener {
            score += 14;
            signals.push(sig("network", "Established external connection with no associated process — possible injection".to_string(), 14));
        }

        // ── 16. Listener with no PID ──────────────────────────────────────────
        if is_listener && connection.pid.is_none() {
            score += 10;
            signals.push(sig("process", "Listener socket has no associated process — possible rootkit or kernel implant".to_string(), 10));
        }

        // ── 17. Ephemeral-range listener from unknown process ─────────────────
        if is_listener && !is_system {
            if let Some(port) = local_port {
                if port >= 49152 {
                    score += 6;
                    signals.push(sig("network", format!("Listener on ephemeral port {port} from non-system process"), 6));
                }
            }
        }

        // ── 18. Outbound SOCKS proxy ──────────────────────────────────────────
        if is_external {
            if let Some(port) = remote_port {
                if port == 1080 || port == 1081 || port == 8888 {
                    score += 15;
                    signals.push(sig("network", format!("Connection to SOCKS proxy port {port}"), 15));
                }
            }
        }

        // ── 19. Local port reuse with non-standard protocol ───────────────────
        // E.g., HTTPS port 443 being listened on by a non-web-server process.
        if is_listener && !is_system && !is_browser {
            if let Some(port) = local_port {
                if matches!(port, 80 | 443 | 8080 | 8443) {
                    score += 10;
                    signals.push(sig("network", format!("Non-browser/non-server process listening on web port {port} — possible masquerading"), 10));
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Apply score reduction for verified clean processes on standard ports
        // (prevents LOLBin rules from firing on legitimate svchost, etc.)
        // ─────────────────────────────────────────────────────────────────────
        if is_system {
            // Cap system process score — they can still be flagged if something
            // is extremely suspicious (e.g., svchost connecting to a C2 port).
            score = score.min(THRESHOLD_MALICIOUS - 1);
        }
        if is_browser {
            if let Some(port) = remote_port {
                if matches!(port, 80 | 443 | 8080 | 8443) {
                    // Browser on web ports — remove any accumulated score below malicious.
                    score = score.min(THRESHOLD_SUSPICIOUS - 1);
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Classify
        // ─────────────────────────────────────────────────────────────────────
        let threat_level = if score >= THRESHOLD_MALICIOUS {
            crate::core::types::ThreatLevel::Malicious
        } else if score >= THRESHOLD_SUSPICIOUS {
            crate::core::types::ThreatLevel::Suspicious
        } else {
            crate::core::types::ThreatLevel::Clean
        };

        connection.threat_score    = score;
        connection.threat_level    = threat_level.clone();
        connection.is_threat       = threat_level.is_threat();
        connection.detection_signals = signals;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn sig(category: &str, description: String, score: i32) -> DetectionSignal {
    DetectionSignal::new(category, description, score)
}

fn parse_port(endpoint: &str) -> Option<u16> {
    // Handle IPv6 bracketed addresses like [::1]:443
    if endpoint.ends_with(":*") { return None; }
    endpoint.rsplit(':').next()?.parse::<u16>().ok()
}

fn is_local_or_private(address: &str) -> bool {
    let lower = address.to_lowercase();
    // Wildcard / no remote peer
    if lower.ends_with(":*") || lower.ends_with(":0") { return true; }
    // Loopback
    if lower.starts_with("127.") || lower.starts_with("::1") || lower.contains("localhost") { return true; }
    // Unspecified
    if lower.starts_with("0.0.0.0") || lower.starts_with("[::]") { return true; }
    // Private RFC 1918
    if lower.starts_with("192.168.") || lower.starts_with("10.")  { return true; }
    if let Some(rest) = lower.strip_prefix("172.") {
        if let Some(second_octet) = rest.split('.').next().and_then(|o| o.parse::<u8>().ok()) {
            if (16..=31).contains(&second_octet) { return true; }
        }
    }
    // Link-local
    if lower.starts_with("169.254.") || lower.starts_with("fe80") { return true; }
    false
}

fn is_clean_system_process(proc: &str) -> bool {
    if proc.is_empty() { return false; }
    CLEAN_SYSTEM_PROCESSES.iter().any(|p| proc.contains(p))
}

fn is_browser_process(proc: &str) -> bool {
    if proc.is_empty() { return false; }
    CLEAN_BROWSER_PROCESSES.iter().any(|p| proc.contains(p))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::network::types::NetworkConnection;

    fn conn(proto: &str, local: &str, remote: &str, state: &str, proc: Option<&str>) -> NetworkConnection {
        NetworkConnection::new(proto, local, remote, state, Some(1234), proc.map(String::from))
    }

    #[test]
    fn c2_port_is_malicious() {
        let mut c = conn("tcp", "192.168.1.5:51000", "1.2.3.4:4444", "ESTABLISHED", Some("evil.exe"));
        NetworkHeuristics::new().analyze(&mut c);
        assert!(c.threat_score >= 35, "score={}", c.threat_score);
        assert_eq!(c.threat_level, crate::core::types::ThreatLevel::Malicious);
    }

    #[test]
    fn meterpreter_is_malicious() {
        let mut c = conn("tcp", "192.168.1.5:51000", "1.2.3.4:443", "ESTABLISHED", Some("meterpreter.exe"));
        NetworkHeuristics::new().analyze(&mut c);
        assert_eq!(c.threat_level, crate::core::types::ThreatLevel::Malicious);
    }

    #[test]
    fn lolbin_external_is_suspicious() {
        let mut c = conn("tcp", "192.168.1.5:51000", "1.2.3.4:8080", "ESTABLISHED", Some("powershell.exe"));
        NetworkHeuristics::new().analyze(&mut c);
        assert!(c.threat_score >= 15, "score={}", c.threat_score);
    }

    #[test]
    fn browser_on_443_is_clean() {
        let mut c = conn("tcp", "192.168.1.5:51000", "142.250.0.1:443", "ESTABLISHED", Some("chrome.exe"));
        NetworkHeuristics::new().analyze(&mut c);
        assert!(c.threat_score < 15, "score={}", c.threat_score);
        assert_eq!(c.threat_level, crate::core::types::ThreatLevel::Clean);
    }

    #[test]
    fn backdoor_listener_is_malicious() {
        let mut c = conn("tcp", "0.0.0.0:4444", "0.0.0.0:0", "LISTENING", Some("nc.exe"));
        NetworkHeuristics::new().analyze(&mut c);
        assert!(c.threat_score >= 35, "score={}", c.threat_score);
    }

    #[test]
    fn ngrok_tunnel_is_suspicious() {
        let mut c = conn("tcp", "192.168.1.5:51000", "3.tcp.ngrok.io:443", "ESTABLISHED", Some("ngrok.exe"));
        NetworkHeuristics::new().analyze(&mut c);
        assert!(c.threat_score >= 15, "score={}", c.threat_score);
    }

    #[test]
    fn svchost_on_standard_port_is_clean() {
        let mut c = conn("tcp", "192.168.1.5:51000", "20.190.128.1:443", "ESTABLISHED", Some("svchost.exe"));
        NetworkHeuristics::new().analyze(&mut c);
        assert!(c.threat_score < 35);
    }
}
