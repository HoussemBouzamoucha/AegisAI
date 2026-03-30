// File: src/core/network/heuristics.rs
// Network heuristics score network connections based on suspicious endpoints, ports, and process metadata.

use crate::core::network::types::NetworkConnection;
use crate::core::types::DetectionSignal;

const SUSPICIOUS_REMOTE_PORTS: &[u16] = &[
    22, 23, 2323, 3128, 3333, 4444, 5555, 6666, 6667, 7777, 8080, 8443, 8888, 9999,
    31337, 3389, 5900, 5901, 1080,
];

const SUSPICIOUS_LOCAL_PORTS: &[u16] = &[
    22, 23, 2222, 2323, 3128, 4444, 5555, 6666, 6667, 8080, 8443, 8888, 9999, 31337,
];

const SUSPICIOUS_PROCESS_PATTERNS: &[&str] = &[
    "tor", "proxy", "vpn", "ngrok", "ssh", "dropbear", "rclone",
    "meterpreter", "cobalt", "mimikatz", "meterpreter", "metasploit",
    "nc.exe", "ncat", "netcat", "psexec", "vnc", "winscp",
];

const SUSPICIOUS_HOST_PATTERNS: &[&str] = &[
    ".onion", ".tor", "c2.", "commandandcontrol", "malware", "evil",
    "proxy", "vpn", "ddns", ".pw", ".top", ".link", ".ru", ".cn",
];

pub struct NetworkHeuristics;

impl NetworkHeuristics {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, connection: &mut NetworkConnection) {
        let mut score: i32 = 0;
        let mut signals: Vec<DetectionSignal> = Vec::new();

        let remote_lower = connection.remote_address.to_lowercase();
        let proc_lower   = connection.process_name.as_deref().unwrap_or("").to_lowercase();

        let remote_port = extract_port(&connection.remote_address);
        let local_port = extract_port(&connection.local_address);

        if let Some(port) = remote_port {
            if SUSPICIOUS_REMOTE_PORTS.contains(&port) && !is_local_address(&connection.remote_address) {
                score += 10;
                signals.push(DetectionSignal::new(
                    "network",
                    format!("Connection to suspicious remote port {}", port),
                    10,
                ));
            }
        }

        if connection.is_listener() {
            if let Some(port) = local_port {
                if SUSPICIOUS_LOCAL_PORTS.contains(&port) {
                    score += 6;
                    signals.push(DetectionSignal::new(
                        "network",
                        format!("Local listener on unusual port {}", port),
                        6,
                    ));
                }
            }
            if connection.process_name.is_none() {
                score += 3;
                signals.push(DetectionSignal::new(
                    "process",
                    "Listening socket has no associated process metadata".to_string(),
                    3,
                ));
            }
        }

        if connection.state.to_uppercase().contains("ESTABLISHED") {
            score += 2;
            signals.push(DetectionSignal::new(
                "network",
                format!("Established connection to {}", connection.remote_address),
                2,
            ));
        }

        if let Some(port) = local_port {
            if port >= 49152 && connection.is_listener() {
                score += 2;
                signals.push(DetectionSignal::new(
                    "network",
                    format!("High ephemeral listener port: {}", port),
                    2,
                ));
            }
        }

        for pattern in SUSPICIOUS_PROCESS_PATTERNS.iter() {
            if proc_lower.contains(pattern) {
                score += 8;
                signals.push(DetectionSignal::new(
                    "process",
                    format!("Suspicious process name: {}", connection.process_name.as_deref().unwrap_or("unknown")),
                    8,
                ));
                break;
            }
        }

        for pattern in SUSPICIOUS_HOST_PATTERNS.iter() {
            if remote_lower.contains(pattern) {
                score += 10;
                signals.push(DetectionSignal::new(
                    "network",
                    format!("Suspicious remote host or domain pattern: {}", pattern),
                    10,
                ));
                break;
            }
        }

        if connection.pid.is_none() && !connection.is_listener() {
            score += 4;
            signals.push(DetectionSignal::new(
                "network",
                "Connection has no associated PID metadata".to_string(),
                4,
            ));
        }

        let threat_level = if score >= 18 {
            crate::core::types::ThreatLevel::Malicious
        } else if score >= 8 {
            crate::core::types::ThreatLevel::Suspicious
        } else {
            crate::core::types::ThreatLevel::Clean
        };

        connection.threat_score = score;
        connection.threat_level = threat_level.clone();
        connection.is_threat = threat_level.is_threat();
        connection.detection_signals = signals;
    }
}

fn extract_port(endpoint: &str) -> Option<u16> {
    endpoint.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
}

fn is_local_address(address: &str) -> bool {
    let lower = address.to_lowercase();
    lower.starts_with("127.") || lower.starts_with("::1") || lower.contains("localhost") || lower.starts_with("0.0.0.0") || lower.starts_with("[::]") || lower.ends_with(":*")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::network::types::NetworkConnection;

    #[test]
    fn suspicious_remote_port_triggers_signal() {
        let mut connection = NetworkConnection::new(
            "tcp",
            "192.168.1.100:5555",
            "198.51.100.10:6666",
            "ESTABLISHED",
            Some(1234),
            Some("weird.exe".to_string()),
        );

        NetworkHeuristics::new().analyze(&mut connection);
        assert!(connection.threat_score >= 10);
        assert!(connection.threat_level != crate::core::types::ThreatLevel::Clean);
    }

    #[test]
    fn listener_on_suspicious_port_scores_high() {
        let mut connection = NetworkConnection::new(
            "tcp",
            "0.0.0.0:4444",
            "0.0.0.0:0",
            "LISTENING",
            None,
            Some("suspicious.exe".to_string()),
        );

        NetworkHeuristics::new().analyze(&mut connection);
        assert!(connection.threat_score >= 6);
        assert!(connection.threat_level == crate::core::types::ThreatLevel::Suspicious);
    }
}
