// File: src/core/network/types.rs
// Network scanner data types and system network enumeration helpers.

use crate::core::types::{DetectionSignal, ThreatLevel};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;
use sysinfo::{Pid, ProcessesToUpdate, System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol:      String,
    pub local_address: String,
    pub remote_address: String,
    pub state:         String,
    pub pid:           Option<u32>,
    pub process_name:  Option<String>,

    pub threat_score:      i32,
    pub threat_level:      ThreatLevel,
    pub is_threat:         bool,
    pub detection_signals: Vec<DetectionSignal>,

    /// ML probability score set by the external pipeline after `run_ml_and_patch_scores`.
    /// `None` when the ML model has not yet scored this connection.
    /// Used (alongside `threat_score`) as a second DPI trigger condition.
    pub ml_score: Option<f32>,

    /// Set to `true` when the DPI engine was invoked on this connection's payload.
    /// Exposed to the UI so analysts can see which connections received deep inspection.
    pub dpi_triggered: bool,
}

impl NetworkConnection {
    pub fn new(
        protocol: impl Into<String>,
        local_address: impl Into<String>,
        remote_address: impl Into<String>,
        state: impl Into<String>,
        pid: Option<u32>,
        process_name: Option<String>,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            local_address: local_address.into(),
            remote_address: remote_address.into(),
            state: state.into(),
            pid,
            process_name,
            threat_score: 0,
            threat_level: ThreatLevel::Clean,
            is_threat: false,
            detection_signals: Vec::new(),
            ml_score: None,
            dpi_triggered: false,
        }
    }

    pub fn is_listener(&self) -> bool {
        let state = self.state.to_uppercase();
        state.contains("LISTEN") || state.contains("LISTENING") || self.remote_address.ends_with(":*")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScanStatistics {
    pub total_connections:      usize,
    pub suspicious_connections: usize,
    pub malicious_connections:  usize,
    pub local_listeners:        usize,
    pub established_connections: usize,
    pub scan_duration_ms:       u64,
}

impl NetworkScanStatistics {
    pub fn from_results(connections: &[NetworkConnection], duration_ms: u64) -> Self {
        let suspicious = connections.iter().filter(|c| c.threat_level == ThreatLevel::Suspicious).count();
        let malicious  = connections.iter().filter(|c| c.threat_level == ThreatLevel::Malicious).count();
        let listeners  = connections.iter().filter(|c| c.is_listener()).count();
        let established = connections.iter().filter(|c| c.state.to_uppercase().contains("ESTABLISHED")).count();

        Self {
            total_connections:      connections.len(),
            suspicious_connections: suspicious,
            malicious_connections:  malicious,
            local_listeners:        listeners,
            established_connections: established,
            scan_duration_ms:       duration_ms,
        }
    }
}

pub fn enumerate_network_connections() -> Result<Vec<NetworkConnection>> {
    #[cfg(windows)]
    let args: &[&str] = &["-ano"];
    #[cfg(not(windows))]
    let args: &[&str] = &["-anp"];

    let output = Command::new("netstat").args(args).output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) if !output.status.success() && !cfg!(windows) => {
            let fallback = Command::new("netstat").args(["-an"]).output()?;
            if !fallback.status.success() {
                return Err(anyhow!("Unable to enumerate network connections: netstat failed"));
            }
            fallback
        }
        Ok(_) => return Err(anyhow!("Unable to enumerate network connections: netstat failed")),
        Err(err) => return Err(anyhow!("Unable to execute netstat: {}", err)),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut connections: Vec<NetworkConnection> = Vec::new();

    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if let Some(connection) = parse_netstat_line(line) {
            connections.push(connection);
        }
    }

    if connections.is_empty() {
        return Ok(connections);
    }

    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);

    for connection in connections.iter_mut() {
        if connection.process_name.is_none() {
            connection.process_name = connection.pid.and_then(|pid| {
                system.process(Pid::from_u32(pid)).map(|proc| proc.name().to_string_lossy().to_string())
            });
        }
    }

    Ok(connections)
}

#[cfg(windows)]
fn parse_netstat_line(line: &str) -> Option<NetworkConnection> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() { return None; }

    let first = tokens[0].to_lowercase();
    if first.starts_with("proto") || first.starts_with("active") { return None; }

    parse_windows_line(&tokens)
}

#[cfg(not(windows))]
fn parse_netstat_line(line: &str) -> Option<NetworkConnection> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() { return None; }

    let first = tokens[0].to_lowercase();
    if first.starts_with("proto") || first.starts_with("active") { return None; }

    parse_unix_line(&tokens)
}

#[cfg(windows)]
fn parse_windows_line(tokens: &[&str]) -> Option<NetworkConnection> {
    if tokens.len() < 4 { return None; }
    let protocol = tokens[0].to_string();
    let local_address = tokens[1].to_string();
    let remote_address = tokens[2].to_string();

    let (state, pid_text) = if tokens.len() == 5 {
        (tokens[3].to_string(), tokens[4])
    } else if tokens.len() == 4 {
        ("UNKNOWN".to_string(), tokens[3])
    } else {
        (tokens[3].to_string(), tokens[tokens.len() - 1])
    };

    let pid = pid_text.parse::<u32>().ok();
    Some(NetworkConnection::new(protocol, local_address, remote_address, state, pid, None))
}

#[cfg(not(windows))]
fn parse_unix_line(tokens: &[&str]) -> Option<NetworkConnection> {
    let proto = tokens[0].to_string();
    if tokens.len() < 4 { return None; }

    let local_address = tokens.get(3)?.to_string();
    let remote_address = tokens.get(4)?.to_string();

    let mut state = "UNKNOWN".to_string();
    let mut pid = None;
    let mut process_name = None;

    if tokens.len() >= 7 {
        state = tokens[5].to_string();
    }

    if let Some(last) = tokens.last() {
        if last.contains('/') && !last.starts_with("[") {
            if let Some((pid_str, proc_name)) = last.split_once('/') {
                pid = pid_str.parse::<u32>().ok();
                process_name = Some(proc_name.to_string());
            }
        }
    }

    Some(NetworkConnection::new(proto, local_address, remote_address, state, pid, process_name))
}
