// File: src/core/network/scanner.rs
// Network scanner orchestration — enumerates connections and applies network heuristics.

use crate::core::network::heuristics::NetworkHeuristics;
use crate::core::network::types::{enumerate_network_connections, NetworkConnection, NetworkScanStatistics};
use anyhow::Result;
use std::time::Instant;

pub struct NetworkScanner {
    heuristics: NetworkHeuristics,
}

impl NetworkScanner {
    pub fn new() -> Self {
        Self {
            heuristics: NetworkHeuristics::new(),
        }
    }

    pub fn scan(&self) -> Result<(Vec<NetworkConnection>, NetworkScanStatistics)> {
        let start = Instant::now();
        let mut connections = enumerate_network_connections()?;
        for connection in connections.iter_mut() {
            self.heuristics.analyze(connection);
        }
        connections.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));
        let duration_ms = start.elapsed().as_millis() as u64;
        let stats = NetworkScanStatistics::from_results(&connections, duration_ms);
        Ok((connections, stats))
    }

    pub fn scan_threats_only(&self) -> Result<(Vec<NetworkConnection>, NetworkScanStatistics)> {
        let (connections, stats) = self.scan()?;
        let threats: Vec<NetworkConnection> = connections.into_iter()
            .filter(|c| c.threat_level != crate::core::types::ThreatLevel::Clean)
            .collect();
        Ok((threats, stats))
    }

    pub fn scan_by_pid(&self, target_pid: u32) -> Result<Vec<NetworkConnection>> {
        let mut connections = enumerate_network_connections()?;
        let mut filtered: Vec<NetworkConnection> = connections
            .drain(..)
            .filter(|c| c.pid == Some(target_pid))
            .collect();

        for connection in filtered.iter_mut() {
            self.heuristics.analyze(connection);
        }

        filtered.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));
        Ok(filtered)
    }

    pub fn scan_listeners(&self) -> Result<(Vec<NetworkConnection>, NetworkScanStatistics)> {
        let start = Instant::now();
        let mut connections = enumerate_network_connections()?;
        connections.retain(|c| c.is_listener());
        for connection in connections.iter_mut() {
            self.heuristics.analyze(connection);
        }
        connections.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));
        let duration_ms = start.elapsed().as_millis() as u64;
        let stats = NetworkScanStatistics::from_results(&connections, duration_ms);
        Ok((connections, stats))
    }

    pub fn scan_all_connections(&self) -> Result<Vec<NetworkConnection>> {
        let (connections, _) = self.scan()?;
        Ok(connections)
    }

    pub fn get_statistics(&self, connections: &[NetworkConnection]) -> NetworkScanStatistics {
        NetworkScanStatistics::from_results(connections, 0)
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}
