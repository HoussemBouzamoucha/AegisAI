// File: src/core/network/scanner.rs
// Network scanner orchestration — enumerates connections, applies heuristics,
// and feeds live packet data into the UNSW-NB15 feature extractor.

use crate::core::network::feature_extractor::FeatureExtractor;
use crate::core::network::heuristics::NetworkHeuristics;
use crate::core::network::types::{
    enumerate_network_connections, NetworkConnection, NetworkScanStatistics,
};
use anyhow::Result;
use crate::core::types::ThreatLevel;
use std::sync::Arc;
use std::time::Instant;

pub struct NetworkScanner {
    heuristics:        NetworkHeuristics,
    feature_extractor: Arc<FeatureExtractor>,
}

impl NetworkScanner {
    pub fn new() -> Self {
        Self {
            heuristics:        NetworkHeuristics::new(),
            feature_extractor: FeatureExtractor::new()
                .expect("Failed to initialise OnePace.csv"),
        }
    }

    /// Full scan: enumerate all connections, score them, write features to CSV.
    pub fn scan(&self) -> Result<(Vec<NetworkConnection>, NetworkScanStatistics)> {
        let start = Instant::now();

        let mut connections = enumerate_network_connections()?;

        for connection in connections.iter_mut() {
            self.heuristics.analyze(connection);
        }

        connections.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));

        let duration_ms = start.elapsed().as_millis() as u64;
        let stats = NetworkScanStatistics::from_results(&connections, duration_ms);

        // ── Feature extraction → OnePace.csv (Suspicious only) ───────────────
        // Clean connections are safe — skip the ML pipeline entirely.
        // Malicious connections are already flagged by heuristics — ML adds nothing.
        // Only Suspicious connections need ML confirmation.
        let suspicious: Vec<NetworkConnection> = connections.iter()
            .filter(|c| c.threat_level == ThreatLevel::Suspicious)
            .cloned()
            .collect();

        if let Err(e) = self.feature_extractor.extract_and_append(&suspicious) {
            eprintln!("[feature_extractor] CSV write error: {e}");
        }
        // ─────────────────────────────────────────────────────────────────────

        Ok((connections, stats))
    }

    /// Return only connections whose threat level is Suspicious or Malicious.
    pub fn scan_threats_only(&self) -> Result<(Vec<NetworkConnection>, NetworkScanStatistics)> {
        let (connections, stats) = self.scan()?;
        let threats: Vec<NetworkConnection> = connections
            .into_iter()
            .filter(|c| c.threat_level != crate::core::types::ThreatLevel::Clean)
            .collect();
        Ok((threats, stats))
    }

    /// Return all connections belonging to a specific PID.
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

    /// Return only listening sockets.
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

    /// Convenience wrapper — returns the connection list only (discards stats).
    pub fn scan_all_connections(&self) -> Result<Vec<NetworkConnection>> {
        let (connections, _) = self.scan()?;
        Ok(connections)
    }

    /// Build statistics from an already-scanned slice without re-scanning.
    pub fn get_statistics(&self, connections: &[NetworkConnection]) -> NetworkScanStatistics {
        NetworkScanStatistics::from_results(connections, 0)
    }

    /// Expose the CSV path so the UI or CLI can display it.
    pub fn csv_path(&self) -> &std::path::Path {
        self.feature_extractor.csv_path()
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}