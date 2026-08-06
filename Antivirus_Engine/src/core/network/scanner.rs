// File: src/core/network/scanner.rs
// Network scanner orchestration — enumerates connections, applies heuristics,
// selectively runs DPI, and feeds live packet data into the UNSW-NB15 feature extractor.

use crate::core::network::dpi::DpiEngine;
use crate::core::network::feature_extractor::FeatureExtractor;
use crate::core::network::heuristics::NetworkHeuristics;
use crate::core::network::types::{
    enumerate_network_connections, NetworkConnection, NetworkScanStatistics,
};
use crate::core::types::{DetectionSignal, ThreatLevel};
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

// ─── Selective DPI thresholds ─────────────────────────────────────────────────

/// Heuristic score above which payload inspection is triggered.
///
/// 14 is the boundary between Clean (0–14) and Suspicious (15–34), so any
/// connection that heuristics consider at least Suspicious will be inspected.
/// Set lower (e.g. 10) to catch borderline cases; higher to reduce overhead.
const DPI_HEURISTIC_THRESHOLD: i32 = 14;

/// ML probability above which DPI is triggered even if heuristics are low.
///
/// A score of 0.5 means the model considers the connection more likely malicious
/// than benign.  Set higher (0.7) to only trigger on confident ML verdicts.
const DPI_ML_THRESHOLD: f32 = 0.5;

// ─── Score → ThreatLevel mapping ─────────────────────────────────────────────

/// Re-classify a connection after DPI may have changed its score.
///
/// Mirrors the thresholds in `heuristics.rs` (0–14 = Clean, 15–34 = Suspicious,
/// 35+ = Malicious).  DPI signals deliberately bypass the per-process caps
/// applied by the heuristics engine because payload evidence overrides
/// process-whitelist assumptions.
fn classify_score(score: i32) -> ThreatLevel {
    if score >= 35 {
        ThreatLevel::Malicious
    } else if score >= 15 {
        ThreatLevel::Suspicious
    } else {
        ThreatLevel::Clean
    }
}

// ─── NetworkScanner ───────────────────────────────────────────────────────────

pub struct NetworkScanner {
    heuristics:        NetworkHeuristics,
    feature_extractor: Arc<FeatureExtractor>,
    /// Selective DPI engine — invoked only when the trigger condition is met.
    dpi:               DpiEngine,
}

impl NetworkScanner {
    pub fn new() -> Self {
        Self {
            heuristics:        NetworkHeuristics::new(),
            feature_extractor: FeatureExtractor::new()
                .expect("Failed to initialise OnePace.csv"),
            dpi: DpiEngine::new(),
        }
    }

    /// Full scan: enumerate all connections, score them, selectively run DPI,
    /// write features to CSV.
    pub fn scan(&self) -> Result<(Vec<NetworkConnection>, NetworkScanStatistics)> {
        let start = Instant::now();

        let mut connections = enumerate_network_connections()?;

        // ── Step 1: heuristics (always runs) ─────────────────────────────────
        for conn in connections.iter_mut() {
            self.heuristics.analyze(conn);
        }

        // ── Step 2: selective DPI ─────────────────────────────────────────────
        //
        // Condition: threat_score > DPI_HEURISTIC_THRESHOLD
        //         OR ml_score     > DPI_ML_THRESHOLD
        //
        // Only connections that pass this gate enter the DPI engine.
        // Clean connections with no ML suspicion are never inspected — their
        // payload bytes are never read or allocated.
        for conn in connections.iter_mut() {
            let ml_suspicious = conn.ml_score
                .map(|s| s > DPI_ML_THRESHOLD)
                .unwrap_or(false);

            let needs_dpi = conn.threat_score > DPI_HEURISTIC_THRESHOLD || ml_suspicious;
            if !needs_dpi { continue; }

            // Ask the feature extractor for any captured payload bytes.
            // Returns None when pcap hasn't seen this flow yet (no overhead).
            let payload = self.feature_extractor.get_payload_for_connection(conn);
            let (src_bytes, dst_bytes) = match payload {
                Some(p) => p,
                None    => continue, // no captured bytes — skip DPI for this connection
            };

            // Run DPI only if at least one direction has payload.
            if src_bytes.is_empty() && dst_bytes.is_empty() { continue; }

            conn.dpi_triggered = true;
            let dpi_signals = self.dpi.inspect(&src_bytes, &dst_bytes, conn);

            for sig in dpi_signals {
                conn.threat_score += sig.score_delta;
                conn.detection_signals.push(
                    DetectionSignal::new("dpi", sig.description, sig.score_delta),
                );
            }

            // Re-classify after DPI may have raised the score.
            conn.threat_level = classify_score(conn.threat_score);
            conn.is_threat    = conn.threat_level != ThreatLevel::Clean;
        }
        // ─────────────────────────────────────────────────────────────────────

        connections.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));

        let duration_ms = start.elapsed().as_millis() as u64;
        let stats = NetworkScanStatistics::from_results(&connections, duration_ms);

        // ── Step 3: feature extraction → OnePace.csv (Suspicious+) ───────────
        // Clean connections are safe — skip the ML pipeline entirely.
        // Malicious connections are already flagged — ML adds nothing new.
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
            .filter(|c| c.threat_level != ThreatLevel::Clean)
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

        for conn in filtered.iter_mut() {
            self.heuristics.analyze(conn);
        }

        filtered.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));
        Ok(filtered)
    }

    /// Return only listening sockets.
    pub fn scan_listeners(&self) -> Result<(Vec<NetworkConnection>, NetworkScanStatistics)> {
        let start = Instant::now();

        let mut connections = enumerate_network_connections()?;
        connections.retain(|c| c.is_listener());

        for conn in connections.iter_mut() {
            self.heuristics.analyze(conn);
        }

        connections.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));

        let duration_ms = start.elapsed().as_millis() as u64;
        let stats = NetworkScanStatistics::from_results(&connections, duration_ms);
        Ok((connections, stats))
    }

    /// Convenience wrapper — returns the connection list only (discards stats).
    #[allow(dead_code)]
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
