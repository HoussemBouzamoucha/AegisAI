// src/core/network/feature_extractor.rs
// ─────────────────────────────────────────────────────────────────────────────
// Rust wrapper that:
//   1. Spawns the C++ flow_extractor binary as a subprocess
//   2. Waits for the CSV output
//   3. Parses it into typed FlowFeatures structs
//   4. Feeds them to the ML inference pipeline
//
// The C++ binary must be built first:
//   cd network_extractor && make
//   sudo cp flow_extractor /usr/local/bin/
//
// Usage:
//   let features = FeatureExtractor::new("/usr/local/bin/flow_extractor")
//       .capture_live("eth0", Duration::from_secs(60))?;
//
//   let features = FeatureExtractor::new("/usr/local/bin/flow_extractor")
//       .capture_pcap("capture.pcap")?;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use std::fs;

// ─── All 47 UNSW-NB15 features ───────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    // Network layer
    pub srcip:  String,
    pub sport:  i32,
    pub dstip:  String,
    pub dsport: i32,
    pub proto:  String,
    pub state:  String,

    // Flow timing
    pub dur: f32,

    // Byte counts
    pub sbytes: f32,
    pub dbytes: f32,

    // TTLs
    pub sttl: f32,
    pub dttl: f32,

    // Loss
    pub sloss: f32,
    pub dloss: f32,

    // Service
    pub service: String,

    // Loads (bps)
    pub sload: f32,
    pub dload: f32,

    // Packet counts
    pub spkts: f32,
    pub dpkts: f32,

    // TCP window sizes
    pub swin: f32,
    pub dwin: f32,

    // TCP base sequence numbers
    pub stcpb: f32,
    pub dtcpb: f32,

    // Mean packet sizes
    pub smeansz: f32,
    pub dmeansz: f32,

    // HTTP depth
    pub trans_depth:  f32,
    pub res_bdy_len:  f32,

    // Jitter
    pub sjit: f32,
    pub djit: f32,

    // Timestamps
    pub stime: i64,
    pub ltime: i64,

    // Inter-packet times (ms)
    pub sintpkt: f32,
    pub dintpkt: f32,

    // TCP handshake timing
    pub tcprtt: f32,
    pub synack: f32,
    pub ackdat: f32,

    // Flags
    pub is_sm_ips_ports: f32,

    // Connection tracking counters
    pub ct_state_ttl:      f32,
    pub ct_flw_http_mthd:  f32,
    pub is_ftp_login:      f32,
    pub ct_ftp_cmd:        f32,
    pub ct_srv_src:        f32,
    pub ct_srv_dst:        f32,
    pub ct_dst_ltm:        f32,
    pub ct_src_ltm:        f32,
    pub ct_src_dport_ltm:  f32,
    pub ct_dst_sport_ltm:  f32,
    pub ct_dst_src_ltm:    f32,
}

impl FlowFeatures {
    /// Returns only the numeric feature vector (drops IPs and categorical strings).
    /// Order matches the model's expected input after label-encoding.
    pub fn numeric_features(&self) -> Vec<f32> {
        vec![
            self.sport as f32, self.dsport as f32,
            self.dur,
            self.sbytes, self.dbytes,
            self.sttl, self.dttl,
            self.sloss, self.dloss,
            self.sload, self.dload,
            self.spkts, self.dpkts,
            self.swin, self.dwin,
            self.stcpb, self.dtcpb,
            self.smeansz, self.dmeansz,
            self.trans_depth, self.res_bdy_len,
            self.sjit, self.djit,
            self.stime as f32, self.ltime as f32,
            self.sintpkt, self.dintpkt,
            self.tcprtt, self.synack, self.ackdat,
            self.is_sm_ips_ports,
            self.ct_state_ttl, self.ct_flw_http_mthd,
            self.is_ftp_login, self.ct_ftp_cmd,
            self.ct_srv_src, self.ct_srv_dst,
            self.ct_dst_ltm, self.ct_src_ltm,
            self.ct_src_dport_ltm, self.ct_dst_sport_ltm,
            self.ct_dst_src_ltm,
        ]
    }
}

// ─── Extractor config ─────────────────────────────────────────────────────────
pub struct FeatureExtractor {
    binary_path:    PathBuf,
    flow_timeout:   u32,
    bpf_filter:     String,
    verbose:        bool,
}

impl FeatureExtractor {
    pub fn new(binary_path: impl AsRef<Path>) -> Self {
        Self {
            binary_path:  binary_path.as_ref().to_path_buf(),
            flow_timeout: 120,
            bpf_filter:   "ip or ip6".to_string(),
            verbose:      false,
        }
    }

    pub fn with_flow_timeout(mut self, secs: u32) -> Self {
        self.flow_timeout = secs; self
    }
    pub fn with_bpf_filter(mut self, f: impl Into<String>) -> Self {
        self.bpf_filter = f.into(); self
    }
    pub fn verbose(mut self) -> Self {
        self.verbose = true; self
    }

    /// Live capture on an interface for a given duration.
    /// Requires root / CAP_NET_RAW.
    pub fn capture_live(
        &self,
        interface: &str,
        duration:  Duration,
    ) -> Result<Vec<FlowFeatures>> {
        let csv_path = std::env::temp_dir().join("flow_features_live.csv");
        self.run_extractor(&[
            "-i", interface,
            "-o", csv_path.to_str().unwrap(),
            "-t", &self.flow_timeout.to_string(),
            "-d", &duration.as_secs().to_string(),
            "-f", &self.bpf_filter,
        ])?;
        let features = parse_csv(&csv_path)?;
        let _ = fs::remove_file(&csv_path);
        Ok(features)
    }

    /// Read features from an existing pcap file.
    pub fn capture_pcap(&self, pcap_path: impl AsRef<Path>) -> Result<Vec<FlowFeatures>> {
        let csv_path = std::env::temp_dir().join("flow_features_pcap.csv");
        self.run_extractor(&[
            "-r", pcap_path.as_ref().to_str().unwrap(),
            "-o", csv_path.to_str().unwrap(),
            "-t", &self.flow_timeout.to_string(),
        ])?;
        let features = parse_csv(&csv_path)?;
        let _ = fs::remove_file(&csv_path);
        Ok(features)
    }

    fn run_extractor(&self, args: &[&str]) -> Result<()> {
        if !self.binary_path.exists() {
            return Err(anyhow!(
                "flow_extractor binary not found at {:?}\n\
                 Build it with: cd network_extractor && make\n\
                 Then: sudo cp flow_extractor /usr/local/bin/",
                self.binary_path
            ));
        }

        let mut cmd = Command::new(&self.binary_path);
        cmd.args(args);

        if self.verbose {
            cmd.arg("-v");
        }

        let status = cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("Failed to spawn {:?}", self.binary_path))?;

        if !status.success() {
            return Err(anyhow!(
                "flow_extractor exited with status: {}",
                status
            ));
        }
        Ok(())
    }
}

// ─── CSV parser ───────────────────────────────────────────────────────────────
fn parse_csv(path: &Path) -> Result<Vec<FlowFeatures>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Cannot read CSV: {:?}", path))?;

    let mut lines = content.lines();
    let header = lines.next().ok_or_else(|| anyhow!("Empty CSV file"))?;

    // Validate header
    let expected_cols = 47;
    let actual_cols = header.split(',').count();
    if actual_cols != expected_cols {
        return Err(anyhow!(
            "CSV has {} columns, expected {}. Header: {}",
            actual_cols, expected_cols, header
        ));
    }

    let mut features = Vec::new();
    let mut line_num = 1usize;

    for line in lines {
        line_num += 1;
        if line.trim().is_empty() { continue; }

        match parse_row(line) {
            Ok(f)  => features.push(f),
            Err(e) => eprintln!("Warning: skipping line {}: {}", line_num, e),
        }
    }

    Ok(features)
}

fn parse_row(line: &str) -> Result<FlowFeatures> {
    let cols: Vec<&str> = line.split(',').collect();
    if cols.len() < 47 {
        return Err(anyhow!("Expected 47 columns, got {}", cols.len()));
    }

    let f32 = |s: &str| -> f32 {
        s.trim().parse::<f32>().unwrap_or(0.0)
    };
    let i32 = |s: &str| -> i32 {
        s.trim().parse::<i32>().unwrap_or(0)
    };
    let i64 = |s: &str| -> i64 {
        s.trim().parse::<i64>().unwrap_or(0)
    };
    let str = |s: &str| -> String {
        s.trim().trim_matches('"').to_string()
    };

    Ok(FlowFeatures {
        srcip:             str(cols[0]),
        sport:             i32(cols[1]),
        dstip:             str(cols[2]),
        dsport:            i32(cols[3]),
        proto:             str(cols[4]),
        state:             str(cols[5]),
        dur:               f32(cols[6]),
        sbytes:            f32(cols[7]),
        dbytes:            f32(cols[8]),
        sttl:              f32(cols[9]),
        dttl:              f32(cols[10]),
        sloss:             f32(cols[11]),
        dloss:             f32(cols[12]),
        service:           str(cols[13]),
        sload:             f32(cols[14]),
        dload:             f32(cols[15]),
        spkts:             f32(cols[16]),
        dpkts:             f32(cols[17]),
        swin:              f32(cols[18]),
        dwin:              f32(cols[19]),
        stcpb:             f32(cols[20]),
        dtcpb:             f32(cols[21]),
        smeansz:           f32(cols[22]),
        dmeansz:           f32(cols[23]),
        trans_depth:       f32(cols[24]),
        res_bdy_len:       f32(cols[25]),
        sjit:              f32(cols[26]),
        djit:              f32(cols[27]),
        stime:             i64(cols[28]),
        ltime:             i64(cols[29]),
        sintpkt:           f32(cols[30]),
        dintpkt:           f32(cols[31]),
        tcprtt:            f32(cols[32]),
        synack:            f32(cols[33]),
        ackdat:            f32(cols[34]),
        is_sm_ips_ports:   f32(cols[35]),
        ct_state_ttl:      f32(cols[36]),
        ct_flw_http_mthd:  f32(cols[37]),
        is_ftp_login:      f32(cols[38]),
        ct_ftp_cmd:        f32(cols[39]),
        ct_srv_src:        f32(cols[40]),
        ct_srv_dst:        f32(cols[41]),
        ct_dst_ltm:        f32(cols[42]),
        ct_src_ltm:        f32(cols[43]),
        ct_src_dport_ltm:  f32(cols[44]),
        ct_dst_sport_ltm:  f32(cols[45]),
        ct_dst_src_ltm:    f32(cols[46]),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_row_valid() {
        let row = "192.168.1.1,443,10.0.0.2,54321,tcp,SF,1.234567,\
                   1500,800,64,128,0,0,http,9600.000000,5120.000000,\
                   10,8,65535,8192,123456,654321,150.000000,100.000000,\
                   2,512,1.5,0.8,1700000000,1700000001,\
                   100.0,125.0,0.045,0.020,0.025,\
                   0,3,2,0,0,5,4,8,6,3,2,7";
        let f = parse_row(row).unwrap();
        assert_eq!(f.srcip, "192.168.1.1");
        assert_eq!(f.sport, 443);
        assert_eq!(f.proto, "tcp");
        assert_eq!(f.service, "http");
        assert!((f.dur - 1.234567).abs() < 0.0001);
    }

    #[test]
    fn numeric_features_length() {
        let row = "192.168.1.1,443,10.0.0.2,54321,tcp,SF,1.0,\
                   100,200,64,128,0,0,http,800.0,400.0,\
                   5,3,65535,8192,0,0,100.0,66.6,\
                   1,200,0.5,0.3,1700000000,1700000001,\
                   50.0,66.0,0.01,0.005,0.005,\
                   0,2,1,0,0,3,2,4,3,2,1,5";
        let f = parse_row(row).unwrap();
        assert_eq!(f.numeric_features().len(), 43);
    }
}