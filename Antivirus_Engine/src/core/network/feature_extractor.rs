// File: src/core/network/feature_extractor.rs
//
// UNSW-NB15 feature extractor — captures EVERY field from live packet data
// via Npcap (Windows) / libpcap (other platforms), correlated with the
// connection table produced by NetworkScanner.
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │  PREREQUISITES                                                            │
// │  Windows: install Npcap (https://npcap.com) with "WinPcap API compat"   │
// │  Linux/mac: sudo apt install libpcap-dev  /  brew install libpcap        │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Cargo.toml additions required:
//
//   [dependencies]
//   pcap        = "2.4"
//   etherparse  = "0.19"
//   dashmap     = "6"
//   parking_lot = "0.12"
//
//   [target.'cfg(windows)'.dependencies]
//   windows-sys = { version = "0.61", features = [
//       "Win32_NetworkManagement_IpHelper",
//       "Win32_Networking_WinSock",
//       "Win32_Foundation",
//   ]}
//
// ─────────────────────────────────────────────────────────────────────────────

use crate::core::network::types::NetworkConnection;
use anyhow::{Context, Result};
use dashmap::DashMap;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use parking_lot::Mutex;
use pcap::{Capture, Device};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

// ─────────────────────────────────────────────────────────────────────────────
// Tuneable constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum packets stored per flow for statistical features.
/// All counters (bytes, pkt count) are still tracked for every packet.
const MAX_PKTS: usize = 200;

/// Maximum number of capture threads (one per physical interface).
const MAX_CAPTURE_IFACES: usize = 4;

/// Seconds of inactivity after which a terminated/idle flow is evicted.
const FLOW_IDLE_SECS: f64 = 30.0;

/// Pcap read timeout in milliseconds. Larger value = kernel does the waiting.
const PCAP_TIMEOUT_MS: i32 = 500;

/// Sleep duration when pcap returns TimeoutExpired to prevent busy-wait spin.
const PCAP_IDLE_SLEEP_MS: u64 = 10;

// ─────────────────────────────────────────────────────────────────────────────
// CSV header — 47 columns, UNSW-NB15 ordering
// ─────────────────────────────────────────────────────────────────────────────

const CSV_HEADER: &str =
    "srcip,sport,dstip,dsport,proto,state,dur,sbytes,dbytes,\
sttl,dttl,sloss,dloss,service,Sload,Dload,Spkts,Dpkts,\
swin,dwin,stcpb,dtcpb,smeansz,dmeansz,trans_depth,res_bdy_len,\
Sjit,Djit,Stime,Ltime,Sintpkt,Dintpkt,\
tcprtt,synack,ackdat,is_sm_ips_ports,ct_state_ttl,\
ct_flw_http_mthd,is_ftp_login,ct_ftp_cmd,\
ct_srv_src,ct_srv_dst,ct_dst_ltm,ct_src_ltm,\
ct_src_dport_ltm,ct_dst_sport_ltm,ct_dst_src_ltm";

// ─────────────────────────────────────────────────────────────────────────────
// Flow key — canonical bidirectional 5-tuple
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src:   String,
    pub dst:   String,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,   // IANA: 1=ICMP, 6=TCP, 17=UDP
}

impl FlowKey {
    /// Canonicalise direction so both directions map to the same key.
    fn new(a: String, b: String, ap: u16, bp: u16, proto: u8) -> Self {
        if (&a, ap) <= (&b, bp) {
            Self { src: a, dst: b, sport: ap, dport: bp, proto }
        } else {
            Self { src: b, dst: a, sport: bp, dport: ap, proto }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-packet summary
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PktSummary {
    ts:           f64,   // Unix epoch (float seconds)
    len:          u32,   // wire length in bytes
    from_src:     bool,  // true = packet came from FlowKey.src
    ttl:          u8,
    tcp_seq:      u32,
    tcp_win:      u16,
    tcp_syn:      bool,
    tcp_ack_flag: bool,
    tcp_fin:      bool,
    tcp_rst:      bool,
    payload_len:  u32,
    // layer-7 detection results
    http_method:         bool,
    http_response_body:  u32,   // Content-Length parsed from HTTP response
    is_ftp_cmd:          bool,
    ftp_logged_in:       bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-flow accumulator
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct FlowAcc {
    /// Capped sample buffer (MAX_PKTS) used for timing statistics only.
    pkts:    Vec<PktSummary>,
    state:   String,
    service: &'static str,
    // TCP 3-way handshake timestamps
    syn_ts:      Option<f64>,
    syn_ack_ts:  Option<f64>,
    ack_ts:      Option<f64>,
    // Loss counters (retransmit heuristic)
    src_retransmits: u32,
    dst_retransmits: u32,
    last_src_seq:    u32,
    last_dst_seq:    u32,
    // HTTP / FTP
    http_req_count:          u32,
    http_response_body_max:  u32,
    ftp_cmd_count:           u32,
    ftp_logged_in:           bool,
    // Running counters — accurate for ALL packets (not capped by MAX_PKTS)
    src_pkt_count:  u32,
    dst_pkt_count:  u32,
    src_byte_count: u64,
    dst_byte_count: u64,
    last_src_win:   u16,
    last_dst_win:   u16,
}

impl FlowAcc {
    fn new(service: &'static str) -> Self {
        Self {
            pkts: Vec::with_capacity(32.min(MAX_PKTS)),
            state: "CON".to_string(),
            service,
            syn_ts: None, syn_ack_ts: None, ack_ts: None,
            src_retransmits: 0, dst_retransmits: 0,
            last_src_seq: 0, last_dst_seq: 0,
            http_req_count: 0, http_response_body_max: 0,
            ftp_cmd_count: 0, ftp_logged_in: false,
            src_pkt_count: 0, dst_pkt_count: 0,
            src_byte_count: 0, dst_byte_count: 0,
            last_src_win: 0, last_dst_win: 0,
        }
    }

    fn push(&mut self, p: PktSummary) {
        // TCP state machine
        if p.tcp_syn && !p.tcp_ack_flag {
            self.syn_ts = Some(p.ts);
            self.state = "SYN".to_string();
        } else if p.tcp_syn && p.tcp_ack_flag {
            self.syn_ack_ts = Some(p.ts);
            self.state = "SA".to_string();
        } else if p.tcp_ack_flag && self.syn_ack_ts.is_some() && self.ack_ts.is_none() {
            self.ack_ts = Some(p.ts);
            self.state = "ESTABLISHED".to_string();
        } else if p.tcp_fin {
            self.state = "FIN".to_string();
        } else if p.tcp_rst {
            self.state = "RST".to_string();
        }

        // Retransmit detection
        if p.payload_len > 0 {
            if p.from_src {
                if p.tcp_seq == self.last_src_seq && self.last_src_seq != 0 {
                    self.src_retransmits += 1;
                }
                self.last_src_seq = p.tcp_seq;
            } else {
                if p.tcp_seq == self.last_dst_seq && self.last_dst_seq != 0 {
                    self.dst_retransmits += 1;
                }
                self.last_dst_seq = p.tcp_seq;
            }
        }

        if p.http_method { self.http_req_count += 1; }
        if p.http_response_body > 0 { self.http_response_body_max = p.http_response_body; }
        if p.is_ftp_cmd    { self.ftp_cmd_count += 1; }
        if p.ftp_logged_in { self.ftp_logged_in = true; }

        // Update running counters for ALL packets (not subject to cap).
        if p.from_src {
            self.src_pkt_count  += 1;
            self.src_byte_count += p.len as u64;
            if p.tcp_win != 0 { self.last_src_win = p.tcp_win; }
        } else {
            self.dst_pkt_count  += 1;
            self.dst_byte_count += p.len as u64;
            if p.tcp_win != 0 { self.last_dst_win = p.tcp_win; }
        }

        // Cap the timing sample buffer to bound memory usage per flow.
        if self.pkts.len() < MAX_PKTS {
            self.pkts.push(p);
        }
    }

    // ── helper iterators ──────────────────────────────────────────────────────

    fn src_pkts(&self) -> impl Iterator<Item = &PktSummary> {
        self.pkts.iter().filter(|p| p.from_src)
    }
    fn dst_pkts(&self) -> impl Iterator<Item = &PktSummary> {
        self.pkts.iter().filter(|p| !p.from_src)
    }

    // ── feature accessors ─────────────────────────────────────────────────────

    fn stime(&self) -> f64 { self.pkts.first().map(|p| p.ts).unwrap_or(0.0) }
    fn ltime(&self) -> f64 { self.pkts.last().map(|p| p.ts).unwrap_or(0.0) }
    fn dur(&self)   -> f64 { (self.ltime() - self.stime()).max(0.0) }

    fn spkts(&self) -> u32 { self.src_pkt_count }
    fn dpkts(&self) -> u32 { self.dst_pkt_count }

    fn sbytes(&self) -> u64 { self.src_byte_count }
    fn dbytes(&self) -> u64 { self.dst_byte_count }

    fn sttl(&self) -> u8 { self.src_pkts().next().map(|p| p.ttl).unwrap_or(128) }
    fn dttl(&self) -> u8 { self.dst_pkts().next().map(|p| p.ttl).unwrap_or(64) }

    fn sloss(&self) -> u32 { self.src_retransmits }
    fn dloss(&self) -> u32 { self.dst_retransmits }

    fn sload(&self) -> f64 {
        let d = self.dur();
        if d <= 0.0 { 0.0 } else { (self.sbytes() as f64 * 8.0) / d }
    }
    fn dload(&self) -> f64 {
        let d = self.dur();
        if d <= 0.0 { 0.0 } else { (self.dbytes() as f64 * 8.0) / d }
    }

    fn swin(&self) -> u32 { self.last_src_win as u32 }
    fn dwin(&self) -> u32 { self.last_dst_win as u32 }

    fn stcpb(&self) -> u32 {
        self.src_pkts().find(|p| p.tcp_syn)
            .or_else(|| self.src_pkts().next())
            .map(|p| p.tcp_seq)
            .unwrap_or(0)
    }
    fn dtcpb(&self) -> u32 {
        self.dst_pkts().find(|p| p.tcp_syn)
            .or_else(|| self.dst_pkts().next())
            .map(|p| p.tcp_seq)
            .unwrap_or(0)
    }

    fn smeansz(&self) -> f64 {
        let n = self.spkts();
        if n == 0 { 0.0 } else { self.sbytes() as f64 / n as f64 }
    }
    fn dmeansz(&self) -> f64 {
        let n = self.dpkts();
        if n == 0 { 0.0 } else { self.dbytes() as f64 / n as f64 }
    }

    /// Compute (mean_iat, jitter) from a sorted slice of packet timestamps.
    /// jitter = mean absolute deviation of inter-arrival times.
    fn iat_stats(ts: &[f64]) -> (f64, f64) {
        if ts.len() < 2 { return (0.0, 0.0); }
        let iats: Vec<f64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
        let mean = iats.iter().sum::<f64>() / iats.len() as f64;
        let mad  = if iats.len() >= 2 {
            iats.iter().map(|v| (v - mean).abs()).sum::<f64>() / iats.len() as f64
        } else { 0.0 };
        (mean, mad)
    }

    /// Returns (mean_iat, jitter) for src packets in one allocation.
    fn src_iat_stats(&self) -> (f64, f64) {
        let ts: Vec<f64> = self.src_pkts().map(|p| p.ts).collect();
        Self::iat_stats(&ts)
    }
    /// Returns (mean_iat, jitter) for dst packets in one allocation.
    fn dst_iat_stats(&self) -> (f64, f64) {
        let ts: Vec<f64> = self.dst_pkts().map(|p| p.ts).collect();
        Self::iat_stats(&ts)
    }


    fn tcprtt(&self) -> f64 {
        match (self.syn_ts, self.ack_ts) {
            (Some(s), Some(a)) => (a - s).max(0.0),
            _ => 0.0,
        }
    }
    fn synack(&self) -> f64 {
        match (self.syn_ts, self.syn_ack_ts) {
            (Some(s), Some(sa)) => (sa - s).max(0.0),
            _ => 0.0,
        }
    }
    fn ackdat(&self) -> f64 {
        match (self.syn_ack_ts, self.ack_ts) {
            (Some(sa), Some(a)) => (a - sa).max(0.0),
            _ => 0.0,
        }
    }

    fn trans_depth(&self)    -> u32 { self.http_req_count }
    fn res_bdy_len(&self)    -> u32 { self.http_response_body_max }
    fn ct_flw_http_mthd(&self) -> u32 { self.http_req_count }
    fn is_ftp_login(&self)   -> u8  { if self.ftp_logged_in { 1 } else { 0 } }
    fn ct_ftp_cmd(&self)     -> u32 { self.ftp_cmd_count }
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer-7 helpers
// ─────────────────────────────────────────────────────────────────────────────

fn service_from_port(port: u16) -> &'static str {
    match port {
        80 | 8080 | 8000 => "http",
        443 | 8443        => "https",
        21                => "ftp",
        22                => "ssh",
        23                => "telnet",
        25 | 587 | 465    => "smtp",
        53                => "dns",
        110               => "pop3",
        143               => "imap",
        3306              => "mysql",
        5432              => "postgresql",
        6379              => "redis",
        27017             => "mongodb",
        3389              => "rdp",
        5900 | 5901       => "vnc",
        1080              => "socks",
        _                 => "-",
    }
}

/// Return the most descriptive service label for a flow given both ports.
/// Prefers the known service over "-" (unknown).
fn best_service(dport: u16, sport: u16) -> &'static str {
    let d = service_from_port(dport);
    let s = service_from_port(sport);
    match (d, s) {
        (svc, _) if svc != "-" => svc,
        (_, svc) if svc != "-" => svc,
        _                      => "-",
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        1  => "icmp",
        6  => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _  => "other",
    }
}

fn is_http_method(payload: &[u8]) -> bool {
    let prefixes: &[&[u8]] = &[
        b"GET ", b"POST ", b"PUT ", b"DELETE ",
        b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    ];
    prefixes.iter().any(|p| payload.starts_with(p))
}

fn extract_http_response_body_len(payload: &[u8]) -> u32 {
    let hay = match std::str::from_utf8(payload) { Ok(s) => s, Err(_) => return 0 };
    for line in hay.lines() {
        if let Some(rest) = line.to_lowercase().strip_prefix("content-length:") {
            if let Ok(n) = rest.trim().parse::<u32>() { return n; }
        }
    }
    0
}

fn classify_ftp(payload: &[u8]) -> (bool, bool) {
    let s = match std::str::from_utf8(payload) { Ok(s) => s, Err(_) => return (false, false) };
    let cmd = ["USER ", "PASS ", "RETR ", "STOR ", "PORT ", "PASV", "LIST", "QUIT"]
        .iter().any(|p| s.starts_with(p));
    (cmd, s.starts_with("230 "))
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw captured frame into (FlowKey, PktSummary).
/// Accepts Ethernet II or raw IP (loopback / null link-type).
fn parse_packet(data: &[u8], ts: f64, wire_len: u32) -> Option<(FlowKey, PktSummary)> {
    let sliced = SlicedPacket::from_ethernet(data)
        .or_else(|_| SlicedPacket::from_ip(data))
        .ok()?;

    // ── IP layer ──────────────────────────────────────────────────────────────
    let (src_ip, dst_ip, ttl, proto_num) = match &sliced.net {
        Some(NetSlice::Ipv4(ip4)) => {
            let h = ip4.header();
            (h.source_addr().to_string(), h.destination_addr().to_string(),
             h.ttl(), h.protocol().0)
        }
        Some(NetSlice::Ipv6(ip6)) => {
            let h = ip6.header();
            (h.source_addr().to_string(), h.destination_addr().to_string(),
             h.hop_limit(), h.next_header().0)
        }
        _ => return None,
    };

    // ── Transport layer ───────────────────────────────────────────────────────
    let (sport, dport, tcp_seq, tcp_win,
         tcp_syn, tcp_ack_flag, tcp_fin, tcp_rst,
         payload_bytes) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            tcp.source_port(), tcp.destination_port(),
            tcp.sequence_number(), tcp.window_size(),
            tcp.syn(), tcp.ack(), tcp.fin(), tcp.rst(),
            tcp.payload().to_vec(),
        ),
        Some(TransportSlice::Udp(udp)) => (
            udp.source_port(), udp.destination_port(),
            0u32, 0u16,
            false, false, false, false,
            udp.payload().to_vec(),
        ),
        Some(TransportSlice::Icmpv4(icmp)) => {
            let raw = icmp.slice();
            let t = raw.first().copied().unwrap_or(0) as u16;
            let c = raw.get(1).copied().unwrap_or(0) as u16;
            (t, c, 0, 0, false, false, false, false, Vec::new())
        }
        _ => return None,
    };

    // ── Layer-7 analysis ──────────────────────────────────────────────────────
    let http_method        = is_http_method(&payload_bytes);
    let http_response_body = extract_http_response_body_len(&payload_bytes);
    let (is_ftp_cmd, ftp_logged_in) = classify_ftp(&payload_bytes);

    // ── Build key + determine direction ───────────────────────────────────────
    let key = FlowKey::new(src_ip.clone(), dst_ip.clone(), sport, dport, proto_num);
    let from_src = key.src == src_ip && key.sport == sport;

    Some((key, PktSummary {
        ts,
        len: wire_len,
        from_src,
        ttl,
        tcp_seq,
        tcp_win,
        tcp_syn,
        tcp_ack_flag,
        tcp_fin,
        tcp_rst,
        payload_len:        payload_bytes.len() as u32,
        http_method,
        http_response_body,
        is_ftp_cmd,
        ftp_logged_in,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Context tables (rolling-100 window for ct_* features)
//
// Each ct_* query must reflect only the last `window` connections.
// We keep a ring-buffer of recent records for eviction and HashMap counters
// for O(1) lookup — important when hundreds of flows are processed per scan.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct ContextTables {
    /// Ring buffer of recent (src, dst, sport, dport, service) records.
    ring:   std::collections::VecDeque<(String, String, u16, u16, &'static str)>,
    window: usize,

    // Aggregated counters — decremented on eviction, incremented on insertion.
    srv_src:      HashMap<(String, &'static str), u32>,  // (src, svc)
    srv_dst:      HashMap<(String, &'static str), u32>,  // (dst, svc)
    dst_cnt:      HashMap<String,                 u32>,  // dst
    src_cnt:      HashMap<String,                 u32>,  // src
    src_dport:    HashMap<(String, u16),          u32>,  // (src, dport)
    dst_sport:    HashMap<(String, u16),          u32>,  // (dst, sport)
    dst_src:      HashMap<(String, String),       u32>,  // (dst, src)
}

impl ContextTables {
    fn new(window: usize) -> Self {
        Self { window, ring: std::collections::VecDeque::with_capacity(window + 1), ..Default::default() }
    }

    fn push(&mut self, src: &str, dst: &str, sport: u16, dport: u16, svc: &'static str) {
        // Evict oldest entry when window is full
        if self.ring.len() >= self.window {
            if let Some((os, od, osp, odp, osvc)) = self.ring.pop_front() {
                dec(&mut self.srv_src,   (os.clone(), osvc));
                dec(&mut self.srv_dst,   (od.clone(), osvc));
                dec(&mut self.dst_cnt,   od.clone());
                dec(&mut self.src_cnt,   os.clone());
                dec(&mut self.src_dport, (os.clone(), odp));
                dec(&mut self.dst_sport, (od.clone(), osp));
                dec(&mut self.dst_src,   (od, os));
            }
        }

        // Insert new entry
        let s = src.to_string();
        let d = dst.to_string();
        *self.srv_src.entry((s.clone(), svc)).or_insert(0) += 1;
        *self.srv_dst.entry((d.clone(), svc)).or_insert(0) += 1;
        *self.dst_cnt.entry(d.clone()).or_insert(0)        += 1;
        *self.src_cnt.entry(s.clone()).or_insert(0)        += 1;
        *self.src_dport.entry((s.clone(), dport)).or_insert(0) += 1;
        *self.dst_sport.entry((d.clone(), sport)).or_insert(0) += 1;
        *self.dst_src.entry((d.clone(), s.clone())).or_insert(0) += 1;
        self.ring.push_back((s, d, sport, dport, svc));
    }

    fn ct_srv_src(&self,  src: &str, svc: &'static str) -> u32 {
        self.srv_src.get(&(src.to_string(), svc)).copied().unwrap_or(0)
    }
    fn ct_srv_dst(&self,  dst: &str, svc: &'static str) -> u32 {
        self.srv_dst.get(&(dst.to_string(), svc)).copied().unwrap_or(0)
    }
    fn ct_dst_ltm(&self,  dst: &str) -> u32 {
        self.dst_cnt.get(dst).copied().unwrap_or(0)
    }
    fn ct_src_ltm(&self,  src: &str) -> u32 {
        self.src_cnt.get(src).copied().unwrap_or(0)
    }
    fn ct_src_dport_ltm(&self, src: &str, dport: u16) -> u32 {
        self.src_dport.get(&(src.to_string(), dport)).copied().unwrap_or(0)
    }
    fn ct_dst_sport_ltm(&self, dst: &str, sport: u16) -> u32 {
        self.dst_sport.get(&(dst.to_string(), sport)).copied().unwrap_or(0)
    }
    fn ct_dst_src_ltm(&self, dst: &str, src: &str) -> u32 {
        self.dst_src.get(&(dst.to_string(), src.to_string())).copied().unwrap_or(0)
    }
}

/// Decrement a counter map entry; remove the key when it reaches zero.
fn dec<K: Eq + std::hash::Hash>(map: &mut HashMap<K, u32>, key: K) {
    if let Some(v) = map.get_mut(&key) {
        if *v <= 1 { map.remove(&key); } else { *v -= 1; }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ct_state_ttl encoding (UNSW-NB15 Table 6 mapping)
// ─────────────────────────────────────────────────────────────────────────────

fn ct_state_ttl(state: &str, sttl: u8, dttl: u8) -> u32 {
    fn bucket(t: u8) -> u8 {
        if t > 128 { 255 } else if t > 64 { 128 } else if t > 32 { 64 } else { 32 }
    }
    let sc: u32 = match state.to_uppercase().as_str() {
        s if s.contains("FIN") || s.contains("CLO") => 1,
        s if s.contains("INT") || s.contains("EST") => 2,
        s if s.contains("REQ") || s.contains("SYN") => 3,
        s if s == "SA"                               => 4,
        s if s.contains("RST")                       => 5,
        s if s.contains("PAR")                       => 6,
        s if s.contains("ACC")                       => 7,
        s if s.contains("CON") || s.contains("LIST") => 8,
        _                                            => 0,
    };
    sc * 10_000 + (bucket(sttl) as u32) * 100 + bucket(dttl) as u32
}

// ─────────────────────────────────────────────────────────────────────────────
// CSV feature row
// ─────────────────────────────────────────────────────────────────────────────

#[allow(non_snake_case)]
pub struct FeatureRow {
    pub srcip:  String, pub sport: u16,
    pub dstip:  String, pub dsport: u16,
    pub proto:  String, pub state: String,
    pub dur:    f64,
    pub sbytes: u64,    pub dbytes: u64,
    pub sttl:   u8,     pub dttl:  u8,
    pub sloss:  u32,    pub dloss: u32,
    pub service: String,
    pub Sload:  f64,    pub Dload:   f64,
    pub Spkts:  u32,    pub Dpkts:   u32,
    pub swin:   u32,    pub dwin:    u32,
    pub stcpb:  u32,    pub dtcpb:   u32,
    pub smeansz: f64,   pub dmeansz: f64,
    pub trans_depth: u32, pub res_bdy_len: u32,
    pub Sjit:   f64,    pub Djit:    f64,
    pub Stime:  f64,    pub Ltime:   f64,
    pub Sintpkt: f64,   pub Dintpkt: f64,
    pub tcprtt: f64,    pub synack:  f64, pub ackdat: f64,
    pub is_sm_ips_ports: u8,
    pub ct_state_ttl:    u32,
    pub ct_flw_http_mthd: u32,
    pub is_ftp_login: u8,  pub ct_ftp_cmd: u32,
    pub ct_srv_src:   u32, pub ct_srv_dst: u32,
    pub ct_dst_ltm:   u32, pub ct_src_ltm: u32,
    pub ct_src_dport_ltm:  u32,
    pub ct_dst_sport_ltm:  u32,
    pub ct_dst_src_ltm:    u32,
}

impl FeatureRow {
    pub fn to_csv_line(&self) -> String {
        format!(
            "{},{},{},{},{},{},{:.6},{},{},\
{},{},{},{},{},{:.4},{:.4},{},{},\
{},{},{},{},{:.4},{:.4},{},{},\
{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},\
{:.6},{:.6},{:.6},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.srcip, self.sport, self.dstip, self.dsport,
            self.proto, self.state, self.dur,
            self.sbytes, self.dbytes,
            self.sttl, self.dttl, self.sloss, self.dloss,
            self.service, self.Sload, self.Dload,
            self.Spkts, self.Dpkts,
            self.swin, self.dwin, self.stcpb, self.dtcpb,
            self.smeansz, self.dmeansz,
            self.trans_depth, self.res_bdy_len,
            self.Sjit, self.Djit,
            self.Stime, self.Ltime,
            self.Sintpkt, self.Dintpkt,
            self.tcprtt, self.synack, self.ackdat,
            self.is_sm_ips_ports, self.ct_state_ttl,
            self.ct_flw_http_mthd, self.is_ftp_login, self.ct_ftp_cmd,
            self.ct_srv_src, self.ct_srv_dst,
            self.ct_dst_ltm, self.ct_src_ltm,
            self.ct_src_dport_ltm, self.ct_dst_sport_ltm, self.ct_dst_src_ltm,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background capture thread
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true for loopback or virtual interfaces we should skip.
fn is_virtual_interface(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("loopback")
        || n.contains("vethernet")
        || n.contains("hyper-v")
        || n.contains("wsl")
        || n.contains("virtual")
        || n.contains("miniport")
        || n == "lo"
        || n.starts_with("virbr")
        || n.starts_with("docker")
}

/// Spawn one capture thread per physical interface (capped at MAX_CAPTURE_IFACES).
/// Returns the thread handles so the caller can join them on shutdown.
fn spawn_capture_threads(
    flow_table: Arc<DashMap<FlowKey, FlowAcc>>,
    stop: Arc<AtomicBool>,
) -> Vec<thread::JoinHandle<()>> {
    let all_devices = Device::list().unwrap_or_default();
    if all_devices.is_empty() {
        eprintln!(
            "[feature_extractor] No pcap devices found. \
             On Windows, install Npcap with 'WinPcap API compatible mode'."
        );
        return Vec::new();
    }

    // Filter out loopback / virtual interfaces, then cap the count.
    let devices: Vec<Device> = all_devices
        .into_iter()
        .filter(|d| !is_virtual_interface(&d.name))
        .take(MAX_CAPTURE_IFACES)
        .collect();

    let mut handles = Vec::new();
    for device in devices {
        let table   = Arc::clone(&flow_table);
        let stopper = Arc::clone(&stop);
        let name    = device.name.clone();

        let h = thread::spawn(move || {
            let cap = Capture::from_device(device)
                .and_then(|c| c.promisc(true).snaplen(65535).timeout(PCAP_TIMEOUT_MS).open());

            let mut cap = match cap {
                Ok(c)  => c,
                Err(e) => { eprintln!("[feature_extractor] {name}: {e}"); return; }
            };

            while !stopper.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(pkt) => {
                        let ts = pkt.header.ts.tv_sec  as f64
                               + pkt.header.ts.tv_usec as f64 * 1e-6;
                        let wlen = pkt.header.len;

                        if let Some((key, summary)) = parse_packet(pkt.data, ts, wlen) {
                            let svc = best_service(key.dport, key.sport);
                            table.entry(key)
                                .or_insert_with(|| FlowAcc::new(svc))
                                .push(summary);
                        }
                    }
                    // Yield CPU instead of spinning when the interface is quiet.
                    Err(pcap::Error::TimeoutExpired) => {
                        thread::sleep(Duration::from_millis(PCAP_IDLE_SLEEP_MS));
                    }
                    Err(e) => { eprintln!("[feature_extractor] {name}: {e}"); break; }
                }
            }
        });
        handles.push(h);
    }
    handles
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

pub struct FeatureExtractor {
    output_path:    PathBuf,
    flow_table:     Arc<DashMap<FlowKey, FlowAcc>>,
    context_tables: Mutex<ContextTables>,
    stop_flag:      Arc<AtomicBool>,
    /// Capture thread handles — joined on Drop to ensure clean shutdown.
    thread_handles: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl FeatureExtractor {
    /// Create extractor and start background packet capture on all interfaces.
    ///
    /// `output_path` defaults to `%USERPROFILE%\OnePace.csv` on Windows.
    pub fn new(output_path: Option<PathBuf>) -> Result<Arc<Self>> {
        let path = output_path.unwrap_or_else(default_csv_path);

        if !path.exists() {
            // Use BufWriter for the initial header write (Issue 9).
            let f = File::create(&path)
                .with_context(|| format!("Cannot create {}", path.display()))?;
            let mut w = BufWriter::new(f);
            writeln!(w, "{}", CSV_HEADER)?;
            w.flush()?;
        }

        let flow_table = Arc::new(DashMap::<FlowKey, FlowAcc>::new());
        let stop_flag  = Arc::new(AtomicBool::new(false));

        // Spawn capture threads and retain handles for clean shutdown (Issue 10).
        let handles = spawn_capture_threads(Arc::clone(&flow_table), Arc::clone(&stop_flag));

        Ok(Arc::new(Self {
            output_path: path,
            flow_table,
            context_tables: Mutex::new(ContextTables::new(100)),
            stop_flag,
            thread_handles: Mutex::new(handles),
        }))
    }

    /// Build feature rows from accumulated packet data, correlated with the
    /// current connection table, and append them to `OnePace.csv`.
    ///
    /// Flows that are no longer present in the connection table AND whose last
    /// packet was more than `FLOW_IDLE_SECS` seconds ago are evicted from the
    /// flow table after their row is written — preventing unbounded growth.
    pub fn extract_and_append(&self, connections: &[NetworkConnection]) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        // Build state lookup from the live connection table.
        let conn_state: HashMap<(String, u16, String, u16, String), String> = connections
            .iter()
            .map(|c| {
                let (s, sp) = split_endpoint(&c.local_address);
                let (d, dp) = split_endpoint(&c.remote_address);
                ((s, sp.unwrap_or(0), d, dp.unwrap_or(0), c.protocol.to_lowercase()),
                 c.state.clone())
            })
            .collect();

        // Snapshot the keys first (can't hold a DashMap iterator while removing).
        let keys: Vec<FlowKey> = self.flow_table.iter().map(|e| e.key().clone()).collect();

        // Build CSV lines under the context lock, then drop the lock before I/O.
        let mut csv_lines  = Vec::with_capacity(keys.len());
        let mut evict_keys = Vec::new();
        {
            let mut ctx = self.context_tables.lock();

            for key in &keys {
                let Some(acc_ref) = self.flow_table.get(key) else { continue };
                let acc = acc_ref.value();
                if acc.pkts.is_empty() && acc.src_pkt_count == 0 { continue; }

                let proto_str = proto_name(key.proto).to_string();
                let svc       = acc.service;

                let live_state = conn_state.get(&(
                    key.src.clone(), key.sport,
                    key.dst.clone(), key.dport,
                    proto_str.clone(),
                ));

                let state = live_state
                    .cloned()
                    .unwrap_or_else(|| acc.state.clone());

                // Eviction: terminated or idle beyond threshold.
                let is_terminated = live_state.is_none()
                    && (acc.state.contains("FIN")
                        || acc.state.contains("RST")
                        || acc.state.contains("CLO"));
                let is_idle = (now - acc.ltime()) > FLOW_IDLE_SECS;
                if is_terminated || (live_state.is_none() && is_idle) {
                    evict_keys.push(key.clone());
                }

                let is_sm = u8::from(key.src == key.dst || key.sport == key.dport);
                ctx.push(&key.src, &key.dst, key.sport, key.dport, svc);

                // Compute IAT stats once per direction (halves allocations vs 4 separate calls).
                let (sintpkt, sjit)   = acc.src_iat_stats();
                let (dintpkt, djit)   = acc.dst_iat_stats();

                let row = FeatureRow {
                    srcip:  key.src.clone(),
                    sport:  key.sport,
                    dstip:  key.dst.clone(),
                    dsport: key.dport,
                    proto:  proto_str,
                    state:  state.clone(),
                    dur:    acc.dur(),
                    sbytes: acc.sbytes(), dbytes: acc.dbytes(),
                    sttl:   acc.sttl(),   dttl:   acc.dttl(),
                    sloss:  acc.sloss(),  dloss:  acc.dloss(),
                    service: svc.to_string(),
                    Sload:  acc.sload(),  Dload:  acc.dload(),
                    Spkts:  acc.spkts(),  Dpkts:  acc.dpkts(),
                    swin:   acc.swin(),   dwin:   acc.dwin(),
                    stcpb:  acc.stcpb(),  dtcpb:  acc.dtcpb(),
                    smeansz: acc.smeansz(), dmeansz: acc.dmeansz(),
                    trans_depth:    acc.trans_depth(),
                    res_bdy_len:    acc.res_bdy_len(),
                    Sjit:   sjit,  Djit:  djit,
                    Stime:  acc.stime(),  Ltime: acc.ltime(),
                    Sintpkt: sintpkt,  Dintpkt: dintpkt,
                    tcprtt: acc.tcprtt(), synack: acc.synack(), ackdat: acc.ackdat(),
                    is_sm_ips_ports: is_sm,
                    ct_state_ttl:    ct_state_ttl(&state, acc.sttl(), acc.dttl()),
                    ct_flw_http_mthd: acc.ct_flw_http_mthd(),
                    is_ftp_login:    acc.is_ftp_login(),
                    ct_ftp_cmd:      acc.ct_ftp_cmd(),
                    ct_srv_src:      ctx.ct_srv_src(&key.src, svc),
                    ct_srv_dst:      ctx.ct_srv_dst(&key.dst, svc),
                    ct_dst_ltm:      ctx.ct_dst_ltm(&key.dst),
                    ct_src_ltm:      ctx.ct_src_ltm(&key.src),
                    ct_src_dport_ltm:  ctx.ct_src_dport_ltm(&key.src, key.dport),
                    ct_dst_sport_ltm:  ctx.ct_dst_sport_ltm(&key.dst, key.sport),
                    ct_dst_src_ltm:    ctx.ct_dst_src_ltm(&key.dst, &key.src),
                };
                // Serialize to string now so FeatureRow is not held past this scope.
                csv_lines.push(row.to_csv_line());
            }
        } // context_tables lock released here

        let n = csv_lines.len();

        // Evict terminated/idle flows.
        for key in evict_keys {
            self.flow_table.remove(&key);
        }

        // Write CSV lines (already buffered via BufWriter in append_lines).
        self.append_lines(&csv_lines)?;
        Ok(n)
    }

    pub fn csv_path(&self) -> &std::path::Path { &self.output_path }

    fn append_lines(&self, lines: &[String]) -> Result<()> {
        if lines.is_empty() { return Ok(()); }
        let file = OpenOptions::new()
            .append(true).create(true)
            .open(&self.output_path)
            .with_context(|| format!("Cannot open {}", self.output_path.display()))?;
        let mut w = BufWriter::new(file);
        for line in lines { writeln!(w, "{}", line)?; }
        w.flush()?;
        Ok(())
    }
}

impl Drop for FeatureExtractor {
    fn drop(&mut self) {
        // Signal all capture threads to exit.
        self.stop_flag.store(true, Ordering::Relaxed);
        // Join them so we don't leak OS threads after the extractor is dropped.
        let mut handles = self.thread_handles.lock();
        for h in handles.drain(..) {
            let _ = h.join();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn default_csv_path() -> PathBuf {
    #[cfg(windows)]
    {
        let home = std::env::var("USERPROFILE")
            .unwrap_or_else(|_| "C:\\Users\\Public".to_string());
        PathBuf::from(home).join("OnePace.csv")
    }
    #[cfg(not(windows))]
    { PathBuf::from("OnePace.csv") }
}

fn split_endpoint(ep: &str) -> (String, Option<u16>) {
    if ep.ends_with(":*") { return (ep.trim_end_matches(":*").to_string(), None); }
    if ep.starts_with('[') {
        if let Some(i) = ep.rfind(']') {
            return (ep[1..i].to_string(), ep[i+1..].trim_start_matches(':').parse().ok());
        }
    }
    if let Some(c) = ep.rfind(':') {
        return (ep[..c].to_string(), ep[c+1..].parse().ok());
    }
    (ep.to_string(), None)
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration — add these lines to scanner.rs
// ─────────────────────────────────────────────────────────────────────────────
//
//  use crate::core::network::feature_extractor::FeatureExtractor;
//  use std::sync::Arc;
//
//  pub struct NetworkScanner {
//      heuristics:        NetworkHeuristics,
//      feature_extractor: Arc<FeatureExtractor>,   // ← ADD
//  }
//
//  impl NetworkScanner {
//      pub fn new() -> Self {
//          Self {
//              heuristics: NetworkHeuristics::new(),
//              feature_extractor: FeatureExtractor::new(None)
//                                     .expect("OnePace.csv init failed"),
//          }
//      }
//
//      pub fn scan(&self) -> Result<(Vec<NetworkConnection>, NetworkScanStatistics)> {
//          /* … existing code … */
//
//          // ── feature extraction ──────────────────────────────────────────
//          if let Err(e) = self.feature_extractor.extract_and_append(&connections) {
//              eprintln!("[feature_extractor] {e}");
//          }
//          // ────────────────────────────────────────────────────────────────
//
//          Ok((connections, stats))
//      }
//  }

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet/IPv4/TCP frame for unit testing the parser.
    fn eth_ipv4_tcp(
        src: [u8; 4], dst: [u8; 4],
        sport: u16, dport: u16,
        seq: u32, win: u16, flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let ip_len  = 20 + tcp_len;
        let mut pkt = vec![0u8; 14 + ip_len];

        // Ethernet II — ethertype IPv4
        pkt[12] = 0x08; pkt[13] = 0x00;

        // IPv4
        let ip = &mut pkt[14..34];
        ip[0] = 0x45;
        ip[2] = (ip_len >> 8) as u8; ip[3] = (ip_len & 0xff) as u8;
        ip[8] = 64; ip[9] = 6;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);

        // TCP
        let tcp = &mut pkt[34..54];
        tcp[0] = (sport >> 8) as u8;  tcp[1] = (sport & 0xff) as u8;
        tcp[2] = (dport >> 8) as u8;  tcp[3] = (dport & 0xff) as u8;
        tcp[4] = (seq >> 24) as u8;   tcp[5] = (seq >> 16) as u8;
        tcp[6] = (seq >> 8)  as u8;   tcp[7] =  seq as u8;
        tcp[12] = 0x50; // data-offset = 5
        tcp[13] = flags;
        tcp[14] = (win >> 8) as u8; tcp[15] = (win & 0xff) as u8;

        pkt[54..54 + payload.len()].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_syn_extracts_correct_fields() {
        let raw = eth_ipv4_tcp(
            [192,168,1,1], [93,184,216,34], 54321, 80,
            1000, 65535, 0x02, b"",
        );
        let (key, pkt) = parse_packet(&raw, 1.0, raw.len() as u32).unwrap();
        assert_eq!(key.dport, 80);
        assert!(pkt.tcp_syn);
        assert!(!pkt.tcp_ack_flag);
        assert_eq!(pkt.tcp_win, 65535);
        assert_eq!(pkt.tcp_seq, 1000);
        assert_eq!(pkt.ttl, 64);
    }

    #[test]
    fn parse_http_get_detected() {
        let raw = eth_ipv4_tcp(
            [10,0,0,1], [10,0,0,2], 44444, 80, 5000, 8192, 0x18,
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        let (_, pkt) = parse_packet(&raw, 2.0, raw.len() as u32).unwrap();
        assert!(pkt.http_method);
    }

    #[test]
    fn parse_http_response_content_length() {
        let raw = eth_ipv4_tcp(
            [10,0,0,2], [10,0,0,1], 80, 44444, 9000, 8192, 0x18,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n",
        );
        let (_, pkt) = parse_packet(&raw, 3.0, raw.len() as u32).unwrap();
        assert_eq!(pkt.http_response_body, 4096);
    }

    #[test]
    fn flow_acc_three_way_handshake_timing() {
        let mut acc = FlowAcc::new("http");

        let base = PktSummary {
            ts: 0.0, len: 60, from_src: true, ttl: 64,
            tcp_seq: 100, tcp_win: 65535,
            tcp_syn: false, tcp_ack_flag: false, tcp_fin: false, tcp_rst: false,
            payload_len: 0, http_method: false, http_response_body: 0,
            is_ftp_cmd: false, ftp_logged_in: false,
        };

        // SYN
        acc.push(PktSummary { ts: 1.000, tcp_syn: true, ..base.clone() });
        // SYN-ACK
        acc.push(PktSummary { ts: 1.010, from_src: false, tcp_syn: true, tcp_ack_flag: true, ttl: 128, ..base.clone() });
        // ACK
        acc.push(PktSummary { ts: 1.012, tcp_ack_flag: true, ..base.clone() });

        assert!((acc.synack() - 0.010).abs() < 1e-9);
        assert!((acc.ackdat() - 0.002).abs() < 1e-9);
        assert!((acc.tcprtt() - 0.012).abs() < 1e-9);
        assert_eq!(acc.sttl(), 64);
        assert_eq!(acc.dttl(), 128);
        assert_eq!(acc.stcpb(), 100);
    }

    #[test]
    fn flow_acc_retransmit_counted_once() {
        let mut acc = FlowAcc::new("-");
        let base = PktSummary {
            ts: 0.0, len: 100, from_src: true, ttl: 64,
            tcp_seq: 500, tcp_win: 1024,
            tcp_syn: false, tcp_ack_flag: true, tcp_fin: false, tcp_rst: false,
            payload_len: 50, http_method: false, http_response_body: 0,
            is_ftp_cmd: false, ftp_logged_in: false,
        };
        acc.push(base.clone());
        acc.push(PktSummary { ts: 0.1, ..base.clone() }); // same seq = retransmit
        acc.push(PktSummary { ts: 0.2, tcp_seq: 550, ..base });
        assert_eq!(acc.sloss(), 1);
        assert_eq!(acc.dloss(), 0);
    }

    #[test]
    fn flow_acc_jitter_nonzero_for_irregular_iats() {
        let ts = vec![0.0_f64, 0.1, 0.35, 0.4, 0.9];
        let (mean_iat, jitter) = FlowAcc::iat_stats(&ts);
        assert!(mean_iat > 0.0, "mean IAT should be > 0");
        assert!(jitter   > 0.0, "jitter should be > 0 for irregular IATs");
    }

    #[test]
    fn csv_row_column_count_matches_header() {
        let row = FeatureRow {
            srcip: "1.2.3.4".into(), sport: 1234,
            dstip: "5.6.7.8".into(), dsport: 80,
            proto: "tcp".into(), state: "ESTABLISHED".into(),
            dur: 1.5, sbytes: 1000, dbytes: 2000,
            sttl: 64, dttl: 128, sloss: 0, dloss: 1,
            service: "http".into(),
            Sload: 5333.0, Dload: 10667.0, Spkts: 10, Dpkts: 12,
            swin: 65535, dwin: 8192, stcpb: 100000, dtcpb: 200000,
            smeansz: 100.0, dmeansz: 166.7, trans_depth: 2, res_bdy_len: 4096,
            Sjit: 0.001, Djit: 0.002,
            Stime: 1_700_000_000.0, Ltime: 1_700_000_001.5,
            Sintpkt: 0.15, Dintpkt: 0.12,
            tcprtt: 0.012, synack: 0.010, ackdat: 0.002,
            is_sm_ips_ports: 0, ct_state_ttl: 20012864,
            ct_flw_http_mthd: 2, is_ftp_login: 0, ct_ftp_cmd: 0,
            ct_srv_src: 3, ct_srv_dst: 5, ct_dst_ltm: 8, ct_src_ltm: 4,
            ct_src_dport_ltm: 2, ct_dst_sport_ltm: 1, ct_dst_src_ltm: 6,
        };
        let line = row.to_csv_line();
        let data_cols   = line.split(',').count();
        let header_cols = CSV_HEADER.split(',').count();
        assert_eq!(data_cols, header_cols,
            "row has {data_cols} cols, header has {header_cols}");
    }

    #[test]
    fn context_tables_rolling_window_evicts_oldest() {
        let mut ctx = ContextTables::new(3);
        ctx.push("1.1.1.1", "2.2.2.2", 1111, 80, "http"); // will be evicted
        ctx.push("1.1.1.1", "2.2.2.2", 1112, 80, "http");
        ctx.push("1.1.1.1", "3.3.3.3", 1113, 80, "http");
        ctx.push("9.9.9.9", "2.2.2.2", 9999, 80, "http"); // evicts entry 1
        // entries 2+3 remain for 1.1.1.1 as src
        assert_eq!(ctx.ct_srv_src("1.1.1.1", "http"), 2);
        // entry 2 (1.1.1.1→2.2.2.2) + entry 4 (9.9.9.9→2.2.2.2) = 2
        assert_eq!(ctx.ct_dst_ltm("2.2.2.2"), 2);
        // entry 4 only
        assert_eq!(ctx.ct_src_ltm("9.9.9.9"), 1);
    }

    #[test]
    fn split_endpoint_all_variants() {
        assert_eq!(split_endpoint("10.0.0.1:443"), ("10.0.0.1".into(), Some(443)));
        assert_eq!(split_endpoint("[::1]:8080"),   ("::1".into(), Some(8080)));
        assert_eq!(split_endpoint("0.0.0.0:*"),   ("0.0.0.0".into(), None));
        assert_eq!(split_endpoint("192.168.1.1"), ("192.168.1.1".into(), None));
    }
}