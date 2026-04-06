#pragma once
/**
 * include/flow.h
 * --------------
 * Core data structures: PacketInfo (per-packet) and FlowRecord (per-flow).
 * FlowRecord accumulates all 47 UNSW-NB15 features across the flow lifetime.
 */

#include <string>
#include <vector>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <netinet/in.h>   // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP

// ─── TCP flag masks ───────────────────────────────────────────────────────────
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint8_t TCP_URG = 0x20;

// ─── Five-tuple flow key ──────────────────────────────────────────────────────
struct FlowKey {
    std::string srcip;
    std::string dstip;
    uint16_t    sport;
    uint16_t    dsport;
    uint8_t     proto;

    bool operator==(const FlowKey& o) const {
        return srcip == o.srcip && dstip == o.dstip &&
               sport == o.sport && dsport == o.dsport && proto == o.proto;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        size_t h = std::hash<std::string>{}(k.srcip);
        h ^= std::hash<std::string>{}(k.dstip)  + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.sport)     + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.dsport)    + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(k.proto)      + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// ─── Per-packet info ──────────────────────────────────────────────────────────
struct PacketInfo {
    std::string srcip, dstip;
    uint16_t    sport   = 0;
    uint16_t    dsport  = 0;
    uint8_t     proto   = 0;
    uint8_t     tcp_flags = 0;
    uint8_t     sttl    = 0;
    uint16_t    swin    = 0;      // TCP source window
    uint32_t    seq     = 0;
    uint32_t    ack     = 0;
    uint32_t    ip_len  = 0;      // total IP packet length
    uint32_t    payload_len = 0;  // application payload bytes
    uint32_t    ts_sec  = 0;
    uint32_t    ts_usec = 0;
    uint32_t    cap_len = 0;

    double timestamp() const {
        return static_cast<double>(ts_sec) + static_cast<double>(ts_usec) / 1e6;
    }
};

// ─── Flow direction ───────────────────────────────────────────────────────────
enum class PktDir { SRC_TO_DST, DST_TO_SRC };

// ─── Welford online variance tracker ─────────────────────────────────────────
struct OnlineStats {
    uint64_t n     = 0;
    double   mean  = 0.0;
    double   M2    = 0.0;  // sum of squared deviations
    double   last  = 0.0;

    void update(double x) {
        ++n;
        double delta  = x - mean;
        mean         += delta / n;
        double delta2 = x - mean;
        M2           += delta * delta2;
        last          = x;
    }

    double variance() const { return (n > 1) ? M2 / (n - 1) : 0.0; }
    double stddev()   const { return std::sqrt(variance()); }
    double jitter()   const { return std::sqrt(variance()); }  // RMS jitter
};

// ─── Per-direction statistics ─────────────────────────────────────────────────
struct DirectionStats {
    uint64_t pkts       = 0;    // Spkts / Dpkts
    uint64_t bytes      = 0;    // sbytes / dbytes
    uint64_t loss_pkts  = 0;    // sloss / dloss
    uint32_t win        = 0;    // swin / dwin (last seen)
    uint32_t tcp_base   = 0;    // stcpb / dtcpb (initial seq number)
    bool     tcp_base_set = false;
    uint32_t last_seq   = 0;
    uint8_t  ttl        = 0;    // sttl / dttl (last seen)

    OnlineStats pkt_size_stats;    // for smeansz / dmeansz
    OnlineStats inter_pkt_stats;   // for Sintpkt / Dintpkt and Sjit / Djit

    double last_pkt_ts  = 0.0;
    double first_pkt_ts = 0.0;
    double last_pkt_end = 0.0;

    // HTTP / FTP state
    uint32_t http_methods = 0;   // ct_flw_http_mthd
    bool     ftp_login    = false;
    uint32_t ftp_cmds     = 0;   // ct_ftp_cmd

    void add_packet(const PacketInfo& p, double ts) {
        pkts++;
        bytes += p.ip_len;
        pkt_size_stats.update(static_cast<double>(p.ip_len));

        if (first_pkt_ts == 0.0) first_pkt_ts = ts;

        if (last_pkt_ts > 0.0) {
            double gap = ts - last_pkt_ts;
            if (gap > 0) inter_pkt_stats.update(gap * 1000.0); // convert to ms
        }
        last_pkt_ts = ts;

        ttl = p.sttl;
        if (p.proto == IPPROTO_TCP) {
            win = p.swin;
            if (!tcp_base_set) {
                tcp_base     = p.seq;
                tcp_base_set = true;
            }
            // Detect loss via sequence gaps (simple heuristic)
            if (last_seq > 0 && p.seq > last_seq + 65536) {
                loss_pkts++;
            }
            last_seq = p.seq;
        }
    }
};

// ─── TCP handshake timing ─────────────────────────────────────────────────────
struct TcpHandshake {
    double syn_ts    = 0.0;
    double synack_ts = 0.0;
    double ack_ts    = 0.0;
    bool   syn_seen    = false;
    bool   synack_seen = false;
    bool   ack_seen    = false;

    void on_syn(double ts)    { if (!syn_seen)    { syn_ts    = ts; syn_seen    = true; } }
    void on_synack(double ts) { if (!synack_seen) { synack_ts = ts; synack_seen = true; } }
    void on_ack(double ts)    { if (!ack_seen)    { ack_ts    = ts; ack_seen    = true; } }

    double synack_time() const {
        return (syn_seen && synack_seen) ? synack_ts - syn_ts : 0.0;
    }
    double ackdat_time() const {
        return (synack_seen && ack_seen) ? ack_ts - synack_ts : 0.0;
    }
    double rtt() const {
        return synack_time() + ackdat_time();
    }
};

// ─── HTTP response body tracking ─────────────────────────────────────────────
struct HttpState {
    uint32_t trans_depth  = 0;    // depth of request/response pipeline
    uint32_t res_bdy_len  = 0;    // bytes of last HTTP response body
    bool     in_response  = false;
    uint32_t http_methods = 0;
};

// ─── Main flow record ─────────────────────────────────────────────────────────
struct FlowRecord {
    FlowKey key;

    double start_ts = 0.0;   // Stime (epoch)
    double end_ts   = 0.0;   // Ltime (epoch)

    DirectionStats fwd;  // source → destination
    DirectionStats bwd;  // destination → source

    TcpHandshake  handshake;
    HttpState     http;

    std::string state;   // TCP state string: e.g. "S0", "SF", "CON", "REQ"
    std::string service; // detected service: http, ftp, dns, ssh, "-"

    // FTP
    bool     ftp_login = false;
    uint32_t ftp_cmds  = 0;

    // Same IP/port flag
    bool is_sm_ips_ports = false;

    // Connection tracking counters (filled by ConnectionTracker at export)
    float ct_state_ttl      = 0;
    float ct_flw_http_mthd  = 0;
    float ct_srv_src        = 0;
    float ct_srv_dst        = 0;
    float ct_dst_ltm        = 0;
    float ct_src_ltm        = 0;
    float ct_src_dport_ltm  = 0;
    float ct_dst_sport_ltm  = 0;
    float ct_dst_src_ltm    = 0;

    bool exported = false;

    // ── Derived feature accessors ─────────────────────────────────────────────

    double dur()   const { return end_ts - start_ts; }
    double sload() const { // bits per second src→dst
        double d = dur();
        return (d > 0) ? (fwd.bytes * 8.0) / d : 0.0;
    }
    double dload() const { // bits per second dst→src
        double d = dur();
        return (d > 0) ? (bwd.bytes * 8.0) / d : 0.0;
    }

    std::string proto_name() const {
        if (key.proto == IPPROTO_TCP)  return "tcp";
        if (key.proto == IPPROTO_UDP)  return "udp";
        if (key.proto == IPPROTO_ICMP) return "icmp";
        return std::to_string(key.proto);
    }

    void update_state() {
        if (key.proto == IPPROTO_TCP) {
            if (handshake.syn_seen && handshake.synack_seen && handshake.ack_seen)
                state = "SF";
            else if (handshake.syn_seen && !handshake.synack_seen)
                state = "S0";
            else if (fwd.pkts > 0 && bwd.pkts > 0)
                state = "CON";
            else
                state = "S1";
        } else if (key.proto == IPPROTO_UDP) {
            state = (fwd.pkts > 0 && bwd.pkts > 0) ? "CON" : "INT";
        } else {
            state = "CON";
        }
    }

    void detect_service() {
        uint16_t p1 = key.sport, p2 = key.dsport;
        auto has = [&](uint16_t p) { return p == p1 || p == p2; };

        if (has(80) || has(8080) || has(8000) || has(443) || has(8443))
            service = "http";
        else if (has(21))   service = "ftp";
        else if (has(22))   service = "ssh";
        else if (has(53))   service = "dns";
        else if (has(25) || has(587) || has(465)) service = "smtp";
        else if (has(110) || has(995))            service = "pop3";
        else if (has(143) || has(993))            service = "imap";
        else if (has(3306)) service = "mysql";
        else if (has(5432)) service = "postgres";
        else                service = "-";
    }
};