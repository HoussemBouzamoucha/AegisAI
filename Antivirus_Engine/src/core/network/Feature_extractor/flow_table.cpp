/**
 * src/flow_table.cpp
 * ------------------
 * FlowTable: manages active flow records, dispatches packets, handles expiry.
 */

#include "../include/flow_table.h"
#include <iostream>
#include <cstring>

FlowTable::FlowTable(int idle_timeout_sec, FeatureWriter* writer,
                     ConnectionTracker* ct, bool verbose)
    : m_idle_timeout(idle_timeout_sec), m_writer(writer),
      m_ct(ct), m_verbose(verbose) {}

FlowTable::~FlowTable() { flush_all(); }

// ─── make_key ─────────────────────────────────────────────────────────────────
// Always stores flow with lower IP/port as "src" so both directions map to
// the same record. Sets dir = SRC_TO_DST or DST_TO_SRC accordingly.
FlowKey FlowTable::make_key(const PacketInfo& p, PktDir& dir) {
    FlowKey k;
    // Canonical ordering: smaller (srcip,sport) is always "src"
    bool fwd = (p.srcip < p.dstip) ||
               (p.srcip == p.dstip && p.sport <= p.dsport);
    if (fwd) {
        k.srcip = p.srcip; k.dstip = p.dstip;
        k.sport = p.sport; k.dsport = p.dsport;
        dir = PktDir::SRC_TO_DST;
    } else {
        k.srcip = p.dstip; k.dstip = p.srcip;
        k.sport = p.dsport; k.dsport = p.sport;
        dir = PktDir::DST_TO_SRC;
    }
    k.proto = p.proto;
    return k;
}

// ─── process_packet ───────────────────────────────────────────────────────────
void FlowTable::process_packet(const PacketInfo& p) {
    double ts = p.timestamp();

    PktDir dir;
    FlowKey key = make_key(p, dir);

    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_flows.find(key);
    if (it == m_flows.end()) {
        // New flow
        FlowRecord flow;
        flow.key      = key;
        flow.start_ts = ts;
        flow.end_ts   = ts;
        flow.detect_service();
        flow.is_sm_ips_ports = (p.srcip == p.dstip && p.sport == p.dsport);
        update_flow(flow, p, dir, ts);
        m_flows[key] = std::move(flow);
    } else {
        FlowRecord& flow = it->second;
        flow.end_ts = ts;
        update_flow(flow, p, dir, ts);

        // TCP teardown: export on FIN+ACK or RST
        if (p.proto == IPPROTO_TCP) {
            if ((p.tcp_flags & TCP_RST) ||
                ((p.tcp_flags & TCP_FIN) && (p.tcp_flags & TCP_ACK))) {
                flow.update_state();
                export_flow(flow);
                m_flows.erase(it);
            }
        }
    }
}

// ─── update_flow ─────────────────────────────────────────────────────────────
void FlowTable::update_flow(FlowRecord& flow, const PacketInfo& p,
                            PktDir dir, double ts) {
    DirectionStats& ds = (dir == PktDir::SRC_TO_DST) ? flow.fwd : flow.bwd;
    ds.add_packet(p, ts);

    // TTL: forward direction gets sttl, backward gets dttl
    if (dir == PktDir::SRC_TO_DST) flow.fwd.ttl = p.sttl;
    else                            flow.bwd.ttl = p.sttl;

    // TCP handshake
    if (p.proto == IPPROTO_TCP) {
        bool is_syn    = (p.tcp_flags & TCP_SYN) && !(p.tcp_flags & TCP_ACK);
        bool is_synack = (p.tcp_flags & TCP_SYN) && (p.tcp_flags & TCP_ACK);
        bool is_ack    = !(p.tcp_flags & TCP_SYN) && (p.tcp_flags & TCP_ACK)
                         && !flow.handshake.ack_seen;

        if (is_syn)    flow.handshake.on_syn(ts);
        if (is_synack) flow.handshake.on_synack(ts);
        if (is_ack)    flow.handshake.on_ack(ts);
    }

    detect_app_layer(flow, p, dir);
}

// ─── detect_app_layer ────────────────────────────────────────────────────────
// Minimal heuristic detection of HTTP/FTP features from port numbers and
// payload size patterns (full DPI would require payload reassembly).
void FlowTable::detect_app_layer(FlowRecord& flow, const PacketInfo& p, PktDir dir) {
    // HTTP method detection (heuristic: port 80/443/8080 + forward direction with payload)
    if (flow.service == "http" && dir == PktDir::SRC_TO_DST && p.payload_len > 0) {
        // Each new request packet with payload ≈ one HTTP method
        flow.http.http_methods++;
        if (flow.http.http_methods == 1) {
            flow.http.trans_depth++;
        }
    }
    // HTTP response body (approximation: backward direction payload on HTTP)
    if (flow.service == "http" && dir == PktDir::DST_TO_SRC && p.payload_len > 0) {
        flow.http.res_bdy_len += p.payload_len;
        flow.http.trans_depth++;
    }

    // FTP detection
    if (flow.service == "ftp") {
        if (dir == PktDir::SRC_TO_DST && p.payload_len > 0) {
            flow.ftp_cmds++;
            // Heuristic: USER/PASS command sequence ≈ login attempt
            if (flow.ftp_cmds >= 2) flow.ftp_login = true;
        }
    }
}

// ─── flush_expired ────────────────────────────────────────────────────────────
void FlowTable::flush_expired() {
    double now = static_cast<double>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_flows.begin(); it != m_flows.end(); ) {
        FlowRecord& flow = it->second;
        if ((now - flow.end_ts) >= m_idle_timeout) {
            flow.update_state();
            export_flow(flow);
            it = m_flows.erase(it);
        } else {
            ++it;
        }
    }
}

// ─── flush_all ────────────────────────────────────────────────────────────────
void FlowTable::flush_all() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [key, flow] : m_flows) {
        flow.update_state();
        export_flow(const_cast<FlowRecord&>(flow));
    }
    m_flows.clear();
}

// ─── export_flow ─────────────────────────────────────────────────────────────
void FlowTable::export_flow(FlowRecord& flow) {
    if (flow.exported) return;
    if (flow.fwd.pkts == 0 && flow.bwd.pkts == 0) return;

    // Fill connection tracking counters
    m_ct->compute_counters(flow);

    m_writer->write(flow);
    flow.exported = true;

    if (m_verbose) {
        std::cout << "  Exported: " << flow.key.srcip << ":" << flow.key.sport
                  << " → " << flow.key.dstip << ":" << flow.key.dsport
                  << " [" << flow.proto_name() << "] "
                  << " dur=" << flow.dur() << "s"
                  << " pkts=" << flow.fwd.pkts + flow.bwd.pkts
                  << "\n";
    }
}

size_t FlowTable::active_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_flows.size();
}