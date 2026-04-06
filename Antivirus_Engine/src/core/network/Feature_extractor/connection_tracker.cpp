/**
 * src/connection_tracker.cpp
 * --------------------------
 * Sliding-window connection tracking counters as defined in UNSW-NB15.
 */

#include "../include/connection_tracker.h"
#include <algorithm>

ConnectionTracker::ConnectionTracker(size_t window_size)
    : m_window(window_size) {}

void ConnectionTracker::trim_window() {
    while (m_history.size() > m_window) {
        m_history.pop_front();
    }
}

void ConnectionTracker::compute_counters(FlowRecord& flow) {
    std::lock_guard<std::mutex> lock(m_mutex);

    const std::string& src     = flow.key.srcip;
    const std::string& dst     = flow.key.dstip;
    const std::string& svc     = flow.service;
    const std::string& state   = flow.state;
    uint8_t            sttl    = flow.fwd.ttl;
    uint16_t           dsport  = flow.key.dsport;
    uint16_t           sport   = flow.key.sport;

    uint32_t ct_state_ttl     = 0;
    uint32_t ct_srv_src       = 0;
    uint32_t ct_srv_dst       = 0;
    uint32_t ct_dst_ltm       = 0;
    uint32_t ct_src_ltm       = 0;
    uint32_t ct_src_dport_ltm = 0;
    uint32_t ct_dst_sport_ltm = 0;
    uint32_t ct_dst_src_ltm   = 0;
    uint32_t ct_flw_http_mthd = 0;

    for (const auto& s : m_history) {
        // ct_state_ttl: same state + same TTL bucket
        uint8_t ttl_bucket    = s.sttl / 64;   // quantise TTL to /64 bucket
        uint8_t cur_ttl_bucket = sttl   / 64;
        if (s.state == state && ttl_bucket == cur_ttl_bucket)
            ct_state_ttl++;

        // ct_srv_src: same service, same source IP
        if (s.service == svc && s.srcip == src)
            ct_srv_src++;

        // ct_srv_dst: same service, same destination IP
        if (s.service == svc && s.dstip == dst)
            ct_srv_dst++;

        // ct_dst_ltm: connections to same destination
        if (s.dstip == dst)
            ct_dst_ltm++;

        // ct_src_ltm: connections from same source
        if (s.srcip == src)
            ct_src_ltm++;

        // ct_src_dport_ltm: same source → same destination port
        if (s.srcip == src && s.dsport == dsport)
            ct_src_dport_ltm++;

        // ct_dst_sport_ltm: same destination ← same source port
        if (s.dstip == dst && s.sport == sport)
            ct_dst_sport_ltm++;

        // ct_dst_src_ltm: unique (dst, src) pairs
        if (s.dstip == dst && s.srcip == src)
            ct_dst_src_ltm++;

        // ct_flw_http_mthd: HTTP flows with any method from this src
        if (s.service == "http" && s.srcip == src)
            ct_flw_http_mthd++;
    }

    flow.ct_state_ttl     = static_cast<float>(ct_state_ttl);
    flow.ct_srv_src       = static_cast<float>(ct_srv_src);
    flow.ct_srv_dst       = static_cast<float>(ct_srv_dst);
    flow.ct_dst_ltm       = static_cast<float>(ct_dst_ltm);
    flow.ct_src_ltm       = static_cast<float>(ct_src_ltm);
    flow.ct_src_dport_ltm = static_cast<float>(ct_src_dport_ltm);
    flow.ct_dst_sport_ltm = static_cast<float>(ct_dst_sport_ltm);
    flow.ct_dst_src_ltm   = static_cast<float>(ct_dst_src_ltm);
    flow.ct_flw_http_mthd = static_cast<float>(ct_flw_http_mthd);

    // Add this flow to the window
    FlowSnapshot snap;
    snap.srcip    = src;
    snap.dstip    = dst;
    snap.service  = svc;
    snap.state    = state;
    snap.sport    = sport;
    snap.dsport   = dsport;
    snap.sttl     = sttl;
    snap.dttl     = flow.bwd.ttl;
    snap.export_ts = flow.end_ts;
    m_history.push_back(snap);

    trim_window();
}