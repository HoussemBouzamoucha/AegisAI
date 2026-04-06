#pragma once
/**
 * include/connection_tracker.h
 * ----------------------------
 * Computes the UNSW-NB15 connection-tracking counter features:
 *
 *   ct_state_ttl      — count of connections with same state+TTL in last 100
 *   ct_flw_http_mthd  — count of HTTP flows with same method in last 100
 *   ct_srv_src        — count of connections to same service from same src
 *   ct_srv_dst        — count of connections to same service to same dst
 *   ct_dst_ltm        — count of connections to same dst in last time window
 *   ct_src_ltm        — count of connections from same src in last window
 *   ct_src_dport_ltm  — count of connections from src to same dst port
 *   ct_dst_sport_ltm  — count of connections from dst to same src port
 *   ct_dst_src_ltm    — count of unique src IPs connecting to same dst
 *
 * Implementation uses a fixed-size sliding window of the last N exported flows.
 */

#include "flow.h"
#include <deque>
#include <mutex>
#include <string>

// Snapshot of exported flow for window-based counting
struct FlowSnapshot {
    std::string srcip, dstip, service, state;
    uint16_t    sport, dsport;
    uint8_t     sttl, dttl;
    double      export_ts;
};

class ConnectionTracker {
public:
    explicit ConnectionTracker(size_t window_size = 100);

    // Called on each flow just before it is written to CSV.
    // Fills the ct_* fields in `flow` from the current window,
    // then adds this flow to the window.
    void compute_counters(FlowRecord& flow);

private:
    size_t              m_window;
    mutable std::mutex  m_mutex;
    std::deque<FlowSnapshot> m_history;

    void trim_window();
};