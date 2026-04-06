#pragma once
/**
 * include/flow_table.h
 * --------------------
 * Hash-table of active flows. Dispatches packets to the right FlowRecord,
 * handles flow expiry (idle timeout), and exports completed flows.
 */

#include "flow.h"
#include "feature_writer.h"
#include "connection_tracker.h"

#include <unordered_map>
#include <mutex>
#include <cstddef>

class FlowTable {
public:
    FlowTable(int idle_timeout_sec, FeatureWriter* writer,
              ConnectionTracker* ct, bool verbose = false);
    ~FlowTable();

    void process_packet(const PacketInfo& p);
    void flush_expired();
    void flush_all();

    size_t active_count() const;

private:
    int               m_idle_timeout;
    FeatureWriter*    m_writer;
    ConnectionTracker* m_ct;
    bool              m_verbose;

    mutable std::mutex                                         m_mutex;
    std::unordered_map<FlowKey, FlowRecord, FlowKeyHash>       m_flows;

    // Returns the flow key normalised to the forward direction.
    // Also returns the direction (fwd / bwd).
    static FlowKey make_key(const PacketInfo& p, PktDir& dir);

    void update_flow(FlowRecord& flow, const PacketInfo& p, PktDir dir, double ts);
    void export_flow(FlowRecord& flow);
    void detect_app_layer(FlowRecord& flow, const PacketInfo& p, PktDir dir);
};