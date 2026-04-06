#pragma once
/**
 * include/feature_writer.h
 * ------------------------
 * Writes completed FlowRecords to CSV with all 47 UNSW-NB15 features.
 */

#include "flow.h"
#include <fstream>
#include <string>
#include <mutex>
#include <atomic>

class FeatureWriter {
public:
    explicit FeatureWriter(const std::string& path);
    ~FeatureWriter();

    void write(const FlowRecord& flow);
    uint64_t rows_written() const { return m_rows.load(); }

    // CSV header exactly matching UNSW-NB15 column order
    static const char* CSV_HEADER;

private:
    std::ofstream      m_file;
    std::mutex         m_mutex;
    std::atomic<uint64_t> m_rows{0};

    static std::string escape(const std::string& s);
    static std::string fmt_float(double v, int decimals = 6);
};