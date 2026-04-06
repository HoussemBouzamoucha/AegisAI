/**
 * src/feature_writer.cpp
 * ----------------------
 * Serialises FlowRecord → CSV row with all 47 UNSW-NB15 features.
 *
 * Column order matches the dataset exactly:
 *   srcip, sport, dstip, dsport, proto, state, dur,
 *   sbytes, dbytes, sttl, dttl, sloss, dloss,
 *   service, Sload, Dload, Spkts, Dpkts,
 *   swin, dwin, stcpb, dtcpb,
 *   smeansz, dmeansz, trans_depth, res_bdy_len,
 *   Sjit, Djit, Stime, Ltime,
 *   Sintpkt, Dintpkt, tcprtt, synack, ackdat,
 *   is_sm_ips_ports, ct_state_ttl, ct_flw_http_mthd,
 *   is_ftp_login, ct_ftp_cmd,
 *   ct_srv_src, ct_srv_dst, ct_dst_ltm, ct_src_ltm,
 *   ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm
 */

#include "../include/feature_writer.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cmath>

const char* FeatureWriter::CSV_HEADER =
    "srcip,sport,dstip,dsport,proto,state,dur,"
    "sbytes,dbytes,sttl,dttl,sloss,dloss,"
    "service,Sload,Dload,Spkts,Dpkts,"
    "swin,dwin,stcpb,dtcpb,"
    "smeansz,dmeansz,trans_depth,res_bdy_len,"
    "Sjit,Djit,Stime,Ltime,"
    "Sintpkt,Dintpkt,tcprtt,synack,ackdat,"
    "is_sm_ips_ports,ct_state_ttl,ct_flw_http_mthd,"
    "is_ftp_login,ct_ftp_cmd,"
    "ct_srv_src,ct_srv_dst,ct_dst_ltm,ct_src_ltm,"
    "ct_src_dport_ltm,ct_dst_sport_ltm,ct_dst_src_ltm";

FeatureWriter::FeatureWriter(const std::string& path) {
    m_file.open(path, std::ios::out | std::ios::trunc);
    if (!m_file.is_open()) {
        throw std::runtime_error("Cannot open output file: " + path);
    }
    m_file << CSV_HEADER << "\n";
    m_file.flush();
    std::cout << "[*] CSV header written to: " << path << "\n";
}

FeatureWriter::~FeatureWriter() {
    if (m_file.is_open()) m_file.close();
}

std::string FeatureWriter::escape(const std::string& s) {
    // CSV-escape: if the value contains comma or quote, wrap in quotes
    if (s.find(',') == std::string::npos && s.find('"') == std::string::npos)
        return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else          out += c;
    }
    out += "\"";
    return out;
}

std::string FeatureWriter::fmt_float(double v, int decimals) {
    if (std::isnan(v) || std::isinf(v)) return "0";
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(decimals) << v;
    return oss.str();
}

void FeatureWriter::write(const FlowRecord& flow) {
    // ── Compute derived values ────────────────────────────────────────────────
    double dur       = flow.dur();
    double sload     = flow.sload();
    double dload     = flow.dload();
    double smeansz   = (flow.fwd.pkts > 0) ? static_cast<double>(flow.fwd.bytes) / flow.fwd.pkts : 0.0;
    double dmeansz   = (flow.bwd.pkts > 0) ? static_cast<double>(flow.bwd.bytes) / flow.bwd.pkts : 0.0;
    double sjit      = flow.fwd.inter_pkt_stats.jitter();
    double djit      = flow.bwd.inter_pkt_stats.jitter();
    double sintpkt   = flow.fwd.inter_pkt_stats.mean;
    double dintpkt   = flow.bwd.inter_pkt_stats.mean;
    double tcprtt    = flow.handshake.rtt();
    double synack_t  = flow.handshake.synack_time();
    double ackdat_t  = flow.handshake.ackdat_time();

    // ── Build CSV row ─────────────────────────────────────────────────────────
    std::ostringstream row;

    // 1. srcip
    row << escape(flow.key.srcip) << ",";
    // 2. sport
    row << flow.key.sport << ",";
    // 3. dstip
    row << escape(flow.key.dstip) << ",";
    // 4. dsport
    row << flow.key.dsport << ",";
    // 5. proto
    row << escape(flow.proto_name()) << ",";
    // 6. state
    row << escape(flow.state) << ",";
    // 7. dur
    row << fmt_float(dur) << ",";
    // 8. sbytes
    row << flow.fwd.bytes << ",";
    // 9. dbytes
    row << flow.bwd.bytes << ",";
    // 10. sttl
    row << static_cast<int>(flow.fwd.ttl) << ",";
    // 11. dttl
    row << static_cast<int>(flow.bwd.ttl) << ",";
    // 12. sloss
    row << flow.fwd.loss_pkts << ",";
    // 13. dloss
    row << flow.bwd.loss_pkts << ",";
    // 14. service
    row << escape(flow.service) << ",";
    // 15. Sload  (bits/sec)
    row << fmt_float(sload) << ",";
    // 16. Dload
    row << fmt_float(dload) << ",";
    // 17. Spkts
    row << flow.fwd.pkts << ",";
    // 18. Dpkts
    row << flow.bwd.pkts << ",";
    // 19. swin (last TCP window size from src)
    row << flow.fwd.win << ",";
    // 20. dwin
    row << flow.bwd.win << ",";
    // 21. stcpb (initial TCP sequence number — base)
    row << flow.fwd.tcp_base << ",";
    // 22. dtcpb
    row << flow.bwd.tcp_base << ",";
    // 23. smeansz
    row << fmt_float(smeansz) << ",";
    // 24. dmeansz
    row << fmt_float(dmeansz) << ",";
    // 25. trans_depth
    row << flow.http.trans_depth << ",";
    // 26. res_bdy_len
    row << flow.http.res_bdy_len << ",";
    // 27. Sjit  (ms)
    row << fmt_float(sjit) << ",";
    // 28. Djit
    row << fmt_float(djit) << ",";
    // 29. Stime (epoch seconds)
    row << static_cast<int64_t>(flow.start_ts) << ",";
    // 30. Ltime
    row << static_cast<int64_t>(flow.end_ts) << ",";
    // 31. Sintpkt (mean inter-packet time ms)
    row << fmt_float(sintpkt) << ",";
    // 32. Dintpkt
    row << fmt_float(dintpkt) << ",";
    // 33. tcprtt
    row << fmt_float(tcprtt) << ",";
    // 34. synack
    row << fmt_float(synack_t) << ",";
    // 35. ackdat
    row << fmt_float(ackdat_t) << ",";
    // 36. is_sm_ips_ports
    row << (flow.is_sm_ips_ports ? 1 : 0) << ",";
    // 37. ct_state_ttl
    row << fmt_float(flow.ct_state_ttl, 0) << ",";
    // 38. ct_flw_http_mthd
    row << fmt_float(flow.ct_flw_http_mthd, 0) << ",";
    // 39. is_ftp_login
    row << (flow.ftp_login ? 1 : 0) << ",";
    // 40. ct_ftp_cmd
    row << flow.ftp_cmds << ",";
    // 41. ct_srv_src
    row << fmt_float(flow.ct_srv_src, 0) << ",";
    // 42. ct_srv_dst
    row << fmt_float(flow.ct_srv_dst, 0) << ",";
    // 43. ct_dst_ltm
    row << fmt_float(flow.ct_dst_ltm, 0) << ",";
    // 44. ct_src_ltm
    row << fmt_float(flow.ct_src_ltm, 0) << ",";
    // 45. ct_src_dport_ltm
    row << fmt_float(flow.ct_src_dport_ltm, 0) << ",";
    // 46. ct_dst_sport_ltm
    row << fmt_float(flow.ct_dst_sport_ltm, 0) << ",";
    // 47. ct_dst_src_ltm
    row << fmt_float(flow.ct_dst_src_ltm, 0);

    row << "\n";

    // ── Write atomically ──────────────────────────────────────────────────────
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_file << row.str();
        if (m_rows % 500 == 0) m_file.flush();
    }
    ++m_rows;
}