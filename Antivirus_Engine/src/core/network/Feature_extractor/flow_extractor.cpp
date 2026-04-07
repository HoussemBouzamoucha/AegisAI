/**
 * flow_extractor.cpp
 * ------------------
 * Captures live network packets via libpcap, reconstructs flows, and computes
 * all 47 UNSW-NB15 features required by the ML model.
 *
 * Build:
 *   g++ -O2 -std=c++17 -o flow_extractor src/flow_extractor.cpp \
 *       src/flow_table.cpp src/feature_writer.cpp \
 *       -lpcap -pthread
 *
 * Usage:
 *   sudo ./flow_extractor -i eth0 -o features.csv -t 60
 *   sudo ./flow_extractor -r capture.pcap -o features.csv
 */

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <mutex>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>
#include <getopt.h>

#include "../include/flow.h"
#include "../include/flow_table.h"
#include "../include/feature_writer.h"
#include "../include/connection_tracker.h"

// ─── Globals ──────────────────────────────────────────────────────────────────
static std::atomic<bool>  g_running{true};
static FlowTable*         g_flow_table   = nullptr;
static FeatureWriter*     g_writer       = nullptr;
static ConnectionTracker* g_ct           = nullptr;

static void signal_handler(int) {
    g_running = false;
}

// ─── Packet callback ──────────────────────────────────────────────────────────
void packet_handler(u_char* /*user*/, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    if (!g_running) return;

    PacketInfo p{};
    p.ts_sec  = hdr->ts.tv_sec;
    p.ts_usec = hdr->ts.tv_usec;
    p.cap_len = hdr->caplen;

    // ── Parse Ethernet ────────────────────────────────────────────────────────
    if (hdr->caplen < sizeof(struct ether_header)) return;
    const auto* eth = reinterpret_cast<const struct ether_header*>(pkt);
    uint16_t ether_type = ntohs(eth->ether_type);
    const u_char* layer3 = pkt + sizeof(struct ether_header);
    size_t remaining = hdr->caplen - sizeof(struct ether_header);

    // ── Parse IP / IPv6 ───────────────────────────────────────────────────────
    if (ether_type == ETHERTYPE_IP) {
        if (remaining < sizeof(struct ip)) return;
        const auto* iph = reinterpret_cast<const struct ip*>(layer3);
        p.proto   = iph->ip_p;
        p.sttl    = iph->ip_ttl;
        p.ip_len  = ntohs(iph->ip_len);

        char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->ip_src, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &iph->ip_dst, dst_buf, sizeof(dst_buf));
        p.srcip = src_buf;
        p.dstip = dst_buf;

        size_t ip_hdr_len = iph->ip_hl * 4;
        if (ip_hdr_len > remaining) return;
        const u_char* layer4 = layer3 + ip_hdr_len;
        size_t l4_remaining = remaining - ip_hdr_len;

        if (p.proto == IPPROTO_TCP) {
            if (l4_remaining < sizeof(struct tcphdr)) return;
            const auto* tcph = reinterpret_cast<const struct tcphdr*>(layer4);
            p.sport    = ntohs(tcph->th_sport);
            p.dsport   = ntohs(tcph->th_dport);
            p.tcp_flags= tcph->th_flags;
            p.swin     = ntohs(tcph->th_win);
            p.seq      = ntohl(tcph->th_seq);
            p.ack      = ntohl(tcph->th_ack);
            size_t tcp_hdr_len = tcph->th_off * 4;
            p.payload_len = (l4_remaining > tcp_hdr_len) ? l4_remaining - tcp_hdr_len : 0;
        } else if (p.proto == IPPROTO_UDP) {
            if (l4_remaining < sizeof(struct udphdr)) return;
            const auto* udph = reinterpret_cast<const struct udphdr*>(layer4);
            p.sport      = ntohs(udph->uh_sport);
            p.dsport     = ntohs(udph->uh_dport);
            p.payload_len= (ntohs(udph->uh_ulen) > 8) ? ntohs(udph->uh_ulen) - 8 : 0;
        } else {
            p.sport = 0; p.dsport = 0;
        }

    } else if (ether_type == ETHERTYPE_IPV6) {
        if (remaining < sizeof(struct ip6_hdr)) return;
        const auto* ip6h = reinterpret_cast<const struct ip6_hdr*>(layer3);
        p.proto  = ip6h->ip6_nxt;
        p.sttl   = ip6h->ip6_hlim;
        p.ip_len = ntohs(ip6h->ip6_plen) + sizeof(struct ip6_hdr);

        char src6[INET6_ADDRSTRLEN], dst6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6h->ip6_src, src6, sizeof(src6));
        inet_ntop(AF_INET6, &ip6h->ip6_dst, dst6, sizeof(dst6));
        p.srcip = src6;
        p.dstip = dst6;

        const u_char* layer4 = layer3 + sizeof(struct ip6_hdr);
        size_t l4_remaining  = remaining - sizeof(struct ip6_hdr);

        if (p.proto == IPPROTO_TCP && l4_remaining >= sizeof(struct tcphdr)) {
            const auto* tcph = reinterpret_cast<const struct tcphdr*>(layer4);
            p.sport    = ntohs(tcph->th_sport);
            p.dsport   = ntohs(tcph->th_dport);
            p.tcp_flags= tcph->th_flags;
            p.swin     = ntohs(tcph->th_win);
            p.seq      = ntohl(tcph->th_seq);
            p.ack      = ntohl(tcph->th_ack);
            size_t tcp_hdr_len = tcph->th_off * 4;
            p.payload_len = (l4_remaining > tcp_hdr_len) ? l4_remaining - tcp_hdr_len : 0;
        } else if (p.proto == IPPROTO_UDP && l4_remaining >= sizeof(struct udphdr)) {
            const auto* udph = reinterpret_cast<const struct udphdr*>(layer4);
            p.sport = ntohs(udph->uh_sport); p.dsport = ntohs(udph->uh_dport);
            p.payload_len = (ntohs(udph->uh_ulen) > 8) ? ntohs(udph->uh_ulen) - 8 : 0;
        }
    } else {
        return; // Not IP
    }

    g_flow_table->process_packet(p);
}

// ─── Usage ────────────────────────────────────────────────────────────────────
static void usage(const char* prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " -i <iface>  -o <output.csv> [-t <timeout_sec>] [-f <bpf_filter>]\n"
              << "  " << prog << " -r <file.pcap> -o <output.csv>\n\n"
              << "Options:\n"
              << "  -i <iface>      Live capture interface (e.g. eth0)\n"
              << "  -r <pcap>       Read from pcap file instead of live\n"
              << "  -o <csv>        Output CSV file path (default: features.csv)\n"
              << "  -t <seconds>    Flow idle timeout in seconds (default: 120)\n"
              << "  -d <seconds>    Capture duration (0 = until Ctrl-C, default: 0)\n"
              << "  -f <filter>     BPF capture filter (default: ip or ip6)\n"
              << "  -v              Verbose output\n";
    exit(1);
}

// ─── Main ────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::string iface, pcap_file, output = "features.csv", bpf_filter = "ip or ip6";
    int flow_timeout = 120, duration = 0;
    bool verbose = false;

    int opt;
    while ((opt = getopt(argc, argv, "i:r:o:t:d:f:v")) != -1) {
        switch (opt) {
            case 'i': iface      = optarg; break;
            case 'r': pcap_file  = optarg; break;
            case 'o': output     = optarg; break;
            case 't': flow_timeout = std::stoi(optarg); break;
            case 'd': duration   = std::stoi(optarg); break;
            case 'f': bpf_filter = optarg; break;
            case 'v': verbose    = true;   break;
            default:  usage(argv[0]);
        }
    }

    if (iface.empty() && pcap_file.empty()) {
        std::cerr << "Error: specify -i <interface> or -r <pcap_file>\n";
        usage(argv[0]);
    }

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ── Initialise subsystems ─────────────────────────────────────────────────
    g_writer     = new FeatureWriter(output);
    g_ct         = new ConnectionTracker();
    g_flow_table = new FlowTable(flow_timeout, g_writer, g_ct, verbose);

    // ── Open pcap handle ──────────────────────────────────────────────────────
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;

    if (!pcap_file.empty()) {
        handle = pcap_open_offline(pcap_file.c_str(), errbuf);
        if (!handle) {
            std::cerr << "Cannot open pcap file: " << errbuf << "\n";
            return 1;
        }
        std::cout << "[*] Reading from: " << pcap_file << "\n";
    } else {
        handle = pcap_open_live(iface.c_str(), 65535, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "Cannot open interface " << iface << ": " << errbuf << "\n";
            std::cerr << "Hint: run as root or with CAP_NET_RAW capability\n";
            return 1;
        }
        std::cout << "[*] Capturing on: " << iface << "\n";
    }

    // ── Apply BPF filter ──────────────────────────────────────────────────────
    struct bpf_program fp{};
    if (pcap_compile(handle, &fp, bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "BPF filter error: " << pcap_geterr(handle) << "\n";
        return 1;
    }

    std::cout << "[*] Output CSV: " << output << "\n";
    std::cout << "[*] Flow idle timeout: " << flow_timeout << "s\n";
    std::cout << "[*] Press Ctrl-C to stop and flush remaining flows\n\n";

    // ── Optional timer thread for duration-based capture ─────────────────────
    std::thread timer_thread;
    if (duration > 0) {
        timer_thread = std::thread([duration]() {
            std::this_thread::sleep_for(std::chrono::seconds(duration));
            g_running = false;
        });
    }

    // ── Capture loop ──────────────────────────────────────────────────────────
    auto start_time = std::chrono::steady_clock::now();
    uint64_t pkt_count = 0;

    while (g_running) {
        struct pcap_pkthdr* hdr;
        const u_char* pkt;
        int ret = pcap_next_ex(handle, &hdr, &pkt);

        if (ret == 1) {
            packet_handler(nullptr, hdr, pkt);
            ++pkt_count;

            if (verbose && pkt_count % 10000 == 0) {
                std::cout << "\r[*] Packets: " << pkt_count
                          << "  Flows active: " << g_flow_table->active_count()
                          << "  Exported: "     << g_writer->rows_written()
                          << std::flush;
            }
        } else if (ret == 0) {
            // Timeout — flush expired flows
            g_flow_table->flush_expired();
        } else if (ret == -2) {
            // EOF (pcap file)
            break;
        } else {
            std::cerr << "pcap error: " << pcap_geterr(handle) << "\n";
            break;
        }
    }

    // ── Flush all remaining flows ─────────────────────────────────────────────
    std::cout << "\n[*] Flushing remaining flows…\n";
    g_flow_table->flush_all();

    auto end_time = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end_time - start_time).count();

    std::cout << "[*] Capture complete\n";
    std::cout << "    Packets processed : " << pkt_count                   << "\n";
    std::cout << "    Flows exported     : " << g_writer->rows_written()   << "\n";
    std::cout << "    Duration           : " << elapsed << "s\n";
    std::cout << "    Output             : " << output                     << "\n";

    if (timer_thread.joinable()) timer_thread.join();

    pcap_freecode(&fp);
    pcap_close(handle);
    delete g_flow_table;
    delete g_writer;
    delete g_ct;

    return 0;
}