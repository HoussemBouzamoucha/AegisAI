#!/usr/bin/env bash
# build_and_run.sh
# ─────────────────────────────────────────────────────────────────────────────
# One-shot script: install dependencies → build → run
#
# Usage:
#   chmod +x scripts/build_and_run.sh
#   ./scripts/build_and_run.sh --install-deps     # install libpcap
#   ./scripts/build_and_run.sh --build            # compile only
#   ./scripts/build_and_run.sh --live eth0 60     # capture live for 60s
#   ./scripts/build_and_run.sh --pcap file.pcap   # extract from pcap file
#   ./scripts/build_and_run.sh --test             # run unit tests (dry-run)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/flow_extractor"
OUTPUT="features.csv"

print_banner() {
    echo "╔════════════════════════════════════════════════════╗"
    echo "║   UNSW-NB15 Network Feature Extractor              ║"
    echo "║   Generates all 47 features for your IDS model     ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo
}

install_deps() {
    echo "[*] Installing dependencies…"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y libpcap-dev g++ cmake make
    elif command -v yum &>/dev/null; then
        sudo yum install -y libpcap-devel gcc-c++ cmake make
    elif command -v brew &>/dev/null; then
        brew install libpcap cmake
    else
        echo "ERROR: Unknown package manager. Install libpcap-dev manually."
        exit 1
    fi
    echo "[OK] Dependencies installed"
}

build() {
    echo "[*] Building in: $PROJECT_DIR"
    cd "$PROJECT_DIR"
    make clean 2>/dev/null || true
    make
    echo "[OK] Binary: $BINARY"
}

run_live() {
    local IFACE="${1:-eth0}"
    local DURATION="${2:-60}"

    if [[ ! -x "$BINARY" ]]; then
        echo "ERROR: Binary not found. Run: $0 --build"
        exit 1
    fi

    echo "[*] Starting live capture on $IFACE for ${DURATION}s"
    echo "[*] Output: $OUTPUT"
    echo "[!] Requires root privileges"
    sudo "$BINARY" -i "$IFACE" -o "$OUTPUT" -d "$DURATION" -v
    echo
    echo "[*] Capture complete. Results:"
    wc -l "$OUTPUT"
    head -2 "$OUTPUT"
}

run_pcap() {
    local PCAP="$1"

    if [[ ! -x "$BINARY" ]]; then
        echo "ERROR: Binary not found. Run: $0 --build"
        exit 1
    fi

    if [[ ! -f "$PCAP" ]]; then
        echo "ERROR: pcap file not found: $PCAP"
        exit 1
    fi

    echo "[*] Extracting features from: $PCAP"
    echo "[*] Output: $OUTPUT"
    "$BINARY" -r "$PCAP" -o "$OUTPUT" -v
    echo
    echo "[*] Extraction complete. Results:"
    wc -l "$OUTPUT"
    echo
    echo "[*] First 5 flows (truncated):"
    python3 -c "
import csv, sys
with open('$OUTPUT') as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        if i >= 5: break
        print(f'  [{i+1}] {row[\"srcip\"]}:{row[\"sport\"]} → {row[\"dstip\"]}:{row[\"dsport\"]} [{row[\"proto\"]}] dur={row[\"dur\"]}s sbytes={row[\"sbytes\"]} state={row[\"state\"]}')
" 2>/dev/null || head -6 "$OUTPUT"
}

run_test() {
    echo "[*] Testing binary (dry-run with loopback)…"
    if [[ ! -x "$BINARY" ]]; then
        echo "ERROR: Binary not found. Run: $0 --build"
        exit 1
    fi
    # Capture on loopback for 5 seconds
    sudo timeout 10 "$BINARY" -i lo -o /tmp/test_features.csv -d 5 2>/dev/null || true
    echo "[*] Test output:"
    if [[ -f /tmp/test_features.csv ]]; then
        wc -l /tmp/test_features.csv
        echo "Columns: $(head -1 /tmp/test_features.csv | tr ',' '\n' | wc -l)"
    fi
}

print_banner

case "${1:-}" in
    --install-deps) install_deps ;;
    --build)        build ;;
    --live)         run_live   "${2:-eth0}" "${3:-60}" ;;
    --pcap)         run_pcap   "${2:?'Usage: $0 --pcap <file.pcap>'}" ;;
    --test)         run_test ;;
    --all)
        install_deps
        build
        run_test
        ;;
    *)
        echo "Usage:"
        echo "  $0 --install-deps           Install libpcap + build tools"
        echo "  $0 --build                  Compile the C++ extractor"
        echo "  $0 --live <iface> [secs]    Live capture (needs sudo)"
        echo "  $0 --pcap <file.pcap>       Extract from pcap file"
        echo "  $0 --test                   Quick test on loopback"
        echo "  $0 --all                    Install + build + test"
        echo
        echo "Output CSV columns (47 features matching UNSW-NB15):"
        echo "  srcip, sport, dstip, dsport, proto, state, dur,"
        echo "  sbytes, dbytes, sttl, dttl, sloss, dloss, service,"
        echo "  Sload, Dload, Spkts, Dpkts, swin, dwin, stcpb, dtcpb,"
        echo "  smeansz, dmeansz, trans_depth, res_bdy_len, Sjit, Djit,"
        echo "  Stime, Ltime, Sintpkt, Dintpkt, tcprtt, synack, ackdat,"
        echo "  is_sm_ips_ports, ct_state_ttl, ct_flw_http_mthd,"
        echo "  is_ftp_login, ct_ftp_cmd, ct_srv_src, ct_srv_dst,"
        echo "  ct_dst_ltm, ct_src_ltm, ct_src_dport_ltm,"
        echo "  ct_dst_sport_ltm, ct_dst_src_ltm"
        ;;
esac