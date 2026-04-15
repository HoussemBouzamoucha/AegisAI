# =============================================================================
# UNSW-NB15 Network IDS — Inference Preprocessing Pipeline
#
# Usage:
#   python preprocessing_pipeline.py [--csv PATH]
#
# Reads OnePace.csv, applies all preprocessing steps, runs the saved XGBoost
# model, and prints a JSON result to stdout.
# Called by the Tauri backend via: python preprocessing_pipeline.py --csv PATH
# =============================================================================

import sys
import os
import ipaddress
import json
import warnings
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
from sklearn.preprocessing import OrdinalEncoder, LabelEncoder
import joblib

# =============================================================================
# Paths
# =============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENGINE_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, '..', '..', '..', '..', '..'))
MODEL_DIR  = os.path.join(ENGINE_DIR, 'models', 'network')

MODEL_PATH_CAL    = os.path.join(MODEL_DIR, 'ids_network_calibrated.pkl')
MODEL_PATH_RAW    = os.path.join(MODEL_DIR, 'ids_network_model.pkl')
ENCODER_PATH      = os.path.join(MODEL_DIR, 'ordinal_encoder.joblib')
SRC_FREQ_PATH     = os.path.join(MODEL_DIR, 'src_freq_map.joblib')
DST_FREQ_PATH     = os.path.join(MODEL_DIR, 'dst_freq_map.joblib')
SUBNET_ENC_PATH   = os.path.join(MODEL_DIR, 'subnet_encoders.joblib')

def _default_csv() -> str:
    home = os.environ.get('USERPROFILE', os.environ.get('HOME', '.'))
    return os.path.join(home, 'OnePace.csv')

# =============================================================================
# Constants
# =============================================================================

# Raw input columns expected in OnePace.csv (47 UNSW-NB15 feature columns)
FEATURE_NAMES_47 = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts',
    'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth',
    'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt',
    'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl',
    'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src',
    'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm',
]

CAT_COLS = ['proto', 'state', 'service']

# IP prefixes belonging to well-known clean infrastructure.
# Connections to/from these ranges are never fed to the model.
CLEAN_PREFIXES = [
    # Google
    '8.8.', '8.34.', '8.35.', '34.', '35.', '64.233.', '66.102.',
    '66.249.', '72.14.', '74.125.', '108.177.', '142.250.', '172.217.',
    '173.194.', '209.85.', '216.58.', '216.239.',
    # Microsoft / Azure
    '13.64.', '13.65.', '13.66.', '13.67.', '13.68.', '13.69.',
    '13.70.', '13.71.', '13.72.', '13.73.', '13.74.', '13.75.',
    '20.', '40.', '52.', '104.40.', '104.41.', '104.42.', '104.43.', '104.44.',
    # Cloudflare
    '1.1.1.', '1.0.0.', '104.16.', '104.17.', '104.18.', '104.19.',
    '104.20.', '104.21.', '172.64.', '172.65.', '172.66.', '172.67.',
    '162.158.', '198.41.',
    # Apple
    '17.',
    # Amazon / AWS
    '54.', '18.', '3.', '52.', '99.', '205.251.',
]

def _is_clean_ip(ip: str) -> bool:
    """Return True if the IP matches a known-clean infrastructure prefix."""
    ip = ip.strip()
    if ip.lower().startswith('::ffff:') and '.' in ip:
        ip = ip[7:]
    return any(ip.startswith(p) for p in CLEAN_PREFIXES)

# Final 56-feature order expected by the trained model
EXPECTED_FEATURE_COLS = [
    'sport', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload',
    'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz',
    'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 'Sintpkt', 'Dintpkt',
    'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl',
    'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'duration_time',
    'src_is_private', 'src_is_global', 'src_is_multicast', 'src_version',
    'dst_is_private', 'dst_is_global', 'dst_is_multicast', 'dst_version',
    'src_subnet', 'dst_subnet', 'src_freq', 'dst_freq',
]

# Detection thresholds
THRESHOLD_MALICIOUS  = 0.80
THRESHOLD_SUSPICIOUS = 0.55

# =============================================================================
# Human-readable label helpers
# =============================================================================

# Well-known IPs → friendly hostname (avoids a DNS round-trip for common hosts)
_KNOWN_HOSTS: dict[str, str] = {
    '127.0.0.1': 'localhost', '::1': 'localhost', '0.0.0.0': 'unspecified',
    '8.8.8.8':   'dns.google', '8.8.4.4': 'dns.google',
    '1.1.1.1':   'cloudflare-dns.com', '1.0.0.1': 'cloudflare-dns.com',
    '9.9.9.9':   'dns.quad9.net',
    '208.67.222.222': 'resolver1.opendns.com',
    '192.168.1.1': 'gateway', '192.168.0.1': 'gateway',
    '10.0.0.1':  'gateway', '172.16.0.1': 'gateway',
}

# Port → service name for the most common ports
_PORT_NAMES: dict[int, str] = {
    20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
    587: 'SMTP-sub', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 6881: 'BitTorrent',
    8080: 'HTTP-alt', 8443: 'HTTPS-alt', 8888: 'HTTP-alt',
    27017: 'MongoDB', 51820: 'WireGuard',
}

_dns_executor = ThreadPoolExecutor(max_workers=16)
_dns_cache: dict[str, str] = {}

def _resolve_ip(ip: str) -> str:
    """Return a friendly hostname for an IP. Cached, 0.5 s DNS timeout."""
    ip = ip.strip()
    if not ip or ip in ('*', '0.0.0.0', '::'):
        return ip

    if ip in _dns_cache:
        return _dns_cache[ip]

    # Strip IPv4-mapped IPv6 prefix before lookup
    lookup = ip[7:] if ip.lower().startswith('::ffff:') and '.' in ip else ip

    # Static table first
    if lookup in _KNOWN_HOSTS:
        _dns_cache[ip] = _KNOWN_HOSTS[lookup]
        return _dns_cache[ip]

    # Loopback / link-local shortcut
    try:
        addr = ipaddress.ip_address(lookup)
        if addr.is_loopback:
            _dns_cache[ip] = 'localhost'
            return 'localhost'
        if addr.is_link_local:
            _dns_cache[ip] = f'link-local ({lookup})'
            return _dns_cache[ip]
    except ValueError:
        pass

    # Reverse DNS with timeout
    try:
        future = _dns_executor.submit(socket.gethostbyaddr, lookup)
        hostname = future.result(timeout=0.5)[0]
        # Truncate very long FQDNs to keep UI compact
        if len(hostname) > 40:
            parts = hostname.split('.')
            hostname = '.'.join(parts[-3:]) if len(parts) >= 3 else hostname[:40]
        _dns_cache[ip] = hostname
    except (FuturesTimeout, OSError, Exception):
        _dns_cache[ip] = ip   # fall back to raw IP

    return _dns_cache[ip]


def _port_label(port: int) -> str:
    """Return 'SERVICE (port)' for known ports, or just the port number."""
    name = _PORT_NAMES.get(port)
    return f'{name} ({port})' if name else str(port)


# =============================================================================
# Helpers
# =============================================================================

def _ip_features(ip_str: str) -> dict:
    """Return is_private, is_global, is_multicast, version for an IP address.
    Handles IPv4, IPv6, and IPv4-mapped IPv6 (::ffff:a.b.c.d).
    """
    ip_str = ip_str.strip()
    if ip_str.lower().startswith('::ffff:') and '.' in ip_str:
        ip_str = ip_str[7:]
    try:
        addr = ipaddress.ip_address(ip_str)
        return {
            'is_private':   int(addr.is_private),
            'is_global':    int(addr.is_global),
            'is_multicast': int(addr.is_multicast),
            'version':      addr.version,
        }
    except ValueError:
        return {'is_private': 0, 'is_global': 0, 'is_multicast': 0, 'version': 4}


def _get_subnet(ip: str) -> str:
    """Coarse subnet label: first two IPv4 octets or first four IPv6 groups."""
    ip = ip.strip().lower()
    if ip.startswith('::ffff:') and '.' in ip:
        return _get_subnet(ip[7:])
    if '.' in ip and ':' not in ip:
        parts = ip.split('.')
        return '.'.join(parts[:2]) if len(parts) >= 2 else ip
    if ':' in ip:
        groups = ip.split(':')
        return ':'.join(groups[:4]) if len(groups) >= 4 else ip
    return ip


def _build_reasons(flow_row: pd.Series, prediction: str, probability: float) -> list:
    """Generate human-readable detection reasons for a flagged flow."""
    reasons = []
    pct = probability * 100

    if prediction == 'Malicious':
        reasons.append(f'ML model confidence: {pct:.1f}%')
    elif prediction == 'Suspicious':
        reasons.append(f'ML model flagged as suspicious ({pct:.1f}% confidence)')

    proto = str(flow_row.get('proto', '')).upper()
    state = str(flow_row.get('state', '')).upper()

    # Unusual protocol/state combinations
    if proto not in ('TCP', 'UDP', 'ICMP', ''):
        reasons.append(f'Unusual protocol: {proto}')
    if state in ('FIN', 'RST', 'INT'):
        reasons.append(f'Abnormal connection state: {state}')

    # Port-based signals
    dsport = int(flow_row.get('dsport', 0) or 0)
    sport  = int(flow_row.get('sport',  0) or 0)
    KNOWN_C2_PORTS = {4444, 1337, 31337, 8888, 9999, 6666, 12345, 54321}
    if dsport in KNOWN_C2_PORTS or sport in KNOWN_C2_PORTS:
        reasons.append(f'Known C2/malware port used ({dsport or sport})')

    return reasons

# =============================================================================
# Inference pipeline
# =============================================================================

def run_inference(csv_path: str) -> None:
    """
    Read OnePace.csv, preprocess, run the saved model, and print a
    JSON object to stdout. stdout is always valid JSON.
    """

    def _fail(msg: str) -> None:
        print(json.dumps({'success': False, 'error': msg}))
        sys.exit(1)

    # ── 1. Load CSV ───────────────────────────────────────────────────────────
    if not os.path.exists(csv_path):
        _fail(f'CSV not found at: {csv_path}')

    try:
        df = pd.read_csv(csv_path, low_memory=False)
    except Exception as e:
        _fail(f'Failed to read CSV: {e}')

    if df.empty:
        print(json.dumps({
            'success': True,
            'summary': {
                'total_flows': 0, 'clean_flows': 0,
                'suspicious_flows': 0, 'malicious_flows': 0,
                'malicious_rate': 0.0,
            },
            'flows': [],
        }))
        return

    missing = [c for c in FEATURE_NAMES_47 if c not in df.columns]
    if missing:
        _fail(f'CSV is missing columns: {missing}')

    # Split into pcap-captured rows (reliable features) and fallback rows
    # (OS-table only — packet-level fields are all zero, unreliable for inference).
    if 'pcap_data' in df.columns:
        df_pcap     = df[df['pcap_data'] == 1].copy()
        df_fallback = df[df['pcap_data'] != 1].copy()
    else:
        # Older CSV without the column — treat everything as pcap data.
        df_pcap     = df.copy()
        df_fallback = df.iloc[0:0].copy()  # empty

    if df_pcap.empty:
        # No pcap rows yet — return all connections as Clean (no packet data to judge).
        flows = []
        for _, row in df_fallback.iterrows():
            srcip  = str(row.get('srcip',  ''))
            dstip  = str(row.get('dstip',  ''))
            sport  = int(row.get('sport',  0) or 0)
            dsport = int(row.get('dsport', 0) or 0)
            flows.append({
                'srcip': srcip, 'dstip': dstip, 'sport': sport, 'dsport': dsport,
                'proto': str(row.get('proto', '')), 'is_ipv6': False,
                'prediction': 'Clean', 'probability': 0.0, 'reasons': [],
                'src_host': _resolve_ip(srcip), 'dst_host': _resolve_ip(dstip),
                'src_service': _port_label(sport), 'dst_service': _port_label(dsport),
            })
        total = len(flows)
        print(json.dumps({
            'success': True,
            'summary': {
                'total_flows': total, 'clean_flows': total,
                'suspicious_flows': 0, 'malicious_flows': 0,
                'malicious_rate': 0.0,
            },
            'flows': flows,
        }))
        return

    # Filter out private→private connections — internal traffic between local
    # hosts is almost never malicious and reliably causes false positives.
    def _is_private(ip: str) -> bool:
        try:
            ip = ip.strip()
            if ip.lower().startswith('::ffff:') and '.' in ip:
                ip = ip[7:]
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    both_private = df_pcap['srcip'].astype(str).apply(_is_private) & \
                   df_pcap['dstip'].astype(str).apply(_is_private)
    df_private  = df_pcap[both_private].copy()
    df_pcap     = df_pcap[~both_private].copy()

    def _clean_rows_to_flows(rows_df: 'pd.DataFrame') -> list:
        out = []
        for _, row in rows_df.iterrows():
            srcip  = str(row.get('srcip',  ''))
            dstip  = str(row.get('dstip',  ''))
            sport  = int(row.get('sport',  0) or 0)
            dsport = int(row.get('dsport', 0) or 0)
            out.append({
                'srcip': srcip, 'dstip': dstip, 'sport': sport, 'dsport': dsport,
                'proto': str(row.get('proto', '')), 'is_ipv6': False,
                'prediction': 'Clean', 'probability': 0.0, 'reasons': [],
                'src_host': _resolve_ip(srcip), 'dst_host': _resolve_ip(dstip),
                'src_service': _port_label(sport), 'dst_service': _port_label(dsport),
            })
        return out

    if df_pcap.empty:
        # All pcap flows are private→private, report them as Clean.
        flows = _clean_rows_to_flows(pd.concat([df_private, df_fallback]))
        total = len(flows)
        print(json.dumps({'success': True, 'summary': {
            'total_flows': total, 'clean_flows': total,
            'suspicious_flows': 0, 'malicious_flows': 0, 'malicious_rate': 0.0,
        }, 'flows': flows}))
        return

    # Whitelist known-clean infrastructure (Google, Microsoft, Cloudflare, etc.).
    is_clean = df_pcap['srcip'].astype(str).apply(_is_clean_ip) | \
               df_pcap['dstip'].astype(str).apply(_is_clean_ip)
    df_whitelisted = df_pcap[is_clean].copy()
    df_pcap        = df_pcap[~is_clean].copy()

    if df_pcap.empty:
        flows = _clean_rows_to_flows(pd.concat([df_private, df_whitelisted, df_fallback]))
        total = len(flows)
        print(json.dumps({'success': True, 'summary': {
            'total_flows': total, 'clean_flows': total,
            'suspicious_flows': 0, 'malicious_flows': 0, 'malicious_rate': 0.0,
        }, 'flows': flows}))
        return

    # Run inference only on the pcap-captured rows.
    df = df_pcap

    # ── 2. Load model ─────────────────────────────────────────────────────────
    model_path = MODEL_PATH_CAL if os.path.exists(MODEL_PATH_CAL) else MODEL_PATH_RAW
    if not os.path.exists(model_path):
        _fail(f'Model not found. Looked for:\n  {MODEL_PATH_CAL}\n  {MODEL_PATH_RAW}')

    try:
        import xgboost  # noqa: F401
    except ImportError:
        _fail('xgboost is not installed. Run: pip install xgboost')

    try:
        model = joblib.load(model_path)
    except Exception as e:
        _fail(f'Failed to load model: {e}')

    # Unwrap dict bundle: {"model": clf, "threshold": 0.3, "features": [...]}
    if isinstance(model, dict):
        model = model.get('model', model)

    # ── 3. Retain identity columns before transforms ──────────────────────────
    id_cols = df[['srcip', 'dstip', 'sport', 'dsport', 'proto']].copy()
    id_cols['sport']  = pd.to_numeric(id_cols['sport'],  errors='coerce').fillna(0).astype(int)
    id_cols['dsport'] = pd.to_numeric(id_cols['dsport'], errors='coerce').fillna(0).astype(int)

    # Stash the raw row data for reason generation (before encoding)
    raw_for_reasons = df[['proto', 'state', 'sport', 'dsport']].copy()

    X = df.copy()

    # ── 4. Fill structural NaNs ───────────────────────────────────────────────
    X['ct_flw_http_mthd'] = pd.to_numeric(X['ct_flw_http_mthd'], errors='coerce').fillna(0).astype('float32')
    X['is_ftp_login']     = pd.to_numeric(X['is_ftp_login'],     errors='coerce').fillna(0).astype('float32')

    # ── 5. Numeric coercion ───────────────────────────────────────────────────
    numeric_cols = [c for c in FEATURE_NAMES_47 if c not in ['srcip', 'dstip', 'proto', 'state', 'service']]
    for col in numeric_cols:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    X['sport']  = X['sport'].fillna(0).astype('Int32')
    X['dsport'] = X['dsport'].fillna(0).astype('Int32')

    # ── 6. Log-transform skewed columns ───────────────────────────────────────
    numeric_only = X.select_dtypes(include=[np.number])
    skewness     = numeric_only.skew(numeric_only=True)
    skewed_cols  = skewness[skewness > 1].index.tolist()

    for col in skewed_cols:
        if col in X.columns:
            X[col] = np.log1p(pd.to_numeric(X[col], errors='coerce').fillna(0))

    # ── 7. duration_time  (Ltime − Stime, log-scaled) ─────────────────────────
    X['duration_time'] = (
        pd.to_numeric(X['Ltime'], errors='coerce').fillna(0)
        - pd.to_numeric(X['Stime'], errors='coerce').fillna(0)
    )
    X['duration_time'] = np.log1p(X['duration_time'].clip(lower=0)).astype('float32')
    X = X.drop(columns=['Stime', 'Ltime'])

    # ── 8. Ordinal-encode categorical columns ─────────────────────────────────
    for col in CAT_COLS:
        X[col] = X[col].astype(str).str.strip().str.lower()

    if os.path.exists(ENCODER_PATH):
        encoder = joblib.load(ENCODER_PATH)
        X[CAT_COLS] = encoder.transform(X[CAT_COLS])
    else:
        encoder = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
        X[CAT_COLS] = encoder.fit_transform(X[CAT_COLS])

    X[CAT_COLS] = X[CAT_COLS].astype('int32')

    # ── 9. Port fixes ─────────────────────────────────────────────────────────
    X['dsport'] = X['dsport'].fillna(0).astype('int32')
    X['sport']  = X['sport'].fillna(0).astype('int32')

    # ── 10. IP-based features ─────────────────────────────────────────────────
    src_feats = X['srcip'].astype(str).apply(_ip_features)
    dst_feats = X['dstip'].astype(str).apply(_ip_features)

    X['src_is_private']   = src_feats.apply(lambda d: d['is_private'])
    X['src_is_global']    = src_feats.apply(lambda d: d['is_global'])
    X['src_is_multicast'] = src_feats.apply(lambda d: d['is_multicast'])
    X['src_version']      = src_feats.apply(lambda d: d['version'])

    X['dst_is_private']   = dst_feats.apply(lambda d: d['is_private'])
    X['dst_is_global']    = dst_feats.apply(lambda d: d['is_global'])
    X['dst_is_multicast'] = dst_feats.apply(lambda d: d['is_multicast'])
    X['dst_version']      = dst_feats.apply(lambda d: d['version'])

    X['src_subnet'] = X['srcip'].astype(str).apply(_get_subnet)
    X['dst_subnet'] = X['dstip'].astype(str).apply(_get_subnet)

    # ── 11. Subnet & frequency encoding (use pre-saved artifacts if available)
    if os.path.exists(SUBNET_ENC_PATH):
        subnet_encoders = joblib.load(SUBNET_ENC_PATH)
        for col in ['src_subnet', 'dst_subnet']:
            le = subnet_encoders[col]
            # Unknown subnets → 0 (neutral, in-distribution) instead of -1
            # (which the model never saw during training and treats as anomalous).
            X[col] = X[col].map(
                lambda x, _le=le: int(_le.transform([x])[0]) if x in _le.classes_ else 0
            )
    else:
        for col in ['src_subnet', 'dst_subnet']:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))

    if os.path.exists(SRC_FREQ_PATH) and os.path.exists(DST_FREQ_PATH):
        src_counts = joblib.load(SRC_FREQ_PATH)
        dst_counts = joblib.load(DST_FREQ_PATH)
        # Unknown IPs fall back to the training median rather than 0,
        # so unseen real-world IPs don't look artificially rare/suspicious.
        src_median_log = float(np.log1p(src_counts.median()))
        dst_median_log = float(np.log1p(dst_counts.median()))
        X['src_freq'] = np.log1p(X['srcip'].map(src_counts).fillna(0))
        X['dst_freq'] = np.log1p(X['dstip'].map(dst_counts).fillna(0))
        X['src_freq'] = X['src_freq'].replace(0.0, src_median_log)
        X['dst_freq'] = X['dst_freq'].replace(0.0, dst_median_log)
    else:
        src_counts = X['srcip'].value_counts()
        dst_counts = X['dstip'].value_counts()
        X['src_freq'] = np.log1p(X['srcip'].map(src_counts).fillna(0))
        X['dst_freq'] = np.log1p(X['dstip'].map(dst_counts).fillna(0))

    X = X.drop(columns=['srcip', 'dstip'])

    # ── 12. Align to model feature order ──────────────────────────────────────
    feature_cols = EXPECTED_FEATURE_COLS

    for col in feature_cols:
        if col not in X.columns:
            X[col] = 0

    X = X[feature_cols]

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    X_arr = X.values.astype('float32')

    # ── 13. Predict ───────────────────────────────────────────────────────────
    try:
        if hasattr(model, 'predict_proba'):
            mal_proba   = model.predict_proba(X_arr)[:, 1].tolist()
            predictions = [
                'Malicious' if p >= THRESHOLD_MALICIOUS
                else ('Suspicious' if p >= THRESHOLD_SUSPICIOUS else 'Clean')
                for p in mal_proba
            ]
        else:
            raw_preds   = model.predict(X_arr).tolist()
            mal_proba   = [float(p) for p in raw_preds]
            predictions = [
                'Malicious' if p >= THRESHOLD_MALICIOUS
                else ('Suspicious' if p >= THRESHOLD_SUSPICIOUS else 'Clean')
                for p in mal_proba
            ]
    except Exception as e:
        _fail(f'Model prediction failed: {e}')

    # ── 14. Build JSON output ─────────────────────────────────────────────────

    # Resolve all unique IPs in parallel before building the flow list.
    all_ips = set(id_cols['srcip'].astype(str).tolist() + id_cols['dstip'].astype(str).tolist())
    for ip in all_ips:
        _resolve_ip(ip)   # warms the cache concurrently via the thread pool

    flows = []
    for i, (pred, prob) in enumerate(zip(predictions, mal_proba)):
        srcip  = str(id_cols.iloc[i]['srcip'])
        dstip  = str(id_cols.iloc[i]['dstip'])
        sport  = int(id_cols.iloc[i]['sport'])
        dsport = int(id_cols.iloc[i]['dsport'])
        is_ipv6 = (':' in srcip and not srcip.lower().startswith('::ffff:')) or \
                  (':' in dstip and not dstip.lower().startswith('::ffff:'))

        reasons = _build_reasons(raw_for_reasons.iloc[i], pred, prob) if pred != 'Clean' else []

        flows.append({
            'srcip':        srcip,
            'dstip':        dstip,
            'sport':        sport,
            'dsport':       dsport,
            'proto':        str(id_cols.iloc[i]['proto']),
            'is_ipv6':      is_ipv6,
            'prediction':   pred,
            'probability':  round(float(prob), 4),
            'reasons':      reasons,
            'src_host':     _resolve_ip(srcip),
            'dst_host':     _resolve_ip(dstip),
            'dst_service':  _port_label(dsport),
            'src_service':  _port_label(sport),
        })

    # Add private→private, whitelisted, and fallback rows back as Clean.
    for _, row in pd.concat([df_private, df_whitelisted, df_fallback]).iterrows():
        srcip  = str(row.get('srcip',  ''))
        dstip  = str(row.get('dstip',  ''))
        sport  = int(row.get('sport',  0) or 0)
        dsport = int(row.get('dsport', 0) or 0)
        flows.append({
            'srcip':  srcip, 'dstip':  dstip,
            'sport':  sport, 'dsport': dsport,
            'proto':  str(row.get('proto', '')),
            'is_ipv6': (':' in srcip and not srcip.lower().startswith('::ffff:')) or
                       (':' in dstip and not dstip.lower().startswith('::ffff:')),
            'prediction':  'Clean',
            'probability': 0.0,
            'reasons':     [],
            'src_host':    _resolve_ip(srcip),
            'dst_host':    _resolve_ip(dstip),
            'dst_service': _port_label(dsport),
            'src_service': _port_label(sport),
        })

    total      = len(flows)
    malicious  = sum(1 for f in flows if f['prediction'] == 'Malicious')
    suspicious = sum(1 for f in flows if f['prediction'] == 'Suspicious')

    print(json.dumps({
        'success': True,
        'summary': {
            'total_flows':     total,
            'clean_flows':     total - malicious - suspicious,
            'suspicious_flows': suspicious,
            'malicious_flows': malicious,
            'malicious_rate':  round((malicious + suspicious) / total, 4) if total > 0 else 0.0,
        },
        'flows': flows,
    }))


# =============================================================================
# Entry point
# =============================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UNSW-NB15 IDS inference pipeline')
    parser.add_argument('--infer', action='store_true', help='Run inference (default)')
    parser.add_argument('--csv',   default=None,        help='Path to OnePace.csv')
    args = parser.parse_args()

    run_inference(args.csv or _default_csv())
