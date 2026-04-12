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
MODEL_DIR  = os.path.join(ENGINE_DIR, 'models')

MODEL_PATH        = os.path.join(MODEL_DIR, 'ids_xgboost_model.pkl')
ENCODER_PATH      = os.path.join(MODEL_DIR, 'ordinal_encoder.joblib')
SKEWED_COLS_PATH  = os.path.join(MODEL_DIR, 'skewed_cols.joblib')
FEATURE_COLS_PATH = os.path.join(MODEL_DIR, 'feature_cols.joblib')

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

# =============================================================================
# Inference pipeline
# =============================================================================

def run_inference(csv_path: str) -> None:
    """
    Read OnePace.csv, preprocess, run the saved XGBoost model, and print a
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
            'summary': {'total_flows': 0, 'clean_flows': 0, 'malicious_flows': 0, 'malicious_rate': 0.0},
            'flows': [],
        }))
        return

    missing = [c for c in FEATURE_NAMES_47 if c not in df.columns]
    if missing:
        _fail(f'CSV is missing columns: {missing}')

    # ── 2. Load model ─────────────────────────────────────────────────────────
    if not os.path.exists(MODEL_PATH):
        _fail(f'Model not found at: {MODEL_PATH}')

    try:
        import xgboost  # noqa: F401
    except ImportError:
        _fail('xgboost is not installed. Run: pip install xgboost')

    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        _fail(f'Failed to load model: {e}')

    # Unwrap dict bundle: {"model": clf, "threshold": 0.3, "features": [...]}
    if isinstance(model, dict):
        model = model.get('model', model)

    # ── 3. Retain identity columns before transforms ──────────────────────────
    id_cols = df[['srcip', 'dstip', 'sport', 'dsport', 'proto']].copy()
    id_cols['sport']  = pd.to_numeric(id_cols['sport'],  errors='coerce').fillna(0).astype(int)
    id_cols['dsport'] = pd.to_numeric(id_cols['dsport'], errors='coerce').fillna(0).astype(int)

    X = df.copy()

    # ── 4. Fill structural NaNs ───────────────────────────────────────────────
    # ct_flw_http_mthd and is_ftp_login are NaN when no HTTP/FTP — fill with 0
    X['ct_flw_http_mthd'] = pd.to_numeric(X['ct_flw_http_mthd'], errors='coerce').fillna(0).astype('float32')
    X['is_ftp_login']     = pd.to_numeric(X['is_ftp_login'],     errors='coerce').fillna(0).astype('float32')

    # ── 5. Numeric coercion ───────────────────────────────────────────────────
    numeric_cols = [c for c in FEATURE_NAMES_47 if c not in ['srcip', 'dstip', 'proto', 'state', 'service']]
    for col in numeric_cols:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    X['sport']  = X['sport'].fillna(0).astype('Int32')
    X['dsport'] = X['dsport'].fillna(0).astype('Int32')

    # ── 6. Log-transform skewed columns ───────────────────────────────────────
    # Load the skewed column list saved at training time; fall back to detecting
    # from the batch (may differ slightly from training).
    if os.path.exists(SKEWED_COLS_PATH):
        skewed_cols = joblib.load(SKEWED_COLS_PATH)
    else:
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
    # Port 0 is a safe placeholder for missing port values
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

    for col in ['src_subnet', 'dst_subnet']:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))

    # IP frequency within batch (log-scaled)
    src_counts = X['srcip'].value_counts()
    dst_counts = X['dstip'].value_counts()
    X['src_freq'] = np.log1p(X['srcip'].map(src_counts).fillna(0))
    X['dst_freq'] = np.log1p(X['dstip'].map(dst_counts).fillna(0))

    X = X.drop(columns=['srcip', 'dstip'])

    # ── 11. Align to model feature order ──────────────────────────────────────
    feature_cols = joblib.load(FEATURE_COLS_PATH) if os.path.exists(FEATURE_COLS_PATH) else EXPECTED_FEATURE_COLS

    for col in feature_cols:
        if col not in X.columns:
            X[col] = 0

    X = X[feature_cols]

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    X_arr = X.values.astype('float32')

    # ── 12. Predict ───────────────────────────────────────────────────────────
    THRESHOLD = 0.75

    try:
        if hasattr(model, 'predict_proba'):
            mal_proba   = model.predict_proba(X_arr)[:, 1].tolist()
            predictions = [1 if p >= THRESHOLD else 0 for p in mal_proba]
        else:
            predictions = model.predict(X_arr).tolist()
            mal_proba   = [float(p) for p in predictions]
    except Exception as e:
        _fail(f'Model prediction failed: {e}')

    # ── 13. Build JSON output ─────────────────────────────────────────────────
    flows = []
    for i, (pred, prob) in enumerate(zip(predictions, mal_proba)):
        flows.append({
            'srcip':       str(id_cols.iloc[i]['srcip']),
            'dstip':       str(id_cols.iloc[i]['dstip']),
            'sport':       int(id_cols.iloc[i]['sport']),
            'dsport':      int(id_cols.iloc[i]['dsport']),
            'proto':       str(id_cols.iloc[i]['proto']),
            'prediction':  'Malicious' if int(pred) == 1 else 'Clean',
            'probability': round(float(prob), 4),
        })

    total     = len(flows)
    malicious = sum(1 for f in flows if f['prediction'] == 'Malicious')

    print(json.dumps({
        'success': True,
        'summary': {
            'total_flows':     total,
            'clean_flows':     total - malicious,
            'malicious_flows': malicious,
            'malicious_rate':  round(malicious / total, 4) if total > 0 else 0.0,
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
