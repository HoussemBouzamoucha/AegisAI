"""
preprocess.py
─────────────
Applies the exact same preprocessing pipeline used in final_network_ids.ipynb
to latest.csv, producing a model-ready CSV: latest_preprocessed.csv

Usage:
    python preprocess.py
    python preprocess.py --input latest.csv --output latest_preprocessed.csv
"""

import argparse
import numpy as np
import pandas as pd

# ── CLI ───────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('--input',  default='../latest.csv',            help='Raw CSV from flow_extractor')
parser.add_argument('--output', default='../latest_preprocessed.csv', help='Output preprocessed CSV')
args = parser.parse_args()

print(f'[*] Loading: {args.input}')
df = pd.read_csv(args.input)
print(f'    Rows: {len(df)}  |  Columns: {df.shape[1]}')

# ── Step 1: Fix structural NaNs ───────────────────────────────────────────────
# ct_flw_http_mthd and is_ftp_login are NaN when there is no HTTP/FTP — fill 0
df['ct_flw_http_mthd'] = df['ct_flw_http_mthd'].fillna(0).astype('float32')
df['is_ftp_login']     = df['is_ftp_login'].fillna(0).astype('float32')

# ── Step 2: IP topology features (derived before dropping IPs) ────────────────
def is_private(ip: str) -> int:
    """Return 1 if ip is RFC-1918 private, else 0."""
    try:
        ip = str(ip)
        if ip.startswith('10.'):       return 1
        if ip.startswith('192.168.'): return 1
        parts = ip.split('.')
        if parts[0] == '172' and 16 <= int(parts[1]) <= 31: return 1
    except Exception:
        pass
    return 0

df['src_private'] = df['srcip'].apply(is_private).astype('int8')
df['dst_private'] = df['dstip'].apply(is_private).astype('int8')
df['same_subnet'] = (
    df['srcip'].str.split('.').str[:3].str.join('.') ==
    df['dstip'].str.split('.').str[:3].str.join('.')
).astype('int8')

# src_unique_dst: how many unique destinations this source contacted
# (within this file — meaningful once you have many flows)
src_unique = df.groupby('srcip')['dstip'].nunique()
median_unique = int(src_unique.median()) if len(src_unique) > 0 else 1
df['src_unique_dst'] = df['srcip'].map(src_unique).fillna(median_unique).astype('float32')

print('[OK] IP topology features added')

# ── Step 3: Flow-level statistical features ───────────────────────────────────
df['total_bytes']      = df['sbytes'] + df['dbytes']
df['byte_ratio']       = np.log1p(df['sbytes']) - np.log1p(df['dbytes'])
total_pkts             = df['Spkts'] + df['Dpkts']
df['bytes_per_packet'] = df['total_bytes'] / (total_pkts + 1)
df['flow_rate']        = df['total_bytes'] / (df['dur'] + 0.001)

# Log-scale extreme-valued features
df['flow_rate']   = np.log1p(df['flow_rate'])
df['total_bytes'] = np.log1p(df['total_bytes'])

print('[OK] Flow statistical features added')

# ── Step 4: Drop columns not used as model features ───────────────────────────
# srcip / dstip  — raw IPs; topology flags already extracted above
# sport / dsport — high cardinality; service/state already capture port info
# Stime / Ltime  — timestamps cause temporal leakage
DROP_COLS = ['srcip', 'dstip', 'sport', 'dsport', 'Stime', 'Ltime']
df.drop(columns=DROP_COLS, inplace=True, errors='ignore')
print(f'[OK] Dropped leakage/identity columns: {DROP_COLS}')

# ── Step 5: Cast numerics to float32 ─────────────────────────────────────────
FLOAT_COLS = [
    'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
    'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
    'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit',
    'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
]
for col in FLOAT_COLS:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='coerce').astype('float32')

# ── Step 6: Replace inf / NaN with 0 ─────────────────────────────────────────
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)
print('[OK] Infinities and NaNs replaced with 0')

# ── Step 7: Label-encode categorical columns ──────────────────────────────────
# These encoders are fitted on THIS file only (inference mode).
# For production, load the saved encoders from Kaggle instead.
from sklearn.preprocessing import LabelEncoder

CATEGORICAL_COLS = ['proto', 'state', 'service', 'ct_ftp_cmd']

encoders = {}
for col in CATEGORICAL_COLS:
    if col not in df.columns:
        continue
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    encoders[col] = le
    print(f'    Encoded {col}: {len(le.classes_)} unique values')

print('[OK] Categorical columns encoded')

# ── Step 8: Verify no object columns remain ───────────────────────────────────
obj_cols = df.select_dtypes(include='object').columns.tolist()
if obj_cols:
    print(f'[WARN] Object columns still present (will be dropped): {obj_cols}')
    df.drop(columns=obj_cols, inplace=True)

# ── Done ──────────────────────────────────────────────────────────────────────
print(f'\n[*] Final shape : {df.shape}')
print(f'[*] Columns     : {list(df.columns)}')

df.to_csv(args.output, index=False)
print(f'\n[OK] Preprocessed CSV saved to: {args.output}')
print('     Ready to feed into the model.')
