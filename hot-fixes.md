# Hot-Fixes — ML IDS Inference Pipeline

## Overview

Three inference-time bugs were corrected in
`Antivirus_Engine/src/core/network/Feature_extractor/ML_IDS/preprocessing_pipeline.py`.
All fixes bring live inference into alignment with what the model saw at training time.
The new model artifacts live in `Antivirus_Engine/models/network/`.

---

## Fix 1 — Model and artifact paths updated

**Problem:** `MODEL_DIR` pointed to `models/` and loaded `ids_xgboost_model.pkl`.
The retrained model and all companion artifacts moved to `models/network/` under the
name `ids_network_model.pkl`.

**Change:** `MODEL_DIR` now resolves to `models/network/`. All artifact paths
(`ordinal_encoder.joblib`, `skewed_cols.joblib`, `feature_cols.joblib`) updated
accordingly.

---

## Fix 2 — Subnet encoding uses training-time encoders

**Problem:** `src_subnet` / `dst_subnet` were encoded each run with a fresh
`LabelEncoder` fitted only on the current batch. This produced arbitrary integer
codes that were meaningless to the model, which was trained with a fixed codec.

**Change:** The pipeline now loads `subnet_encoders.joblib` from `models/network/`
(a dict of `{col: LabelEncoder}` saved during training). Unseen subnets map to `-1`
(handled gracefully by XGBoost). Falls back to the old batch encoder only if the
file is absent.

---

## Fix 3 — IP frequency features use training-time distributions

**Problem:** `src_freq` / `dst_freq` were computed from `value_counts()` of the
current capture batch. A low-traffic attacker IP in a small batch got the same
score as a high-traffic benign host, defeating the feature entirely.

**Change:** The pipeline loads `src_freq_map.joblib` and `dst_freq_map.joblib`
from `models/network/`. These maps were built from the full training corpus so
frequency scores reflect the learned baseline. Live IPs absent from the maps
receive a frequency of 0 (log1p → 0). Falls back to batch counts only if files
are absent.

---

## Remaining training-time tasks (see tofix.txt)

- **Calibrate** the model with `CalibratedClassifierCV` on labeled real-traffic
  samples to align probability outputs with real-world priors.
- **Retrain** with mixed data (UNSW-NB15 + labeled real-world traffic) to teach
  the model your environment's baseline behavior.
