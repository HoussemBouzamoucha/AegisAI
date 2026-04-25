"""
Malware Memory-Forensics — Preprocessing Pipeline (Application Use)
=====================================================================
Adapts the Colab pipeline.py for use in a production application.

Usage
-----
Training / fitting (run once, save artifacts):
    from preprocess import fit_and_save
    fit_and_save("path/to/Obfuscated-MalMem2022.parquet", artifacts_dir="./artifacts")

Loading artifacts and transforming new data:
    from preprocess import MalMemPreprocessor
    pre = MalMemPreprocessor.load("./artifacts")
    X = pre.transform(df_raw)          # numpy float32 array, shape (n, 68)

Single-snapshot dict (e.g. from a live Volatility scan):
    X = pre.transform_dict(volatility_dict)
"""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Union

import numpy as np
import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


# ============================================================================
# DTYPE SCHEMA  (mirrors pipeline.py exactly)
# ============================================================================
DOWNCAST_DTYPES: dict[str, str] = {
    "pslist.nproc": "int16", "pslist.nppid": "int8",
    "pslist.avg_threads": "float32", "pslist.nprocs64bit": "int8",
    "pslist.avg_handlers": "float32",
    "dlllist.ndlls": "int16", "dlllist.avg_dlls_per_proc": "float32",
    "handles.nhandles": "int32", "handles.avg_handles_per_proc": "float32",
    "handles.nport": "int8", "handles.nfile": "int32",
    "handles.nevent": "int16", "handles.ndesktop": "int16",
    "handles.nkey": "int16", "handles.nthread": "int16",
    "handles.ndirectory": "int16", "handles.nsemaphore": "int16",
    "handles.ntimer": "int16", "handles.nsection": "int16",
    "handles.nmutant": "int16",
    "ldrmodules.not_in_load": "int16", "ldrmodules.not_in_init": "int16",
    "ldrmodules.not_in_mem": "int16",
    "ldrmodules.not_in_load_avg": "float32",
    "ldrmodules.not_in_init_avg": "float32",
    "ldrmodules.not_in_mem_avg": "float32",
    "malfind.ninjections": "int16", "malfind.commitCharge": "int32",
    "malfind.protection": "int16", "malfind.uniqueInjections": "float32",
    "psxview.not_in_pslist": "int8", "psxview.not_in_eprocess_pool": "int8",
    "psxview.not_in_ethread_pool": "int16", "psxview.not_in_pspcid_list": "int8",
    "psxview.not_in_csrss_handles": "int16", "psxview.not_in_session": "int8",
    "psxview.not_in_deskthrd": "int16",
    "psxview.not_in_pslist_false_avg": "float32",
    "psxview.not_in_eprocess_pool_false_avg": "float32",
    "psxview.not_in_ethread_pool_false_avg": "float32",
    "psxview.not_in_pspcid_list_false_avg": "float32",
    "psxview.not_in_csrss_handles_false_avg": "float32",
    "psxview.not_in_session_false_avg": "float32",
    "psxview.not_in_deskthrd_false_avg": "float32",
    "modules.nmodules": "int16",
    "svcscan.nservices": "int16", "svcscan.kernel_drivers": "int16",
    "svcscan.fs_drivers": "int8", "svcscan.process_services": "int8",
    "svcscan.shared_process_services": "int8",
    "svcscan.interactive_process_services": "int8",
    "svcscan.nactive": "int16",
    "callbacks.ncallbacks": "int8", "callbacks.nanonymous": "int8",
    "callbacks.ngeneric": "int8",
}
RAW_FEATURES: list[str] = list(DOWNCAST_DTYPES.keys())   # 55 columns


# ============================================================================
# WINDOWS PAGE PROTECTION CONSTANTS
# ============================================================================
PAGE_NOACCESS                           = 0x01
PAGE_READWRITE, PAGE_WRITECOPY         = 0x04, 0x08
PAGE_EXECUTE, PAGE_EXECUTE_READ        = 0x10, 0x20
PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY = 0x40, 0x80

EXEC_MASK  = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
WRITE_MASK = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
COW_MASK   = PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY

PSXVIEW_COUNT_COLS = [
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool", "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles", "psxview.not_in_session",
    "psxview.not_in_deskthrd",
]
LDRMODULES_COUNT_COLS = [
    "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
]


# ============================================================================
# COLUMN GROUPS FOR THE SKLEARN TRANSFORMER
# ============================================================================
LOG_SCALE_COLS: list[str] = [
    "pslist.nproc", "pslist.nppid", "pslist.avg_threads", "pslist.nprocs64bit",
    "pslist.avg_handlers",
    "dlllist.ndlls", "dlllist.avg_dlls_per_proc",
    "handles.nhandles", "handles.avg_handles_per_proc",
    "handles.nport", "handles.nfile", "handles.nevent", "handles.ndesktop",
    "handles.nkey", "handles.nthread", "handles.ndirectory",
    "handles.nsemaphore", "handles.ntimer", "handles.nsection", "handles.nmutant",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
    "malfind.ninjections", "malfind.commitCharge", "malfind.uniqueInjections",
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool", "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles", "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "modules.nmodules",
    "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers",
    "svcscan.process_services", "svcscan.shared_process_services",
    "svcscan.interactive_process_services", "svcscan.nactive",
    "callbacks.ncallbacks", "callbacks.nanonymous", "callbacks.ngeneric",
    "psxview_total_hidden", "ldrmodules_total_missing",
    "handles_per_process", "dlls_per_process",
    "injection_severity", "avg_commit_per_injection",
]

SCALE_ONLY_COLS: list[str] = [
    "ldrmodules.not_in_load_avg", "ldrmodules.not_in_init_avg",
    "ldrmodules.not_in_mem_avg",
    "psxview.not_in_pslist_false_avg", "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg", "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg", "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
    "anonymous_callback_ratio",
]

PASSTHROUGH_COLS: list[str] = [
    "malfind.protection",
    "is_executable", "is_writable", "is_rwx", "is_copy_on_write",
    "is_noaccess", "is_executable_only",
]

ALL_MODEL_COLS = LOG_SCALE_COLS + SCALE_ONLY_COLS + PASSTHROUGH_COLS  # 68 total


# ============================================================================
# STATELESS FEATURE ENGINEERING
# ============================================================================
def _add_protection_flags(df: pd.DataFrame) -> pd.DataFrame:
    prot = df["malfind.protection"].astype("int32")
    df["is_executable"]      = ((prot & EXEC_MASK)  > 0).astype("int8")
    df["is_writable"]        = ((prot & WRITE_MASK) > 0).astype("int8")
    df["is_rwx"]             = (df["is_executable"] & df["is_writable"]).astype("int8")
    df["is_copy_on_write"]   = ((prot & COW_MASK)   > 0).astype("int8")
    df["is_noaccess"]        = ((prot & PAGE_NOACCESS) > 0).astype("int8")
    df["is_executable_only"] = (df["is_executable"] & (1 - df["is_writable"])).astype("int8")
    return df


def _add_cross_check_aggregates(df: pd.DataFrame) -> pd.DataFrame:
    df["psxview_total_hidden"]     = df[PSXVIEW_COUNT_COLS].sum(axis=1).astype("int16")
    df["ldrmodules_total_missing"] = df[LDRMODULES_COUNT_COLS].sum(axis=1).astype("int16")
    return df


def _add_density_ratios(df: pd.DataFrame) -> pd.DataFrame:
    nproc = df["pslist.nproc"].astype("float32") + 1.0
    df["handles_per_process"]      = (df["handles.nhandles"].astype("float32") / nproc).astype("float32")
    df["dlls_per_process"]         = (df["dlllist.ndlls"].astype("float32") / nproc).astype("float32")
    df["anonymous_callback_ratio"] = (
        df["callbacks.nanonymous"].astype("float32")
        / (df["callbacks.ncallbacks"].astype("float32") + 1.0)
    ).astype("float32")
    return df


def _add_injection_features(df: pd.DataFrame) -> pd.DataFrame:
    df["injection_severity"]       = (
        df["malfind.ninjections"].astype("float32") * (1.0 + df["is_rwx"].astype("float32"))
    ).astype("float32")
    df["avg_commit_per_injection"] = (
        df["malfind.commitCharge"].astype("float32")
        / (df["malfind.ninjections"].astype("float32") + 1.0)
    ).astype("float32")
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """All stateless feature engineering. Input: raw Volatility DataFrame.
    Output: same DataFrame with 13 additional columns appended."""
    df = _add_protection_flags(df)
    df = _add_cross_check_aggregates(df)
    df = _add_density_ratios(df)
    df = _add_injection_features(df)
    return df


def _build_column_transformer() -> ColumnTransformer:
    log_then_scale = Pipeline([
        ("log1p", FunctionTransformer(np.log1p, feature_names_out="one-to-one", validate=True)),
        ("scale", StandardScaler()),
    ])
    return ColumnTransformer(
        transformers=[
            ("log_scale",   log_then_scale,   LOG_SCALE_COLS),
            ("scale_only",  StandardScaler(), SCALE_ONLY_COLS),
            ("passthrough", "passthrough",    PASSTHROUGH_COLS),
        ],
        remainder="drop",
        verbose_feature_names_out=False,
    )


# ============================================================================
# MalMemPreprocessor — the main application class
# ============================================================================
class MalMemPreprocessor:
    """
    Stateful preprocessor: wraps engineer_features + ColumnTransformer.

    Typical lifecycle
    -----------------
    1. Fit once on training data:
           pre = MalMemPreprocessor()
           pre.fit(X_train_raw_df)
           pre.save("./artifacts")

    2. Load in your application and transform:
           pre = MalMemPreprocessor.load("./artifacts")
           X = pre.transform(new_df)          # → float32 ndarray (n, 68)
           X = pre.transform_dict(row_dict)   # → float32 ndarray (1, 68)
    """

    PREPROCESSOR_FILE  = "preprocessor.joblib"
    FEATURE_NAMES_FILE = "feature_names.json"

    def __init__(self) -> None:
        self._ct: ColumnTransformer | None = None
        self._feature_names: list[str] = []
        self._fitted = False

    # ------------------------------------------------------------------
    # Fit
    # ------------------------------------------------------------------
    def fit(self, df: pd.DataFrame) -> "MalMemPreprocessor":
        """Fit on a raw Volatility DataFrame (must contain the 55 RAW_FEATURES)."""
        df = self._validate_and_cast(df)
        df = engineer_features(df.copy())
        self._ct = _build_column_transformer()
        self._ct.fit(df[ALL_MODEL_COLS])
        self._feature_names = self._ct.get_feature_names_out().tolist()
        self._fitted = True
        return self

    # ------------------------------------------------------------------
    # Transform
    # ------------------------------------------------------------------
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transform a raw Volatility DataFrame.
        Returns float32 ndarray of shape (n_rows, 68).
        """
        self._check_fitted()
        df = self._validate_and_cast(df.copy())
        df = engineer_features(df)
        return self._ct.transform(df[ALL_MODEL_COLS]).astype(np.float32)

    def transform_dict(self, record: dict) -> np.ndarray:
        """
        Transform a single Volatility snapshot given as a Python dict.
        Returns float32 ndarray of shape (1, 68).

        Example
        -------
        record = {
            "pslist.nproc": 42, "pslist.nppid": 38, ...,  # all 55 raw fields
        }
        X = pre.transform_dict(record)
        """
        df = pd.DataFrame([record])
        return self.transform(df)

    # ------------------------------------------------------------------
    # Save / Load
    # ------------------------------------------------------------------
    def save(self, directory: str) -> None:
        """Persist the fitted transformer and feature names to disk."""
        self._check_fitted()
        Path(directory).mkdir(parents=True, exist_ok=True)
        joblib.dump(self._ct, os.path.join(directory, self.PREPROCESSOR_FILE))
        with open(os.path.join(directory, self.FEATURE_NAMES_FILE), "w") as f:
            json.dump(self._feature_names, f, indent=2)
        print(f"Saved preprocessor to '{directory}/'")

    @classmethod
    def load(cls, directory: str) -> "MalMemPreprocessor":
        """Load a previously saved preprocessor from disk."""
        pre = cls()
        ct_path = os.path.join(directory, cls.PREPROCESSOR_FILE)
        fn_path = os.path.join(directory, cls.FEATURE_NAMES_FILE)
        if not os.path.exists(ct_path):
            raise FileNotFoundError(f"Preprocessor not found at '{ct_path}'. Run fit_and_save() first.")
        pre._ct = joblib.load(ct_path)
        with open(fn_path) as f:
            pre._feature_names = json.load(f)
        pre._fitted = True
        print(f"Loaded preprocessor from '{directory}/' — {len(pre._feature_names)} features")
        return pre

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def feature_names(self) -> list[str]:
        self._check_fitted()
        return self._feature_names

    @property
    def n_features(self) -> int:
        return len(self._feature_names)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _check_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError("Preprocessor is not fitted yet. Call fit() or load() first.")

    @staticmethod
    def _validate_and_cast(df: pd.DataFrame) -> pd.DataFrame:
        missing = [c for c in RAW_FEATURES if c not in df.columns]
        if missing:
            raise KeyError(
                f"Input is missing {len(missing)} required Volatility column(s): {missing[:5]}{'...' if len(missing) > 5 else ''}"
            )
        return df.astype({c: t for c, t in DOWNCAST_DTYPES.items() if c in df.columns})


# ============================================================================
# Convenience: fit_and_save (run once from CLI or a setup script)
# ============================================================================
def fit_and_save(
    parquet_path: str,
    artifacts_dir: str = "./artifacts",
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
) -> dict:
    """
    Load the dataset, engineer features, split, fit the preprocessor on train
    only, save artifacts, and return the processed splits.

    Returns
    -------
    dict with keys: X_train, y_train, X_val, y_val, X_test, y_test,
                    preprocessor (MalMemPreprocessor), feature_names (list)
    """
    print(f"Loading dataset from '{parquet_path}' …")
    df = pd.read_parquet(parquet_path)

    missing = [c for c in RAW_FEATURES + ["Class"] if c not in df.columns]
    if missing:
        raise KeyError(f"Missing expected columns: {missing}")

    df = df.astype({c: t for c, t in DOWNCAST_DTYPES.items() if c in df.columns})
    df = df.dropna(subset=RAW_FEATURES + ["Class"]).reset_index(drop=True)

    # Label: 0 = benign, 1 = malware
    y = (df["Class"].astype(str).str.strip().str.lower() != "benign").astype("int8").to_numpy()

    # Drop metadata columns before engineering
    X_raw = df.drop(columns=[c for c in ("Category", "Class", "label") if c in df.columns])

    # Stratified split BEFORE fitting any statistics-bearing transformer
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X_raw, y, test_size=test_size, stratify=y, random_state=random_state,
    )
    val_relative = val_size / (1.0 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval,
        test_size=val_relative, stratify=y_trainval, random_state=random_state,
    )

    # Fit on TRAIN ONLY
    pre = MalMemPreprocessor()
    pre.fit(X_train)
    pre.save(artifacts_dir)

    X_train_t = pre.transform(X_train)
    X_val_t   = pre.transform(X_val)
    X_test_t  = pre.transform(X_test)

    print(f"Train : {X_train_t.shape}  prevalence={y_train.mean():.4f}")
    print(f"Val   : {X_val_t.shape}  prevalence={y_val.mean():.4f}")
    print(f"Test  : {X_test_t.shape}  prevalence={y_test.mean():.4f}")

    # Save numpy splits alongside the preprocessor
    np.savez_compressed(
        os.path.join(artifacts_dir, "splits.npz"),
        X_train=X_train_t, y_train=y_train,
        X_val=X_val_t,     y_val=y_val,
        X_test=X_test_t,   y_test=y_test,
        feature_names=np.array(pre.feature_names),
    )
    print(f"Saved splits to '{artifacts_dir}/splits.npz'")

    return {
        "X_train": X_train_t, "y_train": y_train,
        "X_val":   X_val_t,   "y_val":   y_val,
        "X_test":  X_test_t,  "y_test":  y_test,
        "preprocessor":   pre,
        "feature_names":  pre.feature_names,
    }


# ============================================================================
# CLI entry point
# ============================================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fit and save MalMem preprocessor.")
    parser.add_argument("parquet", help="Path to Obfuscated-MalMem2022.parquet")
    parser.add_argument("--artifacts-dir", default="./artifacts",
                        help="Directory to save preprocessor artifacts (default: ./artifacts)")
    args = parser.parse_args()

    fit_and_save(args.parquet, artifacts_dir=args.artifacts_dir)