"""
Malware Memory-Forensics — Inference Engine
============================================
Loads a trained model + preprocessor and exposes a clean API for
your application to call.

Supported model formats
-----------------------
  - scikit-learn estimators  (RandomForest, LogisticRegression)
  - XGBoost  (XGBClassifier saved with joblib)
  - LightGBM (LGBMClassifier saved with joblib)
  - ONNX     (.onnx files) — optional, needs onnxruntime

Quick start
-----------
    from inference import MalwareDetector

    detector = MalwareDetector.load(
        model_path="./artifacts/winner_LightGBM.joblib",   # or .onnx
        preprocessor_dir="./artifacts",
    )

    # --- batch prediction from a Volatility DataFrame ---
    results = detector.predict_df(df)          # list[dict]

    # --- single snapshot from a dict (e.g. from a live scan) ---
    result  = detector.predict_dict(record)    # dict

    # --- numpy array if you handle preprocessing yourself ---
    labels, probas = detector.predict_array(X_float32)
"""

from __future__ import annotations

import os
import json
import warnings
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import joblib

from preprocess import MalMemPreprocessor

warnings.filterwarnings("ignore", category=UserWarning)


# ============================================================================
# RESULT DATACLASS (plain dict for maximum compatibility)
# ============================================================================
def _make_result(label: int, proba: float, threshold: float) -> dict:
    """
    Returns a prediction result dict.

    Keys
    ----
    label     : int   — 1 = malware, 0 = benign
    proba     : float — probability of malware (0–1)
    verdict   : str   — 'MALWARE' | 'BENIGN'
    confidence: str   — 'HIGH' (≥0.85 or ≤0.15) | 'MEDIUM' | 'LOW'
    threshold : float — decision threshold used
    """
    verdict = "MALWARE" if label == 1 else "BENIGN"
    if proba >= 0.85 or proba <= 0.15:
        confidence = "HIGH"
    elif proba >= 0.70 or proba <= 0.30:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    return {
        "label":      int(label),
        "proba":      round(float(proba), 6),
        "verdict":    verdict,
        "confidence": confidence,
        "threshold":  threshold,
    }


# ============================================================================
# MODEL LOADERS
# ============================================================================
def _load_sklearn_model(path: str):
    """Load any joblib-serialised sklearn/xgb/lgb model."""
    return joblib.load(path)


def _load_onnx_model(path: str):
    """Load an ONNX model. Requires onnxruntime."""
    try:
        import onnxruntime as ort
    except ImportError as e:
        raise ImportError(
            "onnxruntime is required to load .onnx models. "
            "Install it with: pip install onnxruntime"
        ) from e
    session = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
    return session


def _predict_sklearn(model, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    labels = model.predict(X)
    probas = model.predict_proba(X)[:, 1]
    return labels.astype(int), probas.astype(np.float32)


def _predict_onnx(session, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    import onnxruntime as ort  # noqa: F401 – already imported during load
    input_name  = session.get_inputs()[0].name
    output_names = [o.name for o in session.get_outputs()]
    X_f32 = X.astype(np.float32)
    outputs = session.run(output_names, {input_name: X_f32})
    # Outputs follow sklearn convention: [labels, probas_dict_or_array]
    labels = np.array(outputs[0]).astype(int)
    raw_proba = outputs[1]
    if isinstance(raw_proba[0], dict):
        probas = np.array([p[1] for p in raw_proba], dtype=np.float32)
    else:
        probas = np.array(raw_proba, dtype=np.float32)
        if probas.ndim == 2:
            probas = probas[:, 1]
    return labels, probas


# ============================================================================
# MalwareDetector — main application class
# ============================================================================
class MalwareDetector:
    """
    End-to-end malware detector: preprocessing → model → structured result.

    Parameters
    ----------
    model             : fitted sklearn/xgb/lgb estimator or ONNX session
    preprocessor      : fitted MalMemPreprocessor
    threshold         : float, decision threshold (default 0.5)
    model_name        : str, display name logged in results
    """

    def __init__(
        self,
        model: Any,
        preprocessor: MalMemPreprocessor,
        threshold: float = 0.5,
        model_name: str = "unknown",
    ) -> None:
        self._model       = model
        self._pre         = preprocessor
        self._threshold   = threshold
        self._model_name  = model_name
        self._is_onnx     = _is_onnx_session(model)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------
    @classmethod
    def load(
        cls,
        model_path: str,
        preprocessor_dir: str = "./artifacts",
        threshold: float = 0.5,
    ) -> "MalwareDetector":
        """
        Load a detector from disk.

        Parameters
        ----------
        model_path       : path to a .joblib (sklearn/xgb/lgb) or .onnx model
        preprocessor_dir : directory containing preprocessor.joblib and
                           feature_names.json (output of MalMemPreprocessor.save)
        threshold        : decision threshold (default 0.5)
        """
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model not found: '{model_path}'")

        if path.suffix == ".onnx":
            model = _load_onnx_model(str(path))
        else:
            model = _load_sklearn_model(str(path))

        pre = MalMemPreprocessor.load(preprocessor_dir)

        print(f"Loaded model '{path.name}' | threshold={threshold} | features={pre.n_features}")
        return cls(model, pre, threshold=threshold, model_name=path.stem)

    # ------------------------------------------------------------------
    # Predict from raw Volatility DataFrame
    # ------------------------------------------------------------------
    def predict_df(self, df: pd.DataFrame) -> list[dict]:
        """
        Run end-to-end prediction on a Volatility DataFrame.
        Each row corresponds to one memory snapshot.

        Returns a list of result dicts (one per row).
        """
        X = self._pre.transform(df)
        return self._predict_X(X)

    # ------------------------------------------------------------------
    # Predict from a single dict (live scan scenario)
    # ------------------------------------------------------------------
    def predict_dict(self, record: dict) -> dict:
        """
        Predict a single memory snapshot given as a dict.
        Keys must match the 55 Volatility column names.

        Example
        -------
        result = detector.predict_dict({
            "pslist.nproc": 52,
            "malfind.ninjections": 3,
            "malfind.protection": 0x40,
            ...
        })
        # → {"label": 1, "proba": 0.9823, "verdict": "MALWARE", ...}
        """
        X = self._pre.transform_dict(record)
        return self._predict_X(X)[0]

    # ------------------------------------------------------------------
    # Predict from pre-processed numpy array (bypass preprocessing)
    # ------------------------------------------------------------------
    def predict_array(
        self, X: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Predict on an already-preprocessed float32 array.
        Returns (labels, probas) as numpy arrays.
        Useful when you manage preprocessing separately.
        """
        labels, probas = self._run_model(X)
        return labels, probas

    # ------------------------------------------------------------------
    # Batch scoring — returns a DataFrame with results appended
    # ------------------------------------------------------------------
    def score_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Like predict_df() but returns the original DataFrame with three
        extra columns: 'pred_label', 'pred_proba', 'verdict'.
        """
        results = self.predict_df(df)
        out = df.copy()
        out["pred_label"] = [r["label"]   for r in results]
        out["pred_proba"] = [r["proba"]   for r in results]
        out["verdict"]    = [r["verdict"] for r in results]
        return out

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def threshold(self) -> float:
        return self._threshold

    @threshold.setter
    def threshold(self, value: float) -> None:
        if not 0.0 < value < 1.0:
            raise ValueError("threshold must be in (0, 1)")
        self._threshold = value

    @property
    def feature_names(self) -> list[str]:
        return self._pre.feature_names

    @property
    def model_name(self) -> str:
        return self._model_name

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _run_model(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        if self._is_onnx:
            return _predict_onnx(self._model, X)
        return _predict_sklearn(self._model, X)

    def _predict_X(self, X: np.ndarray) -> list[dict]:
        _, probas = self._run_model(X)
        labels = (probas >= self._threshold).astype(int)
        return [_make_result(int(l), float(p), self._threshold)
                for l, p in zip(labels, probas)]


# ============================================================================
# Utility: batch predict from a parquet / CSV file
# ============================================================================
def predict_file(
    data_path: str,
    model_path: str,
    preprocessor_dir: str = "./artifacts",
    output_path: str | None = None,
    threshold: float = 0.5,
) -> pd.DataFrame:
    """
    Convenience function: load a parquet or CSV, run predictions, optionally save.

    Parameters
    ----------
    data_path        : .parquet or .csv file with Volatility features
    model_path       : .joblib or .onnx model
    preprocessor_dir : directory with saved preprocessor artifacts
    output_path      : if given, write results as CSV here
    threshold        : decision threshold

    Returns
    -------
    DataFrame with original columns + pred_label, pred_proba, verdict
    """
    ext = Path(data_path).suffix.lower()
    if ext == ".parquet":
        df = pd.read_parquet(data_path)
    elif ext in (".csv", ".tsv"):
        df = pd.read_csv(data_path)
    else:
        raise ValueError(f"Unsupported file format: '{ext}'. Use .parquet or .csv")

    detector = MalwareDetector.load(model_path, preprocessor_dir, threshold)
    results  = detector.score_df(df)

    if output_path:
        results.to_csv(output_path, index=False)
        print(f"Saved predictions to '{output_path}'")

    n_malware = (results["pred_label"] == 1).sum()
    print(f"Predictions: {n_malware}/{len(results)} rows flagged as MALWARE "
          f"({100*n_malware/len(results):.1f}%)")
    return results


# ============================================================================
# Helper — detect ONNX session without importing onnxruntime at module level
# ============================================================================
def _is_onnx_session(obj: Any) -> bool:
    try:
        import onnxruntime as ort
        return isinstance(obj, ort.InferenceSession)
    except ImportError:
        return False


# ============================================================================
# CLI entry point
# ============================================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run malware inference on a Volatility feature file."
    )
    parser.add_argument("data",  help="Input .parquet or .csv file")
    parser.add_argument("model", help="Trained model (.joblib or .onnx)")
    parser.add_argument("--artifacts-dir", default="./artifacts",
                        help="Directory containing preprocessor artifacts (default: ./artifacts)")
    parser.add_argument("--output", default=None,
                        help="Save predictions to this CSV path")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Decision threshold (default: 0.5)")
    args = parser.parse_args()

    predict_file(
        data_path=args.data,
        model_path=args.model,
        preprocessor_dir=args.artifacts_dir,
        output_path=args.output,
        threshold=args.threshold,
    )