"""
Malware Memory-Forensics — Model Training & Evaluation
================================================================================
Trains 4 models on the preprocessed splits:
  - Logistic Regression
  - Random Forest
  - XGBoost
  - LightGBM

Evaluates on the held-out test set with:
  - Accuracy, Precision, Recall, F1
  - ROC-AUC, PR-AUC
  - Confusion matrix per model
  - ROC-curve plot (all models overlaid)
  - SHAP feature importance for the winning model (chosen by val ROC-AUC)

Prerequisite: run pipeline.py first to produce /content/splits.npz.

Usage in Colab:
    !python /content/pipeline.py       # produces splits.npz
    !python /content/train.py          # produces metrics + plots
"""

from __future__ import annotations

import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score,
    confusion_matrix, roc_curve,
)
import xgboost as xgb
import lightgbm as lgb

warnings.filterwarnings("ignore", category=UserWarning)


# ============================================================================
# 1. LOAD PRECOMPUTED SPLITS
# ============================================================================
def load_splits(npz_path: str):
    d = np.load(npz_path, allow_pickle=True)
    return {
        "X_train": d["X_train"], "y_train": d["y_train"],
        "X_val":   d["X_val"],   "y_val":   d["y_val"],
        "X_test":  d["X_test"],  "y_test":  d["y_test"],
        "feature_names": d["feature_names"].tolist(),
    }


# ============================================================================
# 2. MODEL FACTORY — sensible defaults, class-balanced where applicable
# ============================================================================
def build_models(random_state: int = 42) -> dict:
    """Return a dict of {name: unfitted_estimator}. Defaults only."""
    return {
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=random_state,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            n_jobs=-1,
            random_state=random_state,
        ),
        "XGBoost": xgb.XGBClassifier(
            n_estimators=300,
            learning_rate=0.1,
            max_depth=6,
            tree_method="hist",  # fast histogram-based training
            eval_metric="logloss",
            n_jobs=-1,
            random_state=random_state,
        ),
        "LightGBM": lgb.LGBMClassifier(
            n_estimators=300,
            learning_rate=0.1,
            max_depth=-1,
            num_leaves=31,
            n_jobs=-1,
            random_state=random_state,
            verbose=-1,
        ),
    }


# ============================================================================
# 3. METRICS
# ============================================================================
def compute_metrics(y_true, y_pred, y_proba) -> dict:
    """Six standard binary-classification metrics."""
    return {
        "accuracy":   accuracy_score(y_true, y_pred),
        "precision":  precision_score(y_true, y_pred, zero_division=0),
        "recall":     recall_score(y_true, y_pred, zero_division=0),
        "f1":         f1_score(y_true, y_pred, zero_division=0),
        "roc_auc":    roc_auc_score(y_true, y_proba),
        "pr_auc":     average_precision_score(y_true, y_proba),
    }


# ============================================================================
# 4. TRAIN + EVALUATE ALL MODELS
# ============================================================================
def train_and_evaluate(splits: dict) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    """
    Fit every model on train, evaluate on val and test.
    Returns: (fitted_models, val_metrics_df, test_metrics_df).
    """
    X_train, y_train = splits["X_train"], splits["y_train"]
    X_val,   y_val   = splits["X_val"],   splits["y_val"]
    X_test,  y_test  = splits["X_test"],  splits["y_test"]

    models = build_models()
    fitted = {}
    val_rows, test_rows = [], []

    for name, model in models.items():
        print(f"\n=== {name} ===")
        t0 = time.time()
        model.fit(X_train, y_train)
        fit_time = time.time() - t0
        print(f"  fit: {fit_time:.1f}s")

        # Validation metrics (used for model selection)
        y_val_pred  = model.predict(X_val)
        y_val_proba = model.predict_proba(X_val)[:, 1]
        val_m = compute_metrics(y_val, y_val_pred, y_val_proba)
        val_m["model"] = name
        val_m["fit_sec"] = fit_time
        val_rows.append(val_m)

        # Test metrics (final reporting only)
        y_test_pred  = model.predict(X_test)
        y_test_proba = model.predict_proba(X_test)[:, 1]
        test_m = compute_metrics(y_test, y_test_pred, y_test_proba)
        test_m["model"] = name
        test_rows.append(test_m)

        print(f"  val  ROC-AUC: {val_m['roc_auc']:.4f}  |  test ROC-AUC: {test_m['roc_auc']:.4f}")
        fitted[name] = model

    col_order = ["model", "accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc"]
    val_df  = pd.DataFrame(val_rows)[col_order + ["fit_sec"]]
    test_df = pd.DataFrame(test_rows)[col_order]
    return fitted, val_df, test_df


# ============================================================================
# 5. PLOTS
# ============================================================================
def plot_confusion_matrices(fitted: dict, X_test, y_test, out_path: str) -> None:
    fig, axes = plt.subplots(1, len(fitted), figsize=(4 * len(fitted), 4))
    if len(fitted) == 1:
        axes = [axes]
    for ax, (name, model) in zip(axes, fitted.items()):
        cm = confusion_matrix(y_test, model.predict(X_test))
        im = ax.imshow(cm, cmap="Blues")
        ax.set_title(name)
        ax.set_xticks([0, 1]); ax.set_xticklabels(["Benign", "Malware"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["Benign", "Malware"])
        ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
        for (i, j), v in np.ndenumerate(cm):
            color = "white" if v > cm.max() / 2 else "black"
            ax.text(j, i, str(v), ha="center", va="center", color=color)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out_path}")


def plot_roc_curves(fitted: dict, X_test, y_test, out_path: str) -> None:
    plt.figure(figsize=(7, 6))
    for name, model in fitted.items():
        proba = model.predict_proba(X_test)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, proba)
        auc = roc_auc_score(y_test, proba)
        plt.plot(fpr, tpr, label=f"{name} (AUC={auc:.4f})")
    plt.plot([0, 1], [0, 1], "k--", alpha=0.3, label="Chance")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curves — Test Set")
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"Saved {out_path}")


# ============================================================================
# 6. SHAP — explain the winner
# ============================================================================
def explain_winner(
    winner_name: str,
    winner_model,
    X_train,
    X_test,
    feature_names: list,
    out_path: str,
    sample_size: int = 1000,
) -> None:
    """SHAP summary for the best model. Uses TreeExplainer for tree models
    and LinearExplainer for Logistic Regression."""
    import shap

    # For speed, explain a random subsample of the test set
    rng = np.random.default_rng(0)
    idx = rng.choice(len(X_test), size=min(sample_size, len(X_test)), replace=False)
    X_sample = X_test[idx]

    print(f"\n=== SHAP: explaining {winner_name} ===")
    if winner_name == "LogisticRegression":
        explainer = shap.LinearExplainer(winner_model, X_train)
        shap_values = explainer.shap_values(X_sample)
    else:
        explainer = shap.TreeExplainer(winner_model)
        raw = explainer.shap_values(X_sample)
        # Some tree explainers return a list (one per class) for binary problems
        if isinstance(raw, list):
            shap_values = raw[1]  # positive class (malware)
        elif raw.ndim == 3:
            shap_values = raw[:, :, 1]
        else:
            shap_values = raw

    plt.figure(figsize=(9, 8))
    shap.summary_plot(shap_values, X_sample, feature_names=feature_names,
                      show=False, max_display=20)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"Saved {out_path}")

    # Also print the top features by mean |SHAP|
    importance = np.abs(shap_values).mean(axis=0)
    top = sorted(zip(feature_names, importance), key=lambda x: -x[1])[:15]
    print("\nTop 15 features by mean |SHAP value|:")
    for name, val in top:
        print(f"  {val:+.4f}  {name}")


# ============================================================================
# 7. COLAB ENTRY POINT
# ============================================================================
SPLITS_PATH = "/content/splits.npz"
OUT_DIR     = "/content"

if __name__ == "__main__":
    Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    splits = load_splits(SPLITS_PATH)
    print(f"Train: {splits['X_train'].shape}  Val: {splits['X_val'].shape}  "
          f"Test: {splits['X_test'].shape}")

    fitted, val_df, test_df = train_and_evaluate(splits)

    print("\n" + "=" * 70)
    print("VALIDATION METRICS (used for model selection)")
    print("=" * 70)
    print(val_df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    # Pick winner by validation ROC-AUC
    winner_name = val_df.loc[val_df["roc_auc"].idxmax(), "model"]
    print(f"\n>>> Winner on validation ROC-AUC: {winner_name} <<<")

    print("\n" + "=" * 70)
    print("TEST METRICS (held-out, final reporting)")
    print("=" * 70)
    print(test_df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    # Save metrics tables
    val_df.to_csv(f"{OUT_DIR}/val_metrics.csv", index=False)
    test_df.to_csv(f"{OUT_DIR}/test_metrics.csv", index=False)

    # Plots
    plot_confusion_matrices(fitted, splits["X_test"], splits["y_test"],
                            f"{OUT_DIR}/confusion_matrices.png")
    plot_roc_curves(fitted, splits["X_test"], splits["y_test"],
                    f"{OUT_DIR}/roc_curves.png")

    # SHAP for the winner
    explain_winner(
        winner_name=winner_name,
        winner_model=fitted[winner_name],
        X_train=splits["X_train"],
        X_test=splits["X_test"],
        feature_names=splits["feature_names"],
        out_path=f"{OUT_DIR}/shap_{winner_name}.png",
    )

    # Persist the winning model
    import joblib
    joblib.dump(fitted[winner_name], f"{OUT_DIR}/winner_{winner_name}.joblib")
    print(f"\nWrote {OUT_DIR}/winner_{winner_name}.joblib")
    print("Done.")