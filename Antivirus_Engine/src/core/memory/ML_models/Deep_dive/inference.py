"""
Diagnostics — check for leakage, overfitting, and inflated metrics.

Run AFTER pipeline.py + train.py. Reads /content/splits.npz and optionally
retrains small probes. Produces a leakage_report.txt and plots.

Six diagnostics, in order of suspicion:

  1. Single-feature AUC           — can any single feature already hit ~1.0?
  2. Train vs test gap            — classic overfitting check
  3. Permutation test on labels   — shuffle y_train, does AUC stay high? (should drop to 0.5)
  4. Duplicate / near-duplicate rows across train and test splits
  5. Feature distribution drift   — KS test on every feature, benign vs malware
  6. Held-out-feature probe       — drop the top SHAP feature, retrain, see if AUC collapses
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from scipy.stats import ks_2samp
import matplotlib.pyplot as plt


SPLITS_PATH = "/content/splits.npz"
OUT_DIR     = "/content"


def load():
    d = np.load(SPLITS_PATH, allow_pickle=True)
    return {
        "X_train": d["X_train"], "y_train": d["y_train"],
        "X_val":   d["X_val"],   "y_val":   d["y_val"],
        "X_test":  d["X_test"],  "y_test":  d["y_test"],
        "feature_names": d["feature_names"].tolist(),
    }


# ============================================================================
# DIAGNOSTIC 1 — Single-feature AUC
# ============================================================================
def single_feature_auc(X_train, y_train, X_test, y_test, names):
    """Fit LogReg on each feature alone. If any hits AUC > 0.99, that feature
    is doing all the work — a strong leakage indicator."""
    results = []
    for i, name in enumerate(names):
        xt = X_train[:, [i]]
        xe = X_test[:, [i]]
        # Skip zero-variance features
        if xt.std() < 1e-9:
            continue
        model = LogisticRegression(max_iter=500)
        model.fit(xt, y_train)
        proba = model.predict_proba(xe)[:, 1]
        auc = roc_auc_score(y_test, proba)
        results.append((name, auc))
    df = pd.DataFrame(results, columns=["feature", "auc"]).sort_values("auc", ascending=False)
    return df


# ============================================================================
# DIAGNOSTIC 2 — Train vs test gap
# ============================================================================
def train_test_gap(X_train, y_train, X_test, y_test):
    """Fit a strong but not-too-strong model; compare train and test AUC.
    A gap > ~0.02 usually means overfitting."""
    from sklearn.ensemble import RandomForestClassifier
    model = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=0)
    model.fit(X_train, y_train)
    train_auc = roc_auc_score(y_train, model.predict_proba(X_train)[:, 1])
    test_auc  = roc_auc_score(y_test,  model.predict_proba(X_test)[:,  1])
    return train_auc, test_auc


# ============================================================================
# DIAGNOSTIC 3 — Permutation test on labels
# ============================================================================
def permutation_test(X_train, y_train, X_test, y_test, n_perms=3):
    """Shuffle y_train randomly. If the model can STILL separate, the 'signal'
    is really in the splitting procedure, not in real features.
    Expected AUC under permutation: ~0.5. Anything much above = leakage."""
    rng = np.random.default_rng(0)
    aucs = []
    for _ in range(n_perms):
        y_shuf = rng.permutation(y_train)
        model = LogisticRegression(max_iter=500)
        model.fit(X_train, y_shuf)
        aucs.append(roc_auc_score(y_test, model.predict_proba(X_test)[:, 1]))
    return aucs


# ============================================================================
# DIAGNOSTIC 4 — Cross-split duplicates
# ============================================================================
def duplicate_check(X_train, X_test):
    """Hash each row; count how many test rows have an exact match in train.
    MalMem2022 in particular has repeated captures — a test row that is
    identical to a train row turns evaluation into memorization."""
    # Round to avoid float32 hash noise
    Xt = np.round(X_train, 6)
    Xe = np.round(X_test, 6)
    train_hashes = {hash(row.tobytes()) for row in Xt}
    dups = sum(1 for row in Xe if hash(row.tobytes()) in train_hashes)
    return dups, len(Xe)


# ============================================================================
# DIAGNOSTIC 5 — Feature distribution drift (benign vs malware)
# ============================================================================
def feature_drift(X_train, y_train, names, top_k=10):
    """KS test comparing benign vs malware distribution per feature.
    Huge separations (KS > 0.8) suggest the distributions barely overlap —
    which makes classification trivial but may not reflect a real-world
    deployment where benign and malware processes run on the same machine."""
    benign = X_train[y_train == 0]
    malware = X_train[y_train == 1]
    rows = []
    for i, name in enumerate(names):
        if benign[:, i].std() < 1e-9 and malware[:, i].std() < 1e-9:
            continue
        stat, _ = ks_2samp(benign[:, i], malware[:, i])
        rows.append((name, stat))
    df = pd.DataFrame(rows, columns=["feature", "ks_statistic"]).sort_values(
        "ks_statistic", ascending=False
    )
    return df


# ============================================================================
# DIAGNOSTIC 6 — Held-out-feature probe
# ============================================================================
def holdout_feature_probe(X_train, y_train, X_test, y_test, names, drop_feature):
    """Drop the top-SHAP feature and retrain. If AUC barely moves, the model
    has backups. If AUC collapses, that one feature was carrying the result —
    which is fragile for deployment."""
    idx = names.index(drop_feature)
    keep = [i for i in range(len(names)) if i != idx]
    model = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=0)
    model.fit(X_train[:, keep], y_train)
    auc = roc_auc_score(y_test, model.predict_proba(X_test[:, keep])[:, 1])
    return auc


# ============================================================================
# RUN ALL + REPORT
# ============================================================================
if __name__ == "__main__":
    Path(OUT_DIR).mkdir(parents=True, exist_ok=True)
    splits = load()
    X_train, y_train = splits["X_train"], splits["y_train"]
    X_test,  y_test  = splits["X_test"],  splits["y_test"]
    names = splits["feature_names"]

    report_lines = []
    def log(s): print(s); report_lines.append(s)

    log("=" * 70)
    log("DIAGNOSTIC 1 — Single-feature AUC")
    log("=" * 70)
    sf = single_feature_auc(X_train, y_train, X_test, y_test, names)
    log("Top 10 features by single-feature test AUC:")
    log(sf.head(10).to_string(index=False))
    n_high = (sf["auc"] > 0.99).sum()
    n_very_high = (sf["auc"] > 0.95).sum()
    log(f"\n{n_high} features alone achieve AUC > 0.99")
    log(f"{n_very_high} features alone achieve AUC > 0.95")
    if n_high > 0:
        log(">>> SUSPICIOUS: at least one feature is a near-perfect classifier on its own.")
        log("    This is the #1 leakage signature.")

    log("\n" + "=" * 70)
    log("DIAGNOSTIC 2 — Train vs test AUC gap (overfitting)")
    log("=" * 70)
    train_auc, test_auc = train_test_gap(X_train, y_train, X_test, y_test)
    gap = train_auc - test_auc
    log(f"Train AUC: {train_auc:.4f}")
    log(f"Test  AUC: {test_auc:.4f}")
    log(f"Gap      : {gap:+.4f}")
    if gap > 0.02:
        log(">>> Overfitting: train significantly beats test.")
    elif test_auc > 0.999 and train_auc > 0.999:
        log(">>> Both essentially perfect — problem is too easy or leaked.")

    log("\n" + "=" * 70)
    log("DIAGNOSTIC 3 — Permutation test (labels shuffled)")
    log("=" * 70)
    perm_aucs = permutation_test(X_train, y_train, X_test, y_test)
    log(f"AUCs after shuffling train labels: {[f'{a:.4f}' for a in perm_aucs]}")
    mean_perm = np.mean(perm_aucs)
    log(f"Mean: {mean_perm:.4f}  (expected ~0.5)")
    if abs(mean_perm - 0.5) > 0.1:
        log(">>> SUSPICIOUS: model separates test even when train labels are random.")
        log("    This means train and test rows have structural overlap.")
    else:
        log("    Good: when train labels are random, the model cannot predict test.")

    log("\n" + "=" * 70)
    log("DIAGNOSTIC 4 — Duplicate rows across train/test")
    log("=" * 70)
    dups, n_test = duplicate_check(X_train, X_test)
    log(f"Test rows with exact match in train: {dups}/{n_test} ({100*dups/n_test:.2f}%)")
    if dups > 0:
        log(">>> Duplicates found: test set contains rows the model has seen verbatim.")

    log("\n" + "=" * 70)
    log("DIAGNOSTIC 5 — Feature drift (KS test, benign vs malware)")
    log("=" * 70)
    drift = feature_drift(X_train, y_train, names)
    log("Top 10 features by KS statistic:")
    log(drift.head(10).to_string(index=False))
    n_huge = (drift["ks_statistic"] > 0.8).sum()
    log(f"\n{n_huge} features have KS > 0.8 (distributions barely overlap)")
    if n_huge > 5:
        log(">>> Several features have near-disjoint distributions.")
        log("    Classification is trivial; real deployment will differ.")

    log("\n" + "=" * 70)
    log("DIAGNOSTIC 6 — Drop top feature, see if AUC survives")
    log("=" * 70)
    top_feat = sf.iloc[0]["feature"]
    log(f"Top single-feature classifier: {top_feat} (AUC={sf.iloc[0]['auc']:.4f})")
    auc_without = holdout_feature_probe(X_train, y_train, X_test, y_test, names, top_feat)
    log(f"Test AUC after dropping {top_feat}: {auc_without:.4f}")
    if auc_without < 0.90:
        log(">>> Dropping one feature collapses the model — brittle.")
    else:
        log("    Model has backups; other features still carry signal.")

    # Save report
    with open(f"{OUT_DIR}/leakage_report.txt", "w") as f:
        f.write("\n".join(report_lines))
    log(f"\nFull report saved to {OUT_DIR}/leakage_report.txt")

    # Plot: single-feature AUC distribution
    plt.figure(figsize=(10, 5))
    plt.hist(sf["auc"], bins=50, edgecolor="black")
    plt.axvline(0.95, color="orange", linestyle="--", label="0.95 threshold")
    plt.axvline(0.99, color="red", linestyle="--", label="0.99 (leakage zone)")
    plt.xlabel("Single-feature test AUC")
    plt.ylabel("Number of features")
    plt.title("Distribution of single-feature classifier AUCs")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{OUT_DIR}/single_feature_auc_hist.png", dpi=120, bbox_inches="tight")
    plt.close()
    print(f"Saved {OUT_DIR}/single_feature_auc_hist.png")