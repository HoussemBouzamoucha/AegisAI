# -*- coding: utf-8 -*-
"""
inference.py

Loads the trained GRU-Attention model + vocabulary from GRU_API/ and
exposes `predict_process()` for runtime malware classification.

Architecture and inference logic mirror GRU.py exactly:
  - GRUAttentionModel  (Embedding → GRU → masked Attention → FC)
  - Single-chunk inference for short sequences
  - Sliding-window (STRIDE=100) for long sequences, pick highest-prob chunk
  - Attention weights → top-10 "trigger" API calls for explainability
"""

import os
import json
import pickle
import numpy as np
import torch
import torch.nn as nn
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence
from typing import List, Dict, Any

from preprocessing_pipeline import (
    preprocess,
    pad_sequence,
    split_sequence,
    PAD_IDX,
    MAX_LEN,
    STRIDE,
    MIN_VALID_LEN,
)

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────
_HERE     = os.path.dirname(os.path.abspath(__file__))
_API_DIR  = os.path.join(_HERE, "GRU_API")
_MODEL_PATH = os.path.join(_API_DIR, "gru_attention_model.pth")
_VOCAB_PATH = os.path.join(_API_DIR, "vocab.pkl")
_CONFIG_PATH = os.path.join(_API_DIR, "config.json")


# ──────────────────────────────────────────────
# 1. Model definition  (must match training exactly)
# ──────────────────────────────────────────────
class GRUAttentionModel(nn.Module):
    def __init__(self, vocab_size: int, embed_dim: int = 64, hidden_dim: int = 128):
        super().__init__()
        self.embedding  = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.gru        = nn.GRU(embed_dim, hidden_dim, batch_first=True)
        self.attention  = nn.Linear(hidden_dim, 1)
        self.dropout    = nn.Dropout(0.3)
        self.fc         = nn.Linear(hidden_dim, 1)

    def forward(self, x: torch.Tensor, lengths: torch.Tensor):
        x_embed = self.embedding(x)

        packed = pack_padded_sequence(
            x_embed, lengths.cpu(), batch_first=True, enforce_sorted=False
        )
        packed_out, _ = self.gru(packed)
        output, _     = pad_packed_sequence(packed_out, batch_first=True)

        attn_scores = self.attention(output).squeeze(-1)

        max_len = output.size(1)
        mask = (
            torch.arange(max_len, device=lengths.device)
            .expand(len(lengths), max_len) < lengths.unsqueeze(1)
        )
        attn_scores[~mask] = -1e9
        attn_weights = torch.softmax(attn_scores, dim=1)

        context = torch.sum(output * attn_weights.unsqueeze(-1), dim=1)
        context = self.dropout(context)
        logits  = self.fc(context).squeeze(1)

        return logits, attn_weights


# ──────────────────────────────────────────────
# 2. Load artefacts (lazy singleton)
# ──────────────────────────────────────────────
_model:  GRUAttentionModel | None = None
_vocab:  dict               | None = None
_device: torch.device       | None = None


def _load_artefacts() -> tuple[GRUAttentionModel, dict, torch.device]:
    """Load model + vocab once and cache them in module-level globals."""
    global _model, _vocab, _device

    if _model is not None:
        return _model, _vocab, _device

    # --- config
    with open(_CONFIG_PATH, "r") as f:
        cfg = json.load(f)

    vocab_size = cfg["vocab_size"]
    embed_dim  = cfg["embed_dim"]
    hidden_dim = cfg["hidden_dim"]

    # --- vocabulary
    with open(_VOCAB_PATH, "rb") as f:
        _vocab = pickle.load(f)

    # --- model
    _device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    _model  = GRUAttentionModel(vocab_size, embed_dim, hidden_dim).to(_device)
    _model.load_state_dict(
        torch.load(_MODEL_PATH, map_location=_device, weights_only=True)
    )
    _model.eval()

    return _model, _vocab, _device


# ──────────────────────────────────────────────
# 3. Single-chunk prediction helper
# ──────────────────────────────────────────────
def _predict_with_attention(
    seq_encoded: List[int],
    model: GRUAttentionModel,
    device: torch.device,
) -> tuple[float, np.ndarray]:
    """
    Run one forward pass on a single (already encoded) sequence.

    Returns (probability, attention_weights_array).
    Safety: returns (0.0, zeros) for all-zero input to avoid degenerate output.
    """
    seq_padded, length = pad_sequence(seq_encoded, MAX_LEN)

    if sum(seq_padded) == 0:
        return 0.0, np.zeros(MAX_LEN)

    X       = torch.tensor([seq_padded], dtype=torch.long).to(device)
    lengths = torch.tensor([length],     dtype=torch.long).to(device)

    with torch.no_grad():
        logits, attn = model(X, lengths)
        prob = torch.sigmoid(logits).item()

    return prob, attn.squeeze().cpu().numpy()


# ──────────────────────────────────────────────
# 4. Public inference entry-point
# ──────────────────────────────────────────────
def predict_process(
    api_sequence: List[str],
    threshold: float = 0.55,
) -> Dict[str, Any]:
    """
    Classify a process by its sequence of Windows API calls.

    Parameters
    ----------
    api_sequence : list[str]
        Raw API call names captured at runtime (order matters).
    threshold : float
        Decision boundary for MALWARE label (default 0.55).

    Returns
    -------
    dict with keys:
        probability   – sigmoid score in [0, 1]
        label         – 1 = malware, 0 = benign
        verdict       – "MALWARE" | "BENIGN" | "UNKNOWN"
        reason        – human-readable explanation (set on UNKNOWN)
        trigger_chunk – chunk index with the highest maliciousness score
        top_api_calls – list of (api_name, attention_weight) for top-10 triggers
    """
    model, vocab, device = _load_artefacts()

    # ── Preprocessing ──────────────────────────────────────────────
    result = preprocess(api_sequence, vocab)

    if result["status"] == "EMPTY":
        return _unknown("Empty or invalid API sequence")
    if result["status"] == "TOO_SHORT":
        return _unknown(f"Too few valid API calls (need ≥ {MIN_VALID_LEN})")

    valid_calls = result["valid_calls"]
    seq_encoded = result["encoded"]

    # ── Inference ──────────────────────────────────────────────────
    if not result["needs_chunking"]:
        # Short path: single forward pass
        prob, best_attn = _predict_with_attention(seq_encoded, model, device)
        best_chunk = 0
        start_idx  = 0
    else:
        # Long path: sliding-window, pick highest-prob chunk
        chunks  = split_sequence(seq_encoded, MAX_LEN, STRIDE)
        results = []
        for i, chunk in enumerate(chunks):
            prob_i, attn_i = _predict_with_attention(chunk, model, device)
            results.append((i, prob_i, attn_i))

        best_chunk, prob, best_attn = max(results, key=lambda t: t[1])
        start_idx = best_chunk * STRIDE

    # ── Attention → top API calls ──────────────────────────────────
    chunk_calls    = valid_calls[start_idx : start_idx + MAX_LEN]
    important_calls = sorted(
        zip(chunk_calls, best_attn[: len(chunk_calls)]),
        key=lambda t: t[1],
        reverse=True,
    )[:10]

    return {
        "probability":   round(float(prob), 6),
        "label":         int(prob > threshold),
        "verdict":       "MALWARE" if prob > threshold else "BENIGN",
        "reason":        None,
        "trigger_chunk": int(best_chunk),
        "top_api_calls": [(api, float(w)) for api, w in important_calls],
    }


def _unknown(reason: str) -> Dict[str, Any]:
    return {
        "probability":   0.0,
        "label":         0,
        "verdict":       "UNKNOWN",
        "reason":        reason,
        "trigger_chunk": None,
        "top_api_calls": [],
    }
