# -*- coding: utf-8 -*-
"""
preprocessing_pipeline.py

Mirrors exactly the preprocessing logic used during training (GRU.py):
  - API validation via regex
  - Sequence cleaning (length + repetition-ratio filters)
  - Vocabulary encoding
  - Padding / chunking for fixed-length model input
"""

import re
import numpy as np
from typing import List, Tuple, Dict, Optional

# ──────────────────────────────────────────────
# Constants — must match training-time values
# ──────────────────────────────────────────────
PAD_TOKEN           = "PAD"
PAD_IDX             = 0
MIN_VALID_LEN       = 5          # minimum real API calls needed
MAX_LEN_ALLOWED     = 200        # hard ceiling used during dataset cleaning
MAX_REPETITION_RATIO = 10        # spammy-sequence detector (unique-call ratio)
MAX_LEN             = 177        # fixed model input length (from config.json)
STRIDE              = 100        # sliding-window stride for long sequences


# ──────────────────────────────────────────────
# 1. API-name validation
# ──────────────────────────────────────────────
def is_valid_api(call: str) -> bool:
    """
    Returns True if `call` is a syntactically valid Windows-API name
    (letter or underscore, followed by alphanumeric/underscore).
    PAD tokens are explicitly allowed through.
    """
    if call == PAD_TOKEN:
        return True
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", call))


# ──────────────────────────────────────────────
# 2a. Training-time sequence cleaning
#     (mirrors the dataset-preparation loop in GRU.py)
# ──────────────────────────────────────────────
def validate_and_clean_sequence(
    api_sequence: List[str],
    vocab: Dict[str, int],
) -> Tuple[Optional[List[str]], str]:
    """
    Replicates the per-sample filtering applied during dataset preparation
    (the loop that builds ``clean_rows`` in GRU.py).  Use this when
    rebuilding or auditing the training set — NOT for runtime inference.

    Returns
    -------
    (valid_calls, status)
        valid_calls : list of known, validated API names — None on failure
        status      : "OK" | "EMPTY" | "TOO_SHORT" | "TOO_LONG" | "REPETITION"
    """
    # --- strip blanks / None
    api_sequence = [
        c for c in api_sequence
        if isinstance(c, str) and c.strip() != ""
    ]

    # --- apply regex gate (same applymap used on training DataFrame)
    api_sequence = [c if is_valid_api(c) else PAD_TOKEN for c in api_sequence]

    # --- keep only calls that are in the vocab and are not PAD
    valid_calls = [c for c in api_sequence if c in vocab and c != PAD_TOKEN]

    if len(valid_calls) == 0:
        return None, "EMPTY"

    if len(valid_calls) < MIN_VALID_LEN:
        return None, "TOO_SHORT"

    if len(valid_calls) > MAX_LEN_ALLOWED:
        return None, "TOO_LONG"

    repetition_ratio = len(valid_calls) / len(set(valid_calls))
    if repetition_ratio > MAX_REPETITION_RATIO:
        return None, "REPETITION"

    return valid_calls, "OK"


# ──────────────────────────────────────────────
# 2b. Inference-time sequence cleaning
#     (mirrors the input-validation block inside
#      predict_process() in GRU.py)
# ──────────────────────────────────────────────
def clean_for_inference(
    api_sequence: List[str],
    vocab: Dict[str, int],
) -> Tuple[Optional[List[str]], str]:
    """
    Lightweight cleaning used at runtime:
      1. Drop empty / None entries.
      2. Retain only API names that exist in the vocabulary (unknown calls
         are simply ignored, matching ``vocab.get(call, 0)`` behaviour).
      3. Reject if no valid calls remain, or fewer than MIN_VALID_LEN.

    Repetition-ratio and MAX_LEN_ALLOWED guards are intentionally absent —
    they were training-dataset quality filters, not inference constraints.
    Long sequences are handled by the sliding-window chunker in inference.py.

    Returns
    -------
    (valid_calls, status)
        valid_calls : list of known API names — None on failure
        status      : "OK" | "EMPTY" | "TOO_SHORT"
    """
    # --- strip blanks / None  (matches the first filter in predict_process)
    api_sequence = [
        c for c in api_sequence
        if isinstance(c, str) and c.strip() != ""
    ]

    # --- keep only vocab-known, non-PAD calls
    valid_calls = [c for c in api_sequence if c in vocab and c != PAD_TOKEN]

    if len(valid_calls) == 0:
        return None, "EMPTY"

    if len(valid_calls) < MIN_VALID_LEN:
        return None, "TOO_SHORT"

    return valid_calls, "OK"


# ──────────────────────────────────────────────
# 3. Vocabulary encoding
# ──────────────────────────────────────────────
def encode_sequence(api_sequence: List[str], vocab: Dict[str, int]) -> List[int]:
    """
    Maps API names to integer IDs using the training vocabulary.
    Unknown calls map to PAD_IDX (0), exactly as `vocab.get(call, 0)` in training.
    """
    return [vocab.get(call, PAD_IDX) for call in api_sequence]


# ──────────────────────────────────────────────
# 4. Padding / truncation for single-chunk input
# ──────────────────────────────────────────────
def pad_sequence(
    seq: List[int],
    max_len: int = MAX_LEN,
) -> Tuple[List[int], int]:
    """
    Pads (right) or truncates `seq` to exactly `max_len` tokens.

    Returns (padded_seq, effective_length) where effective_length is the
    number of real (non-pad) tokens, capped at max_len.
    """
    length = min(len(seq), max_len)
    if len(seq) < max_len:
        seq = seq + [PAD_IDX] * (max_len - len(seq))
    else:
        seq = seq[:max_len]
    return seq, length


# ──────────────────────────────────────────────
# 5. Sliding-window chunking for long sequences
# ──────────────────────────────────────────────
def split_sequence(
    seq: List[int],
    max_len: int = MAX_LEN,
    stride: int = STRIDE,
) -> List[List[int]]:
    """
    Splits `seq` into overlapping chunks of length `max_len` with step `stride`.
    Each chunk is right-padded to `max_len` if necessary.

    Replicates the `split_sequence` helper used in inference inside GRU.py.
    """
    chunks = []
    for i in range(0, len(seq), stride):
        chunk = seq[i : i + max_len]
        if len(chunk) < max_len:
            chunk = chunk + [PAD_IDX] * (max_len - len(chunk))
        chunks.append(chunk)
    return chunks


# ──────────────────────────────────────────────
# 6. Full inference pipeline (convenience wrapper)
# ──────────────────────────────────────────────
def preprocess(
    api_sequence: List[str],
    vocab: Dict[str, int],
) -> Dict:
    """
    End-to-end inference preprocessing: clean → encode → ready for model.

    Uses ``clean_for_inference`` (not the stricter training-time filters).

    Returns a dict with:
      "status"        : "OK" | "EMPTY" | "TOO_SHORT"
      "valid_calls"   : cleaned list of API names (None on failure)
      "encoded"       : integer-encoded list (None on failure)
      "needs_chunking": True if len(encoded) > MAX_LEN
    """
    valid_calls, status = clean_for_inference(api_sequence, vocab)
    if status != "OK":
        return {"status": status, "valid_calls": None, "encoded": None, "needs_chunking": False}

    encoded = encode_sequence(valid_calls, vocab)
    return {
        "status": "OK",
        "valid_calls": valid_calls,
        "encoded": encoded,
        "needs_chunking": len(encoded) > MAX_LEN,
    }
