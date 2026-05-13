"""
AegisAI — EMBER2024 ML bridge
==============================
Called by the Rust scanner ONLY when heuristics/YARA already flagged a
file as Suspicious or Malicious.  Selects the correct LightGBM model
based on file content (magic bytes first, extension as fallback).

File-type routing — magic bytes take priority over extension:
  MZ header  → PE file  → Win32 / Win64 / DotNet model
  %PDF       → PDF file → PDF model
  No match   → skipped  (scripts, archives, text, etc.)

This means files like .tmp, .dat, .bin that are actually PE executables
are still scanned; the extension is only used as a last-resort hint
when magic-byte detection is inconclusive.

Real API (thrember v0.1.0):
  thrember.predict_sample(lgbm_model, file_data) -> float
  PEFeatureExtractor: 2568-dim vector (byte histogram, entropy, strings,
  PE header, sections, imports, exports, rich header, authenticode …)
  When pefile.PE() fails (non-PE content), PE sub-features are zeroed and
  byte-level features still run — useful for the PDF model.

Usage:
  python bridge.py <filepath>

Output JSON (success):
  { "file": str, "file_type": str, "score": float, "malicious": bool }

Output JSON (skipped / error):
  { "file": str, "skipped": true, "reason": str }
  { "file": str, "skipped": true, "error":  str }
"""

# ── Venv bootstrap (must run before any third-party imports) ──────────────────
# Rust spawns whichever `python` is on PATH, which is usually the system Python
# without thrember/lightgbm.  This block detects that situation and re-launches
# the script under the project venv — no rebuild required.
import sys as _sys, os as _os, subprocess as _sp

_SCRIPT   = _os.path.abspath(__file__)
_SCRIPT_DIR = _os.path.dirname(_SCRIPT)

# Walk up:  Ember2024/ → file_system/ → core/ → src/ → Antivirus_Engine/ → AegisAI/
_AEGIS_ROOT = _SCRIPT_DIR
for _ in range(5):
    _AEGIS_ROOT = _os.path.dirname(_AEGIS_ROOT)

_VENV_PYTHON = _os.path.join(_AEGIS_ROOT, "ai_agent", ".venv", "Scripts", "python.exe")

# Only re-launch if the venv exists AND we are not already running inside it
if (
    _os.path.exists(_VENV_PYTHON)
    and _os.path.normcase(_sys.executable) != _os.path.normcase(_VENV_PYTHON)
):
    _r = _sp.run([_VENV_PYTHON, _SCRIPT] + _sys.argv[1:], capture_output=True, text=True)
    _sys.stdout.write(_r.stdout)
    _sys.exit(_r.returncode)

# ─────────────────────────────────────────────────────────────────────────────

import warnings
warnings.filterwarnings("ignore")

import sys
import os
import json
import struct

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(SCRIPT_DIR, "Models")

_MODEL_FILES = {
    "Win32":  "EMBER2024_Win32.model",
    "Win64":  "EMBER2024_Win64.model",
    "DotNet": "EMBER2024_Dot_Net.model",
    "PDF":    "EMBER2024_PDF.model",
    # Catch-all: used for any file that is neither PE nor PDF.
    # PEFeatureExtractor handles non-PE gracefully — PE sub-features zero out,
    # byte histogram + entropy + strings still run giving useful signal for
    # scripts, archives, and other file types.
    "All":    "EMBER2024_all.model",
}

# ── Load models once at startup ───────────────────────────────────────────────

def _load_models():
    try:
        import lightgbm as lgb
        return {
            key: lgb.Booster(model_file=os.path.join(MODELS_DIR, fname))
            for key, fname in _MODEL_FILES.items()
        }
    except Exception as exc:
        return {"_load_error": str(exc)}

MODELS = _load_models()

# ── Magic-byte detection ──────────────────────────────────────────────────────

_MZ  = b"MZ"
_PDF = b"%PDF"

def _is_pe(data: bytes) -> bool:
    """True when the file starts with the MZ DOS stub."""
    return len(data) >= 2 and data[:2] == _MZ

def _is_pdf(data: bytes) -> bool:
    """True when the file starts with the %PDF signature."""
    return len(data) >= 4 and data[:4] == _PDF

# ── PE header helpers ─────────────────────────────────────────────────────────

_MACHINE_AMD64 = 0x8664
_MACHINE_IA64  = 0x0200
_MACHINE_ARM64 = 0xAA64

def _pe_machine(data: bytes) -> int:
    """Return the COFF Machine field, or 0 on failure."""
    try:
        pe_offset = struct.unpack_from("<I", data, 60)[0]
        if pe_offset + 6 > len(data):
            return 0
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return 0
        return struct.unpack_from("<H", data, pe_offset + 4)[0]
    except Exception:
        return 0

def _has_clr_header(data: bytes) -> bool:
    """True when the PE optional header contains a non-empty CLR data directory."""
    try:
        pe_offset  = struct.unpack_from("<I", data, 60)[0]
        opt_offset = pe_offset + 24
        if opt_offset + 2 > len(data):
            return False
        magic = struct.unpack_from("<H", data, opt_offset)[0]
        if magic == 0x10B:        # PE32
            dd_offset = opt_offset + 96
        elif magic == 0x20B:      # PE32+
            dd_offset = opt_offset + 112
        else:
            return False
        clr_offset = dd_offset + 14 * 8
        if clr_offset + 8 > len(data):
            return False
        clr_rva, clr_size = struct.unpack_from("<II", data, clr_offset)
        return clr_rva != 0 and clr_size != 0
    except Exception:
        return False

def _detect_pe_model(data: bytes) -> str:
    """
    Choose Win32 / Win64 / DotNet based on PE header fields.

    Priority:
      1. CLR data directory present → DotNet
      2. COFF Machine field         → Win64 (AMD64/IA64/ARM64) or Win32
      3. Fallback                   → Win32
    """
    if _has_clr_header(data):
        return "DotNet"
    machine = _pe_machine(data)
    if machine in (_MACHINE_AMD64, _MACHINE_IA64, _MACHINE_ARM64):
        return "Win64"
    return "Win32"

# ── Content-type routing ──────────────────────────────────────────────────────

# Extensions that are almost certainly PE regardless of magic bytes
# (used only when the file is too small to read magic bytes reliably)
_PE_EXTENSIONS  = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".scr",
    ".cpl", ".com", ".pif", ".mui", ".efi",
}
_PDF_EXTENSIONS = {".pdf"}

def _route(data: bytes, ext: str) -> str:
    """
    Return the model family: 'PE', 'PDF', or 'All'.

    Magic bytes take full priority — a .tmp that starts with MZ is a PE;
    a .pdf that starts with MZ is a PE-wrapped dropper and gets the PE model.
    Extension is a fallback for very small or truncated files.
    Anything unrecognised falls through to 'All' — the catch-all model scores
    every file type via byte-level features (histogram, entropy, strings).
    """
    if len(data) >= 4:
        if _is_pe(data):
            return "PE"
        if _is_pdf(data):
            return "PDF"
        # No recognised magic — use the catch-all model
        return "All"

    # Tiny file: trust extension, then fall through to All
    if ext in _PE_EXTENSIONS:
        return "PE"
    if ext in _PDF_EXTENSIONS:
        return "PDF"
    return "All"

# ── Main scan function ────────────────────────────────────────────────────────

def scan_file(filepath: str) -> dict:
    if "_load_error" in MODELS:
        return {"file": filepath, "skipped": True, "error": MODELS["_load_error"]}

    try:
        from thrember import predict_sample

        with open(filepath, "rb") as fh:
            data = fh.read()

        ext    = os.path.splitext(filepath)[1].lower()
        family = _route(data, ext)

        if family == "PDF":
            model_key = "PDF"
        elif family == "PE":
            model_key = _detect_pe_model(data)
        else:  # "All" — catch-all for scripts, archives, and anything else
            model_key = "All"

        model = MODELS.get(model_key)
        if model is None:
            return {"file": filepath, "skipped": True, "reason": f"no_model_{model_key}"}

        score = float(predict_sample(model, data))

        return {
            "file":      filepath,
            "file_type": model_key,
            "score":     round(score, 6),
            "malicious": score >= 0.8,
        }

    except Exception as exc:
        return {"file": filepath, "skipped": True, "error": str(exc)}

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: bridge.py <filepath>"}))
        sys.exit(1)

    result = scan_file(sys.argv[1])
    print(json.dumps(result))
