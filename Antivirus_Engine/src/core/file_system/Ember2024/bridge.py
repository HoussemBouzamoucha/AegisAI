"""
AegisAI — EMBER2024 ML bridge
==============================
Called by the Rust scanner ONLY when heuristics/YARA already flagged a
file as Suspicious or Malicious.  Selects the correct LightGBM model
based on file content (magic bytes first, extension as fallback).

File-type routing — magic bytes take priority over extension:

  Magic / trigger              Model          Extensions
  ─────────────────────────────────────────────────────────────────────────
  MZ + CLR header              DotNet         .exe .dll
  MZ + entropy > 7.2           packer         .exe .dll .sys .scr
  MZ + 64-bit COFF             Win64          .exe .dll .sys .drv .efi
  MZ + 32-bit COFF             Win32          .exe .dll .sys .drv .ocx
                                              .scr .cpl .com .pif .efi
  MZ + unknown arch            PE             .exe .dll .sys
  \\x7fELF magic               ELF            .elf .so .out .bin
  PK\\x03\\x04 + .apk/.xapk   APK            .apk .xapk
  PK\\x03\\x04 + Office XML    exploit        .docx .xlsx .pptx .odt .ods
  \\xD0\\xCF\\x11\\xE0 (OLE2) exploit        .doc .xls .ppt .msg .vsd
  {\\rtf / %RTF                exploit        .rtf
  %PDF                         PDF            .pdf
  Script extension             behavior       .js .vbs .ps1 .bat .cmd
                                              .sh .hta .wsf
  .msi/.cab extension          family         .msi .cab .msp .msix
  LNK magic / .lnk             group          .lnk .url .scf
  Archive extension            file_property  .zip .rar .7z .tar .gz
                                              .bz2 .xz .iso .img
  Anything else                All            *

Real API (thrember v0.1.0):
  thrember.predict_sample(lgbm_model, file_data) -> float
  PEFeatureExtractor: 2568-dim vector (byte histogram, entropy, strings,
  PE header, sections, imports, exports, rich header, authenticode …)
  When pefile.PE() fails (non-PE content), PE sub-features are zeroed and
  byte-level features still run — useful for non-PE models.

Usage:
  python bridge.py <filepath>
  python bridge.py --batch <f1> <f2> …
  python bridge.py --server

Output JSON (success):
  { "file": str, "file_type": str, "score": float, "malicious": bool }

Output JSON (skipped / error):
  { "file": str, "skipped": true, "reason": str }
  { "file": str, "skipped": true, "error":  str }
"""

# ── Venv bootstrap (must run before any third-party imports) ──────────────────
import sys as _sys, os as _os, subprocess as _sp

_SCRIPT     = _os.path.abspath(__file__)
_SCRIPT_DIR = _os.path.dirname(_SCRIPT)

# Walk up: Ember2024/ → file_system/ → core/ → src/ → Antivirus_Engine/ → AegisAI/
_AEGIS_ROOT = _SCRIPT_DIR
for _ in range(5):
    _AEGIS_ROOT = _os.path.dirname(_AEGIS_ROOT)

_VENV_PYTHON = _os.path.join(_AEGIS_ROOT, "ai_agent", ".venv", "Scripts", "python.exe")

if (
    _os.path.exists(_VENV_PYTHON)
    and _os.path.normcase(_sys.executable) != _os.path.normcase(_VENV_PYTHON)
):
    if "--server" in _sys.argv[1:]:
        _sys.exit(_sp.run([_VENV_PYTHON, _SCRIPT] + _sys.argv[1:]).returncode)
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
import math

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(SCRIPT_DIR, "Models")

_MODEL_FILES = {
    # ── Windows PE variants ───────────────────────────────────────────────────
    "Win32":         "EMBER2024_Win32.model",      # 32-bit PE executables
    "Win64":         "EMBER2024_Win64.model",      # 64-bit PE executables
    "DotNet":        "EMBER2024_Dot_Net.model",    # .NET managed assemblies
    "PE":            "EMBER2024_PE.model",         # generic PE fallback
    # ── Specialized PE analysis ───────────────────────────────────────────────
    "packer":        "EMBER2024_packer.model",     # packed / crypted PE (high entropy)
    "behavior":      "EMBER2024_behavior.model",   # script / behavioural-proxy files
    "family":        "EMBER2024_family.model",     # Windows installer packages
    "group":         "EMBER2024_group.model",      # LNK / shortcut / dropper files
    "file_property": "EMBER2024_file_property.model",  # archives (property-level features)
    # ── Documents ─────────────────────────────────────────────────────────────
    "PDF":           "EMBER2024_PDF.model",        # PDF documents
    "exploit":       "EMBER2024_exploit.model",    # OLE2 / Office XML / RTF
    # ── Linux / Android ───────────────────────────────────────────────────────
    "ELF":           "EMBER2024_ELF.model",        # Linux / Unix ELF binaries
    "APK":           "EMBER2024_APK.model",        # Android APK packages
    # ── Catch-all ─────────────────────────────────────────────────────────────
    "All":           "EMBER2024_all.model",        # anything unrecognised
}

# ── Ensemble wrapper ──────────────────────────────────────────────────────────

class _EnsembleBooster:
    """
    Wraps a list of LightGBM Boosters (cross-validation ensemble) so that
    `thrember.predict_sample` can call `.predict()` on it like a single model.
    Predictions are averaged across all boosters.
    """
    def __init__(self, boosters: list):
        self._boosters = boosters

    def predict(self, data, **kwargs):
        import numpy as np
        preds = [b.predict(data, **kwargs) for b in self._boosters]
        return np.mean(preds, axis=0)


def _load_one_model(lgb, path: str):
    """
    Load a single model file in either native LightGBM text format or pickle.

    Native format  → starts with b'tree' → lgb.Booster(model_file=path)
    Pickle format  → starts with 0x80   → pickle.load()
      • If the pickle contains a single Booster  → return it directly
      • If the pickle contains a list of Boosters → return _EnsembleBooster
    """
    with open(path, "rb") as fh:
        header = fh.read(1)

    if header != b"\x80":
        # Native LightGBM text format
        return lgb.Booster(model_file=path)

    # Pickle format
    import pickle
    with open(path, "rb") as fh:
        obj = pickle.load(fh)

    if isinstance(obj, lgb.Booster):
        return obj

    if isinstance(obj, list) and obj and isinstance(obj[0], lgb.Booster):
        return _EnsembleBooster(obj)

    raise ValueError(f"unrecognised pickle payload: {type(obj)}")


# ── Load models once at startup ───────────────────────────────────────────────

def _load_models():
    try:
        import lightgbm as lgb
        loaded, failed = {}, []
        for key, fname in _MODEL_FILES.items():
            path = os.path.join(MODELS_DIR, fname)
            if os.path.exists(path):
                try:
                    loaded[key] = _load_one_model(lgb, path)
                    if isinstance(loaded[key], _EnsembleBooster):
                        import sys as _s
                        _s.stderr.write(
                            f"bridge: {key} loaded as ensemble "
                            f"({len(loaded[key]._boosters)} boosters)\n"
                        )
                except Exception as exc:
                    failed.append(f"{key}: {exc}")
            else:
                failed.append(f"{key}: file_not_found ({fname})")
        if failed:
            import sys as _s
            _s.stderr.write(f"bridge: skipped models — {'; '.join(failed)}\n")
        if not loaded:
            return {"_load_error": "no models could be loaded"}
        return loaded
    except Exception as exc:
        return {"_load_error": str(exc)}

MODELS = _load_models()

# ── Magic byte constants ──────────────────────────────────────────────────────

_MZ     = b"MZ"                          # Windows PE / DOS stub
_ELF    = b"\x7fELF"                     # Linux / Unix ELF
_PDF    = b"%PDF"                        # PDF document
_ZIP    = b"PK\x03\x04"                  # ZIP (APK, Office Open XML)
_OLE2   = b"\xD0\xCF\x11\xE0"           # OLE2 Compound Document (legacy Office)
_RTF_L  = b"{\\rtf"                      # RTF lower-case
_RTF_U  = b"%RTF"                        # RTF upper-case variant
_LNK    = b"\x4C\x00\x00\x00"           # MS Shell Link (LNK)

# ── Extension sets ────────────────────────────────────────────────────────────

_EXT_SCRIPT = {
    ".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh", ".hta", ".wsf",
}
_EXT_INSTALLER = {
    ".msi", ".cab", ".msp", ".msix",
}
_EXT_LNK = {
    ".lnk", ".url", ".scf",
}
_EXT_ARCHIVE = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".img",
}
_EXT_APK = {
    ".apk", ".xapk",
}
_EXT_OFFICE_XML = {
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
}
_EXT_PE = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".scr",
    ".cpl", ".com", ".pif", ".mui", ".efi",
}

# ── Entropy helper ────────────────────────────────────────────────────────────

_PACKER_ENTROPY_THRESHOLD = 7.2

def _file_entropy(data: bytes) -> float:
    """Shannon entropy over the full file content (bits per byte, 0–8)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)

# ── PE header helpers ─────────────────────────────────────────────────────────

_MACHINE_AMD64 = 0x8664
_MACHINE_IA64  = 0x0200
_MACHINE_ARM64 = 0xAA64

def _pe_machine(data: bytes) -> int:
    """Return the COFF Machine field, or 0 on parse failure."""
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

def _route_pe(data: bytes) -> str:
    """
    Select among DotNet / packer / Win64 / Win32 / PE for an MZ file.

    Priority:
      1. CLR data directory present            → DotNet
      2. File entropy > 7.2                    → packer
      3. COFF Machine = AMD64 / IA64 / ARM64   → Win64
      4. COFF Machine = anything else (x86 …) → Win32
      5. COFF parse failed                     → PE  (generic fallback)
    """
    if _has_clr_header(data):
        return "DotNet"
    if _file_entropy(data) > _PACKER_ENTROPY_THRESHOLD:
        return "packer"
    machine = _pe_machine(data)
    if machine == 0:
        return "PE"
    if machine in (_MACHINE_AMD64, _MACHINE_IA64, _MACHINE_ARM64):
        return "Win64"
    return "Win32"

# ── Content-type routing ──────────────────────────────────────────────────────

def _route(data: bytes, ext: str) -> str:
    """
    Return a model key for the file.  Magic bytes always take priority;
    extension is used only when the file is too small or has no clear magic.

    Routing table (first match wins):
      MZ  magic                 → _route_pe()  (DotNet / packer / Win64 / Win32 / PE)
      ELF magic                 → ELF
      ZIP magic + APK ext       → APK
      ZIP magic + Office XML ext→ exploit
      OLE2 magic                → exploit
      RTF header                → exploit
      %PDF magic                → PDF
      script extension          → behavior
      installer extension       → family
      LNK magic / extension     → group
      archive extension         → file_property
      fallback                  → All
    """
    head4 = data[:4] if len(data) >= 4 else b""
    head2 = data[:2] if len(data) >= 2 else b""

    # ── Magic-byte branch ─────────────────────────────────────────────────────
    if head2 == _MZ:
        return _route_pe(data)

    if head4 == _ELF:
        return "ELF"

    if head4 == _ZIP:
        if ext in _EXT_APK:
            return "APK"
        if ext in _EXT_OFFICE_XML:
            return "exploit"
        # ZIP with unknown extension — fall through to extension checks below
        if ext in _EXT_ARCHIVE:
            return "file_property"
        return "All"

    if head4 == _OLE2:
        return "exploit"

    if data[:5] in (_RTF_L, b"%RTF-") or data[:4] == _RTF_U[:4]:
        return "exploit"

    if head4 == _PDF[:4] and data[:4] == b"%PDF":
        return "PDF"

    if head4 == _LNK:
        return "group"

    # ── Extension fallback ────────────────────────────────────────────────────
    if ext in _EXT_SCRIPT:
        return "behavior"
    if ext in _EXT_INSTALLER:
        return "family"
    if ext in _EXT_LNK:
        return "group"
    if ext in _EXT_ARCHIVE:
        return "file_property"
    if ext in _EXT_APK:
        return "APK"
    if ext in _EXT_OFFICE_XML:
        return "exploit"
    if ext in _EXT_PE:
        # Tiny / truncated PE-extension file with no readable MZ header
        return "Win32"

    return "All"

# ── Main scan function ────────────────────────────────────────────────────────

def scan_file(filepath: str) -> dict:
    if "_load_error" in MODELS:
        return {"file": filepath, "skipped": True, "error": MODELS["_load_error"]}

    try:
        from thrember import predict_sample

        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            return {"file": filepath, "skipped": True, "skip_reason": "file_unavailable",
                    "error": str(exc)}

        if not data:
            return {"file": filepath, "file_type": "empty", "score": 0.0, "malicious": False}

        ext       = os.path.splitext(filepath)[1].lower()
        model_key = _route(data, ext)

        model = MODELS.get(model_key)
        if model is None:
            # Requested model didn't load — try the catch-all
            model = MODELS.get("All")
            if model is None:
                return {"file": filepath, "skipped": True, "skip_reason": "no_model",
                        "error": f"no_model_{model_key}"}
            model_key = "All"

        score = float(predict_sample(model, data))

        return {
            "file":      filepath,
            "file_type": model_key,
            "score":     round(score, 6),
            "malicious": score >= 0.8,
        }

    except Exception as exc:
        return {"file": filepath, "skipped": True, "skip_reason": "prediction_error",
                "error": str(exc)}

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: bridge.py <filepath> | --batch <f1> … | --server"}))
        sys.exit(1)

    if sys.argv[1] == "--server":
        sys.stderr.write("bridge: server ready\n")
        sys.stderr.flush()
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            filepath = line.rstrip("\n").rstrip("\r")
            if not filepath:
                continue
            result = scan_file(filepath)
            sys.stdout.write(json.dumps(result) + "\n")
            sys.stdout.flush()

    elif sys.argv[1] == "--batch":
        paths   = sys.argv[2:]
        results = [scan_file(p) for p in paths]
        print(json.dumps(results))

    else:
        result = scan_file(sys.argv[1])
        print(json.dumps(result))
