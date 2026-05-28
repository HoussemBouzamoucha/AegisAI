"""
AegisAI — GRU-Attention process ML bridge
==========================================
Feeds a process executable's PE import table into the GRU-Attention model
that was trained on Windows API call sequences.

Since live ETW-based API capture is not yet active, the PE import table is
the best static approximation we have.  Unrecognised imports (not in the
GRU vocabulary) are silently discarded.  The remaining known-API list is
passed to predict_process() as if they were an observed call sequence.

Note on accuracy: the GRU model was trained on ordered call sequences, so
static imports are a structural approximation.  Results should be interpreted
as "this executable exposes capabilities consistent with malware behaviour"
rather than "this process was observed calling these APIs in this order".

Usage
-----
  python process_bridge.py <exe_path>
  python process_bridge.py --batch <exe1> <exe2> ...
  python process_bridge.py --server          # persistent stdin/stdout server

Output JSON (success):
  { "exe_path": str, "probability": float, "verdict": str, "label": int,
    "top_api_calls": [[name, weight], ...], "trigger_chunk": int|null,
    "api_count": int, "source": "pe_imports" }

Output JSON (skipped / error):
  { "exe_path": str, "skipped": true, "reason": str }
"""

# ── Venv bootstrap ─────────────────────────────────────────────────────────────
import sys as _sys, os as _os, subprocess as _sp

_SCRIPT     = _os.path.abspath(__file__)
_SCRIPT_DIR = _os.path.dirname(_SCRIPT)

# Walk up: Sys_API/ → process/ → core/ → src/ → Antivirus_Engine/ → AegisAI/
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

# ── Imports ────────────────────────────────────────────────────────────────────

import json
import struct

# inference.py + preprocessing_pipeline.py are in the same directory
_sys.path.insert(0, _SCRIPT_DIR)

_IMPORT_ERROR: str | None = None
try:
    from inference import predict_process  # noqa: E402
except ImportError as _ie:
    _IMPORT_ERROR = f"dependency_missing: {_ie}"
    predict_process = None  # type: ignore[assignment]  # noqa: F841

# ── PE import-table parser ─────────────────────────────────────────────────────

def _rva_to_offset(rva: int, sections: list) -> int | None:
    """Convert a Relative Virtual Address to a raw file offset."""
    for (va, vsz, roff, rsz) in sections:
        span = max(vsz, rsz, 1)
        if va <= rva < va + span:
            off = roff + (rva - va)
            return off
    return None


def extract_pe_imports(data: bytes) -> list[str]:
    """
    Parse the PE import directory table and return a flat list of imported
    function names (ordinal-only imports are skipped).

    Returns an empty list for non-PE files or on any parse error.
    Uses only the Python standard-library struct module — no external deps.
    """
    if len(data) < 64 or data[:2] != b"MZ":
        return []

    try:
        pe_off = struct.unpack_from("<I", data, 60)[0]
        if pe_off + 24 > len(data):
            return []
        if data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return []

        num_sections    = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_hdr_size    = struct.unpack_from("<H", data, pe_off + 20)[0]
        opt_off         = pe_off + 24

        if opt_off + 2 > len(data):
            return []
        magic = struct.unpack_from("<H", data, opt_off)[0]

        # Data-directory base
        if magic == 0x10B:       # PE32
            dd_base = opt_off + 96
        elif magic == 0x20B:     # PE32+
            dd_base = opt_off + 112
        else:
            return []

        if dd_base + 16 > len(data):
            return []

        import_rva = struct.unpack_from("<I", data, dd_base + 8)[0]
        if import_rva == 0:
            return []

        # Section table
        # IMAGE_SECTION_HEADER: Name(8) VirtualSize(4) VirtualAddress(4)
        #                       SizeOfRawData(4) PointerToRawData(4) ...
        sec_base = pe_off + 24 + opt_hdr_size
        sections = []
        for i in range(num_sections):
            s = sec_base + i * 40
            if s + 40 > len(data):
                break
            va   = struct.unpack_from("<I", data, s + 12)[0]
            vsz  = struct.unpack_from("<I", data, s + 16)[0]
            roff = struct.unpack_from("<I", data, s + 20)[0]
            rsz  = struct.unpack_from("<I", data, s + 24)[0]  # SizeOfRawData at +16; PointerToRawData at +20
            # Correct offsets per PECOFF spec:
            # +8  Name(8 bytes already consumed above)
            # +12 VirtualAddress
            # +16 SizeOfRawData
            # +20 PointerToRawData
            rsz  = struct.unpack_from("<I", data, s + 16)[0]
            roff = struct.unpack_from("<I", data, s + 20)[0]
            sections.append((va, vsz, roff, rsz))

        # Parse IMAGE_IMPORT_DESCRIPTOR array (20 bytes each):
        # OriginalFirstThunk(4) TimeDateStamp(4) ForwarderChain(4) Name(4) FirstThunk(4)
        ptr_size     = 8 if magic == 0x20B else 4
        ordinal_flag = (1 << 63) if ptr_size == 8 else (1 << 31)

        imported = []
        desc_off = _rva_to_offset(import_rva, sections)
        if desc_off is None:
            return []

        while desc_off + 20 <= len(data):
            oft = struct.unpack_from("<I", data, desc_off)[0]       # OriginalFirstThunk
            nrv = struct.unpack_from("<I", data, desc_off + 12)[0]  # Name RVA
            ft  = struct.unpack_from("<I", data, desc_off + 16)[0]  # FirstThunk
            desc_off += 20

            if oft == 0 and nrv == 0 and ft == 0:
                break   # sentinel

            # Walk the INT (prefer OriginalFirstThunk) or IAT
            thunk_rva = oft if oft != 0 else ft
            thunk_off = _rva_to_offset(thunk_rva, sections)
            if thunk_off is None:
                continue

            while thunk_off + ptr_size <= len(data):
                if ptr_size == 4:
                    entry = struct.unpack_from("<I", data, thunk_off)[0]
                else:
                    entry = struct.unpack_from("<Q", data, thunk_off)[0]
                thunk_off += ptr_size

                if entry == 0:
                    break
                if entry & ordinal_flag:
                    continue   # ordinal import — no name

                # RVA to IMAGE_IMPORT_BY_NAME { Hint(2), Name(…) }
                ibn_rva = int(entry & (0x7FFFFFFF if ptr_size == 4 else 0x7FFFFFFFFFFFFFFF))
                ibn_off = _rva_to_offset(ibn_rva, sections)
                if ibn_off is None or ibn_off + 2 >= len(data):
                    continue

                name_start = ibn_off + 2
                name_end   = data.find(b"\x00", name_start)
                if name_end == -1 or name_end - name_start > 128:
                    continue

                try:
                    func = data[name_start:name_end].decode("ascii", errors="ignore").strip()
                    if func:
                        imported.append(func)
                except Exception:
                    pass

        return imported

    except Exception:
        return []


# ── Known-safe whitelist ───────────────────────────────────────────────────────
# Executables whose PE import table reliably triggers GRU false positives because
# they legitimately import the same security/process APIs as malware (antivirus
# engines, debuggers, browsers, runtimes).
#
# Format: { exe_name_lower: path_keyword_lower | None }
#   - path_keyword: substring the exe_path must contain (case-insensitive).
#     Use None to match by name alone (only for executables with globally unique
#     names where path verification adds no security benefit).
#
# This whitelist is intentionally narrow.  A process only bypasses GRU if BOTH
# its name AND (when specified) its install-path keyword match.  Malware that
# renames itself to "node.exe" but runs from %TEMP% is NOT matched here because
# its path won't contain the expected install-directory keyword.

KNOWN_SAFE_EXECUTABLES: dict[str, str | None] = {
    # AegisAI self-protection — our own engine imports VirtualQueryEx, OpenProcess,
    # NtQuerySystemInformation, etc., which are indistinguishable from malware APIs.
    "antivirus.exe":                        "aegisai",
    "aegisai-ui.exe":                       "aegisai",
    # Rust IDE toolchain — proc-macro server imports many compiler-internal APIs.
    "rust-analyzer.exe":                    ".rustup",
    "rust-analyzer-proc-macro-srv.exe":     ".rustup",
    "cargo.exe":                            ".rustup",
    "rustc.exe":                            ".rustup",
    # Node.js runtime — Electron / V8 imports mimic process-injection patterns.
    "node.exe":                             "node",     # matches nodejs, nvm, node_modules paths
    # Postman — network API testing tool; imports reflect/socket APIs heavily.
    "postman agent.exe":                    "postman",
    "postman.exe":                          "postman",
    # VS Code (Electron) — same V8/Chromium import fingerprint as node.exe.
    "code.exe":                             "microsoft vs code",
    "code - insiders.exe":                  "vscode",
    # Chromium-based browsers — import sandbox / inter-process APIs for child processes.
    "brave.exe":                            "bravesoftware",
    "chrome.exe":                           "google",
    "msedge.exe":                           "microsoft\\edge",
    "firefox.exe":                          "mozilla",
    # Python interpreter — ML-model runners import ctypes / memory / thread APIs.
    "python.exe":                           "python",   # matches Python3xx, conda, venv paths
    "python3.exe":                          "python",
}


def _is_known_safe(exe_path: str) -> bool:
    """Return True if the executable matches the known-safe whitelist."""
    name = _os.path.basename(exe_path).lower()
    if name not in KNOWN_SAFE_EXECUTABLES:
        return False
    keyword = KNOWN_SAFE_EXECUTABLES[name]
    if keyword is None:
        return True
    return keyword in exe_path.lower()


# ── Main scan function ─────────────────────────────────────────────────────────

def scan_exe(exe_path: str) -> dict:
    """
    Extract PE imports from `exe_path`, feed them to the GRU model, and
    return a result dict.
    """
    # Fast-path: skip GRU for known-safe executables whose PE import tables
    # reliably produce false positives (security tools, browsers, runtimes).
    if _is_known_safe(exe_path):
        return {
            "exe_path":      exe_path,
            "skipped":       False,
            "reason":        None,
            "probability":   0.0,
            "label":         0,
            "verdict":       "BENIGN",
            "top_api_calls": [],
            "trigger_chunk": None,
            "api_count":     0,
            "source":        "whitelist",
        }

    if _IMPORT_ERROR:
        return {"exe_path": exe_path, "skipped": True, "reason": _IMPORT_ERROR}

    # Read the binary
    try:
        with open(exe_path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return {"exe_path": exe_path, "skipped": True, "reason": f"file_unavailable: {exc}"}

    if not data:
        return {"exe_path": exe_path, "skipped": True, "reason": "empty_file"}

    # Parse import table
    imports = extract_pe_imports(data)
    if not imports:
        return {"exe_path": exe_path, "skipped": True, "reason": "no_pe_imports"}

    # Run the GRU model — it will filter to vocab-known APIs internally
    try:
        result = predict_process(imports)
    except Exception as exc:
        return {"exe_path": exe_path, "skipped": True, "reason": f"inference_error: {exc}"}

    if result["verdict"] == "UNKNOWN":
        return {
            "exe_path": exe_path,
            "skipped":  True,
            "reason":   result.get("reason") or "too_few_vocab_apis",
        }

    return {
        "exe_path":     exe_path,
        "skipped":      False,
        "reason":       None,
        "probability":  result["probability"],
        "label":        result["label"],
        "verdict":      result["verdict"],
        "top_api_calls": result["top_api_calls"],
        "trigger_chunk": result["trigger_chunk"],
        "api_count":    len(imports),
        "source":       "pe_imports",
    }


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: process_bridge.py <exe_path> | --batch <e1> … | --server"}))
        sys.exit(1)

    if sys.argv[1] == "--server":
        # Persistent server: one exe_path per stdin line → one JSON line on stdout
        sys.stderr.write("process_bridge: server ready\n")
        sys.stderr.flush()
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            exe_path = line.rstrip("\n").rstrip("\r")
            if not exe_path:
                continue
            result = scan_exe(exe_path)
            sys.stdout.write(json.dumps(result) + "\n")
            sys.stdout.flush()

    elif sys.argv[1] == "--batch":
        paths   = sys.argv[2:]
        results = [scan_exe(p) for p in paths]
        print(json.dumps(results))

    else:
        print(json.dumps(scan_exe(sys.argv[1])))
