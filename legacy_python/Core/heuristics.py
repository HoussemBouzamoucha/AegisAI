from pathlib import Path
from typing import List

from .types import ThreatLevel, ScanResult
from .utils import is_pe_file
from .utils import calculate_entropy

def run_heuristics(file_path: Path) -> ScanResult:
    """
    Apply simple heuristic rules to detect suspicious files.
    Returns SUSPICIOUS result if any rule triggers.
    """
    reasons: List[str] = []

    # Rule 1: Executable-looking file without valid PE header
    if file_path.suffix.lower() in {".exe", ".dll", ".scr", ".pif"}:
        if not is_pe_file(file_path):
            reasons.append("Invalid PE header for executable extension")

    # Rule 2: Zero-byte file with executable extension
    if file_path.stat().st_size == 0 and file_path.suffix.lower() in {".exe", ".dll"}:
        reasons.append("Zero-byte file with executable extension")

    # You can add more rules here later, for example:
    # - Very high entropy (packed/obfuscated file)
    # - Suspicious double extensions (invoice.pdf.exe)
    # - Known malicious file names

    entropy = calculate_entropy(file_path)
    if entropy > 7.0:
        reasons.append(f"High entropy ({entropy:.2f}) - possible packed/obfuscated file")
    # Zero-byte + executable-looking extension
    executable_exts = {".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".js", ".vbs", ".ps1"}
    if file_path.stat().st_size == 0 and file_path.suffix.lower() in executable_exts:
        reasons.append(f"Zero-byte file with suspicious executable extension '{file_path.suffix}'")
    
    
    if reasons:
        return ScanResult(
            file_path=file_path,
            threat_level=ThreatLevel.SUSPICIOUS,
            reason="; ".join(reasons)
        )

    # No suspicion → clean
    return ScanResult(
        file_path=file_path,
        threat_level=ThreatLevel.CLEAN
    )
    