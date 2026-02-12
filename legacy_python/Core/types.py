from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class ThreatLevel(Enum):
    """Possible outcomes of scanning a file."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class ScanResult:
    """Structured result of scanning one file."""
    file_path: Path
    threat_level: ThreatLevel
    reason: str = ""                    # Why it was flagged (or empty if clean)
    hash_value: Optional[str] = None    # SHA-256 hash (if computed)
    signature_match: Optional[str] = None  # Name of matched malware (if any)