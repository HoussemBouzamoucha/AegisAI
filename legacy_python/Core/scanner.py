import os
from pathlib import Path
from typing import Generator

from .heuristics import run_heuristics
from .signature import SignatureDatabase
from .yara_scanner import YaraScanner
from .types import ScanResult, ThreatLevel
from .utils import get_file_hashes


class FileScanner:
    """Central scanner – coordinates all detection layers."""

    def __init__(self):
        self.signature_db = SignatureDatabase()
        self.yara_scanner = YaraScanner()

    def scan_file(self, file_path: Path) -> ScanResult:
        if not file_path.is_file():
            return ScanResult(file_path, ThreatLevel.CLEAN, "Not a regular file")

        hashes = get_file_hashes(file_path)

        # Layer 1: Hash signatures
        malware_name = self.signature_db.check_hashes(hashes)
        if malware_name:
            return ScanResult(
                file_path=file_path,
                threat_level=ThreatLevel.MALICIOUS,
                reason=f"Known hash signature: {malware_name}",
                hash_value=hashes,
                signature_match=malware_name
            )

        # Layer 2: YARA pattern matching
        yara_matches = self.yara_scanner.match(file_path)
        if yara_matches:
            return ScanResult(
                file_path=file_path,
                threat_level=ThreatLevel.MALICIOUS,
                reason=f"YARA match: {', '.join(yara_matches)}",
                hash_value=hashes,
                signature_match=", ".join(yara_matches)
            )

        # Layer 3: Heuristics
        heuristic_result = run_heuristics(file_path)
        if heuristic_result.threat_level != ThreatLevel.CLEAN:
            return heuristic_result

        # Clean
        return ScanResult(
            file_path=file_path,
            threat_level=ThreatLevel.CLEAN,
            hash_value=hashes
        )

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = True
    ) -> Generator[ScanResult, None, None]:
        """Scan all files in a directory."""
        if recursive:
            for root, _, files in os.walk(directory):
                for file_name in files:
                    file_path = Path(root) / file_name
                    yield self.scan_file(file_path)
        else:
            for item in directory.iterdir():
                if item.is_file():
                    yield self.scan_file(item)