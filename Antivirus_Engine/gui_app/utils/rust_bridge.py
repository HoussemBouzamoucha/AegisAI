"""
Rust Engine Bridge
==================
Interface to communicate with the Rust antivirus engine via CLI.
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import hashlib
import random


class ThreatLevel(Enum):
    """Threat level enumeration matching Rust engine."""
    CLEAN = "Clean"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"
    ERROR = "Error"


@dataclass
class ScanResult:
    """Represents a scan result from the Rust engine."""
    path: str
    level: ThreatLevel
    reason: str
    hash: Optional[str] = None
    signature: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict):
        """Create ScanResult from dictionary."""
        level_str = data.get('level', 'Clean')
        if '::' in level_str:
            level_str = level_str.split('::')[-1]
        return cls(
            path=data.get('path', ''),
            level=ThreatLevel(level_str),
            reason=data.get('reason', ''),
            hash=data.get('hash'),
            signature=data.get('signature')
        )


class RustEngine:
    """Bridge to the Rust antivirus engine."""

    def __init__(self, engine_path: Optional[Path]):
        """Initialize Rust engine bridge."""
        self.engine_path = engine_path if engine_path else None
        self.engine_available = self._check_engine() if engine_path else False

        if self.engine_available:
            print(f"✅ Rust engine found at: {self.engine_path}")
        else:
            print("⚠️  Rust engine not found - using simulation mode")
            print("   Build it with: cd ../Antivirus_Engine && cargo build --release")

    def _check_engine(self) -> bool:
        """Check if the Rust engine exists and is executable."""
        if not self.engine_path or not self.engine_path.is_file():
            return False
        try:
            result = subprocess.run(
                [str(self.engine_path), "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file."""
        if not self.engine_available:
            return self._simulate_scan(file_path)

        abs_path = str(Path(file_path).resolve())
        try:
            result = subprocess.run(
                [
                    str(self.engine_path),
                    "scan-file",
                    "--path", abs_path,
                    "--format", "json"
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return ScanResult(
                    path=file_path,
                    level=ThreatLevel.ERROR,
                    reason=f"Scan failed: {result.stderr}"
                )

            output = json.loads(result.stdout)
            if output.get('success') and output.get('results'):
                return ScanResult.from_dict(output['results'][0])
            else:
                return ScanResult(
                    path=file_path,
                    level=ThreatLevel.ERROR,
                    reason="Invalid response from engine"
                )

        except subprocess.TimeoutExpired:
            return ScanResult(path=file_path, level=ThreatLevel.ERROR, reason="Scan timeout")
        except json.JSONDecodeError:
            return ScanResult(path=file_path, level=ThreatLevel.ERROR, reason="Failed to parse engine response")
        except Exception as e:
            return ScanResult(path=file_path, level=ThreatLevel.ERROR, reason=f"Scan error: {str(e)}")

    def scan_directory(self, directory: str, recursive: bool = True, callback=None) -> List[ScanResult]:
        """Scan a directory."""
        if not self.engine_available:
            return self._simulate_directory_scan(directory, recursive, callback)

        dir_path = Path(directory).resolve()
        if not dir_path.exists():
            return [ScanResult(path=directory, level=ThreatLevel.ERROR, reason="Directory not found")]

        abs_dir = str(dir_path)
        cmd = [
            str(self.engine_path),
            "scan-dir",
            "--path", abs_dir,
            "--format", "json"
        ]
        # Add --recursive as a flag only
        if recursive:
            cmd.append("--recursive")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes for large directories
            )

            if result.returncode != 0:
                return [ScanResult(path=directory, level=ThreatLevel.ERROR, reason=f"Scan failed: {result.stderr}")]

            output = json.loads(result.stdout)
            results = []

            if output.get('success') and output.get('results'):
                total = len(output['results'])
                for idx, rdata in enumerate(output['results']):
                    scan_result = ScanResult.from_dict(rdata)
                    results.append(scan_result)
                    if callback:
                        callback(idx + 1, total, scan_result)
            return results

        except subprocess.TimeoutExpired:
            return [ScanResult(path=directory, level=ThreatLevel.ERROR, reason="Scan timeout - directory too large")]
        except json.JSONDecodeError:
            return [ScanResult(path=directory, level=ThreatLevel.ERROR, reason="Failed to parse engine response")]
        except Exception as e:
            return [ScanResult(path=directory, level=ThreatLevel.ERROR, reason=f"Scan error: {str(e)}")]

    # ---------------- Simulation Fallbacks ---------------- #

    def _simulate_directory_scan(self, directory: str, recursive: bool, callback=None) -> List[ScanResult]:
        """Simulate a directory scan (used if engine not available)."""
        results = []
        dir_path = Path(directory).resolve()
        if not dir_path.exists():
            return [ScanResult(path=directory, level=ThreatLevel.ERROR, reason="Directory not found")]

        files = list(dir_path.rglob('*') if recursive else dir_path.glob('*'))
        files = [f for f in files if f.is_file()]
        total_files = len(files)

        for idx, file_path in enumerate(files):
            try:
                result = self._simulate_scan(str(file_path))
                results.append(result)
                if callback:
                    callback(idx + 1, total_files, result)
            except Exception as e:
                results.append(ScanResult(path=str(file_path), level=ThreatLevel.ERROR, reason=str(e)))
        return results

    def _simulate_scan(self, file_path: str) -> ScanResult:
        """Simulate a scan result for a single file."""
        path = Path(file_path).resolve()
        try:
            with open(path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            file_hash = None

        filename_lower = path.name.lower()
        ext = path.suffix.lower()

        if 'eicar' in filename_lower:
            return ScanResult(path=file_path, level=ThreatLevel.MALICIOUS,
                              reason="EICAR test file detected", hash=file_hash, signature="EICAR-Test-File")

        malicious_patterns = ['virus', 'malware', 'trojan', 'ransomware', 'backdoor']
        if any(p in filename_lower for p in malicious_patterns):
            return ScanResult(path=file_path, level=ThreatLevel.MALICIOUS,
                              reason="Suspicious filename pattern detected", hash=file_hash, signature="Generic.Malware")

        suspicious_exts = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs']
        if ext in suspicious_exts and random.random() < 0.15:
            return ScanResult(path=file_path, level=ThreatLevel.SUSPICIOUS,
                              reason=f"Potentially unwanted program - suspicious extension: {ext}", hash=file_hash)

        return ScanResult(path=file_path, level=ThreatLevel.CLEAN, reason="No threats detected", hash=file_hash)

    # ---------------- Statistics ---------------- #

    def get_statistics(self, results: List[ScanResult]) -> Dict[str, int]:
        """Calculate statistics from scan results."""
        stats = {'total': len(results), 'clean': 0, 'suspicious': 0, 'malicious': 0, 'errors': 0}
        for r in results:
            if r.level == ThreatLevel.CLEAN:
                stats['clean'] += 1
            elif r.level == ThreatLevel.SUSPICIOUS:
                stats['suspicious'] += 1
            elif r.level == ThreatLevel.MALICIOUS:
                stats['malicious'] += 1
            elif r.level == ThreatLevel.ERROR:
                stats['errors'] += 1
        return stats
