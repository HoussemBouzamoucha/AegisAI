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
        
        # Handle both "Clean" and "ThreatLevel::Clean" formats
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
    
    def __init__(self, engine_path: Path):
        """
        Initialize the Rust engine bridge.
        
        Args:
            engine_path: Path to the Rust engine executable
        """
        self.engine_path = engine_path
        self.engine_available = self._check_engine()
        
        if self.engine_available:
            print(f"✅ Rust engine found at: {self.engine_path}")
        else:
            print("⚠️  Rust engine not found - using simulation mode")
            print("   Build it with: cd ../Antivirus_Engine && cargo build --release")
    
    def _check_engine(self):
        """Check if the Rust engine exists and is executable."""
        if not self.engine_path.exists():
            return False
        
        # Try to run version command
        try:
            result = subprocess.run(
                [str(self.engine_path), "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a single file.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult object
        """
        if not self.engine_available:
            return self._simulate_scan(file_path)
        
        try:
            # Call Rust engine CLI
            result = subprocess.run(
                [
                    str(self.engine_path),
                    "scan-file",
                    "--path", file_path,
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
            
            # Parse JSON output
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
            return ScanResult(
                path=file_path,
                level=ThreatLevel.ERROR,
                reason="Scan timeout"
            )
        except json.JSONDecodeError:
            return ScanResult(
                path=file_path,
                level=ThreatLevel.ERROR,
                reason="Failed to parse engine response"
            )
        except Exception as e:
            return ScanResult(
                path=file_path,
                level=ThreatLevel.ERROR,
                reason=f"Scan error: {str(e)}"
            )
    
    def scan_directory(
        self, 
        directory: str, 
        recursive: bool = True,
        callback=None
    ) -> List[ScanResult]:
        """
        Scan a directory.
        
        Args:
            directory: Path to directory to scan
            recursive: Whether to scan recursively
            callback: Optional callback function for progress updates
            
        Returns:
            List of ScanResult objects
        """
        if not self.engine_available:
            return self._simulate_directory_scan(directory, recursive, callback)
        
        results = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            return [ScanResult(
                path=directory,
                level=ThreatLevel.ERROR,
                reason="Directory not found"
            )]
        
        try:
            # Call Rust engine CLI for directory scan
            result = subprocess.run(
                [
                    str(self.engine_path),
                    "scan-dir",
                    "--path", directory,
                    "--recursive", str(recursive).lower(),
                    "--format", "json"
                ],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for large scans
            )
            
            if result.returncode != 0:
                return [ScanResult(
                    path=directory,
                    level=ThreatLevel.ERROR,
                    reason=f"Scan failed: {result.stderr}"
                )]
            
            # Parse JSON output
            output = json.loads(result.stdout)
            
            if output.get('success') and output.get('results'):
                total = len(output['results'])
                
                for idx, result_data in enumerate(output['results']):
                    scan_result = ScanResult.from_dict(result_data)
                    results.append(scan_result)
                    
                    # Progress callback
                    if callback:
                        callback(idx + 1, total, scan_result)
            
            return results
                
        except subprocess.TimeoutExpired:
            return [ScanResult(
                path=directory,
                level=ThreatLevel.ERROR,
                reason="Scan timeout - directory too large"
            )]
        except json.JSONDecodeError:
            return [ScanResult(
                path=directory,
                level=ThreatLevel.ERROR,
                reason="Failed to parse engine response"
            )]
        except Exception as e:
            return [ScanResult(
                path=directory,
                level=ThreatLevel.ERROR,
                reason=f"Scan error: {str(e)}"
            )]
    
    def _simulate_directory_scan(self, directory: str, recursive: bool, callback=None):
        """Simulate directory scan when engine not available."""
        results = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            return [ScanResult(
                path=directory,
                level=ThreatLevel.ERROR,
                reason="Directory not found"
            )]
        
        # Collect files
        if recursive:
            files = list(dir_path.rglob('*'))
        else:
            files = list(dir_path.glob('*'))
        
        files = [f for f in files if f.is_file()]
        total_files = len(files)
        
        for idx, file_path in enumerate(files):
            try:
                result = self._simulate_scan(str(file_path))
                results.append(result)
                
                if callback:
                    callback(idx + 1, total_files, result)
                    
            except Exception as e:
                results.append(ScanResult(
                    path=str(file_path),
                    level=ThreatLevel.ERROR,
                    reason=str(e)
                ))
        
        return results
    
    def _simulate_scan(self, file_path: str) -> ScanResult:
        """
        Simulate a scan result.
        Used when Rust engine is not available.
        """
        import random
        import hashlib
        
        path = Path(file_path)
        
        # Calculate file hash
        try:
            with open(path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        except:
            file_hash = None
        
        ext = path.suffix.lower()
        filename_lower = path.name.lower()
        
        # EICAR test file
        if 'eicar' in filename_lower:
            return ScanResult(
                path=file_path,
                level=ThreatLevel.MALICIOUS,
                reason="EICAR test file detected",
                hash=file_hash,
                signature="EICAR-Test-File"
            )
        
        # Malicious patterns
        malicious_patterns = ['virus', 'malware', 'trojan', 'ransomware', 'backdoor']
        if any(pattern in filename_lower for pattern in malicious_patterns):
            return ScanResult(
                path=file_path,
                level=ThreatLevel.MALICIOUS,
                reason="Suspicious filename pattern detected",
                hash=file_hash,
                signature="Generic.Malware"
            )
        
        # Suspicious executables
        suspicious_exts = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs']
        if ext in suspicious_exts and random.random() < 0.15:
            return ScanResult(
                path=file_path,
                level=ThreatLevel.SUSPICIOUS,
                reason=f"Potentially unwanted program - suspicious extension: {ext}",
                hash=file_hash
            )
        
        # Clean files
        return ScanResult(
            path=file_path,
            level=ThreatLevel.CLEAN,
            reason="No threats detected",
            hash=file_hash
        )
    
    def get_statistics(self, results: List[ScanResult]) -> Dict[str, int]:
        """
        Calculate statistics from scan results.
        
        Args:
            results: List of ScanResult objects
            
        Returns:
            Dictionary with statistics
        """
        stats = {
            'total': len(results),
            'clean': 0,
            'suspicious': 0,
            'malicious': 0,
            'errors': 0
        }
        
        for result in results:
            if result.level == ThreatLevel.CLEAN:
                stats['clean'] += 1
            elif result.level == ThreatLevel.SUSPICIOUS:
                stats['suspicious'] += 1
            elif result.level == ThreatLevel.MALICIOUS:
                stats['malicious'] += 1
            elif result.level == ThreatLevel.ERROR:
                stats['errors'] += 1
        
        return stats