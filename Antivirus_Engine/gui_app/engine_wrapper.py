"""
Python Wrapper for Rust Antivirus Engine
Provides easy integration with JSON-based communication
"""

import subprocess
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Union

class AntivirusEngine:
    """Python wrapper for the Rust-based antivirus engine"""
    
    def __init__(self, rust_binary_path: Optional[str] = None):
        """
        Initialize the antivirus engine
        
        Args:
            rust_binary_path: Path to the Rust antivirus binary. 
                            If None, looks in target/release/antivirus.exe
        """
        if rust_binary_path is None:
            # Try to find the binary
            possible_paths = [
                "target/release/antivirus.exe",  # Windows release
                "target/debug/antivirus.exe",    # Windows debug
                "target/release/antivirus",      # Linux/Mac release
                "target/debug/antivirus",        # Linux/Mac debug
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    rust_binary_path = path
                    break
            
            if rust_binary_path is None:
                raise FileNotFoundError(
                    "Antivirus binary not found. Please build it first with 'cargo build --release'"
                )
        
        self.binary_path = rust_binary_path
        
        # Verify the binary exists
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Antivirus binary not found at: {self.binary_path}")
    
    def scan_file(self, file_path: Union[str, Path]) -> Dict:
        """
        Scan a single file
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dict with scan results:
            {
                "success": bool,
                "path": str,
                "level": str,  # "Clean", "Suspicious", or "Malicious"
                "reason": str,
                "hash": Optional[str],
                "signature": Optional[str],
                "is_threat": bool
            }
        """
        file_path = str(file_path)
        
        try:
            result = subprocess.run(
                [self.binary_path, "scan-file", file_path],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            
            if result.returncode != 0 and not result.stdout:
                return {
                    "success": False,
                    "error": f"Scanner returned error code {result.returncode}: {result.stderr}"
                }
            
            # Parse JSON output
            return json.loads(result.stdout)
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scan timeout (30s)"}
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Invalid JSON response: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def scan_directory(self, dir_path: Union[str, Path], recursive: bool = True) -> Dict:
        """
        Scan a directory
        
        Args:
            dir_path: Path to the directory to scan
            recursive: Whether to scan subdirectories (currently always True in Rust)
            
        Returns:
            Dict with scan results:
            {
                "success": bool,
                "statistics": {
                    "total_files": int,
                    "clean_files": int,
                    "suspicious_files": int,
                    "malicious_files": int,
                    "error_files": int,
                    "total_size_mb": float
                },
                "files": [
                    {
                        "path": str,
                        "level": str,
                        "reason": str,
                        "hash": Optional[str],
                        "signature": Optional[str],
                        "is_threat": bool
                    },
                    ...
                ]
            }
        """
        dir_path = str(dir_path)
        
        try:
            result = subprocess.run(
                [self.binary_path, "scan-dir", dir_path],
                capture_output=True,
                text=True,
                check=False,
                timeout=300  # 5 minutes for directory scans
            )
            
            if result.returncode != 0 and not result.stdout:
                return {
                    "success": False,
                    "error": f"Scanner returned error code {result.returncode}: {result.stderr}"
                }
            
            # Parse JSON output
            return json.loads(result.stdout)
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scan timeout (5 minutes)"}
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Invalid JSON response: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_threats(self, scan_result: Dict) -> List[Dict]:
        """
        Extract only the threats from a scan result
        
        Args:
            scan_result: Result from scan_directory()
            
        Returns:
            List of files that are threats (suspicious or malicious)
        """
        if not scan_result.get("success"):
            return []
        
        files = scan_result.get("files", [])
        return [f for f in files if f.get("is_threat", False)]
    
    def run_tests(self) -> bool:
        """
        Run the built-in test suite
        
        Returns:
            True if all tests passed, False otherwise
        """
        try:
            result = subprocess.run(
                [self.binary_path, "test"],
                capture_output=True,
                text=True,
                check=False,
                timeout=60
            )
            
            # Print output for user to see
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
            
            # Check if all tests passed
            return "All tests passed!" in result.stdout
            
        except Exception as e:
            print(f"Error running tests: {e}")
            return False
    
    def scan_processes(self) -> Dict:
        """
        Scan all running processes for threats
        
        Returns:
            Dict with process scan results:
            {
                "success": bool,
                "statistics": {
                    "total_processes": int,
                    "safe_processes": int,
                    "suspicious_processes": int,
                    "malicious_processes": int,
                    "critical_processes": int,
                    "total_memory_mb": str
                },
                "processes": [
                    {
                        "pid": int,
                        "name": str,
                        "path": Optional[str],
                        "memory_mb": str,
                        "cpu_usage": float,
                        "threat_level": str,
                        "suspicious_behaviors": List[str],
                        "is_threat": bool
                    },
                    ...
                ]
            }
        """
        try:
            result = subprocess.run(
                [self.binary_path, "scan-processes"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            
            if result.returncode != 0 and not result.stdout:
                return {
                    "success": False,
                    "error": f"Scanner returned error code {result.returncode}: {result.stderr}"
                }
            
            # Parse JSON output
            return json.loads(result.stdout)
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Process scan timeout (30s)"}
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Invalid JSON response: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def kill_process(self, pid: int) -> Dict:
        """
        Terminate a malicious process
        
        Args:
            pid: Process ID to terminate
            
        Returns:
            Dict with termination result:
            {
                "success": bool,
                "message": Optional[str],
                "error": Optional[str]
            }
        """
        try:
            result = subprocess.run(
                [self.binary_path, "kill-process", str(pid)],
                capture_output=True,
                text=True,
                check=False,
                timeout=10
            )
            
            if result.stdout:
                return json.loads(result.stdout)
            else:
                return {"success": False, "error": "No response from engine"}
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout terminating process"}
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Invalid JSON response: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_process_threats(self, scan_result: Dict) -> List[Dict]:
        """
        Extract only threatening processes from scan result
        
        Args:
            scan_result: Result from scan_processes()
            
        Returns:
            List of processes that are threats
        """
        if not scan_result.get("success"):
            return []
        
        processes = scan_result.get("processes", [])
        return [p for p in processes if p.get("is_threat", False)]


# Example usage and integration helper
def integrate_with_existing_scanner(file_path: str) -> Dict:
    """
    Helper function to integrate with your existing Python scanner
    
    Args:
        file_path: Path to file to scan
        
    Returns:
        Normalized result dict compatible with your existing code
    """
    engine = AntivirusEngine()
    result = engine.scan_file(file_path)
    
    if not result.get("success"):
        return {
            "threat_level": "error",
            "details": result.get("error", "Unknown error"),
            "is_threat": False
        }
    
    # Map to your existing format
    level = result.get("level", "Clean")
    
    return {
        "threat_level": level.lower(),  # "clean", "suspicious", "malicious"
        "details": result.get("reason", ""),
        "is_threat": result.get("is_threat", False),
        "hash": result.get("hash"),
        "signature": result.get("signature"),
    }


if __name__ == "__main__":
    # Example usage
    print("🛡️  Rust Antivirus Engine - Python Integration Test\n")
    
    try:
        engine = AntivirusEngine()
        print(f"✅ Found engine at: {engine.binary_path}\n")
        
        # Run built-in tests
        print("Running engine tests...")
        engine.run_tests()
        print()
        
        # Example: Scan a single file
        print("Example: Scanning a test file...")
        test_file = "test_file.txt"
        
        # Create test file
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        result = engine.scan_file(test_file)
        print(f"Result: {json.dumps(result, indent=2)}")
        
        # Clean up
        os.remove(test_file)
        
    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        print("\nPlease build the Rust engine first:")
        print("  cd antivirus_engine")
        print("  cargo build --release")
    except Exception as e:
        print(f"❌ Error: {e}")