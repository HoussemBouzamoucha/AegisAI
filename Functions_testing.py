from pathlib import Path
from typing import List

from Core.scanner import FileScanner
from Core.types import ThreatLevel


def print_result(result):
    """Helper to display one scan result."""
    print(f"File: {result.file_path}")
    print(f"Threat: {result.threat_level.value.upper()}")
    if result.reason:
        print(f"Reason: {result.reason}")
    if result.signature_match:
        print(f"Signature: {result.signature_match}")
    print("-" * 60)


def summarize_results(results: List):
    """Print summary statistics."""
    total = len(results)
    malicious = sum(1 for r in results if r.threat_level == ThreatLevel.MALICIOUS)
    suspicious = sum(1 for r in results if r.threat_level == ThreatLevel.SUSPICIOUS)
    clean = total - malicious - suspicious

    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print(f"Total files scanned: {total}")
    print(f"Malicious: {malicious}")
    print(f"Suspicious: {suspicious}")
    print(f"Clean: {clean}")
    print("=" * 60)


def main():
    scanner = FileScanner()

    print("=== AegisAI Scanner - Test Mode ===\n")

    # === Test 1: Single file ===
    single_file = Path(r"C:\TestAV\eicar.txt")
    print(f"Scanning single file: {single_file}")
    print("-" * 60)
    result = scanner.scan_file(single_file)
    print_result(result)

    # === Test 2: Scan folder recursively ===
    folder_path = Path(r"C:\TestAV")
    print(f"\nScanning folder RECURSIVELY: {folder_path}")
    print("-" * 60)

    recursive_results = []
    for result in scanner.scan_directory(folder_path, recursive=True):
        print_result(result)
        recursive_results.append(result)

    summarize_results(recursive_results)

    # === Test 3: Scan folder non-recursively (only top level) ===
    print(f"\nScanning folder NON-RECURSIVELY: {folder_path}")
    print("-" * 60)

    non_recursive_results = []
    for result in scanner.scan_directory(folder_path, recursive=False):
        print_result(result)
        non_recursive_results.append(result)

    summarize_results(non_recursive_results)


if __name__ == "__main__":
    main()