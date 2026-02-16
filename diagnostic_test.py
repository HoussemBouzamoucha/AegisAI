"""
Diagnostic script to test Rust antivirus engine
Run this to check if the engine is working correctly
"""

import subprocess
import json
import sys

RUST_BINARY = r"C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\target\release\antivirus.exe"

print("="*80)
print("Rust Antivirus Engine Diagnostic")
print("="*80)

# Test 1: Check if binary exists
print("\n[Test 1] Checking if binary exists...")
import os
if os.path.exists(RUST_BINARY):
    print(f"✅ Binary found: {RUST_BINARY}")
else:
    print(f"❌ Binary NOT found: {RUST_BINARY}")
    print("\nPlease build the Rust engine first:")
    print("  cd C:\\Users\\houss\\Desktop\\AegisAI\\Antivirus_Engine")
    print("  cargo build --release")
    sys.exit(1)

# Test 2: Run help command
print("\n[Test 2] Testing help command...")
try:
    result = subprocess.run(
        [RUST_BINARY, "help"],
        capture_output=True,
        text=True,
        timeout=5
    )
    print("Output:")
    print(result.stdout[:500])  # First 500 chars
    if "scan-file" in result.stdout:
        print("✅ Help command works, scan-file command is available")
    else:
        print("⚠️  scan-file command not found in help")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 3: Test scan-file command
print("\n[Test 3] Testing scan-file command...")
TEST_FILE = r"C:\TestAV\eicar.txt"

if not os.path.exists(TEST_FILE):
    print(f"⚠️  Test file not found: {TEST_FILE}")
    print("Creating a clean test file instead...")
    TEST_FILE = "test_clean.txt"
    with open(TEST_FILE, "w") as f:
        f.write("This is a clean test file")

try:
    print(f"Scanning: {TEST_FILE}")
    result = subprocess.run(
        [RUST_BINARY, "scan-file", TEST_FILE],
        capture_output=True,
        text=True,
        timeout=30
    )
    
    print(f"\nReturn code: {result.returncode}")
    print(f"\nStdout length: {len(result.stdout)} chars")
    print(f"Stderr length: {len(result.stderr)} chars")
    
    print("\n--- STDOUT ---")
    print(result.stdout)
    
    if result.stderr:
        print("\n--- STDERR ---")
        print(result.stderr)
    
    # Try to parse as JSON
    if result.stdout.strip():
        print("\n[Test 4] Parsing JSON output...")
        try:
            data = json.loads(result.stdout)
            print("✅ Valid JSON received!")
            print("\nParsed data:")
            print(json.dumps(data, indent=2))
            
            if data.get("success"):
                print(f"\n✅ Scan successful!")
                print(f"   Level: {data.get('level')}")
                print(f"   Reason: {data.get('reason')}")
            else:
                print(f"\n⚠️  Scan returned success=false")
                print(f"   Error: {data.get('error')}")
                
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON: {e}")
            print("\nThis means the Rust engine needs to be rebuilt with the new main.rs")
    else:
        print("❌ No output received from engine")
        
except subprocess.TimeoutExpired:
    print("❌ Command timeout (30s)")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 5: Check if old or new version
print("\n[Test 5] Checking engine version...")
try:
    result = subprocess.run(
        [RUST_BINARY, "--help"],
        capture_output=True,
        text=True,
        timeout=5
    )
    
    if "scan-file" in result.stdout or "scan-dir" in result.stdout:
        print("✅ New version detected (with JSON support)")
    else:
        print("⚠️  Old version detected (no JSON commands)")
        print("\nAction needed:")
        print("1. Replace src/main.rs with the new version")
        print("2. Replace Cargo.toml with the new version")
        print("3. Run: cargo build --release")
        
except Exception as e:
    print(f"❌ Error: {e}")

print("\n" + "="*80)
print("Diagnostic complete!")
print("="*80)

# Cleanup
if os.path.exists("test_clean.txt"):
    os.remove("test_clean.txt")