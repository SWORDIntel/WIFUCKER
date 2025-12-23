#!/usr/bin/env python3
"""
WIFUCKER Test Runner
====================

Run all WIFUCKER tests from the tests directory.

Usage: python3 tests/run_all_tests.py
"""

import sys
import os
import subprocess
from pathlib import Path

def run_test(test_file, test_name):
    """Run a single test file"""
    print(f"\n{'='*60}")
    print(f"Running {test_name}")
    print('='*60)

    try:
        result = subprocess.run(
            [sys.executable, test_file],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print(f"❌ {test_name} timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"❌ {test_name} failed to run: {e}")
        return False

def main():
    """Run all tests"""
    tests_dir = Path(__file__).parent
    wifucker_root = tests_dir.parent

    print("🧪 WIFUCKER Test Suite Runner")
    print("=" * 60)
    print(f"Tests directory: {tests_dir}")
    print(f"WIFUCKER root: {wifucker_root}")
    print()

    # Change to WIFUCKER root directory for proper imports
    os.chdir(wifucker_root)

    # Test files to run
    test_files = [
        ("UK WPS Tests", tests_dir / "test_uk_wps.py"),
        ("IoT WPS Tests", tests_dir / "test_iot_wps.py"),
        ("Advanced WPS Tests", tests_dir / "test_advanced_wps.py"),
        ("Evil Twin Tests", tests_dir / "test_evil_twin.py"),
        ("Demo Router Cracking", tests_dir / "demo_router_cracking.py"),
    ]

    passed = 0
    total = len(test_files)

    for test_name, test_file in test_files:
        if test_file.exists():
            if run_test(str(test_file), test_name):
                passed += 1
        else:
            print(f"❌ {test_name}: Test file not found - {test_file}")

    print(f"\n{'='*60}")
    print("📊 Test Summary")
    print('='*60)
    print(f"Tests run: {total}")
    print(f"Tests passed: {passed}")
    print(f"Success rate: {passed/total*100:.1f}%" if total > 0 else "Success rate: N/A")

    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
