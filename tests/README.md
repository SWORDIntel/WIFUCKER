# WIFUCKER Tests

This directory contains all test and demonstration scripts for WIFUCKER.

## Test Files

- `test_uk_wps.py` - Tests for UK router WPS functionality
- `test_advanced_wps.py` - Tests for advanced WPS attack methods
- `test_evil_twin.py` - Tests for evil twin suite functionality
- `demo_router_cracking.py` - Demonstration of router cracking capabilities
- `run_all_tests.py` - Test runner script

## Running Tests

### Run All Tests
```bash
cd /path/to/wifucker
python3 tests/run_all_tests.py
```

### Run Individual Tests
```bash
cd /path/to/wifucker

# UK WPS Tests
python3 tests/test_uk_wps.py

# Advanced WPS Tests
python3 tests/test_advanced_wps.py

# Evil Twin Tests
python3 tests/test_evil_twin.py

# Router Cracking Demo
python3 tests/demo_router_cracking.py
```

## Test Dependencies

Tests may require some Python packages to be installed. Run the bootstrap script first:

```bash
# Install system dependencies
sudo ./bootstrap_evil_twin.sh

# Install Python dependencies
./wifucker_launcher  # This will set up the virtual environment
```

## Test Coverage

### UK WPS Tests (`test_uk_wps.py`)
- ✅ UK router database functionality
- ✅ WPS PIN generation algorithms
- ✅ UK router WPS cracker
- ✅ Router cracker integration
- ✅ WPS attack pipeline
- ✅ TUI integration

### Advanced WPS Tests (`test_advanced_wps.py`)
- ✅ Small DH Key attack implementation
- ✅ WPS Registrar PIN disclosure
- ✅ EAP message injection
- ✅ Attack coordinator functionality
- ✅ WPS integration with UK crackers

### Evil Twin Tests (`test_evil_twin.py`)
- ✅ UK ISP template validation
- ✅ Evil twin AP configuration
- ✅ Evil twin suite coordination
- ✅ Captive portal templates
- ✅ Network scanning (mock)
- ✅ Template configurations

## Adding New Tests

When adding new test files:

1. Place them in this `tests/` directory
2. Update the `run_all_tests.py` script to include them
3. Ensure they follow the same import pattern:
   ```python
   # Add the package to path
   sys.path.insert(0, str(Path(__file__).parent.parent / 'wifucker_pkg'))
   ```
4. Update this README.md

## Test Results

Tests will output detailed results showing:
- ✅ Passed tests
- ❌ Failed tests
- ⏭️ Skipped tests (missing dependencies)

## Troubleshooting

### Import Errors
If you get import errors, ensure you're running tests from the WIFUCKER root directory:
```bash
cd /path/to/wifucker
python3 tests/test_uk_wps.py
```

### Missing Dependencies
Install required dependencies:
```bash
# System packages
sudo ./bootstrap_evil_twin.sh

# Python packages
./wifucker_launcher  # Sets up virtual environment
```

### Permission Issues
Some tests may require root privileges for network operations:
```bash
sudo python3 tests/test_advanced_wps.py
```

## Continuous Integration

These tests are designed to run in CI/CD environments and will gracefully handle missing dependencies by skipping relevant tests rather than failing completely.
