# WIFUCKER Installation Guide

## Quick Install (Recommended)

```bash
cd /run/media/john/bc5e73fe-fa71-4ed0-802c-36fc31781616/DSMIL/DSMILSystem/tools/WIFUCKER
./wifucker
```

The launcher will:
- ✅ Create virtual environment
- ✅ Install all dependencies
- ✅ Set Layer 9 (QUANTUM) clearance by default
- ✅ Configure full 9-layer acceleration stack
- ✅ Enable WPA2/PSK2 routing through all layers
- ✅ Create system-wide symlink (optional)

## What Gets Installed

### Core Dependencies
- `textual` - TUI framework
- `rich` - Rich text formatting
- `requests` - HTTP requests
- `numpy` - Numerical computing
- `tqdm` - Progress bars
- `cryptography` - Cryptographic functions
- `openvino` - Intel OpenVINO (hardware acceleration)

### Optional Dependencies
- `qiskit` - Quantum computing framework
- `qiskit-aer` - Quantum simulator

### System Configuration
- Virtual environment in `venv/`
- Layer 9 (QUANTUM) clearance set automatically
- Launcher script configured
- System-wide access (if permissions allow)

## Post-Installation

After installation, WIFUCKER will:
1. **Automatically set QUANTUM clearance (Layer 9)** on every launch
2. **Route WPA2/PSK2 cracking** through:
   - Quantum Processor (Layer 9) - if available
   - Unified Accelerator System (80+ TOPS)
   - Hardware acceleration (NPU/GPU/NCS2)
3. **Display total TOPS** in GUI
4. **Show acceleration routing** during cracking

## Usage

### Launch WIFUCKER
```bash
./wifucker
```

### Launch with sudo (for WiFi operations)
```bash
sudo -E ./wifucker
```

### Check Total TOPS
```bash
python3 scripts/check_tops.py
```

## Manual Installation

If you prefer manual installation:

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install quantum (optional)
pip install qiskit qiskit-aer

# Set Layer 9 clearance
python3 scripts/set_max_clearance.py

# Launch
./wifucker
```

## Verification

After installation, verify:

1. **Check clearance level:**
   ```bash
   python3 scripts/set_max_clearance.py
   ```

2. **Check TOPS:**
   ```bash
   python3 scripts/check_tops.py
   ```

3. **Launch GUI:**
   ```bash
   ./wifucker
   ```

## Troubleshooting

### Virtual environment issues
```bash
rm -rf venv
./wifucker
```

### Missing dependencies
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Clearance not setting
- May require kernel driver (`dsmil_unified.ko`)
- Will be set automatically on launch
- Check `/dev/dsmil0` exists for kernel-level access

### Quantum not available
- Install: `pip install qiskit qiskit-aer`
- Quantum is optional - system works without it
- Falls back to unified accelerators

## Default Configuration

WIFUCKER is configured with:
- **Clearance Level**: QUANTUM (Layer 9)
- **Acceleration Priority**: Quantum → Unified → Hardware → CPU
- **WPA2/PSK2 Routing**: Full 9-layer stack
- **TOPS Display**: Enabled in GUI
- **Auto-clearance**: Set on every launch

## System Requirements

- Python 3.8+
- Linux (for kernel drivers)
- Intel hardware (for NPU/Arc GPU acceleration)
- Optional: Quantum processor dependencies

## Support

For issues or questions, check:
- `tools/WIFUCKER/README.md`
- `tools/WIFUCKER/QUANTUM_INTEGRATION.md` (if exists)
- Launcher output for error messages

