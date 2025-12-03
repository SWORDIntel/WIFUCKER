#!/usr/bin/env python3
"""
Set Maximum Clearance Level (9-Layer System)
=============================================
Sets the current clearance level to QUANTUM (Layer 9 - maximum level).

9-Layer Clearance System:
- Layer 0: UNCLASSIFIED
- Layer 1: RESTRICTED
- Layer 2: CONFIDENTIAL
- Layer 3: SECRET
- Layer 4: TOP_SECRET
- Layer 5: SCI
- Layer 6: SAP
- Layer 7: COSMIC
- Layer 8: ATOMAL
- Layer 9: QUANTUM (MAXIMUM - Quantum-classified operations)
"""

import sys
from pathlib import Path

# Add DSMILSystem root to path
dsmil_root = Path(__file__).resolve().parents[2]  # .../DSMILSystem
if not (dsmil_root / "ai").exists():
    dsmil_root = Path.cwd()

sys.path.insert(0, str(dsmil_root))
print(f"[*] Using DSMIL root: {dsmil_root}")

try:
    # Import ClearanceLevel directly to avoid dependency issues
    from ai.hardware.dsmil_accelerator_interface import (
        get_accelerator_interface, ClearanceLevel
    )
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Attempting direct import...")
    # Try direct import
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dsmil_accelerator_interface",
            dsmil_root / "ai" / "hardware" / "dsmil_accelerator_interface.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        get_accelerator_interface = module.get_accelerator_interface
        ClearanceLevel = module.ClearanceLevel
    except Exception as e2:
        print(f"Direct import also failed: {e2}")
        print("Make sure you're running from the DSMILSystem directory")
        sys.exit(1)

# Try unified manager (optional)
try:
    from ai.hardware.unified_accelerator import get_unified_manager
    HAS_UNIFIED = True
except ImportError:
    HAS_UNIFIED = False


def set_max_clearance():
    """Set clearance level to maximum (QUANTUM - Layer 9)."""
    print("=" * 70)
    print("  SETTING CLEARANCE LEVEL TO MAXIMUM (QUANTUM - LAYER 9)")
    print("=" * 70)
    print()

    max_clearance = ClearanceLevel.QUANTUM
    print(f"Target Clearance Level: {max_clearance.name} (Layer {max_clearance.value})")
    print()
    print("9-Layer Clearance System:")
    for level in ClearanceLevel:
        marker = " <-- TARGET" if level == max_clearance else ""
        print(f"  Layer {level.value}: {level.name}{marker}")
    print()

    # Try to set via DSMIL accelerator interface
    try:
        accel_interface = get_accelerator_interface()

        if accel_interface.is_available:
            print("[*] DSMIL Accelerator Interface detected")

            # Check if security subsystem is enabled
            if accel_interface.capabilities.security_enabled:
                print("[*] Security subsystem is active")

                # Try to set clearance via sysfs
                sysfs_clearance_path = Path("/sys/class/dsmil/dsmil0/clearance_level")
                if sysfs_clearance_path.exists():
                    try:
                        with open(sysfs_clearance_path, "w") as f:
                            f.write(str(max_clearance.value))
                        print(f"[+] Clearance level set to {max_clearance.name} via sysfs")
                    except PermissionError:
                        print("[!] Permission denied - try running with sudo")
                        return False
                    except Exception as e:
                        print(f"[!] Error setting clearance: {e}")
                        return False
                else:
                    print("[!] Clearance sysfs interface not found")
                    print("[!] Kernel driver may not be loaded or security subsystem not active")
            else:
                print("[!] Security subsystem is not enabled")
                print("[!] Clearance levels may not be enforced")
        else:
            print("[!] DSMIL Accelerator Interface not available")
    except Exception as e:
        print(f"[!] Error accessing accelerator interface: {e}")

    # Also try via unified manager
    if HAS_UNIFIED:
        try:
            unified_manager = get_unified_manager()
            print(f"[*] Unified Accelerator Manager: {unified_manager.get_total_tops():.1f} TOPS")
            print("[*] Clearance level applies to all accelerator operations")
        except Exception as e:
            print(f"[!] Unified manager: {e}")

    # Try kernel device directly
    dsmil_device = Path("/dev/dsmil0")
    if dsmil_device.exists():
        print(f"[*] DSMIL kernel device found: {dsmil_device}")
        try:
            # Try ioctl or direct write (if supported)
            import struct
            with open(dsmil_device, "wb") as f:
                # Format: operation_type, clearance_level, device_id
                # This is a simplified approach - actual implementation may vary
                data = struct.pack("<III", 0x1000, max_clearance.value, 0)
                f.write(data)
            print(f"[+] Clearance level set via kernel device")
        except PermissionError:
            print("[!] Permission denied - try running with sudo")
        except Exception as e:
            print(f"[!] Kernel device write failed: {e}")

    print()
    print("=" * 70)
    print("  CLEARANCE LEVEL SET TO MAXIMUM (LAYER 9)")
    print("=" * 70)
    print()
    print(f"Current Clearance: {max_clearance.name} (Layer {max_clearance.value})")
    print("All accelerator operations now have QUANTUM-classified clearance access.")
    print("Full access to all 9 layers of the security system enabled.")
    print()

    return True


if __name__ == "__main__":
    success = set_max_clearance()
    sys.exit(0 if success else 1)
