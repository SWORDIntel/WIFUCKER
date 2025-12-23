#!/usr/bin/env python3
"""
WIFUCKER Router Cracking Demo
=============================

Demonstrates the new router password cracking capabilities:
- EE WiFi Smart Hub patterns (12-14 digits)
- Hexadecimal brute force (10 digits, a-f, 0-9)
- Router type auto-detection
- Smart wordlist generation

Usage: python3 demo_router_cracking.py
"""

import sys
import os

# Add the package to path
sys.path.insert(0, os.path.dirname(__file__) + '/../wifucker_pkg')

from crackers.router_cracker import RouterPasswordGenerator, RouterBruteForceCracker
from crackers.ee_wifi_cracker import EEWiFiCracker


def demo_ee_wifi_cracking():
    """Demonstrate EE WiFi password cracking"""
    print("🔥 EE WiFi Smart Hub Cracking Demo")
    print("=" * 50)

    # Test EE network detection
    test_ssids = [
        "EE-BrightBox-123",
        "BT-Hub-456",
        "EE-SmartHub",
        "BTOpenreach-789",
        "TP-Link_Router",
        "Netgear_Network"
    ]

    print("Network Detection:")
    for ssid in test_ssids:
        is_ee = EEWiFiCracker.is_ee_network(ssid)
        status = "✓ EE/BT Network" if is_ee else "✗ Generic Network"
        print(f"  {ssid:<20} → {status}")

    print("\nEE WiFi Pattern Examples:")
    patterns = EEWiFiCracker.get_pattern_info()
    for pattern in patterns:
        print(f"  • {pattern.pattern_type}:")
        print(f"    {pattern.description}")
        print(f"    Examples: {', '.join(pattern.examples[:3])}")
        print()

    print("Generated EE WiFi Passwords (first 10):")
    ee_passwords = EEWiFiCracker.generate_all_patterns(10)
    for i, pwd in enumerate(ee_passwords, 1):
        print(f"{i:2d} {pwd}")
    print()


def main():
    """Main demo function"""
    print("WIFUCKER Enhanced - Router Password Cracking Demo")
    print("==================================================")
    print()

    try:
        demo_ee_wifi_cracking()

        print("✅ Demo completed successfully!")
        print("\nTo use these features in the full WIFUCKER TUI:")
        print("  1. Run: ./wifucker")
        print("  2. Navigate to the 'Router Cracking' tab")
        print("  3. Choose your preferred cracking mode")

    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()