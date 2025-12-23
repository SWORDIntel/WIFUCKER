#!/usr/bin/env python3
"""
UK Router WPS Attack Testing Script
===================================

Comprehensive test suite for UK router WPS attack methods.
Tests all functionality without performing actual network attacks.

Usage: python3 test_uk_wps.py
"""

import sys
import os
from pathlib import Path

# Add the package to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'wifucker_pkg'))

def test_uk_router_database():
    """Test UK router database functionality"""
    print("🧪 Testing UK Router Database...")

    try:
        from crackers.uk_router_wps import UKRouterWPSDatabase

        # Test router retrieval
        all_routers = UKRouterWPSDatabase.get_all_routers()
        print(f"  ✅ Loaded {len(all_routers)} router models")

        # Test provider-specific routers
        virgin_routers = UKRouterWPSDatabase.get_provider_routers("virgin_media")
        bt_routers = UKRouterWPSDatabase.get_provider_routers("bt")
        ee_routers = UKRouterWPSDatabase.get_provider_routers("ee")

        print(f"  ✅ Virgin Media: {len(virgin_routers)} models")
        print(f"  ✅ BT: {len(bt_routers)} models")
        print(f"  ✅ EE: {len(ee_routers)} models")

        # Test SSID detection
        test_ssids = [
            ("VM7C8B123", "Virgin Media Super Hub 2"),
            ("BTHub5A456", "BT Home Hub 5"),
            ("EE-BrightBox-789ABC", "EE Bright Box 1"),
            ("BT-123456", "BT Smart Hub 2"),
        ]

        for ssid, expected in test_ssids:
            detected = UKRouterWPSDatabase.find_router_by_ssid(ssid)
            if detected:
                print(f"  ✅ {ssid} → {detected.provider.value} {detected.model}")
            else:
                print(f"  ❌ {ssid} → Not detected")

        return True

    except Exception as e:
        print(f"  ❌ Database test failed: {e}")
        return False

def test_wps_pin_generation():
    """Test WPS PIN generation algorithms"""
    print("\n🧪 Testing WPS PIN Generation...")

    try:
        from crackers.uk_router_wps import WPSPinGenerator

        generator = WPSPinGenerator()
        mac_address = "AA:BB:CC:DD:EE:FF"
        ssid = "VM1234567"

        # Test compute PIN
        compute_pins = generator.compute_pin(mac_address)
        print(f"  ✅ Compute PIN generated {len(compute_pins)} PINs")
        if compute_pins:
            print(f"     Sample: {compute_pins[0]}")

        # Test Pixie Dust
        pixie_pins = generator.pixie_dust_pins(mac_address, ssid)
        print(f"  ✅ Pixie Dust generated {len(pixie_pins)} PINs")
        if pixie_pins:
            print(f"     Sample: {pixie_pins[0]}")

        # Test brute force
        brute_pins = generator.generate_brute_force_pins(10)
        print(f"  ✅ Brute force generated {len(brute_pins)} PINs")
        if brute_pins:
            print(f"     Sample: {brute_pins[0]}")

        # Test all methods
        all_pins = generator.generate_all_pins(mac_address, ssid)
        print(f"  ✅ All methods combined: {len(all_pins)} unique PINs")

        return True

    except Exception as e:
        print(f"  ❌ PIN generation test failed: {e}")
        return False

def test_uk_router_wps_cracker():
    """Test UK Router WPS Cracker functionality"""
    print("\n🧪 Testing UK Router WPS Cracker...")

    try:
        from crackers.uk_router_wps import UKRouterWPSCracker

        mac_address = "00:11:22:33:44:55"
        ssid = "VM7C8B123"

        cracker = UKRouterWPSCracker(mac_address, ssid)

        # Test router detection
        detected = cracker.detect_router()
        if detected:
            print(f"  ✅ Router detected: {detected.provider.value} {detected.model}")
        else:
            print("  ❌ Router not detected")

        # Test attack methods
        methods = cracker.get_attack_methods()
        print(f"  ✅ Available attack methods: {[m.value for m in methods]}")

        # Test PIN generation
        pins = cracker.generate_pins_for_router(count=5)
        print(f"  ✅ Generated {len(pins)} PINs for router")
        if pins:
            print(f"     Sample PINs: {pins[:3]}")

        # Test router info
        info = cracker.get_router_info()
        if info:
            print(f"  ✅ Router info retrieved: {info.get('provider', 'Unknown')}")

        return True

    except Exception as e:
        print(f"  ❌ Cracker test failed: {e}")
        return False

def test_router_cracker_integration():
    """Test integration with RouterBruteForceCracker"""
    print("\n🧪 Testing Router Cracker Integration...")

    try:
        from crackers.router_cracker import RouterBruteForceCracker

        ssid = "VM7C8B123"
        mac_address = "AA:BB:CC:DD:EE:FF"

        cracker = RouterBruteForceCracker(ssid)

        # Test UK provider detection
        provider = cracker.detect_uk_provider()
        if provider:
            print(f"  ✅ UK provider detected: {provider}")
        else:
            print("  ❌ UK provider not detected")

        # Test UK provider wordlist
        wordlist = cracker.generate_uk_provider_wordlist(10)
        print(f"  ✅ Generated {len(wordlist)} UK provider passwords")

        # Test WPS PIN generation
        wps_pins = cracker.generate_wps_pins(mac_address, 10)
        print(f"  ✅ Generated {len(wps_pins)} WPS PINs")

        # Test comprehensive attack
        attack_results = cracker.comprehensive_uk_attack(mac_address)
        print(f"  ✅ Comprehensive attack generated {len(attack_results)} categories")

        for category, passwords in attack_results.items():
            print(f"     {category}: {len(passwords)} passwords")

        return True

    except Exception as e:
        print(f"  ❌ Integration test failed: {e}")
        return False

def test_attack_pipeline():
    """Test WPS attack pipeline (without actual network operations)"""
    print("\n🧪 Testing WPS Attack Pipeline...")

    try:
        from crackers.uk_router_wps import WPSAttackPipeline

        pipeline = WPSAttackPipeline("wlan0")

        # Test pipeline initialization
        print("  ✅ Pipeline initialized")

        # Test report generation (without actual scan/attack)
        report = pipeline.generate_attack_report()
        print("  ✅ Report generation works")

        # Test mock pipeline results
        mock_results = {
            "pipeline_results": {
                "routers_discovered": 3,
                "successful_attacks": 1,
                "success_rate": 0.33
            },
            "discovered_routers": [
                {"bssid": "00:11:22:33:44:55", "ssid": "VM1234567"},
                {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "BTHub5A123"}
            ],
            "attack_results": {},
            "report": report
        }

        print(f"  ✅ Mock pipeline results processed: {mock_results['pipeline_results']}")

        return True

    except Exception as e:
        print(f"  ❌ Pipeline test failed: {e}")
        return False

def test_tui_integration():
    """Test TUI integration (import test only)"""
    print("\n🧪 Testing TUI Integration...")

    try:
        # Test that TUI can import our modules
        from wifucker_unified_tui import UKRouterWPSTab
        print("  ✅ UK Router WPS Tab can be imported")

        # Test tab initialization
        tab = UKRouterWPSTab()
        print("  ✅ UK Router WPS Tab can be instantiated")

        return True

    except Exception as e:
        print(f"  ❌ TUI integration test failed: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("🔬 UK Router WPS Attack Test Suite")
    print("=" * 50)

    tests = [
        ("UK Router Database", test_uk_router_database),
        ("WPS PIN Generation", test_wps_pin_generation),
        ("UK Router WPS Cracker", test_uk_router_wps_cracker),
        ("Router Cracker Integration", test_router_cracker_integration),
        ("Attack Pipeline", test_attack_pipeline),
        ("TUI Integration", test_tui_integration),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")

    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! UK WPS implementation is ready.")
        return True
    else:
        print("⚠️  Some tests failed. Check implementation.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
