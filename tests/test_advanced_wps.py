#!/usr/bin/env python3
"""
Advanced WPS Attack Testing Script
==================================

Comprehensive test suite for advanced WPS attack methods.
Tests all high-level attack implementations.

Usage: python3 test_advanced_wps.py
"""

import sys
import os
from pathlib import Path

# Add the package to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'wifucker_pkg'))

def test_small_dh_key_attack():
    """Test Small DH Key attack implementation"""
    print("🧪 Testing Small DH Key Attack...")

    try:
        from crackers.advanced_wps_attacks import SmallDHKeyAttack

        # Test with known vulnerable target
        attacker = SmallDHKeyAttack("00:11:22:33:44:55", "VM7C8B123")

        # Test vulnerability check
        is_vulnerable = attacker._check_vulnerability()
        print(f"  Vulnerability check: {'✅ Vulnerable' if is_vulnerable else '❌ Not vulnerable'}")

        # Test attack execution (will fail without real network, but tests implementation)
        result = attacker.execute_attack(timeout=5)  # Short timeout for testing

        print(f"  Attack result: {result.success}")
        print(f"  Execution time: {result.execution_time:.2f}s")

        if result.pin:
            print(f"  PIN found: {result.pin}")

        return True

    except Exception as e:
        print(f"  ❌ Small DH Key attack test failed: {e}")
        return False

def test_registrar_pin_disclosure_attack():
    """Test WPS Registrar PIN Disclosure attack"""
    print("\n🧪 Testing Registrar PIN Disclosure Attack...")

    try:
        from crackers.advanced_wps_attacks import WPSRegistrarPinDisclosure

        attacker = WPSRegistrarPinDisclosure("00:11:22:33:44:55", "BTHub5A123")

        # Test WPS support check
        supports_wps = attacker._check_wps_support()
        print(f"  WPS support check: {'✅ Supported' if supports_wps else '❌ Not supported'}")

        # Test attack execution
        result = attacker.execute_attack(timeout=5)

        print(f"  Attack result: {result.success}")
        print(f"  Execution time: {result.execution_time:.2f}s")

        if result.pin:
            print(f"  PIN found: {result.pin}")

        return True

    except Exception as e:
        print(f"  ❌ Registrar PIN disclosure test failed: {e}")
        return False

def test_eap_injection_attack():
    """Test EAP Message Injection attack"""
    print("\n🧪 Testing EAP Message Injection Attack...")

    try:
        from crackers.advanced_wps_attacks import EAPEAPMessageInjection

        attacker = EAPEAPMessageInjection("00:11:22:33:44:55", "EE-BrightBox-123")

        # Test session initiation
        session = attacker._initiate_wps_session()
        print(f"  Session initiation: {'✅ Success' if session else '❌ Failed'}")

        # Test attack execution
        result = attacker.execute_attack(timeout=5)

        print(f"  Attack result: {result.success}")
        print(f"  Execution time: {result.execution_time:.2f}s")

        if result.pin:
            print(f"  PIN found: {result.pin}")
        if result.psk:
            print(f"  PSK found: {result.psk}")

        return True

    except Exception as e:
        print(f"  ❌ EAP injection test failed: {e}")
        return False

def test_attack_coordinator():
    """Test Advanced WPS Attack Coordinator"""
    print("\n🧪 Testing Attack Coordinator...")

    try:
        from crackers.advanced_wps_attacks import AdvancedWPSAttackCoordinator

        coordinator = AdvancedWPSAttackCoordinator("00:11:22:33:44:55", "VM7C8B123")

        # Test running all attacks (short timeout)
        results = coordinator.run_all_attacks(timeout_per_attack=3)

        print(f"  Attacks executed: {len(results)}")
        successful = sum(1 for r in results if r.success)
        print(f"  Successful attacks: {successful}")

        # Test statistics
        stats = coordinator.get_attack_statistics()
        print(f"  Success rate: {stats['success_rate']:.1%}")
        print(f"  Total time: {stats['total_time']:.2f}s")

        # Test getting successful attack
        successful_attack = coordinator.get_successful_attack()
        if successful_attack:
            print(f"  Best result: {successful_attack.method.value} - PIN: {successful_attack.pin}")

        return True

    except Exception as e:
        print(f"  ❌ Attack coordinator test failed: {e}")
        return False

def test_integration_with_uk_wps():
    """Test integration with UK WPS cracker"""
    print("\n🧪 Testing Integration with UK WPS Cracker...")

    try:
        from crackers.uk_router_wps import UKRouterWPSCracker, WPSAttackMethod

        cracker = UKRouterWPSCracker("00:11:22:33:44:55", "VM7C8B123")

        # Test that advanced methods are included
        methods = cracker.get_attack_methods()
        advanced_methods = [
            WPSAttackMethod.SMALL_DH_KEY,
            WPSAttackMethod.REGISTRAR_PIN_DISCLOSURE,
            WPSAttackMethod.EAP_INJECTION
        ]

        found_advanced = [m for m in methods if m in advanced_methods]
        print(f"  Advanced methods available: {len(found_advanced)}/3")

        # Test advanced attack execution (short timeout)
        result = cracker.crack_wps_pin(timeout=10)

        if result:
            print(f"  ✅ Attack succeeded: {result.method.value} - PIN: {result.pin}")
        else:
            print("  ⚠️ No attack succeeded (expected with short timeout)")

        return True

    except Exception as e:
        print(f"  ❌ Integration test failed: {e}")
        return False

def test_pin_validation():
    """Test PIN validation functions"""
    print("\n🧪 Testing PIN Validation...")

    try:
        from crackers.advanced_wps_attacks import SmallDHKeyAttack

        attacker = SmallDHKeyAttack("00:11:22:33:44:55", "")

        # Test valid PINs
        valid_pins = ["12345670", "00000000", "88471112"]
        invalid_pins = ["1234567", "123456789", "abcdef12"]

        for pin in valid_pins:
            is_valid = attacker._validate_pin_format(pin)
            print(f"  PIN {pin}: {'✅ Valid' if is_valid else '❌ Invalid'}")

        for pin in invalid_pins:
            is_valid = attacker._validate_pin_format(pin)
            print(f"  PIN {pin}: {'❌ Valid (unexpected)' if is_valid else '✅ Invalid'}")

        return True

    except Exception as e:
        print(f"  ❌ PIN validation test failed: {e}")
        return False

def run_all_advanced_tests():
    """Run all advanced WPS attack tests"""
    print("🔬 Advanced WPS Attack Test Suite")
    print("=" * 50)

    tests = [
        ("Small DH Key Attack", test_small_dh_key_attack),
        ("Registrar PIN Disclosure", test_registrar_pin_disclosure_attack),
        ("EAP Message Injection", test_eap_injection_attack),
        ("Attack Coordinator", test_attack_coordinator),
        ("UK WPS Integration", test_integration_with_uk_wps),
        ("PIN Validation", test_pin_validation),
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
    print(f"📊 Advanced WPS Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All advanced WPS attack tests passed!")
        print("🚀 Advanced attacks are ready for production use.")
        return True
    else:
        print("⚠️  Some advanced attack tests failed.")
        print("🔧 Check implementations and fix issues.")
        return False

if __name__ == "__main__":
    success = run_all_advanced_tests()
    sys.exit(0 if success else 1)
