#!/usr/bin/env python3
"""
IoT WPS Attack Tests
Tests for IoT device WPS cracking functionality including HP printers
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import subprocess

# Add the wifucker_pkg directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'wifucker_pkg'))

# Import test dependencies
try:
    from crackers.iot_wps_cracker import (
        IoTWPSCracker,
        IoTDevice,
        IoTDeviceType,
        HPPrinterWPSDatabase,
        HPWPSPinGenerator,
        IoTDeviceDetector,
        IoTDeviceScanner,
        IoTDevicePivot,
        WPSAttackMethod,
        WPSAttackResult
    )
    DEPENDENCIES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: IoT WPS dependencies not available: {e}")
    DEPENDENCIES_AVAILABLE = False

@unittest.skipUnless(DEPENDENCIES_AVAILABLE, "IoT WPS dependencies not available")
class TestHPPrinterWPSDatabase(unittest.TestCase):
    """Test HP printer database functionality"""

    def test_detect_hp_printer_envy_series(self):
        """Test HP Envy printer detection"""
        # Test Envy 1000 series
        result = HPPrinterWPSDatabase.detect_hp_printer("ENVY1000")
        self.assertIsNotNone(result)
        self.assertEqual(result["series"], "Envy 1000")

        # Test OfficeJet
        result = HPPrinterWPSDatabase.detect_hp_printer("OfficeJet123")
        self.assertIsNotNone(result)
        self.assertIn("OfficeJet", result["series"])

    def test_detect_non_hp_printer(self):
        """Test non-HP device detection"""
        result = HPPrinterWPSDatabase.detect_hp_printer("NETGEAR123")
        self.assertIsNone(result)

    def test_get_model_info(self):
        """Test model information retrieval"""
        model_info = HPPrinterWPSDatabase.HP_MODELS["envy_1000"]
        self.assertIn("default_pins", model_info)
        self.assertIn("vulnerabilities", model_info)
        self.assertIn("series", model_info)

class TestHPWPSPinGenerator(unittest.TestCase):
    """Test HP WPS PIN generation"""

    def test_generate_default_pins(self):
        """Test default PIN generation"""
        model_info = {"default_pins": ["12345670", "00000000"]}
        pins = HPWPSPinGenerator.generate_default_pins(model_info)
        self.assertEqual(len(pins), 2)
        self.assertIn("12345670", pins)

    def test_generate_mac_based_pins(self):
        """Test MAC address based PIN generation"""
        mac = "00:11:22:33:44:55"
        model_info = {"vulnerabilities": ["mac_based"]}

        pins = HPWPSPinGenerator.generate_mac_based_pins(mac, model_info)
        self.assertGreater(len(pins), 0)

        # Test invalid MAC
        pins_invalid = HPWPSPinGenerator.generate_mac_based_pins("invalid", model_info)
        self.assertEqual(len(pins_invalid), 0)

    def test_calculate_wps_checksum(self):
        """Test WPS checksum calculation"""
        # Test known values
        checksum = HPWPSPinGenerator._calculate_wps_checksum(1234567)
        self.assertIsInstance(checksum, int)
        self.assertGreaterEqual(checksum, 0)
        self.assertLessEqual(checksum, 9)

class TestIoTDeviceDetector(unittest.TestCase):
    """Test IoT device detection"""

    def test_detect_hp_printer_device(self):
        """Test HP printer device detection"""
        device = IoTDeviceDetector.detect_device("HP-PRINT-12")

        self.assertEqual(device.device_type, IoTDeviceType.HP_PRINTER)
        self.assertEqual(device.vendor, "HP")
        self.assertTrue(device.wps_enabled)

    def test_detect_generic_device(self):
        """Test generic device detection"""
        device = IoTDeviceDetector.detect_device("UnknownDevice123")

        self.assertEqual(device.device_type, IoTDeviceType.GENERIC_IOT)
        self.assertEqual(device.vendor, "Unknown")

    def test_detect_smart_tv(self):
        """Test smart TV detection"""
        device = IoTDeviceDetector.detect_device("SamsungSmartTV")

        self.assertEqual(device.device_type, IoTDeviceType.SMART_TV)
        self.assertTrue(device.wps_enabled)

class TestIoTDeviceScanner(unittest.TestCase):
    """Test IoT device scanning"""

    def setUp(self):
        """Set up test fixtures"""
        self.scanner = IoTDeviceScanner("wlan0")

    @patch('subprocess.run')
    def test_scan_with_airodump(self, mock_subprocess):
        """Test scanning with airodump-ng"""
        # Mock successful airodump scan
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
BSSID,First time seen,Last time seen,channel,Speed,Privacy,Cipher,Authentication,Power,beacons,IV,LAN IP,IP,ESSID

00:11:22:33:44:55,2024-01-01 12:00:00,2024-01-01 12:01:00,6,-1,WPA2,CCMP,PSK,-50,100,0,0.0.0.0,0.0.0.0,HP-PRINT-12
"""
        mock_subprocess.return_value = mock_result

        # Mock file operations by creating the actual CSV file
        csv_content = """BSSID,First time seen,Last time seen,channel,Speed,Privacy,Cipher,Authentication,Power,beacons,IV,LAN IP,IP,ESSID

00:11:22:33:44:55,2024-01-01 12:00:00,2024-01-01 12:01:00,6,-1,WPA2,CCMP,PSK,-50,100,0,0.0.0.0,0.0.0.0,HP-PRINT-12
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', unittest.mock.mock_open(read_data=csv_content)):
            devices = self.scanner.scan_iot_devices(duration=1)

        self.assertGreater(len(devices), 0)
        self.assertEqual(devices[0].device_type, IoTDeviceType.HP_PRINTER)

    @patch('subprocess.run')
    def test_scan_with_iw_fallback(self, mock_subprocess):
        """Test scanning with iw fallback"""
        # Mock airodump failure, iw success
        mock_airodump = Mock()
        mock_airodump.returncode = 1

        mock_iw = Mock()
        mock_iw.returncode = 0
        mock_iw.stdout = """
BSS 00:11:22:33:44:55(on wlan0)
        TSF: 1234567890123 usec (0d, 00:00:00)
        freq: 2437
        beacon interval: 100 TUs
        capability: ESS Privacy ShortPreamble (0x0031)
        signal: -50.00 dBm
        last seen: 1234 ms ago
        SSID: HP-PRINT-12
"""

        mock_subprocess.side_effect = [mock_airodump, mock_iw]

        devices = self.scanner.scan_iot_devices(duration=1)

        self.assertGreater(len(devices), 0)

class TestIoTWPSCracker(unittest.TestCase):
    """Test IoT WPS cracker"""

    def setUp(self):
        """Set up test fixtures"""
        self.cracker = IoTWPSCracker("wlan0")

    def test_initialization(self):
        """Test cracker initialization"""
        self.assertEqual(self.cracker.interface, "wlan0")
        self.assertIsInstance(self.cracker.pin_generator, HPWPSPinGenerator)

    @patch('subprocess.run')
    def test_crack_hp_printer_success(self, mock_subprocess):
        """Test successful HP printer WPS cracking"""
        # Create test device
        device = IoTDevice(
            ssid="HP-PRINT-AB",
            mac_address="00:11:22:33:44:55",
            device_type=IoTDeviceType.HP_PRINTER,
            vendor="HP",
            wps_enabled=True
        )

        # Mock successful reaver execution
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "WPS PIN: '12345670' WPS PIN found! Associated with AP successfully"
        mock_subprocess.return_value = mock_result

        result = self.cracker.crack_hp_printer_wps(device, WPSAttackMethod.DEFAULT_PIN)

        self.assertTrue(result.success)
        self.assertEqual(result.pin_found, "12345670")
        self.assertEqual(result.device, device)

    @patch('subprocess.run')
    def test_crack_hp_printer_failure(self, mock_subprocess):
        """Test failed HP printer WPS cracking"""
        device = IoTDevice(
            ssid="HP-PRINT-AB",
            mac_address="00:11:22:33:44:55",
            device_type=IoTDeviceType.HP_PRINTER,
            vendor="HP",
            wps_enabled=True
        )

        # Mock failed reaver execution
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = "Failed to associate"
        mock_subprocess.return_value = mock_result

        result = self.cracker.crack_hp_printer_wps(device, WPSAttackMethod.DEFAULT_PIN)

        self.assertFalse(result.success)
        self.assertIsNone(result.pin_found)

    def test_get_pin_candidates_default(self):
        """Test getting default PIN candidates"""
        device = IoTDevice(ssid="HP-Print-AB-CD", device_type=IoTDeviceType.HP_PRINTER)
        model_info = {"default_pins": ["12345670", "00000000"]}

        pins = self.cracker._get_pin_candidates(device, WPSAttackMethod.DEFAULT_PIN, model_info)
        self.assertIn("12345670", pins)
        self.assertIn("00000000", pins)

class TestIoTDevicePivot(unittest.TestCase):
    """Test IoT device pivot functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.pivot = IoTDevicePivot("wlan0")

    def test_initialization(self):
        """Test pivot initialization"""
        self.assertEqual(self.pivot.interface, "wlan0")
        self.assertEqual(len(self.pivot.compromised_devices), 0)

    @patch('subprocess.run')
    def test_get_device_ip_success(self, mock_subprocess):
        """Test successful device IP detection"""
        device = IoTDevice(
            ssid="HP-Print-AB-CD",
            mac_address="00:11:22:33:44:55",
            device_type=IoTDeviceType.HP_PRINTER
        )

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "192.168.1.100\t00:11:22:33:44:55"
        mock_subprocess.return_value = mock_result

        ip = self.pivot._get_device_ip(device)
        self.assertEqual(ip, "192.168.1.100")

    @patch('subprocess.run')
    def test_get_device_ip_failure(self, mock_subprocess):
        """Test failed device IP detection"""
        device = IoTDevice(
            ssid="HP-Print-AB-CD",
            mac_address="00:11:22:33:44:55",
            device_type=IoTDeviceType.HP_PRINTER
        )

        mock_result = Mock()
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result

        ip = self.pivot._get_device_ip(device)
        self.assertIsNone(ip)

    @patch('subprocess.run')
    def test_test_pivot_connectivity_success(self, mock_subprocess):
        """Test successful pivot connectivity"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        result = self.pivot._test_pivot_connectivity()
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_test_pivot_connectivity_failure(self, mock_subprocess):
        """Test failed pivot connectivity"""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result

        result = self.pivot._test_pivot_connectivity()
        self.assertFalse(result)

if __name__ == '__main__':
    # Set up test environment
    if DEPENDENCIES_AVAILABLE:
        print("Running IoT WPS tests...")
        unittest.main(verbosity=2)
    else:
        print("IoT WPS dependencies not available. Install required packages:")
        print("  pip install -r requirements.txt")
        print("  sudo ./bootstrap_evil_twin.sh")
        sys.exit(1)
