#!/usr/bin/env python3
"""
Router Password Cracker Module
Specialized for router default passwords and brute force patterns
Supports EE wifi, hexadecimal patterns, common router password formats, and UK router WPS attacks
"""

import itertools
import string
from typing import List, Set, Optional, Callable, Dict
from dataclasses import dataclass
from pathlib import Path
from enum import Enum


@dataclass
class RouterPasswordPattern:
    """Router password pattern definition"""
    name: str
    description: str
    charset: str
    length_range: tuple
    examples: List[str]


class RouterPasswordGenerator:
    """Generates router-specific password patterns"""

    # Common router password patterns
    ROUTER_PATTERNS = [
        RouterPasswordPattern(
            name="Hexadecimal (10 digits)",
            description="10-digit hexadecimal passwords (a-f, 0-9)",
            charset="abcdef0123456789",
            length_range=(10, 10),
            examples=["a1b2c3d4e5", "1234567890", "abcdef1234"]
        ),
        RouterPasswordPattern(
            name="EE WiFi Numbers (12-14 chars)",
            description="EE WiFi default passwords (numbers-only, 12-14 characters)",
            charset="0123456789",
            length_range=(12, 14),
            examples=["123456789012", "98765432109876", "111111111111"]
        ),
        RouterPasswordPattern(
            name="Mixed Hex (8-12 chars)",
            description="Mixed hexadecimal patterns for various routers",
            charset="abcdef0123456789",
            length_range=(8, 12),
            examples=["a1b2c3d4", "1234abcd", "deadbeef"]
        ),
        RouterPasswordPattern(
            name="Numeric Serial (10-16 chars)",
            description="Numeric serial number patterns",
            charset="0123456789",
            length_range=(10, 16),
            examples=["1234567890", "0987654321", "111222333444"]
        ),
        RouterPasswordPattern(
            name="Alphanumeric Router (8-12 chars)",
            description="Common router alphanumeric passwords",
            charset="abcdefghijklmnopqrstuvwxyz0123456789",
            length_range=(8, 12),
            examples=["password", "admin123", "router123"]
        ),
        RouterPasswordPattern(
            name="UK Virgin Media (8-14 chars)",
            description="Virgin Media router default passwords",
            charset="abcdefghijklmnopqrstuvwxyz0123456789",
            length_range=(8, 14),
            examples=["virgin123", "superhub", "virgin2024", "vmconnect"]
        ),
        RouterPasswordPattern(
            name="UK BT Hub (8-14 chars)",
            description="BT Home/Smart Hub default passwords",
            charset="abcdefghijklmnopqrstuvwxyz0123456789",
            length_range=(8, 14),
            examples=["bthub1234", "smarthub", "bthomehub", "btbroadband"]
        ),
        RouterPasswordPattern(
            name="UK EE Bright Box (10-16 chars)",
            description="EE Bright Box router default passwords",
            charset="abcdefghijklmnopqrstuvwxyz0123456789",
            length_range=(10, 16),
            examples=["eebrightbox", "brightbox123", "eehub2024", "eesmarthub"]
        ),
        RouterPasswordPattern(
            name="UK Sky Router (8-12 chars)",
            description="Sky broadband router default passwords",
            charset="abcdefghijklmnopqrstuvwxyz0123456789",
            length_range=(8, 12),
            examples=["skybroadband", "skyhub123", "skyrouter", "sky2024"]
        ),
        RouterPasswordPattern(
            name="UK TalkTalk (8-14 chars)",
            description="TalkTalk router default passwords",
            charset="abcdefghijklmnopqrstuvwxyz0123456789",
            length_range=(8, 14),
            examples=["talktalk", "tthub123", "talktalkwifi", "ttbroadband"]
        )
    ]

    # EE WiFi specific patterns
    EE_WIFI_PATTERNS = [
        # EE Smart Hub patterns
        "EEBrightBox",  # Common EE brand
        "BrightBox123",  # Pattern with numbers
        "EEHub2024",     # Year-based
        "SmartHubEE",    # Brand variation
        "EEWifi2023",    # WiFi specific
        "BrightBox2024", # Updated pattern
    ]

    # UK Provider specific patterns
    UK_ROUTER_PATTERNS = {
        "virgin_media": [
            "VirginMedia", "VM1234567", "SuperHub", "Hub2024",
            "Virgin2023", "VMHub2024", "SuperHub2", "SuperHub3",
            "Hub4", "Hub5", "VMConnect"
        ],
        "bt": [
            "BTHub12345", "BT-123456", "HomeHub5", "HomeHub6",
            "SmartHub2", "BTBroadband", "BTHomeHub", "BTWifi",
            "BTConnect", "BTSmartHub"
        ],
        "ee": [
            "EEBrightBox", "BrightBox123", "EEHub2024", "SmartHubEE",
            "EEWifi2023", "BrightBox2024", "EEBroadband", "EEHome",
            "EESmartHub", "EEConnect"
        ],
        "sky": [
            "SkyBroadband", "SkyHub", "SkyRouter", "Sky2024",
            "SkyConnect", "SkyWifi", "SkyHub2"
        ],
        "talk_talk": [
            "TalkTalk", "TT-Hub", "TalkTalkHub", "TTBroadband",
            "TalkTalkWifi", "TTConnect"
        ]
    }

    @staticmethod
    def generate_hex_10digit(count: int = 1000) -> List[str]:
        """
        Generate 10-digit hexadecimal passwords (a-f, 0-9)

        Args:
            count: Number of passwords to generate

        Returns:
            List of 10-digit hex passwords
        """
        charset = "abcdef0123456789"
        passwords = set()

        # Generate some common patterns first
        common_prefixes = ["a1b2c3", "123456", "abcdef", "deadbe", "facebo", "badc0d", "c0ffee"]

        for prefix in common_prefixes:
            remaining = 10 - len(prefix)
            if remaining > 0:
                for combo in itertools.product(charset, repeat=remaining):
                    password = prefix + ''.join(combo)
                    passwords.add(password)
                    if len(passwords) >= count:
                        break
                if len(passwords) >= count:
                    break

        # Fill remaining with random combinations
        while len(passwords) < count:
            password = ''.join(itertools.choice(charset) for _ in range(10))
            passwords.add(password)

        return sorted(list(passwords))[:count]

    @staticmethod
    def generate_ee_wifi_patterns(count: int = 2000) -> List[str]:
        """
        Generate EE WiFi specific password patterns

        Args:
            count: Number of passwords to generate

        Returns:
            List of EE WiFi style passwords
        """
        passwords = set()

        # Add known EE patterns
        passwords.update(RouterPasswordGenerator.EE_WIFI_PATTERNS)

        # Generate numeric patterns (12-14 digits)
        import random

        # Common EE patterns: sequential numbers, repeated digits, etc.
        base_patterns = [
            "123456789012",  # 12 digits
            "987654321098",  # 12 digits reversed
            "111111111111",  # 12 ones
            "222222222222",  # 12 twos
            "123123123123",  # 12 repeating 123
            "456456456456",  # 12 repeating 456
            "000000000000",  # 12 zeros (sometimes default)
            "999999999999",  # 12 nines
        ]

        # Extend to 13-14 characters
        for pattern in base_patterns:
            passwords.add(pattern)
            if len(pattern) < 14:
                passwords.add(pattern + "0")  # Add zero
                passwords.add(pattern + "1")  # Add one
                passwords.add(pattern + "23") # Add 23
                passwords.add(pattern + "456") # Add 456

        # Generate random numeric patterns
        charset = "0123456789"
        lengths = [12, 13, 14]

        while len(passwords) < count:
            length = random.choice(lengths)
            password = ''.join(random.choice(charset) for _ in range(length))
            passwords.add(password)

        # Add some common router patterns that EE might use
        brand_patterns = [
            "EEBrightBox", "BrightBoxEE", "EEHub", "SmartHub",
            "EEWifi", "BrightBox", "EEBroadband", "EEHome"
        ]

        for brand in brand_patterns:
            passwords.add(brand)
            # Add with numbers
            for num in ["2024", "2023", "123", "2025"]:
                passwords.add(brand + num)
                passwords.add(num + brand)

        return sorted(list(passwords))[:count]

    @staticmethod
    def generate_router_patterns(pattern_name: str, count: int = 1000) -> List[str]:
        """
        Generate passwords for a specific router pattern

        Args:
            pattern_name: Name of the pattern to generate
            count: Number of passwords to generate

        Returns:
            List of passwords for the specified pattern
        """
        for pattern in RouterPasswordGenerator.ROUTER_PATTERNS:
            if pattern.name == pattern_name:
                return RouterPasswordGenerator._generate_from_pattern(pattern, count)

        # Fallback to hex if not found
        return RouterPasswordGenerator.generate_hex_10digit(count)

    @staticmethod
    def _generate_from_pattern(pattern: RouterPasswordPattern, count: int) -> List[str]:
        """Generate passwords from a pattern definition"""
        passwords = set()

        # Add examples first
        passwords.update(pattern.examples)

        # Generate combinations
        min_len, max_len = pattern.length_range

        for length in range(min_len, max_len + 1):
            if len(passwords) >= count:
                break

            # Generate combinations for this length
            for combo in itertools.product(pattern.charset, repeat=length):
                password = ''.join(combo)
                passwords.add(password)
                if len(passwords) >= count:
                    break

        return sorted(list(passwords))[:count]

    @staticmethod
    def get_available_patterns() -> List[RouterPasswordPattern]:
        """Get all available router password patterns"""
        return RouterPasswordGenerator.ROUTER_PATTERNS.copy()

    @staticmethod
    def detect_router_type(ssid: str) -> Optional[str]:
        """
        Attempt to detect router type from SSID

        Args:
            ssid: Network SSID

        Returns:
            Suggested pattern name or None
        """
        ssid_lower = ssid.lower()

        # EE/BT patterns
        if any(keyword in ssid_lower for keyword in ['ee-', 'bt-', 'brightbox', 'smarthub']):
            return "EE WiFi Numbers (12-14 chars)"

        # Generic router patterns
        if any(keyword in ssid_lower for keyword in ['router', 'gateway', 'modem', 'ap']):
            return "Alphanumeric Router (8-12 chars)"

        # Hex patterns for technical devices
        if any(keyword in ssid_lower for keyword in ['wifi', 'wlan', 'access']):
            return "Hexadecimal (10 digits)"

        return None

    @staticmethod
    def detect_uk_provider(ssid: str) -> Optional[str]:
        """
        Detect UK provider from SSID

        Args:
            ssid: Network SSID

        Returns:
            Provider name or None
        """
        ssid_lower = ssid.lower()

        # Virgin Media patterns
        if any(keyword in ssid_lower for keyword in ['vm', 'virgin', 'superhub']):
            return 'virgin_media'

        # BT patterns
        if any(keyword in ssid_lower for keyword in ['bt', 'bthub', 'homehub', 'smarthub']):
            return 'bt'

        # EE patterns
        if any(keyword in ssid_lower for keyword in ['ee', 'brightbox', 'ee-']):
            return 'ee'

        # Sky patterns
        if 'sky' in ssid_lower:
            return 'sky'

        # TalkTalk patterns
        if 'talktalk' in ssid_lower or 'tt-' in ssid_lower:
            return 'talk_talk'

        return None

    @staticmethod
    def generate_uk_provider_patterns(provider: str, count: int = 1000) -> List[str]:
        """
        Generate UK provider-specific password patterns

        Args:
            provider: UK provider name ('virgin_media', 'bt', 'ee', 'sky', 'talk_talk')
            count: Number of passwords to generate

        Returns:
            List of provider-specific passwords
        """
        import random
        passwords = set()

        if provider in RouterPasswordGenerator.UK_ROUTER_PATTERNS:
            # Add known patterns
            passwords.update(RouterPasswordGenerator.UK_ROUTER_PATTERNS[provider])

            # Generate variations
            base_patterns = RouterPasswordGenerator.UK_ROUTER_PATTERNS[provider][:10]  # Limit base patterns

            for base in base_patterns:
                passwords.add(base)
                # Add numeric suffixes
                for num in ["123", "2024", "2023", "1234", "admin"]:
                    passwords.add(base + num)
                    passwords.add(num + base)

                # Add common router passwords
                passwords.update(["admin", "password", "12345678", "qwerty123"])

        # Fill with generated patterns if needed
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"

        while len(passwords) < count:
            length = random.randint(8, 14)
            password = ''.join(random.choice(charset) for _ in range(length))
            passwords.add(password)

        return sorted(list(passwords))[:count]


class RouterBruteForceCracker:
    """Router-specific brute force cracker"""

    def __init__(self, target_ssid: str = ""):
        self.target_ssid = target_ssid
        self.generator = RouterPasswordGenerator()

    def generate_wordlist(self, pattern: str, count: int = 10000) -> List[str]:
        """
        Generate router-specific wordlist

        Args:
            pattern: Pattern name to use
            count: Number of passwords to generate

        Returns:
            List of passwords
        """
        if pattern == "Hexadecimal (10 digits)":
            return self.generator.generate_hex_10digit(count)
        elif pattern == "EE WiFi Numbers (12-14 chars)":
            return self.generator.generate_ee_wifi_patterns(count)
        else:
            return self.generator.generate_router_patterns(pattern, count)

    def auto_detect_and_generate(self, count: int = 5000) -> List[str]:
        """
        Auto-detect router type and generate appropriate wordlist

        Args:
            count: Number of passwords to generate

        Returns:
            List of passwords
        """
        if self.target_ssid:
            detected = self.generator.detect_router_type(self.target_ssid)
            if detected:
                return self.generate_wordlist(detected, count)

        # Default to EE WiFi patterns if no specific detection
        return self.generator.generate_ee_wifi_patterns(count)

    def get_available_patterns(self) -> List[str]:
        """Get list of available pattern names"""
        return [p.name for p in self.generator.get_available_patterns()]

    def detect_uk_provider(self) -> Optional[str]:
        """Detect UK provider from target SSID"""
        if not self.target_ssid:
            return None
        return self.generator.detect_uk_provider(self.target_ssid)

    def generate_uk_provider_wordlist(self, count: int = 5000) -> List[str]:
        """
        Generate UK provider-specific wordlist based on detected provider

        Args:
            count: Number of passwords to generate

        Returns:
            List of provider-specific passwords
        """
        provider = self.detect_uk_provider()
        if provider:
            return self.generator.generate_uk_provider_patterns(provider, count)
        else:
            # Fallback to EE WiFi patterns
            return self.generator.generate_ee_wifi_patterns(count)

    def generate_wps_pins(self, mac_address: str = "", count: int = 1000) -> List[str]:
        """
        Generate WPS PINs for UK routers

        Args:
            mac_address: Router MAC address (optional)
            count: Number of PINs to generate

        Returns:
            List of 8-digit WPS PINs
        """
        try:
            from .uk_router_wps import UKRouterWPSCracker
            wps_cracker = UKRouterWPSCracker(mac_address, self.target_ssid)
            return wps_cracker.generate_pins_for_router(count=count)
        except ImportError:
            # Fallback to basic PIN generation
            return self._generate_basic_wps_pins(count)

    def _generate_basic_wps_pins(self, count: int = 1000) -> List[str]:
        """Generate basic WPS PIN patterns as fallback"""
        import random
        pins = set()

        # Common WPS PINs
        common_pins = [
            "12345670", "00000000", "12345678", "87654321",
            "11111111", "22222222", "33333333", "44444444"
        ]
        pins.update(common_pins)

        # Generate random 8-digit pins
        while len(pins) < count:
            pin = str(random.randint(10000000, 99999999))
            pins.add(pin)

        return sorted(list(pins))[:count]

    def comprehensive_uk_attack(self, mac_address: str = "", include_wps: bool = True) -> Dict[str, List[str]]:
        """
        Generate comprehensive UK router attack wordlists

        Args:
            mac_address: Router MAC address for WPS attacks
            include_wps: Whether to include WPS PINs

        Returns:
            Dictionary with different attack categories and their wordlists
        """
        results = {}

        # Detect provider
        provider = self.detect_uk_provider()

        if provider:
            results[f"{provider}_patterns"] = self.generate_uk_provider_wordlist(2000)

        # EE WiFi patterns (always include as many UK routers use similar patterns)
        results["ee_wifi_patterns"] = self.generator.generate_ee_wifi_patterns(2000)

        # Hex patterns for technical devices
        results["hex_patterns"] = self.generator.generate_hex_10digit(1000)

        # WPS PINs if requested and MAC available
        if include_wps:
            if mac_address:
                results["wps_pins"] = self.generate_wps_pins(mac_address, 1000)
            else:
                results["wps_pins"] = self._generate_basic_wps_pins(500)

        # Generic router patterns
        results["generic_router"] = self.generator.generate_router_patterns(
            "Alphanumeric Router (8-12 chars)", 1000
        )

        return results
