#!/usr/bin/env python3
"""
EE WiFi Cracker Module
Specialized for EE (BT) Smart Hub default passwords
Supports 12-14 character numeric patterns and common EE password schemes
"""

import random
import itertools
from typing import List, Set, Optional
from dataclasses import dataclass


@dataclass
class EEPasswordPattern:
    """EE WiFi password pattern"""
    pattern_type: str
    description: str
    examples: List[str]


class EEWiFiCracker:
    """EE WiFi specific password cracker"""

    # Known EE WiFi password patterns
    EE_PATTERNS = [
        EEPasswordPattern(
            pattern_type="Sequential Numbers",
            description="Sequential or reverse sequential numbers",
            examples=[
                "123456789012", "1234567890123", "12345678901234",
                "987654321098", "9876543210987", "98765432109876"
            ]
        ),
        EEPasswordPattern(
            pattern_type="Repeated Digits",
            description="Same digit repeated",
            examples=[
                "111111111111", "1111111111111", "11111111111111",
                "222222222222", "2222222222222", "22222222222222",
                "000000000000", "0000000000000", "00000000000000",
                "999999999999", "9999999999999", "99999999999999"
            ]
        ),
        EEPasswordPattern(
            pattern_type="Pattern Repeat",
            description="Repeating number patterns",
            examples=[
                "123123123123", "1231231231231", "12312312312312",
                "456456456456", "4564564564564", "45645645645645",
                "789789789789", "7897897897897", "78978978978978"
            ]
        ),
        EEPasswordPattern(
            pattern_type="Incremental",
            description="Incrementing number patterns",
            examples=[
                "123456789012", "234567890123", "345678901234",
                "456789012345", "567890123456", "678901234567"
            ]
        ),
        EEPasswordPattern(
            pattern_type="EE Brand + Numbers",
            description="EE brand names with numbers",
            examples=[
                "EEBrightBox2024", "BrightBoxEE2024", "EEHub2024",
                "SmartHubEE2024", "EEWifi2024", "BrightBox2024"
            ]
        )
    ]

    # Common EE router SSID patterns
    EE_SSIDS = [
        "EE-", "BT-", "EE-Hub-", "BT-Hub-", "BrightBox-", "EEBrightBox",
        "BTOpenreach", "BTHomeHub", "EEHome", "EESmart"
    ]

    @staticmethod
    def is_ee_network(ssid: str) -> bool:
        """
        Check if network appears to be an EE/BT network

        Args:
            ssid: Network SSID

        Returns:
            True if likely EE network
        """
        ssid_lower = ssid.lower()
        return any(pattern.lower() in ssid_lower for pattern in EEWiFiCracker.EE_SSIDS)

    @staticmethod
    def generate_sequential_patterns(count: int = 1000) -> List[str]:
        """
        Generate sequential number patterns (12-14 digits)

        Args:
            count: Number of patterns to generate

        Returns:
            List of sequential passwords
        """
        passwords = set()

        # Basic sequential patterns
        base_patterns = [
            "123456789012",  # 12 digits
            "987654321098",  # 12 digits reversed
        ]

        for pattern in base_patterns:
            passwords.add(pattern)
            # Extend to 13-14 digits
            for i in range(1, 5):
                extended = pattern + str(i)
                passwords.add(extended)

        # Generate variations
        while len(passwords) < count:
            # Random sequential starting point
            start = random.randint(0, 7)
            length = random.choice([12, 13, 14])

            pattern = ""
            for i in range(length):
                pattern += str((start + i) % 10)

            passwords.add(pattern)

        return sorted(list(passwords))[:count]

    @staticmethod
    def generate_repeated_patterns(count: int = 1000) -> List[str]:
        """
        Generate repeated digit patterns

        Args:
            count: Number of patterns to generate

        Returns:
            List of repeated digit passwords
        """
        passwords = set()

        # All same digits
        for digit in "0123456789":
            for length in [12, 13, 14]:
                pattern = digit * length
                passwords.add(pattern)

        # Alternating patterns
        alternating = [
            "121212121212", "212121212121", "343434343434",
            "454545454545", "565656565656", "676767676767"
        ]

        for pattern in alternating:
            passwords.add(pattern)
            # Extend patterns
            passwords.add(pattern + "1")
            passwords.add(pattern + "2")

        # Fill with random if needed
        while len(passwords) < count:
            digit = random.choice("0123456789")
            length = random.choice([12, 13, 14])
            pattern = digit * length
            passwords.add(pattern)

        return sorted(list(passwords))[:count]

    @staticmethod
    def generate_pattern_repeat(count: int = 1000) -> List[str]:
        """
        Generate repeating pattern passwords

        Args:
            count: Number of patterns to generate

        Returns:
            List of pattern repeat passwords
        """
        passwords = set()

        # Common repeating patterns
        base_patterns = ["123", "456", "789", "321", "654", "987"]

        for base in base_patterns:
            # Repeat pattern to fill 12-14 digits
            for length in [12, 13, 14]:
                repeats = length // len(base)
                remainder = length % len(base)
                pattern = base * repeats + base[:remainder]
                passwords.add(pattern)

        # Mathematical patterns
        math_patterns = [
            "246813579024", "135792468013", "864213579086",
            "112233445566", "223344556677", "334455667788"
        ]

        passwords.update(math_patterns)

        # Generate more variations
        while len(passwords) < count:
            # Random pattern repeat
            pattern_len = random.choice([2, 3, 4])
            base_pattern = ''.join(random.choice("0123456789") for _ in range(pattern_len))
            total_len = random.choice([12, 13, 14])

            repeats = total_len // len(base_pattern)
            remainder = total_len % len(base_pattern)
            password = base_pattern * repeats + base_pattern[:remainder]
            passwords.add(password)

        return sorted(list(passwords))[:count]

    @staticmethod
    def generate_brand_patterns(count: int = 500) -> List[str]:
        """
        Generate EE brand + number patterns

        Args:
            count: Number of patterns to generate

        Returns:
            List of brand-based passwords
        """
        passwords = set()

        # EE brand bases
        brands = [
            "EE", "BT", "BrightBox", "SmartHub", "EEHub", "BTHome",
            "EEBrightBox", "EESmart", "BTBrightBox", "EEWifi"
        ]

        # Numbers to append
        numbers = [
            "2024", "2023", "2025", "123", "1234", "2024!",
            "2023!", "123!", "2024!!", "1234!"
        ]

        # Generate combinations
        for brand in brands:
            for number in numbers:
                passwords.add(brand + number)
                passwords.add(number + brand)
                passwords.add(brand + number + "!")

        # Add some longer numeric patterns that might follow brand names
        for brand in brands[:5]:  # Limit to avoid explosion
            # Add 8-10 digit numbers
            for _ in range(20):
                digits = ''.join(random.choice("0123456789") for _ in range(random.choice([8, 9, 10])))
                passwords.add(brand + digits)

        return sorted(list(passwords))[:count]

    @staticmethod
    def generate_all_patterns(count_per_type: int = 1000) -> List[str]:
        """
        Generate comprehensive EE WiFi password list

        Args:
            count_per_type: Number of passwords per pattern type

        Returns:
            Combined list of all EE WiFi patterns
        """
        passwords = set()

        # Generate each pattern type
        passwords.update(EEWiFiCracker.generate_sequential_patterns(count_per_type))
        passwords.update(EEWiFiCracker.generate_repeated_patterns(count_per_type))
        passwords.update(EEWiFiCracker.generate_pattern_repeat(count_per_type))
        passwords.update(EEWiFiCracker.generate_brand_patterns(count_per_type // 2))

        # Add some known defaults that might not be caught by generators
        known_defaults = [
            "password123", "admin123456", "EEBrightBox",
            "BrightBox123", "EESmartHub", "BT12345678",
            "EEHub123456", "123456789EE", "EEWifi1234"
        ]
        passwords.update(known_defaults)

        return sorted(list(passwords))

    @staticmethod
    def smart_generate(ssid: str, count: int = 5000) -> List[str]:
        """
        Smart generation based on SSID analysis

        Args:
            ssid: Network SSID
            count: Number of passwords to generate

        Returns:
            Smart password list based on SSID
        """
        if EEWiFiCracker.is_ee_network(ssid):
            # EE network detected, prioritize EE patterns
            return EEWiFiCracker.generate_all_patterns(count)
        else:
            # Non-EE network, still include some EE patterns as fallback
            ee_patterns = EEWiFiCracker.generate_all_patterns(count // 4)

            # Add some generic patterns for non-EE networks
            generic = [
                "password", "admin123", "12345678", "qwerty123",
                "letmein123", "welcome123", "adminadmin"
            ]
            ee_patterns.extend(generic)

            return ee_patterns[:count]

    @staticmethod
    def get_pattern_info() -> List[EEPasswordPattern]:
        """Get information about available EE patterns"""
        return EEWiFiCracker.EE_PATTERNS.copy()
