#!/usr/bin/env python3
"""
Context-Aware Wordlist Generator
Generates password candidates from project/environment context
"""

from typing import List, Set


class ContextWordlistGenerator:
    """Generates wordlist from project-specific context"""

    PROJECT_KEYWORDS = [
        'DSMIL', 'dsmil', 'Dsmil',
        'LAT5150', 'lat5150', 'Lat5150',
        'WIFUCKER', 'wifucker', 'Wifucker', 'WiFucker',
        'Intel', 'intel', 'INTEL',
        'Meteorlake', 'meteorlake', 'METEORLAKE',
        'NPU', 'npu', 'Npu',
    ]

    SYSTEM_WORDS = [
        'debian', 'linux', 'john', 'root', 'admin',
        'quantum', 'crypto', 'secure', 'unlock',
        'steganography', 'hidden', 'secret', 'message',
        'encrypt', 'decrypt', 'password', 'test'
    ]

    TECHNICAL_TERMS = [
        'LAT5150DRVMIL', 'lat5150drvmil',
        'openvino', 'hardware', 'accelerate',
        'GPU', 'gpu', 'accelerator',
        'kernel', 'driver', 'module', 'device'
    ]

    YEARS = ['2024', '2023', '2025', '2021', '2022']
    SPECIAL_NUMS = ['123', '1', '1786', '500', '1000', '2024']
    SPECIAL_CHARS = ['!', '@', '#', '$', '%', '!!', '@#$']

    TEST_PASSWORDS = [
        'TestPassword', 'Test123!', 'Test2024!',
        'Password123', 'Crypto2024', 'SecureTest',
        'Hidden2024', 'Steganography', 'QuantumKey',
        'LAT5150Test', 'DSMIL2024', 'WiFiCracker',
        'IntegrityCheck', 'HardwareTest', 'DriverTest'
    ]

    @staticmethod
    def generate(max_passwords: int = 10000) -> List[str]:
        """
        Generate context-aware wordlist.

        Args:
            max_passwords: Maximum passwords to generate

        Returns:
            List of context-specific passwords
        """
        wordlist = set()

        # Add all base words
        all_words = (
            ContextWordlistGenerator.PROJECT_KEYWORDS +
            ContextWordlistGenerator.SYSTEM_WORDS +
            ContextWordlistGenerator.TECHNICAL_TERMS
        )

        # Generate base passwords from keywords
        for word in all_words:
            wordlist.add(word)
            wordlist.add(word.lower())
            wordlist.add(word.upper())
            wordlist.add(word.capitalize())

        # Add combinations with years
        for word in list(wordlist)[:100]:
            for year in ContextWordlistGenerator.YEARS:
                wordlist.add(word + year)
                wordlist.add(year + word)
                wordlist.add(word + year + '!')

        # Add combinations with special numbers
        for word in list(wordlist)[:100]:
            for num in ContextWordlistGenerator.SPECIAL_NUMS:
                wordlist.add(word + num)
                wordlist.add(num + word)

        # Add combinations with special chars
        for word in list(wordlist)[:100]:
            for char in ContextWordlistGenerator.SPECIAL_CHARS:
                wordlist.add(word + char)

        # Add test passwords
        wordlist.update(ContextWordlistGenerator.TEST_PASSWORDS)

        # Add reverses
        for word in list(wordlist)[:50]:
            if len(word) >= 4:
                wordlist.add(word[::-1])

        # Limit to max
        return sorted(list(wordlist))[:max_passwords]

    @staticmethod
    def generate_with_mutations(max_passwords: int = 10000) -> List[str]:
        """
        Generate context-aware wordlist with additional mutations.

        Args:
            max_passwords: Maximum passwords to generate

        Returns:
            List of mutated context-specific passwords
        """
        base = ContextWordlistGenerator.generate(max_passwords // 2)
        wordlist = set(base)

        # Apply mutations to base
        for word in base[:200]:
            # Case swap
            wordlist.add(word.swapcase())

            # Mixed case
            if len(word) > 2:
                wordlist.add(word[0].upper() + word[1:].lower())

            # Double char suffix
            wordlist.add(word + word[-1])

            # Number suffixes
            for num in ['2024', '123', '1']:
                wordlist.add(word + num)
                wordlist.add(num + word)

        return sorted(list(wordlist))[:max_passwords]
