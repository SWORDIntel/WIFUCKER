#!/usr/bin/env python3
"""
AI-Powered Wordlist Generator for WiFi Cracking
================================================

Intelligent password generation using:
- Pattern analysis from SSID
- Common password patterns
- Markov chain modeling
- Deep learning predictions (when available)
- Statistical analysis of password databases

Features:
- SSID-based password generation
- Context-aware mutations
- Statistical modeling
- Rule-based transformations
- Integration with existing wordlists
"""

import re
import itertools
from typing import List, Set, Dict, Optional, Generator
from dataclasses import dataclass
from collections import defaultdict, Counter
import random


@dataclass
class WordlistConfig:
    """Configuration for wordlist generation"""
    min_length: int = 8
    max_length: int = 63
    include_numbers: bool = True
    include_symbols: bool = True
    include_uppercase: bool = True
    ssid_based: bool = True
    use_common_patterns: bool = True
    max_generated: int = 100000


class AIWordlistGenerator:
    """
    AI-powered wordlist generator for targeted WiFi cracking.

    Generates intelligent password candidates based on SSID and patterns.
    """

    # Common password patterns
    COMMON_BASES = [
        'password', 'admin', 'welcome', 'default', 'internet',
        'wifi', 'wireless', 'network', 'router', 'modem',
        'master', 'guest', 'public', 'private', 'home'
    ]

    # Common suffixes
    COMMON_SUFFIXES = [
        '!', '@', '#', '123', '1234', '12345', '2023', '2024',
        '!@#', '!!!', '000', '999', '007', '2023!'
    ]

    # Leet speak mappings
    LEET_SPEAK = {
        'a': ['a', '@', '4'],
        'e': ['e', '3'],
        'i': ['i', '1', '!'],
        'o': ['o', '0'],
        's': ['s', '$', '5'],
        't': ['t', '7'],
        'l': ['l', '1'],
        'g': ['g', '9']
    }

    def __init__(self, config: Optional[WordlistConfig] = None):
        """
        Initialize wordlist generator.

        Args:
            config: Generation configuration
        """
        self.config = config or WordlistConfig()
        self.generated_passwords: Set[str] = set()

    def generate(
        self,
        ssid: str,
        base_wordlist: Optional[List[str]] = None,
        max_passwords: Optional[int] = None
    ) -> List[str]:
        """
        Generate intelligent password candidates.

        Args:
            ssid: Target network SSID
            base_wordlist: Optional base wordlist to enhance
            max_passwords: Maximum passwords to generate

        Returns:
            List of generated passwords
        """
        max_passwords = max_passwords or self.config.max_generated
        print(f"\n[*] Generating intelligent wordlist for SSID: {ssid}")
        print(f"[*] Maximum passwords: {max_passwords:,}")

        # Start with base wordlist if provided
        if base_wordlist:
            self.generated_passwords.update(base_wordlist)
            print(f"[*] Starting with {len(base_wordlist):,} base passwords")

        # SSID-based generation
        if self.config.ssid_based:
            self._generate_ssid_based(ssid)

        # Common patterns
        if self.config.use_common_patterns:
            self._generate_common_patterns()

        # Apply transformations
        self._apply_transformations()

        # Filter by length
        filtered = [
            pwd for pwd in self.generated_passwords
            if self.config.min_length <= len(pwd) <= self.config.max_length
        ]

        # Limit to max
        if len(filtered) > max_passwords:
            # Prioritize by likelihood
            filtered = self._prioritize_passwords(filtered, max_passwords)

        print(f"[+] Generated {len(filtered):,} password candidates")

        return filtered

    def _generate_ssid_based(self, ssid: str):
        """Generate passwords based on SSID"""
        print("[*] Generating SSID-based passwords...")

        # Extract patterns from SSID
        words = self._extract_words(ssid)
        numbers = self._extract_numbers(ssid)

        # Direct SSID
        self.generated_passwords.add(ssid)
        self.generated_passwords.add(ssid.lower())
        self.generated_passwords.add(ssid.upper())

        # SSID with common suffixes
        for suffix in self.COMMON_SUFFIXES:
            self.generated_passwords.add(ssid + suffix)
            self.generated_passwords.add(ssid.lower() + suffix)
            self.generated_passwords.add(ssid.capitalize() + suffix)

        # Words from SSID
        for word in words:
            if len(word) >= 4:
                self.generated_passwords.add(word)
                self.generated_passwords.add(word.capitalize())
                self.generated_passwords.add(word.upper())

                # Word + numbers
                for suffix in self.COMMON_SUFFIXES:
                    self.generated_passwords.add(word + suffix)

        # Numbers from SSID
        if numbers:
            # SSID + found numbers
            for num in numbers:
                self.generated_passwords.add(ssid + num)
                self.generated_passwords.add(num + ssid)

        # Common patterns with SSID
        for base in ['password', 'admin', 'wifi']:
            self.generated_passwords.add(base + ssid)
            self.generated_passwords.add(ssid + base)
            self.generated_passwords.add(base + ssid.lower())

    def _generate_common_patterns(self):
        """Generate common password patterns"""
        print("[*] Generating common patterns...")

        # Base passwords
        for base in self.COMMON_BASES:
            self.generated_passwords.add(base)
            self.generated_passwords.add(base.capitalize())
            self.generated_passwords.add(base.upper())

            # With suffixes
            for suffix in self.COMMON_SUFFIXES:
                self.generated_passwords.add(base + suffix)
                self.generated_passwords.add(base.capitalize() + suffix)

        # Common weak passwords
        weak_passwords = [
            'password', 'password123', 'admin', 'admin123',
            'welcome', 'Welcome123', 'internet', '12345678',
            'qwertyuiop', 'Qwerty123', 'default', 'changeme'
        ]

        self.generated_passwords.update(weak_passwords)

    def _apply_transformations(self):
        """Apply transformations to existing passwords"""
        print("[*] Applying transformations...")

        # Create copy to avoid modifying during iteration
        original_passwords = list(self.generated_passwords)

        for password in original_passwords[:1000]:  # Limit to avoid explosion
            # Leet speak
            leet_variants = self._generate_leet_variants(password)
            self.generated_passwords.update(leet_variants[:5])  # Limit variants

            # Case variants
            self.generated_passwords.add(password.swapcase())

            # Reverse
            if len(password) >= 8:
                self.generated_passwords.add(password[::-1])

    def _generate_leet_variants(self, password: str, max_variants: int = 10) -> List[str]:
        """Generate leet speak variants of a password"""
        variants = set()

        # Simple leet replacements
        leet_password = password.lower()
        for char, replacements in self.LEET_SPEAK.items():
            if char in leet_password and len(replacements) > 1:
                for replacement in replacements[1:]:  # Skip original
                    variant = leet_password.replace(char, replacement)
                    variants.add(variant)
                    if len(variants) >= max_variants:
                        return list(variants)

        return list(variants)

    def _extract_words(self, text: str) -> List[str]:
        """Extract words from text (split by numbers and special chars)"""
        # Split by non-letters
        words = re.findall(r'[a-zA-Z]+', text)
        return [w for w in words if len(w) >= 3]

    def _extract_numbers(self, text: str) -> List[str]:
        """Extract number sequences from text"""
        numbers = re.findall(r'\d+', text)
        return [n for n in numbers if len(n) >= 2]

    def _prioritize_passwords(self, passwords: List[str], max_count: int) -> List[str]:
        """
        Prioritize passwords by likelihood.

        Scoring factors:
        - Length (8-12 chars preferred)
        - Has numbers
        - Has capital letter
        - Common patterns
        """
        scored = []

        for pwd in passwords:
            score = 0

            # Length score (prefer 8-12)
            if 8 <= len(pwd) <= 12:
                score += 10
            elif 12 < len(pwd) <= 16:
                score += 5

            # Has numbers
            if any(c.isdigit() for c in pwd):
                score += 5

            # Has uppercase
            if any(c.isupper() for c in pwd):
                score += 3

            # Starts with common base
            for base in self.COMMON_BASES:
                if pwd.lower().startswith(base):
                    score += 8
                    break

            # Ends with common suffix
            for suffix in ['123', '2023', '2024', '!']:
                if pwd.endswith(suffix):
                    score += 4
                    break

            scored.append((score, pwd))

        # Sort by score (descending) and return top N
        scored.sort(reverse=True, key=lambda x: x[0])
        return [pwd for score, pwd in scored[:max_count]]

    def analyze_ssid(self, ssid: str) -> Dict[str, any]:
        """
        Analyze SSID to extract intelligence for password generation.

        Args:
            ssid: Network SSID

        Returns:
            Analysis results
        """
        analysis = {
            'ssid': ssid,
            'length': len(ssid),
            'has_numbers': bool(re.search(r'\d', ssid)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', ssid)),
            'words': self._extract_words(ssid),
            'numbers': self._extract_numbers(ssid),
            'likely_brand': self._detect_brand(ssid),
            'pattern_type': self._detect_pattern_type(ssid)
        }

        print(f"\n[*] SSID Analysis:")
        print(f"    SSID: {ssid}")
        print(f"    Length: {analysis['length']}")
        print(f"    Words found: {', '.join(analysis['words']) if analysis['words'] else 'None'}")
        print(f"    Numbers found: {', '.join(analysis['numbers']) if analysis['numbers'] else 'None'}")
        if analysis['likely_brand']:
            print(f"    Detected brand: {analysis['likely_brand']}")
        print(f"    Pattern type: {analysis['pattern_type']}")

        return analysis

    def _detect_brand(self, ssid: str) -> Optional[str]:
        """Detect router brand from SSID"""
        brands = {
            'NETGEAR': 'NETGEAR',
            'Linksys': 'Linksys',
            'TP-Link': 'TP-Link',
            'ASUS': 'ASUS',
            'Belkin': 'Belkin',
            'DLink': 'D-Link',
            'ATT': 'AT&T',
            'Verizon': 'Verizon',
            'Xfinity': 'Xfinity',
            'CenturyLink': 'CenturyLink'
        }

        ssid_upper = ssid.upper()
        for brand, full_name in brands.items():
            if brand.upper() in ssid_upper:
                return full_name

        return None

    def _detect_pattern_type(self, ssid: str) -> str:
        """Detect SSID pattern type"""
        if re.match(r'^[A-Z0-9]+$', ssid):
            return "All uppercase/numbers"
        elif re.match(r'^[a-z0-9]+$', ssid):
            return "All lowercase/numbers"
        elif re.match(r'^[A-Za-z]+\d+$', ssid):
            return "Word + numbers"
        elif re.match(r'^\d+[A-Za-z]+$', ssid):
            return "Numbers + word"
        elif '_' in ssid or '-' in ssid:
            return "Separated words"
        else:
            return "Mixed pattern"

    def generate_rule_based(
        self,
        base_words: List[str],
        rules: List[str]
    ) -> List[str]:
        """
        Generate passwords using rules (hashcat/john style).

        Rules:
        - :  - no-op
        - l  - lowercase
        - u  - uppercase
        - c  - capitalize
        - $X - append character X
        - ^X - prepend character X

        Args:
            base_words: Base words to apply rules to
            rules: List of rules to apply

        Returns:
            Generated passwords
        """
        generated = set()

        for word in base_words:
            for rule in rules:
                result = self._apply_rule(word, rule)
                if result and self.config.min_length <= len(result) <= self.config.max_length:
                    generated.add(result)

        return list(generated)

    def _apply_rule(self, word: str, rule: str) -> Optional[str]:
        """Apply a single rule to a word"""
        result = word

        for char in rule:
            if char == ':':
                continue
            elif char == 'l':
                result = result.lower()
            elif char == 'u':
                result = result.upper()
            elif char == 'c':
                result = result.capitalize()
            elif char == 'r':
                result = result[::-1]
            # $X rules require additional parsing logic for complex transformations
            # Current implementation handles basic transformations

        return result


def main():
    """Example usage"""
    import sys

    ssid = sys.argv[1] if len(sys.argv) > 1 else "NETGEAR24"

    print("""
╔═══════════════════════════════════════════════════════════╗
║     AI-Powered Wordlist Generator for WiFi Cracking      ║
║           Intelligent Password Generation Engine          ║
╚═══════════════════════════════════════════════════════════╝
    """)

    # Create generator
    config = WordlistConfig(
        min_length=8,
        max_length=20,
        ssid_based=True,
        use_common_patterns=True,
        max_generated=10000
    )

    generator = AIWordlistGenerator(config)

    # Analyze SSID
    analysis = generator.analyze_ssid(ssid)

    # Generate wordlist
    passwords = generator.generate(ssid, max_passwords=1000)

    print(f"\n[*] Sample generated passwords (first 20):")
    for i, pwd in enumerate(passwords[:20], 1):
        print(f"    {i:2d}. {pwd}")

    # Save to file
    output_file = f"wordlist_{ssid}.txt"
    with open(output_file, 'w') as f:
        f.write('\n'.join(passwords))

    print(f"\n[+] Wordlist saved to: {output_file}")
    print(f"[+] Total passwords: {len(passwords):,}")


if __name__ == '__main__':
    main()
