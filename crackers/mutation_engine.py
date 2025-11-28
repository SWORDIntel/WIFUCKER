#!/usr/bin/env python3
"""
Password Mutation Engine
Generates rule-based mutations for enhanced password cracking
"""

from typing import List, Set


class MutationEngine:
    """Generates password mutations using rule-based transformations"""

    YEARS = ['2023', '2024', '2025', '2026', '123', '1', '12']
    SPECIAL_CHARS = ['!', '@', '#', '$', '%', '!!', '@@', '!@#']
    NUMBERS = ['0', '1', '123', '1234', '12345', '123456']

    @staticmethod
    def apply_mutations(word: str, max_mutations: int = 100) -> List[str]:
        """
        Apply rule-based mutations to a password.

        Args:
            word: Base password to mutate
            max_mutations: Maximum mutations to generate

        Returns:
            List of mutated passwords
        """
        mutations = set([word])

        # Case variations
        mutations.add(word.upper())
        mutations.add(word.capitalize())
        mutations.add(word.lower())

        # Add years
        for year in MutationEngine.YEARS:
            mutations.add(word + year)
            mutations.add(word.capitalize() + year)
            mutations.add(year + word)

        # Add special characters
        for char in MutationEngine.SPECIAL_CHARS[:5]:
            mutations.add(word + char)
            mutations.add(word.capitalize() + char)
            mutations.add(char + word)

        # Leet speak variations
        leet = MutationEngine._leet_speak(word)
        mutations.add(leet)
        mutations.add(leet.upper())

        # Reverse
        if len(word) >= 4:
            mutations.add(word[::-1])
            mutations.add(word[::-1].capitalize())

        # Double characters
        mutations.add(word + word[-1])

        # Limit mutations
        return list(mutations)[:max_mutations]

    @staticmethod
    def _leet_speak(word: str) -> str:
        """Convert to leet speak"""
        mapping = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0',
            's': '$', 't': '7', 'l': '1', 'g': '9'
        }
        result = word.lower()
        for char, replacement in mapping.items():
            result = result.replace(char, replacement)
        return result

    @staticmethod
    def apply_rule_set(words: List[str], rules: List[str]) -> List[str]:
        """
        Apply rule set to wordlist (hashcat-style rules).

        Rules:
        - :        no-op
        - l        lowercase
        - u        uppercase
        - c        capitalize
        - r        reverse
        - $X       append X
        - ^X       prepend X

        Args:
            words: Base wordlist
            rules: Rules to apply

        Returns:
            Transformed wordlist
        """
        results = set()

        for word in words:
            for rule in rules:
                transformed = MutationEngine._apply_single_rule(word, rule)
                if transformed:
                    results.add(transformed)

        return list(results)

    @staticmethod
    def _apply_single_rule(word: str, rule: str) -> str:
        """Apply a single rule to a word"""
        result = word

        i = 0
        while i < len(rule):
            char = rule[i]

            if char == ':':
                pass  # no-op
            elif char == 'l':
                result = result.lower()
            elif char == 'u':
                result = result.upper()
            elif char == 'c':
                result = result.capitalize()
            elif char == 'r':
                result = result[::-1]
            elif char == '$':
                if i + 1 < len(rule):
                    result = result + rule[i + 1]
                    i += 1
            elif char == '^':
                if i + 1 < len(rule):
                    result = rule[i + 1] + result
                    i += 1

            i += 1

        return result

    @staticmethod
    def generate_combinations(base: List[str], count: int = 1000) -> List[str]:
        """
        Generate password combinations from base wordlist.

        Args:
            base: Base wordlist
            count: Maximum combinations to generate

        Returns:
            List of combinations
        """
        combinations = set()

        # Direct mutations
        for word in base[:100]:
            combinations.update(MutationEngine.apply_mutations(word))

        # Common suffixes
        for word in base[:50]:
            for year in MutationEngine.YEARS:
                combinations.add(word.capitalize() + year + '!')
                combinations.add(word + year + '@')

        return list(combinations)[:count]
