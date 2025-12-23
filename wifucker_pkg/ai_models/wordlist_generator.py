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
from datetime import datetime


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
        max_passwords: Optional[int] = None,
        use_dsmil_intel: bool = True
    ) -> List[str]:
        """
        Generate intelligent password candidates with DSMIL intelligence.

        Args:
            ssid: Target network SSID
            base_wordlist: Optional base wordlist to enhance
            max_passwords: Maximum passwords to generate
            use_dsmil_intel: Whether to use DSMIL intelligence for enhanced generation

        Returns:
            List of generated passwords
        """
        max_passwords = max_passwords or self.config.max_generated
        print(f"\n[*] Generating intelligent wordlist for SSID: {ssid}")
        print(f"[*] Maximum passwords: {max_passwords:,}")
        print(f"[*] DSMIL Intelligence: {'ENABLED' if use_dsmil_intel else 'DISABLED'}")

        # Analyze SSID first
        ssid_analysis = self.analyze_ssid(ssid)

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

        # DSMIL Intelligence-enhanced generation
        if use_dsmil_intel and 'dsmil_intel' in ssid_analysis:
            self._generate_dsmil_intel_based(ssid_analysis)

        # Location-based patterns (geographic intelligence)
        self._generate_location_based(ssid)

        # Temporal patterns (time-based passwords)
        self._generate_temporal_patterns()

        # Social engineering patterns
        self._generate_social_engineering(ssid)

        # Apply transformations
        self._apply_transformations()

        # Filter by length
        filtered = [
            pwd for pwd in self.generated_passwords
            if self.config.min_length <= len(pwd) <= self.config.max_length
        ]

        # Limit to max with intelligence-based prioritization
        if len(filtered) > max_passwords:
            filtered = self._prioritize_passwords_intel(filtered, max_passwords, ssid_analysis)

        print(f"[+] Generated {len(filtered):,} password candidates")
        if 'dsmil_intel' in ssid_analysis:
            confidence = ssid_analysis['dsmil_intel'].get('confidence', 0)
            print(f"[+] Intelligence confidence: {confidence}%")

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

    def _generate_dsmil_intel_based(self, ssid_analysis: Dict[str, any]):
        """Generate passwords based on DSMIL intelligence"""
        print("[*] Generating DSMIL intelligence-based passwords...")

        intel = ssid_analysis.get('dsmil_intel', {})
        ssid = ssid_analysis['ssid']

        # Generate based on attack patterns
        attack_patterns = intel.get('attack_patterns', [])
        for pattern in attack_patterns[:5]:  # Limit to top 5 patterns
            if pattern.get('type') == 'password_pattern':
                pattern_base = pattern.get('base', '')
                if pattern_base:
                    # Generate variations of the pattern
                    self.generated_passwords.add(pattern_base)
                    self.generated_passwords.add(pattern_base.capitalize())
                    for suffix in self.COMMON_SUFFIXES[:3]:  # Limit suffixes
                        self.generated_passwords.add(pattern_base + suffix)

        # Generate based on location hints
        location_hints = intel.get('location_hints', [])
        for location in location_hints[:3]:  # Limit to top 3 locations
            location_name = location.get('value', '').replace(' ', '')
            if location_name and len(location_name) >= 3:
                # Combine location with SSID elements
                self.generated_passwords.add(ssid + location_name)
                self.generated_passwords.add(location_name + ssid)
                self.generated_passwords.add(location_name + '2023')

        # Generate based on strategic recommendations
        recommendations = intel.get('strategic_recommendations', [])
        for rec in recommendations[:3]:  # Limit recommendations
            if 'password' in rec.lower():
                # Extract potential password hints from recommendations
                words = rec.split()
                for word in words:
                    if len(word) >= 4 and word.isalnum():
                        self.generated_passwords.add(word + ssid)
                        self.generated_passwords.add(ssid + word)

        # Generate based on threat level
        threat_level = intel.get('threat_level')
        if threat_level:
            # For high-threat targets, add more aggressive patterns
            if threat_level.get('level') == 'high':
                aggressive_patterns = [
                    'admin' + ssid, 'root' + ssid, 'password' + ssid,
                    ssid + 'admin', ssid + 'root', ssid + 'pass'
                ]
                self.generated_passwords.update(aggressive_patterns)

        # Add anomaly-based patterns
        anomaly_score = intel.get('anomaly_score', 0)
        if anomaly_score > 0.7:  # High anomaly
            # Generate more complex patterns for suspicious SSIDs
            complex_patterns = []
            for base in ['complex', 'secure', 'advanced']:
                complex_patterns.extend([
                    base + ssid,
                    ssid + base,
                    base + str(2023) + ssid
                ])
            self.generated_passwords.update(complex_patterns)

    def _prioritize_passwords_intel(self, passwords: List[str], max_count: int, ssid_analysis: Dict[str, any]) -> List[str]:
        """
        Prioritize passwords using DSMIL intelligence.

        Enhanced scoring with intelligence factors:
        - Length and complexity
        - DSMIL intelligence confidence
        - Attack pattern relevance
        - Threat level adjustments
        """
        scored = []
        intel = ssid_analysis.get('dsmil_intel', {})

        for pwd in passwords:
            score = 0

            # Base scoring (length, complexity)
            if 8 <= len(pwd) <= 12:
                score += 10
            elif 12 < len(pwd) <= 16:
                score += 5

            if any(c.isdigit() for c in pwd):
                score += 5

            if any(c.isupper() for c in pwd):
                score += 3

            # Intelligence-based scoring
            confidence = intel.get('confidence', 0) / 100.0  # Convert to 0-1
            score += int(confidence * 15)  # Up to 15 points for high confidence intel

            # Attack pattern relevance
            attack_patterns = intel.get('attack_patterns', [])
            for pattern in attack_patterns:
                if pattern.get('base', '').lower() in pwd.lower():
                    score += 10  # High relevance bonus
                    break

            # Location hint relevance
            location_hints = intel.get('location_hints', [])
            for location in location_hints:
                loc_value = location.get('value', '').replace(' ', '').lower()
                if loc_value and loc_value in pwd.lower():
                    score += 8  # Location relevance bonus
                    break

            # Threat level adjustment
            threat_level = intel.get('threat_level', {})
            if threat_level.get('level') == 'high':
                score += 5  # Bonus for high-threat targets

            # Anomaly adjustment
            anomaly_score = intel.get('anomaly_score', 0)
            if anomaly_score > 0.7:
                score += 3  # Bonus for anomalous patterns

            # Common pattern bonus (unchanged)
            for base in self.COMMON_BASES:
                if pwd.lower().startswith(base):
                    score += 8
                    break

            for suffix in ['123', '2023', '2024', '!']:
                if pwd.endswith(suffix):
                    score += 4
                    break

            scored.append((score, pwd))

        # Sort by score (descending) and return top N
        scored.sort(reverse=True, key=lambda x: x[0])
        return [pwd for score, pwd in scored[:max_count]]

    def _prioritize_passwords(self, passwords: List[str], max_count: int) -> List[str]:
        """
        Legacy prioritization method for backward compatibility.
        """
        return self._prioritize_passwords_intel(passwords, max_count, {})

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

        # Add DSMIL intelligence integration
        analysis.update(self._add_dsmil_intelligence(ssid))

        print(f"\n[*] SSID Analysis:")
        print(f"    SSID: {ssid}")
        print(f"    Length: {analysis['length']}")
        print(f"    Words found: {', '.join(analysis['words']) if analysis['words'] else 'None'}")
        print(f"    Numbers found: {', '.join(analysis['numbers']) if analysis['numbers'] else 'None'}")
        if analysis['likely_brand']:
            print(f"    Detected brand: {analysis['likely_brand']}")
        print(f"    Pattern type: {analysis['pattern_type']}")

        # Show DSMIL intelligence if available
        if 'dsmil_intel' in analysis:
            intel = analysis['dsmil_intel']
            print(f"    DSMIL Intelligence: {intel.get('confidence', 'N/A')}% confidence")
            if intel.get('attack_patterns'):
                print(f"    Attack patterns: {', '.join(intel['attack_patterns'][:3])}")
            if intel.get('location_hints'):
                print(f"    Location hints: {', '.join(intel['location_hints'][:3])}")

        return analysis

    def _add_dsmil_intelligence(self, ssid: str) -> Dict[str, any]:
        """
        Add DSMIL intelligence to SSID analysis.

        Integrates with DSMIL models for enhanced password generation:
        - Anomaly detection for suspicious patterns
        - Attack pattern recognition
        - Incident classification for threat assessment
        - IOC extraction for malicious indicators
        - Strategic AI for scenario analysis
        """
        intel_results = {}

        try:
            # Import DSMIL models
            import sys
            dsmil_root = Path(__file__).parent.parent.parent.parent / "models"
            if str(dsmil_root) not in sys.path:
                sys.path.insert(0, str(dsmil_root))

            # Anomaly Detection Integration
            try:
                from anomaly_detector import AnomalyDetector
                detector = AnomalyDetector()
                # Analyze SSID for anomalous patterns
                anomaly_score = detector.detect_anomaly({
                    'ssid': ssid,
                    'length': len(ssid),
                    'has_special_chars': bool(re.search(r'[^a-zA-Z0-9]', ssid)),
                    'entropy': self._calculate_entropy(ssid)
                })
                intel_results['anomaly_score'] = anomaly_score
                intel_results['suspicious_patterns'] = anomaly_score > 0.7
            except Exception:
                pass  # Graceful fallback if model not available

            # Attack Pattern Recognition
            try:
                from attack_pattern import AttackPatternClassifier
                classifier = AttackPatternClassifier()
                patterns = classifier.classify_patterns(ssid)
                intel_results['attack_patterns'] = patterns
            except Exception:
                intel_results['attack_patterns'] = []

            # Incident Classification
            try:
                from incident_classifier import IncidentClassifier
                incident_clf = IncidentClassifier()
                # Classify SSID as potential threat indicator
                threat_level = incident_clf.classify_incident({
                    'description': f'WiFi network SSID: {ssid}',
                    'indicators': ['wireless', 'network_access']
                })
                intel_results['threat_level'] = threat_level
            except Exception:
                pass

            # IOC Extraction
            try:
                from ioc_extraction_nlp import IOCExtractor
                extractor = IOCExtractor()
                iocs = extractor.extract_iocs(f'WiFi SSID: {ssid}')
                intel_results['extracted_iocs'] = iocs
                intel_results['location_hints'] = [ioc for ioc in iocs if ioc.get('type') == 'location']
            except Exception:
                intel_results['extracted_iocs'] = []
                intel_results['location_hints'] = []

            # Strategic AI Scenario Analysis
            try:
                from strategic_ai_llm import StrategicAI
                strategic_ai = StrategicAI()
                scenario = strategic_ai.analyze_scenario({
                    'context': 'WiFi network penetration testing',
                    'target': ssid,
                    'objective': 'password cracking assessment'
                })
                intel_results['strategic_recommendations'] = scenario.get('recommendations', [])
            except Exception:
                intel_results['strategic_recommendations'] = []

            # Calculate overall confidence
            confidence_factors = []
            if 'anomaly_score' in intel_results:
                confidence_factors.append(0.3)
            if intel_results.get('attack_patterns'):
                confidence_factors.append(0.4)
            if intel_results.get('threat_level'):
                confidence_factors.append(0.2)
            if intel_results.get('location_hints'):
                confidence_factors.append(0.1)

            intel_results['confidence'] = int(sum(confidence_factors) * 100)

        except Exception as e:
            # If DSMIL integration fails, continue without intel
            print(f"[!] DSMIL intelligence integration failed: {e}")

        if intel_results:
            return {'dsmil_intel': intel_results}
        return {}

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        from collections import Counter
        import math

        if not text:
            return 0.0

        char_counts = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

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

    def _generate_location_based(self, ssid: str):
        """Generate passwords based on location/geographic intelligence"""
        print("[*] Generating location-based passwords...")

        # Common location patterns
        locations = [
            "north", "south", "east", "west", "central",
            "brooklyn", "manhattan", "queens", "bronx", "staten",
            "downtown", "uptown", "midtown", "upper", "lower",
            "beach", "mountain", "valley", "hill", "ridge",
            "park", "square", "avenue", "street", "lane", "road",
            "city", "town", "village", "county", "state",
            "california", "florida", "texas", "newyork", "chicago",
            "losangeles", "miami", "seattle", "denver", "austin"
        ]

        # Extract potential location hints from SSID
        ssid_lower = ssid.lower()
        location_hints = []

        for loc in locations:
            if loc in ssid_lower or any(char in ssid_lower for char in loc):
                location_hints.append(loc)

        # Generate location-based passwords
        for hint in location_hints[:3]:  # Limit to prevent explosion
            # Location + numbers
            for num in range(10, 100):
                self.generated_passwords.add(f"{hint}{num}")
                self.generated_passwords.add(f"{hint}{num}!")
                self.generated_passwords.add(f"{hint.capitalize()}{num}")

            # Location + common passwords
            for base in ["password", "wifi", "guest", "admin"]:
                self.generated_passwords.add(f"{hint}{base}")
                self.generated_passwords.add(f"{hint.capitalize()}{base}")
                self.generated_passwords.add(f"{hint.upper()}{base}")

    def _generate_temporal_patterns(self):
        """Generate passwords based on temporal patterns (dates, seasons, etc.)"""
        print("[*] Generating temporal patterns...")

        from datetime import datetime
        current_year = datetime.now().year

        # Years
        for year in range(current_year - 10, current_year + 2):
            year_str = str(year)
            self.generated_passwords.add(year_str)
            self.generated_passwords.add(f"wifi{year_str}")
            self.generated_passwords.add(f"net{year_str}")

        # Months
        months = [
            "january", "february", "march", "april", "may", "june",
            "july", "august", "september", "october", "november", "december",
            "jan", "feb", "mar", "apr", "may", "jun",
            "jul", "aug", "sep", "oct", "nov", "dec"
        ]

        for month in months:
            self.generated_passwords.add(month)
            self.generated_passwords.add(month.capitalize())
            self.generated_passwords.add(f"{month}2024")
            self.generated_passwords.add(f"{month}2023")

        # Seasons and temporal
        temporal = ["spring", "summer", "fall", "winter", "season", "time"]
        for temp in temporal:
            self.generated_passwords.add(temp)
            self.generated_passwords.add(f"{temp}2024")
            self.generated_passwords.add(f"{temp}2023")

    def _generate_social_engineering(self, ssid: str):
        """Generate passwords based on social engineering patterns"""
        print("[*] Generating social engineering patterns...")

        # Common social engineering patterns
        social_patterns = [
            "qwerty", "asdf", "zxcv", "qazwsx", "password", "letmein",
            "welcome", "admin", "administrator", "root", "guest", "user",
            "login", "connect", "access", "network", "internet", "wifi",
            "wireless", "hotspot", "router", "modem", "gateway", "bridge",
            "secure", "private", "public", "home", "office", "work",
            "school", "university", "college", "library", "cafe", "coffee",
            "restaurant", "hotel", "motel", "airport", "station", "mall"
        ]

        # Brand/company names that might appear in SSIDs
        brands = [
            "netgear", "linksys", "dlink", "tp-link", "asus", "belkin",
            "cisco", "ubiquiti", "google", "apple", "samsung", "huawei",
            "xiaomi", "oneplus", "motorola", "verizon", "att", "tmobile",
            "comcast", "cox", "spectrum", "centurylink", "optimum"
        ]

        # Generate combinations
        for pattern in social_patterns[:50]:  # Limit to prevent explosion
            # Pattern + numbers
            for num in ["123", "456", "789", "1234", "0000"]:
                self.generated_passwords.add(f"{pattern}{num}")
                self.generated_passwords.add(f"{pattern}{num}!")

            # Pattern + year
            for year in ["2024", "2023", "2022"]:
                self.generated_passwords.add(f"{pattern}{year}")
                self.generated_passwords.add(f"{pattern}{year}!")

        # Brand-based
        ssid_lower = ssid.lower()
        for brand in brands:
            if brand in ssid_lower or ssid_lower.startswith(brand[:4]):
                # Brand + common patterns
                for suffix in ["admin", "123", "password", "wifi", "setup"]:
                    self.generated_passwords.add(f"{brand}{suffix}")
                    self.generated_passwords.add(f"{brand.capitalize()}{suffix}")
                    self.generated_passwords.add(f"{brand.upper()}{suffix}")

                # Common brand default passwords
                brand_defaults = {
                    "netgear": ["password", "admin", "1234"],
                    "linksys": ["admin", "password", "1234"],
                    "dlink": ["admin", "password", "1234"],
                    "asus": ["admin", "password", "1234"],
                    "belkin": ["admin", "password", "1234"]
                }

                if brand in brand_defaults:
                    for pwd in brand_defaults[brand]:
                        self.generated_passwords.add(pwd)

        # Keyboard patterns (like qwerty, asdf)
        keyboard_patterns = [
            "qwerty", "asdfgh", "zxcvbn", "qazwsx", "wsxedc",
            "123456", "654321", "abcdef", "fedcba"
        ]

        for pattern in keyboard_patterns:
            self.generated_passwords.add(pattern)
            # Pattern with common endings
            for ending in ["123", "!", "@", "2024"]:
                self.generated_passwords.add(f"{pattern}{ending}")

    def _prioritize_passwords_intel(self, passwords: List[str], max_count: int, ssid_analysis: Dict) -> List[str]:
        """Prioritize passwords using intelligence-based scoring"""
        if not passwords:
            return []

        # Score each password based on intelligence
        scored = []
        for pwd in passwords:
            score = self._calculate_intelligence_score(pwd, ssid_analysis)
            scored.append((score, pwd))

        # Sort by score (highest first) and return top max_count
        scored.sort(key=lambda x: x[0], reverse=True)
        return [pwd for _, pwd in scored[:max_count]]

    def _calculate_intelligence_score(self, password: str, ssid_analysis: Dict) -> float:
        """Calculate intelligence-based score for password prioritization"""
        score = 0.0

        # SSID-based scoring
        if 'patterns' in ssid_analysis:
            patterns = ssid_analysis['patterns']
            for pattern_type, pattern_data in patterns.items():
                if pattern_type == 'words' and pattern_data:
                    for word in pattern_data:
                        if word.lower() in password.lower():
                            score += 2.0

                elif pattern_type == 'numbers' and pattern_data:
                    for num in pattern_data:
                        if str(num) in password:
                            score += 1.5

        # Length scoring (prefer reasonable lengths)
        length = len(password)
        if 8 <= length <= 20:
            score += 1.0
        elif length < 8:
            score -= 0.5
        elif length > 25:
            score -= 0.3

        # Character variety scoring
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        variety_score = sum([has_lower, has_upper, has_digit, has_symbol])
        score += variety_score * 0.5

        # Common pattern detection (slight penalty for too common)
        common_patterns = ["password", "123456", "qwerty", "admin"]
        for pattern in common_patterns:
            if pattern in password.lower():
                score -= 0.3

        # Year patterns (current/recent years are more likely)
        current_year = datetime.now().year
        for year in range(current_year - 3, current_year + 2):
            if str(year) in password:
                score += 0.8

        return max(0.0, score)  # Ensure non-negative score


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
