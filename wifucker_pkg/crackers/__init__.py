"""
WiFi & PBKDF2 password cracking engines with hardware acceleration.

Modules:
- openvino_cracker: Hardware-accelerated WiFi WPA cracking
- hardware_detector: Detect and optimize hardware for cracking
- pbkdf2_cracker: PBKDF2 password dictionary attack
- mutation_engine: Rule-based password mutations
- context_generator: Context-aware wordlist generation
- router_cracker: Router-specific password patterns (hex, EE WiFi, etc.)
- ee_wifi_cracker: EE/BT Smart Hub specialized cracking
- avx512_wrapper: AVX-512 optimized cracking (C backend)
"""

from .pbkdf2_cracker import PBKDF2Cracker, CrackingResult
from .mutation_engine import MutationEngine
from .context_generator import ContextWordlistGenerator
from .intel_enhanced_cracker import IntelEnhancedCracker, IntelEnhancedResult
from .router_cracker import RouterPasswordGenerator, RouterBruteForceCracker
from .ee_wifi_cracker import EEWiFiCracker

__all__ = [
    "PBKDF2Cracker",
    "CrackingResult",
    "MutationEngine",
    "ContextWordlistGenerator",
    "IntelEnhancedCracker",
    "IntelEnhancedResult",
    "RouterPasswordGenerator",
    "RouterBruteForceCracker",
    "EEWiFiCracker",
    "openvino_cracker",
    "hardware_detector",
    "avx512_wrapper",
]
