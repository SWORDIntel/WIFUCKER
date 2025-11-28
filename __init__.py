"""
WiFi Security Suite with OpenVINO Hardware Acceleration
========================================================

Advanced WiFi security assessment and PCAP cracking with hardware acceleration
using Intel OpenVINO (NPU, NCS2, ARC GPU).

Features:
- PCAP parsing for WPA/WPA2/WPA3 handshakes
- Hardware-accelerated password cracking (NPU, NCS2, ARC GPU)
- AI-powered wordlist generation
- Multi-device parallel processing
- Real-time progress tracking
- Surveillance detection via Kismet integration (NEW!)
- Multi-factor persistence scoring
- GPS location tracking and correlation
- Multi-format reporting (Markdown, HTML, KML)

Supported Hardware:
- Intel NPU (Neural Processing Unit) - Military-grade acceleration
- Intel NCS2 (Neural Compute Stick 2) - USB acceleration
- Intel ARC GPU - High-performance graphics acceleration
- CPU fallback for compatibility

For authorized security testing and educational purposes only.
"""

__version__ = "2.0.0"
__author__ = "DavBest WiFi Team"

from .parsers import pcap_parser
from .crackers import openvino_cracker
from .ai_models import wordlist_generator
from .surveillance import (
    kismet_monitor,
    probe_tracker,
    persistence_detector,
    location_tracker,
    wigle_api,
    report_generator,
)

__all__ = [
    "pcap_parser",
    "openvino_cracker",
    "wordlist_generator",
    "kismet_monitor",
    "probe_tracker",
    "persistence_detector",
    "location_tracker",
    "wigle_api",
    "report_generator",
]
