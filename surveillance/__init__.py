"""
WiFi Surveillance Detection Module
====================================

Advanced probe request monitoring and surveillance detection system based on
Chasing-Your-Tail-NG methodology.

Features:
- Kismet database integration for probe request monitoring
- Multi-factor persistence scoring (0.0-1.0 scale)
- GPS/location tracking and correlation
- Time window analysis (overlapping windows)
- WiGLE API integration for SSID geolocation
- Multi-format reporting (Markdown, HTML, KML)

For authorized security testing and educational purposes only.
"""

__version__ = "1.0.0"
__author__ = "DavBest WiFi Team"

from .kismet_monitor import KismetMonitor, SecureKismetDB
from .probe_tracker import ProbeTracker, ProbeRequest, TimeWindows
from .persistence_detector import PersistenceDetector, DeviceScore, RiskLevel
from .location_tracker import LocationTracker, GPSLocation, LocationCluster
from .wigle_api import WiGLEAPI, SSIDLocation
from .report_generator import ReportGenerator, ReportFormat

__all__ = [
    "KismetMonitor",
    "SecureKismetDB",
    "ProbeTracker",
    "ProbeRequest",
    "TimeWindows",
    "PersistenceDetector",
    "DeviceScore",
    "RiskLevel",
    "LocationTracker",
    "GPSLocation",
    "LocationCluster",
    "WiGLEAPI",
    "SSIDLocation",
    "ReportGenerator",
    "ReportFormat",
]
