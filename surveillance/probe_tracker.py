#!/usr/bin/env python3
"""
Probe Request Tracker with Time Windows
========================================

Tracks wireless probe requests across overlapping time windows for
temporal persistence analysis.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict


@dataclass
class ProbeRequest:
    """Represents a single probe request observation."""
    mac_address: str
    ssid: Optional[str] = None
    signal_strength: int = 0
    latitude: float = 0.0
    longitude: float = 0.0
    timestamp: float = field(default_factory=time.time)
    device_key: Optional[str] = None

    def __post_init__(self):
        """Validate probe request data."""
        if not self.mac_address:
            raise ValueError("MAC address is required")

        # Normalize MAC address to uppercase
        self.mac_address = self.mac_address.upper()

    @property
    def has_location(self) -> bool:
        """Check if probe has valid GPS coordinates."""
        return self.latitude != 0.0 and self.longitude != 0.0

    def __str__(self):
        location = f"({self.latitude:.6f}, {self.longitude:.6f})" if self.has_location else "No GPS"
        ssid_str = f" -> {self.ssid}" if self.ssid else ""
        return f"{self.mac_address}{ssid_str} @ {self.signal_strength}dBm {location}"


@dataclass
class DeviceAppearance:
    """Tracks device appearances over time."""
    mac_address: str
    appearances: List[ProbeRequest] = field(default_factory=list)
    ssids: Set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0

    def add_appearance(self, probe: ProbeRequest):
        """Add a new probe request appearance."""
        self.appearances.append(probe)

        if probe.ssid:
            self.ssids.add(probe.ssid)

        # Update timestamps
        if self.first_seen == 0.0:
            self.first_seen = probe.timestamp
        self.last_seen = probe.timestamp

    @property
    def appearance_count(self) -> int:
        """Total number of appearances."""
        return len(self.appearances)

    @property
    def time_span_seconds(self) -> float:
        """Time span between first and last appearance."""
        return self.last_seen - self.first_seen

    @property
    def time_span_hours(self) -> float:
        """Time span in hours."""
        return self.time_span_seconds / 3600.0

    def get_appearances_in_window(self, start: float, end: float) -> List[ProbeRequest]:
        """Get appearances within a specific time window."""
        return [
            probe for probe in self.appearances
            if start <= probe.timestamp <= end
        ]


class TimeWindows:
    """
    Manages overlapping time windows for temporal analysis.
    Implements 4 windows: recent (5min), medium (10min), old (15min), oldest (20min)
    """

    def __init__(
        self,
        window_sizes: List[int] = None
    ):
        """
        Initialize time windows.

        Args:
            window_sizes: List of window sizes in seconds
                         Default: [300, 600, 900, 1200] (5, 10, 15, 20 minutes)
        """
        self.window_sizes = window_sizes or [300, 600, 900, 1200]  # seconds
        self.window_names = ["recent", "medium", "old", "oldest"]

    def get_window_bounds(self, current_time: Optional[float] = None) -> Dict[str, tuple]:
        """
        Calculate time boundaries for each window.

        Args:
            current_time: Reference time (default: now)

        Returns:
            Dictionary mapping window names to (start_time, end_time) tuples
        """
        if current_time is None:
            current_time = time.time()

        bounds = {}
        for name, size in zip(self.window_names, self.window_sizes):
            start_time = current_time - size
            bounds[name] = (start_time, current_time)

        return bounds

    def get_window_size_minutes(self, window_name: str) -> int:
        """Get window size in minutes."""
        idx = self.window_names.index(window_name)
        return self.window_sizes[idx] // 60


class ProbeTracker:
    """
    Advanced probe request tracker with time window analysis.
    """

    def __init__(
        self,
        window_sizes: List[int] = None,
        rotation_interval: int = 300  # 5 minutes
    ):
        """
        Initialize probe tracker.

        Args:
            window_sizes: List of window sizes in seconds
            rotation_interval: Seconds between tracking list rotations
        """
        self.time_windows = TimeWindows(window_sizes)
        self.rotation_interval = rotation_interval

        # Device tracking
        self.devices: Dict[str, DeviceAppearance] = {}
        self.ssid_index: Dict[str, Set[str]] = defaultdict(set)  # SSID -> MAC addresses

        # Tracking metadata
        self.last_rotation: float = time.time()
        self.total_probes_processed: int = 0

    def add_probe(self, probe: ProbeRequest):
        """
        Add a new probe request to tracking.

        Args:
            probe: ProbeRequest object to track
        """
        mac = probe.mac_address

        # Get or create device appearance record
        if mac not in self.devices:
            self.devices[mac] = DeviceAppearance(mac_address=mac)

        self.devices[mac].add_appearance(probe)

        # Index by SSID
        if probe.ssid:
            self.ssid_index[probe.ssid].add(mac)

        self.total_probes_processed += 1

    def add_probes_batch(self, probes: List[ProbeRequest]):
        """Add multiple probe requests."""
        for probe in probes:
            self.add_probe(probe)

    def get_device(self, mac_address: str) -> Optional[DeviceAppearance]:
        """Get device appearance record by MAC address."""
        return self.devices.get(mac_address.upper())

    def get_devices_by_ssid(self, ssid: str) -> List[DeviceAppearance]:
        """Get all devices that probed for a specific SSID."""
        mac_addresses = self.ssid_index.get(ssid, set())
        return [self.devices[mac] for mac in mac_addresses if mac in self.devices]

    def get_active_devices(
        self,
        window_name: str = "recent",
        min_appearances: int = 1
    ) -> List[DeviceAppearance]:
        """
        Get devices active in a specific time window.

        Args:
            window_name: Time window name (recent, medium, old, oldest)
            min_appearances: Minimum number of appearances required

        Returns:
            List of DeviceAppearance objects
        """
        bounds = self.time_windows.get_window_bounds()
        start_time, end_time = bounds[window_name]

        active = []
        for device in self.devices.values():
            appearances_in_window = device.get_appearances_in_window(start_time, end_time)
            if len(appearances_in_window) >= min_appearances:
                active.append(device)

        return active

    def get_persistent_devices(
        self,
        min_windows: int = 2,
        min_appearances_per_window: int = 1
    ) -> List[DeviceAppearance]:
        """
        Get devices appearing across multiple time windows.

        Args:
            min_windows: Minimum number of windows device must appear in
            min_appearances_per_window: Minimum appearances per window

        Returns:
            List of persistent DeviceAppearance objects
        """
        bounds = self.time_windows.get_window_bounds()
        persistent = []

        for device in self.devices.values():
            windows_present = 0

            for window_name in self.time_windows.window_names:
                start_time, end_time = bounds[window_name]
                appearances = device.get_appearances_in_window(start_time, end_time)

                if len(appearances) >= min_appearances_per_window:
                    windows_present += 1

            if windows_present >= min_windows:
                persistent.append(device)

        return persistent

    def rotate_tracking_lists(self):
        """
        Rotate tracking lists - remove old data outside the oldest window.
        """
        current_time = time.time()
        oldest_window_size = max(self.time_windows.window_sizes)
        cutoff_time = current_time - oldest_window_size

        # Remove old appearances
        devices_to_remove = []
        for mac, device in self.devices.items():
            # Filter appearances
            device.appearances = [
                probe for probe in device.appearances
                if probe.timestamp >= cutoff_time
            ]

            # Remove device if no recent appearances
            if not device.appearances:
                devices_to_remove.append(mac)
            else:
                # Update timestamps
                device.first_seen = device.appearances[0].timestamp
                device.last_seen = device.appearances[-1].timestamp

        # Clean up empty devices
        for mac in devices_to_remove:
            del self.devices[mac]

        # Clean up SSID index
        for ssid in list(self.ssid_index.keys()):
            self.ssid_index[ssid] = {
                mac for mac in self.ssid_index[ssid]
                if mac in self.devices
            }
            if not self.ssid_index[ssid]:
                del self.ssid_index[ssid]

        self.last_rotation = current_time

    def should_rotate(self) -> bool:
        """Check if tracking lists should be rotated."""
        return (time.time() - self.last_rotation) >= self.rotation_interval

    def get_statistics(self) -> Dict:
        """Get tracker statistics."""
        return {
            "total_devices": len(self.devices),
            "total_probes_processed": self.total_probes_processed,
            "unique_ssids": len(self.ssid_index),
            "last_rotation": datetime.fromtimestamp(self.last_rotation).isoformat(),
            "active_devices_recent": len(self.get_active_devices("recent")),
            "active_devices_medium": len(self.get_active_devices("medium")),
            "active_devices_old": len(self.get_active_devices("old")),
            "active_devices_oldest": len(self.get_active_devices("oldest")),
        }

    def get_device_intervals(self, mac_address: str) -> List[float]:
        """
        Get time intervals between consecutive appearances for a device.

        Args:
            mac_address: Device MAC address

        Returns:
            List of intervals in seconds
        """
        device = self.get_device(mac_address)
        if not device or len(device.appearances) < 2:
            return []

        intervals = []
        appearances = sorted(device.appearances, key=lambda x: x.timestamp)

        for i in range(1, len(appearances)):
            interval = appearances[i].timestamp - appearances[i-1].timestamp
            intervals.append(interval)

        return intervals


# Example usage
if __name__ == "__main__":
    # Example: Track probe requests
    tracker = ProbeTracker()

    # Simulate probe requests
    for i in range(10):
        probe = ProbeRequest(
            mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            ssid="TestNetwork" if i % 2 == 0 else None,
            signal_strength=-60 - i,
            timestamp=time.time() - (i * 60)  # 1 minute apart
        )
        tracker.add_probe(probe)

    # Get statistics
    stats = tracker.get_statistics()
    print(f"Total devices: {stats['total_devices']}")
    print(f"Active devices (recent): {stats['active_devices_recent']}")

    # Get persistent devices
    persistent = tracker.get_persistent_devices(min_windows=2)
    print(f"\nPersistent devices: {len(persistent)}")
    for device in persistent:
        print(f"  {device.mac_address}: {device.appearance_count} appearances")
