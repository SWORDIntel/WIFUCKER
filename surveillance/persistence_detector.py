#!/usr/bin/env python3
"""
Persistence Detection and Scoring Algorithms
=============================================

Multi-factor surveillance detection using temporal persistence,
geographic correlation, and behavioral pattern analysis.
"""

import statistics
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime

from .probe_tracker import DeviceAppearance, ProbeRequest


class RiskLevel(Enum):
    """Surveillance risk classification levels."""
    NORMAL = "normal"           # 0.0-0.5
    SUSPICIOUS = "suspicious"   # 0.6-0.7
    HIGH = "high"              # 0.8-0.9
    CRITICAL = "critical"      # 0.9-1.0

    @property
    def color(self) -> str:
        """Get color code for risk level."""
        return {
            RiskLevel.NORMAL: "green",
            RiskLevel.SUSPICIOUS: "yellow",
            RiskLevel.HIGH: "orange",
            RiskLevel.CRITICAL: "red",
        }[self]

    @property
    def icon(self) -> str:
        """Get icon for risk level."""
        return {
            RiskLevel.NORMAL: "🟢",
            RiskLevel.SUSPICIOUS: "🟡",
            RiskLevel.HIGH: "⚠️",
            RiskLevel.CRITICAL: "🚨",
        }[self]


@dataclass
class DeviceScore:
    """Persistence score for a device."""
    mac_address: str
    base_score: float = 0.0
    geographic_bonus: float = 0.0
    total_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.NORMAL

    # Metrics
    total_appearances: int = 0
    time_span_hours: float = 0.0
    appearance_rate: float = 0.0  # appearances per hour
    unique_locations: int = 0
    interval_variance: float = 0.0
    work_hours_ratio: float = 0.0
    off_hours_ratio: float = 0.0
    rapid_transitions: int = 0

    # SSIDs
    ssids_probed: Set[str] = field(default_factory=set)

    # Reasons
    detection_reasons: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Calculate total score and risk level."""
        self.total_score = min(self.base_score + self.geographic_bonus, 1.0)
        self.risk_level = self._calculate_risk_level()

    def _calculate_risk_level(self) -> RiskLevel:
        """Determine risk level from score."""
        if self.total_score >= 0.9:
            return RiskLevel.CRITICAL
        elif self.total_score >= 0.8:
            return RiskLevel.HIGH
        elif self.total_score >= 0.6:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.NORMAL

    def is_threat(self) -> bool:
        """Check if device is a potential threat."""
        return self.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]

    def __str__(self):
        return (
            f"{self.risk_level.icon} {self.mac_address}: "
            f"Score={self.total_score:.2f} "
            f"({self.total_appearances} appearances, "
            f"{self.time_span_hours:.1f}h span)"
        )


class PersistenceDetector:
    """
    Advanced persistence detection using multi-factor scoring.
    """

    def __init__(
        self,
        min_appearances: int = 3,
        min_time_span_hours: float = 1.0,
        min_persistence_score: float = 0.5,
        geographic_bonus_threshold: int = 2  # locations
    ):
        """
        Initialize persistence detector.

        Args:
            min_appearances: Minimum appearances to analyze
            min_time_span_hours: Minimum time span in hours
            min_persistence_score: Minimum score for threat detection
            geographic_bonus_threshold: Locations needed for bonus
        """
        self.min_appearances = min_appearances
        self.min_time_span_hours = min_time_span_hours
        self.min_persistence_score = min_persistence_score
        self.geographic_bonus_threshold = geographic_bonus_threshold

    def analyze_device(self, device: DeviceAppearance) -> Optional[DeviceScore]:
        """
        Analyze a device for surveillance patterns.

        Args:
            device: DeviceAppearance object to analyze

        Returns:
            DeviceScore if device meets minimum thresholds, None otherwise
        """
        # Check minimum thresholds
        if device.appearance_count < self.min_appearances:
            return None

        if device.time_span_hours < self.min_time_span_hours:
            return None

        # Calculate base metrics
        appearance_rate = device.appearance_count / max(device.time_span_hours, 0.1)

        # Base persistence score
        # Score reaches 0.5 at 0.5 appearances/hour (every 2 hours)
        base_score = min(appearance_rate / 2.0, 1.0)

        # Geographic analysis
        unique_locations = self._count_unique_locations(device)
        geographic_bonus = 0.0

        if unique_locations >= self.geographic_bonus_threshold:
            geographic_bonus = 0.3  # Bonus for multi-location tracking

        # Temporal pattern analysis
        intervals = self._calculate_intervals(device)
        interval_variance = statistics.variance(intervals) if len(intervals) > 1 else 0

        # Time-of-day analysis
        work_hours_ratio, off_hours_ratio = self._analyze_time_of_day(device)

        # Rapid location transitions
        rapid_transitions = self._count_rapid_transitions(device)

        # Create score object
        score = DeviceScore(
            mac_address=device.mac_address,
            base_score=base_score,
            geographic_bonus=geographic_bonus,
            total_appearances=device.appearance_count,
            time_span_hours=device.time_span_hours,
            appearance_rate=appearance_rate,
            unique_locations=unique_locations,
            interval_variance=interval_variance,
            work_hours_ratio=work_hours_ratio,
            off_hours_ratio=off_hours_ratio,
            rapid_transitions=rapid_transitions,
            ssids_probed=device.ssids.copy()
        )

        # Add detection reasons
        self._add_detection_reasons(score, device, intervals)

        return score

    def analyze_devices(
        self,
        devices: List[DeviceAppearance]
    ) -> List[DeviceScore]:
        """
        Analyze multiple devices and return scored results.

        Args:
            devices: List of DeviceAppearance objects

        Returns:
            List of DeviceScore objects, sorted by score (highest first)
        """
        scores = []

        for device in devices:
            score = self.analyze_device(device)
            if score and score.total_score >= self.min_persistence_score:
                scores.append(score)

        # Sort by score, highest first
        scores.sort(key=lambda x: x.total_score, reverse=True)

        return scores

    def get_threats(
        self,
        devices: List[DeviceAppearance]
    ) -> List[DeviceScore]:
        """
        Get only threat-level devices (HIGH or CRITICAL).

        Args:
            devices: List of DeviceAppearance objects

        Returns:
            List of DeviceScore objects classified as threats
        """
        scores = self.analyze_devices(devices)
        return [score for score in scores if score.is_threat()]

    def _count_unique_locations(self, device: DeviceAppearance) -> int:
        """Count unique GPS locations for a device."""
        locations = set()

        for probe in device.appearances:
            if probe.has_location:
                # Round to ~100m precision (0.001 degrees ≈ 111m)
                loc = (round(probe.latitude, 3), round(probe.longitude, 3))
                locations.add(loc)

        return len(locations)

    def _calculate_intervals(self, device: DeviceAppearance) -> List[float]:
        """Calculate time intervals between consecutive appearances."""
        if len(device.appearances) < 2:
            return []

        sorted_appearances = sorted(device.appearances, key=lambda x: x.timestamp)
        intervals = []

        for i in range(1, len(sorted_appearances)):
            interval = sorted_appearances[i].timestamp - sorted_appearances[i-1].timestamp
            intervals.append(interval)

        return intervals

    def _analyze_time_of_day(self, device: DeviceAppearance) -> tuple:
        """
        Analyze work hours vs off-hours activity.

        Returns:
            Tuple of (work_hours_ratio, off_hours_ratio)
        """
        work_hours_count = 0  # 9 AM - 5 PM
        off_hours_count = 0   # 10 PM - 6 AM

        for probe in device.appearances:
            dt = datetime.fromtimestamp(probe.timestamp)
            hour = dt.hour

            if 9 <= hour < 17:
                work_hours_count += 1
            elif hour >= 22 or hour < 6:
                off_hours_count += 1

        total = len(device.appearances)
        work_hours_ratio = work_hours_count / total if total > 0 else 0
        off_hours_ratio = off_hours_count / total if total > 0 else 0

        return work_hours_ratio, off_hours_ratio

    def _count_rapid_transitions(
        self,
        device: DeviceAppearance,
        threshold_minutes: int = 30
    ) -> int:
        """
        Count rapid location transitions (< 30 minutes between different locations).

        Args:
            device: DeviceAppearance object
            threshold_minutes: Maximum minutes between locations

        Returns:
            Number of rapid transitions
        """
        if len(device.appearances) < 2:
            return 0

        sorted_appearances = sorted(device.appearances, key=lambda x: x.timestamp)
        rapid_count = 0
        threshold_seconds = threshold_minutes * 60

        for i in range(1, len(sorted_appearances)):
            current = sorted_appearances[i]
            previous = sorted_appearances[i-1]

            if not (current.has_location and previous.has_location):
                continue

            # Check if locations are different
            loc1 = (round(current.latitude, 3), round(current.longitude, 3))
            loc2 = (round(previous.latitude, 3), round(previous.longitude, 3))

            if loc1 != loc2:
                time_diff = current.timestamp - previous.timestamp
                if time_diff < threshold_seconds:
                    rapid_count += 1

        return rapid_count

    def _add_detection_reasons(
        self,
        score: DeviceScore,
        device: DeviceAppearance,
        intervals: List[float]
    ):
        """Add human-readable detection reasons to score."""
        reasons = []

        # High appearance rate
        if score.appearance_rate >= 0.5:
            reasons.append(
                f"High appearance rate: {score.appearance_rate:.2f} times/hour"
            )

        # Multi-location tracking
        if score.unique_locations >= self.geographic_bonus_threshold:
            reasons.append(
                f"Multiple locations: {score.unique_locations} distinct areas"
            )

        # Clustered timing (low variance = regular intervals)
        if intervals and score.interval_variance < 3600:  # < 1 hour variance
            avg_interval = statistics.mean(intervals)
            reasons.append(
                f"Regular timing: {avg_interval/60:.1f} min average intervals"
            )

        # Rapid transitions
        if score.rapid_transitions > 0:
            reasons.append(
                f"Rapid movements: {score.rapid_transitions} quick location changes"
            )

        # Work hours concentration
        if score.work_hours_ratio > 0.7:
            reasons.append(
                f"Work hours activity: {score.work_hours_ratio*100:.0f}% during 9-5"
            )

        # Off hours activity
        if score.off_hours_ratio > 0.3:
            reasons.append(
                f"Late night activity: {score.off_hours_ratio*100:.0f}% during 10PM-6AM"
            )

        # Long-term tracking
        if score.time_span_hours > 24:
            reasons.append(
                f"Extended tracking: {score.time_span_hours:.1f} hour span"
            )

        # SSID probing
        if len(score.ssids_probed) > 5:
            reasons.append(
                f"Multiple SSIDs: Probing {len(score.ssids_probed)} networks"
            )

        score.detection_reasons = reasons


# Example usage
if __name__ == "__main__":
    from .probe_tracker import ProbeRequest
    import time

    # Example: Create test device with surveillance pattern
    device = DeviceAppearance(mac_address="AA:BB:CC:DD:EE:FF")

    # Simulate regular appearances every 30 minutes over 4 hours
    base_time = time.time() - (4 * 3600)  # 4 hours ago
    for i in range(8):
        probe = ProbeRequest(
            mac_address="AA:BB:CC:DD:EE:FF",
            ssid=f"Network_{i % 3}",
            signal_strength=-65,
            latitude=37.7749 + (i * 0.001),  # Moving locations
            longitude=-122.4194 + (i * 0.001),
            timestamp=base_time + (i * 1800)  # Every 30 minutes
        )
        device.add_appearance(probe)

    # Analyze device
    detector = PersistenceDetector()
    score = detector.analyze_device(device)

    if score:
        print(score)
        print(f"\nRisk Level: {score.risk_level.value.upper()}")
        print(f"Detection Reasons:")
        for reason in score.detection_reasons:
            print(f"  - {reason}")
