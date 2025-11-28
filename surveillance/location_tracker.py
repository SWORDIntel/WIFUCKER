#!/usr/bin/env python3
"""
GPS Location Tracking and Correlation
======================================

Geographic analysis for surveillance detection including location clustering,
movement pattern analysis, and multi-device correlation.
"""

import math
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

from .probe_tracker import DeviceAppearance, ProbeRequest


@dataclass
class GPSLocation:
    """Represents a GPS coordinate."""
    latitude: float
    longitude: float
    timestamp: float = 0.0
    altitude: float = 0.0

    def __post_init__(self):
        """Validate GPS coordinates."""
        if not (-90 <= self.latitude <= 90):
            raise ValueError(f"Invalid latitude: {self.latitude}")
        if not (-180 <= self.longitude <= 180):
            raise ValueError(f"Invalid longitude: {self.longitude}")

    def distance_to(self, other: 'GPSLocation') -> float:
        """
        Calculate distance to another location using Haversine formula.

        Args:
            other: Another GPSLocation

        Returns:
            Distance in meters
        """
        # Earth radius in meters
        R = 6371000

        # Convert to radians
        lat1 = math.radians(self.latitude)
        lat2 = math.radians(other.latitude)
        dlat = math.radians(other.latitude - self.latitude)
        dlon = math.radians(other.longitude - self.longitude)

        # Haversine formula
        a = (math.sin(dlat/2) ** 2 +
             math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2) ** 2)
        c = 2 * math.asin(math.sqrt(a))

        return R * c

    def __str__(self):
        return f"({self.latitude:.6f}, {self.longitude:.6f})"


@dataclass
class LocationCluster:
    """Represents a cluster of nearby GPS locations."""
    cluster_id: int
    center: GPSLocation
    locations: List[GPSLocation] = field(default_factory=list)
    device_macs: Set[str] = field(default_factory=set)
    radius_meters: float = 0.0

    @property
    def device_count(self) -> int:
        """Number of unique devices in cluster."""
        return len(self.device_macs)

    @property
    def location_count(self) -> int:
        """Number of location observations in cluster."""
        return len(self.locations)

    def add_location(self, location: GPSLocation, mac_address: str):
        """Add a location to this cluster."""
        self.locations.append(location)
        self.device_macs.add(mac_address)
        self._recalculate_center()

    def _recalculate_center(self):
        """Recalculate cluster center as centroid."""
        if not self.locations:
            return

        avg_lat = sum(loc.latitude for loc in self.locations) / len(self.locations)
        avg_lon = sum(loc.longitude for loc in self.locations) / len(self.locations)

        self.center = GPSLocation(avg_lat, avg_lon)

        # Calculate radius
        if len(self.locations) > 1:
            distances = [self.center.distance_to(loc) for loc in self.locations]
            self.radius_meters = max(distances)

    def __str__(self):
        return (
            f"Cluster {self.cluster_id}: {self.center} "
            f"({self.device_count} devices, "
            f"{self.location_count} locations, "
            f"radius: {self.radius_meters:.0f}m)"
        )


class LocationTracker:
    """
    GPS location tracking and correlation system.
    Implements 100-meter clustering and movement pattern analysis.
    """

    def __init__(
        self,
        cluster_threshold_meters: float = 100.0,
        min_cluster_devices: int = 2
    ):
        """
        Initialize location tracker.

        Args:
            cluster_threshold_meters: Distance threshold for clustering (default: 100m)
            min_cluster_devices: Minimum devices for significant cluster
        """
        self.cluster_threshold = cluster_threshold_meters
        self.min_cluster_devices = min_cluster_devices

        self.clusters: List[LocationCluster] = []
        self.next_cluster_id = 1

    def create_clusters(self, devices: List[DeviceAppearance]) -> List[LocationCluster]:
        """
        Create location clusters from device appearances.

        Args:
            devices: List of DeviceAppearance objects

        Returns:
            List of LocationCluster objects
        """
        self.clusters = []
        self.next_cluster_id = 1

        # Collect all locations with their MAC addresses
        all_locations: List[Tuple[GPSLocation, str]] = []

        for device in devices:
            for probe in device.appearances:
                if probe.has_location:
                    location = GPSLocation(
                        latitude=probe.latitude,
                        longitude=probe.longitude,
                        timestamp=probe.timestamp
                    )
                    all_locations.append((location, device.mac_address))

        # Cluster using simple distance-based algorithm
        for location, mac in all_locations:
            # Find nearest cluster
            nearest_cluster = None
            min_distance = float('inf')

            for cluster in self.clusters:
                distance = location.distance_to(cluster.center)
                if distance < min_distance:
                    min_distance = distance
                    nearest_cluster = cluster

            # Add to nearest cluster if within threshold, else create new
            if nearest_cluster and min_distance <= self.cluster_threshold:
                nearest_cluster.add_location(location, mac)
            else:
                # Create new cluster
                new_cluster = LocationCluster(
                    cluster_id=self.next_cluster_id,
                    center=GPSLocation(location.latitude, location.longitude)
                )
                new_cluster.add_location(location, mac)
                self.clusters.append(new_cluster)
                self.next_cluster_id += 1

        return self.clusters

    def get_significant_clusters(self) -> List[LocationCluster]:
        """
        Get clusters with multiple devices (surveillance hotspots).

        Returns:
            List of clusters meeting minimum device threshold
        """
        return [
            cluster for cluster in self.clusters
            if cluster.device_count >= self.min_cluster_devices
        ]

    def get_device_clusters(self, mac_address: str) -> List[LocationCluster]:
        """
        Get all clusters containing a specific device.

        Args:
            mac_address: Device MAC address

        Returns:
            List of LocationCluster objects
        """
        return [
            cluster for cluster in self.clusters
            if mac_address.upper() in cluster.device_macs
        ]

    def analyze_device_movement(self, device: DeviceAppearance) -> Dict:
        """
        Analyze movement patterns for a device.

        Args:
            device: DeviceAppearance object

        Returns:
            Dictionary with movement statistics
        """
        locations_with_gps = [
            probe for probe in device.appearances
            if probe.has_location
        ]

        if len(locations_with_gps) < 2:
            return {
                "total_distance_meters": 0.0,
                "max_distance_from_start": 0.0,
                "avg_speed_mps": 0.0,
                "locations_tracked": len(locations_with_gps),
                "is_stationary": len(locations_with_gps) == 1,
            }

        # Sort by timestamp
        sorted_locations = sorted(locations_with_gps, key=lambda x: x.timestamp)

        # Calculate total distance traveled
        total_distance = 0.0
        for i in range(1, len(sorted_locations)):
            loc1 = GPSLocation(
                sorted_locations[i-1].latitude,
                sorted_locations[i-1].longitude
            )
            loc2 = GPSLocation(
                sorted_locations[i].latitude,
                sorted_locations[i].longitude
            )
            total_distance += loc1.distance_to(loc2)

        # Calculate max distance from starting point
        start_loc = GPSLocation(
            sorted_locations[0].latitude,
            sorted_locations[0].longitude
        )
        max_distance = 0.0
        for probe in sorted_locations[1:]:
            loc = GPSLocation(probe.latitude, probe.longitude)
            distance = start_loc.distance_to(loc)
            max_distance = max(max_distance, distance)

        # Calculate average speed
        time_span = sorted_locations[-1].timestamp - sorted_locations[0].timestamp
        avg_speed = total_distance / max(time_span, 1)  # meters per second

        # Determine if stationary (all within cluster threshold)
        is_stationary = max_distance <= self.cluster_threshold

        return {
            "total_distance_meters": total_distance,
            "max_distance_from_start": max_distance,
            "avg_speed_mps": avg_speed,
            "avg_speed_kmh": avg_speed * 3.6,
            "locations_tracked": len(locations_with_gps),
            "is_stationary": is_stationary,
            "time_span_seconds": time_span,
        }

    def find_correlated_devices(
        self,
        min_shared_clusters: int = 2
    ) -> List[Tuple[str, str, int]]:
        """
        Find devices appearing together in multiple clusters (coordinated surveillance).

        Args:
            min_shared_clusters: Minimum shared clusters to report

        Returns:
            List of (mac1, mac2, shared_count) tuples
        """
        # Build device-to-clusters mapping
        device_clusters: Dict[str, Set[int]] = defaultdict(set)

        for cluster in self.clusters:
            for mac in cluster.device_macs:
                device_clusters[mac].add(cluster.cluster_id)

        # Find pairs with shared clusters
        correlated = []
        macs = list(device_clusters.keys())

        for i in range(len(macs)):
            for j in range(i + 1, len(macs)):
                mac1, mac2 = macs[i], macs[j]
                shared = device_clusters[mac1] & device_clusters[mac2]

                if len(shared) >= min_shared_clusters:
                    correlated.append((mac1, mac2, len(shared)))

        # Sort by shared count, highest first
        correlated.sort(key=lambda x: x[2], reverse=True)

        return correlated

    def get_cluster_timeline(self, cluster_id: int) -> List[Dict]:
        """
        Get chronological timeline of device appearances in a cluster.

        Args:
            cluster_id: Cluster ID

        Returns:
            List of timeline events
        """
        cluster = next(
            (c for c in self.clusters if c.cluster_id == cluster_id),
            None
        )

        if not cluster:
            return []

        # Sort locations by timestamp
        timeline = sorted(cluster.locations, key=lambda x: x.timestamp)

        events = []
        for location in timeline:
            events.append({
                "timestamp": location.timestamp,
                "location": str(location),
            })

        return events


# Example usage
if __name__ == "__main__":
    from .probe_tracker import ProbeRequest
    import time

    # Example: Create test devices with location data
    devices = []

    # Device 1: Stationary
    device1 = DeviceAppearance(mac_address="AA:BB:CC:DD:EE:01")
    for i in range(5):
        probe = ProbeRequest(
            mac_address="AA:BB:CC:DD:EE:01",
            latitude=37.7749,
            longitude=-122.4194,
            timestamp=time.time() - (i * 600)
        )
        device1.add_appearance(probe)
    devices.append(device1)

    # Device 2: Moving
    device2 = DeviceAppearance(mac_address="AA:BB:CC:DD:EE:02")
    for i in range(5):
        probe = ProbeRequest(
            mac_address="AA:BB:CC:DD:EE:02",
            latitude=37.7749 + (i * 0.001),
            longitude=-122.4194 + (i * 0.001),
            timestamp=time.time() - (i * 600)
        )
        device2.add_appearance(probe)
    devices.append(device2)

    # Analyze locations
    tracker = LocationTracker(cluster_threshold_meters=100)
    clusters = tracker.create_clusters(devices)

    print(f"Found {len(clusters)} location clusters:")
    for cluster in clusters:
        print(f"  {cluster}")

    # Analyze movement
    for device in devices:
        movement = tracker.analyze_device_movement(device)
        print(f"\nMovement analysis for {device.mac_address}:")
        print(f"  Total distance: {movement['total_distance_meters']:.0f}m")
        print(f"  Stationary: {movement['is_stationary']}")
        print(f"  Avg speed: {movement['avg_speed_kmh']:.1f} km/h")
