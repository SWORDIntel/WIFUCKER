#!/usr/bin/env python3
"""
Kismet Database Monitor
=======================

Secure integration with Kismet wireless monitoring databases.
Handles probe request extraction and real-time monitoring.
"""

import sqlite3
import glob
import os
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from contextlib import contextmanager


class SecureKismetDB:
    """
    Secure Kismet SQLite database connection manager.
    Implements parameterized queries to prevent SQL injection.
    """

    def __init__(self, db_path: str):
        """
        Initialize secure Kismet database connection.

        Args:
            db_path: Path to Kismet SQLite database file
        """
        self.db_path = Path(db_path)
        self.connection: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None

        if not self.db_path.exists():
            raise FileNotFoundError(f"Kismet database not found: {db_path}")

        if not self.db_path.is_file():
            raise ValueError(f"Path is not a file: {db_path}")

    def __enter__(self):
        """Context manager entry - establish database connection."""
        self.connection = sqlite3.connect(str(self.db_path))
        self.connection.row_factory = sqlite3.Row  # Enable column access by name
        self.cursor = self.connection.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()

    def execute_safe(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """
        Execute parameterized query safely.

        Args:
            query: SQL query with ? placeholders
            params: Tuple of parameters for query

        Returns:
            List of result rows
        """
        if not self.cursor:
            raise RuntimeError("Database not connected. Use with statement.")

        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def get_probe_requests(
        self,
        since_timestamp: Optional[float] = None,
        mac_filter: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Extract probe requests from Kismet database.

        Args:
            since_timestamp: Only get requests after this Unix timestamp
            mac_filter: List of MAC addresses to filter (None = all)

        Returns:
            List of probe request dictionaries
        """
        query = """
            SELECT
                devmac as mac_address,
                devkey as device_key,
                type as device_type,
                strongest_signal as signal_strength,
                min_lat as latitude,
                min_lon as longitude,
                first_time as first_seen,
                last_time as last_seen
            FROM devices
            WHERE type LIKE '%probe%'
        """

        params = []

        if since_timestamp:
            query += " AND last_time > ?"
            params.append(since_timestamp)

        if mac_filter:
            placeholders = ",".join("?" * len(mac_filter))
            query += f" AND devmac IN ({placeholders})"
            params.extend(mac_filter)

        query += " ORDER BY last_time DESC"

        rows = self.execute_safe(query, tuple(params))

        results = []
        for row in rows:
            results.append({
                "mac_address": row["mac_address"],
                "device_key": row["device_key"],
                "device_type": row["device_type"],
                "signal_strength": row["signal_strength"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            })

        return results

    def get_ssid_probes(
        self,
        since_timestamp: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Extract SSID probe requests (devices looking for specific networks).

        Args:
            since_timestamp: Only get probes after this Unix timestamp

        Returns:
            List of SSID probe dictionaries
        """
        query = """
            SELECT DISTINCT
                ssid.devmac as mac_address,
                ssid.ssid as ssid_name,
                ssid.firsttime as first_seen,
                ssid.lasttime as last_seen,
                devices.strongest_signal as signal_strength,
                devices.min_lat as latitude,
                devices.min_lon as longitude
            FROM ssid
            JOIN devices ON ssid.devmac = devices.devmac
            WHERE ssid.ssid != ''
        """

        params = []

        if since_timestamp:
            query += " AND ssid.lasttime > ?"
            params.append(since_timestamp)

        query += " ORDER BY ssid.lasttime DESC"

        rows = self.execute_safe(query, tuple(params))

        results = []
        for row in rows:
            results.append({
                "mac_address": row["mac_address"],
                "ssid_name": row["ssid_name"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "signal_strength": row["signal_strength"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
            })

        return results


class KismetMonitor:
    """
    Real-time Kismet database monitoring system.
    Automatically finds and monitors the latest Kismet database.
    """

    def __init__(
        self,
        kismet_db_dir: str = "/var/log/kismet",
        check_interval: int = 60,
        ignore_list: Optional[List[str]] = None
    ):
        """
        Initialize Kismet monitor.

        Args:
            kismet_db_dir: Directory containing Kismet database files
            check_interval: Seconds between database checks
            ignore_list: List of MAC addresses or SSIDs to ignore
        """
        self.kismet_db_dir = Path(kismet_db_dir)
        self.check_interval = check_interval
        self.ignore_list = set(ignore_list or [])
        self.last_check_time: float = 0
        self.current_db_path: Optional[Path] = None

    def find_latest_database(self) -> Optional[Path]:
        """
        Find the most recently modified Kismet database file.

        Returns:
            Path to latest database or None if not found
        """
        pattern = str(self.kismet_db_dir / "Kismet-*.kismet")
        db_files = glob.glob(pattern)

        if not db_files:
            return None

        # Sort by modification time, most recent first
        db_files.sort(key=os.path.getctime, reverse=True)
        return Path(db_files[0])

    def start_monitoring(self, callback=None):
        """
        Start continuous monitoring loop.

        Args:
            callback: Function to call with new probe requests
        """
        print(f"[*] Starting Kismet monitoring in: {self.kismet_db_dir}")
        print(f"[*] Check interval: {self.check_interval}s")

        try:
            while True:
                # Find latest database
                latest_db = self.find_latest_database()

                if not latest_db:
                    print(f"[!] No Kismet databases found in {self.kismet_db_dir}")
                    time.sleep(self.check_interval)
                    continue

                # Check if database changed
                if latest_db != self.current_db_path:
                    print(f"[+] Using database: {latest_db.name}")
                    self.current_db_path = latest_db
                    self.last_check_time = time.time()

                # Query for new probe requests
                try:
                    with SecureKismetDB(str(self.current_db_path)) as db:
                        probes = db.get_probe_requests(
                            since_timestamp=self.last_check_time
                        )
                        ssid_probes = db.get_ssid_probes(
                            since_timestamp=self.last_check_time
                        )

                        # Filter ignored devices
                        probes = self._filter_ignored(probes)
                        ssid_probes = self._filter_ignored_ssid(ssid_probes)

                        # Update last check time
                        self.last_check_time = time.time()

                        # Process results
                        if probes or ssid_probes:
                            print(f"[+] Found {len(probes)} new probe requests")
                            print(f"[+] Found {len(ssid_probes)} new SSID probes")

                            if callback:
                                callback(probes, ssid_probes)

                except Exception as e:
                    print(f"[!] Database error: {e}")

                time.sleep(self.check_interval)

        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user")

    def _filter_ignored(self, probes: List[Dict]) -> List[Dict]:
        """Filter out ignored MAC addresses."""
        return [
            p for p in probes
            if p["mac_address"] not in self.ignore_list
        ]

    def _filter_ignored_ssid(self, probes: List[Dict]) -> List[Dict]:
        """Filter out ignored SSIDs and MAC addresses."""
        return [
            p for p in probes
            if p["mac_address"] not in self.ignore_list
            and p["ssid_name"] not in self.ignore_list
        ]

    def add_to_ignore_list(self, identifier: str):
        """Add MAC address or SSID to ignore list."""
        self.ignore_list.add(identifier)

    def remove_from_ignore_list(self, identifier: str):
        """Remove MAC address or SSID from ignore list."""
        self.ignore_list.discard(identifier)


# Example usage
if __name__ == "__main__":
    # Example: Monitor Kismet databases
    monitor = KismetMonitor(
        kismet_db_dir="/var/log/kismet",
        check_interval=30
    )

    def on_new_probes(probes, ssid_probes):
        """Callback for new probe requests."""
        for probe in probes:
            print(f"Device: {probe['mac_address']} @ {probe['signal_strength']}dBm")

        for probe in ssid_probes:
            print(f"SSID Probe: {probe['mac_address']} -> {probe['ssid_name']}")

    monitor.start_monitoring(callback=on_new_probes)
