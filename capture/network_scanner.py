#!/usr/bin/env python3
"""
WiFi Network Scanner
====================

Scans for nearby WiFi networks and displays them for selection.
"""

import subprocess
import re
import time
import signal
from typing import List, Optional, Dict
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class WiFiNetwork:
    """WiFi network information"""
    bssid: str
    channel: int
    essid: str
    power: int  # Signal strength in dBm
    encryption: str
    cipher: str
    authentication: str
    clients: List[str] = field(default_factory=list)
    beacons: int = 0
    data_packets: int = 0
    last_seen: datetime = field(default_factory=datetime.now)

    def __str__(self):
        client_count = len(self.clients)
        return (f"{self.essid:25s} | {self.bssid} | Ch {self.channel:2d} | "
                f"{self.power:3d} dBm | {self.encryption:8s} | {client_count} client(s)")

    @property
    def has_clients(self) -> bool:
        """Check if network has connected clients"""
        return len(self.clients) > 0

    @property
    def signal_quality(self) -> str:
        """Get signal quality description"""
        if self.power >= -50:
            return "Excellent"
        elif self.power >= -60:
            return "Good"
        elif self.power >= -70:
            return "Fair"
        else:
            return "Weak"


class NetworkScanner:
    """WiFi network scanner"""

    def __init__(self, interface: str):
        self.interface = interface
        self.networks: Dict[str, WiFiNetwork] = {}
        self.scan_process = None

    def scan(self, duration: int = 10, channel: Optional[int] = None) -> List[WiFiNetwork]:
        """
        Scan for networks

        Args:
            duration: Scan duration in seconds
            channel: Specific channel to scan (None for all channels)

        Returns:
            List of discovered networks
        """
        print(f"[*] Scanning for networks on {self.interface}...")
        if channel:
            print(f"[*] Locked to channel {channel}")
        else:
            print(f"[*] Hopping across all channels")

        # Try airodump-ng first (best option)
        if self._command_exists('airodump-ng'):
            return self._scan_with_airodump(duration, channel)

        # Fallback to iw scan
        print("[!] airodump-ng not found, using iw scan (less detailed)")
        return self._scan_with_iw()

    def _command_exists(self, command: str) -> bool:
        """Check if command exists"""
        try:
            subprocess.run(
                ['which', command],
                capture_output=True,
                check=True
            )
            return True
        except:
            return False

    def _scan_with_airodump(self, duration: int, channel: Optional[int] = None) -> List[WiFiNetwork]:
        """Scan using airodump-ng"""
        import tempfile
        import os

        # Create temporary file for output
        temp_prefix = tempfile.mktemp(prefix='davbest_scan_')

        # Build command
        cmd = ['airodump-ng', self.interface, '-w', temp_prefix, '--output-format', 'csv']

        if channel:
            cmd.extend(['-c', str(channel)])

        try:
            # Start airodump-ng
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

            self.scan_process = process

            # Let it run for specified duration
            print(f"[*] Scanning for {duration} seconds...")
            for i in range(duration):
                time.sleep(1)
                print(f"\r[*] Progress: {i+1}/{duration} seconds", end='', flush=True)

            print()

            # Stop process
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=2)

        except Exception as e:
            print(f"[-] Error during scan: {e}")
            if process:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except:
                    pass

        finally:
            self.scan_process = None

        # Parse results
        csv_file = f"{temp_prefix}-01.csv"
        if os.path.exists(csv_file):
            networks = self._parse_airodump_csv(csv_file)

            # Clean up temp files
            for f in os.listdir(os.path.dirname(temp_prefix)):
                if f.startswith(os.path.basename(temp_prefix)):
                    try:
                        os.remove(os.path.join(os.path.dirname(temp_prefix), f))
                    except:
                        pass

            return networks

        print("[-] No scan results found")
        return []

    def _parse_airodump_csv(self, csv_file: str) -> List[WiFiNetwork]:
        """Parse airodump-ng CSV output"""
        networks = []

        try:
            with open(csv_file, 'r', errors='ignore') as f:
                content = f.read()

            # Split into AP and client sections
            parts = content.split('\r\n\r\n')

            if len(parts) < 1:
                return networks

            # Parse APs
            ap_lines = parts[0].split('\n')

            # Find header line
            header_idx = 0
            for i, line in enumerate(ap_lines):
                if 'BSSID' in line:
                    header_idx = i
                    break

            # Parse AP data
            for line in ap_lines[header_idx + 1:]:
                line = line.strip()
                if not line or line.startswith('Station'):
                    continue

                parts = [p.strip() for p in line.split(',')]

                if len(parts) >= 14:
                    bssid = parts[0]
                    try:
                        power = int(parts[8])
                    except:
                        power = -100

                    try:
                        channel = int(parts[3])
                    except:
                        channel = 0

                    try:
                        beacons = int(parts[9])
                    except:
                        beacons = 0

                    try:
                        data = int(parts[10])
                    except:
                        data = 0

                    essid = parts[13] if len(parts) > 13 else ""

                    # Parse encryption
                    encryption = parts[5] if len(parts) > 5 else ""
                    cipher = parts[6] if len(parts) > 6 else ""
                    auth = parts[7] if len(parts) > 7 else ""

                    network = WiFiNetwork(
                        bssid=bssid,
                        channel=channel,
                        essid=essid if essid else f"Hidden-{bssid}",
                        power=power,
                        encryption=encryption,
                        cipher=cipher,
                        authentication=auth,
                        beacons=beacons,
                        data_packets=data
                    )

                    networks.append(network)
                    self.networks[bssid] = network

            # Parse clients (if available)
            if len(parts) > 1:
                client_lines = parts[1].split('\n')

                for line in client_lines:
                    line = line.strip()
                    if not line or 'Station MAC' in line:
                        continue

                    parts = [p.strip() for p in line.split(',')]

                    if len(parts) >= 6:
                        client_mac = parts[0]
                        ap_bssid = parts[5]

                        # Add client to AP
                        if ap_bssid in self.networks:
                            if client_mac not in self.networks[ap_bssid].clients:
                                self.networks[ap_bssid].clients.append(client_mac)

        except Exception as e:
            print(f"[-] Error parsing CSV: {e}")

        return networks

    def _scan_with_iw(self) -> List[WiFiNetwork]:
        """Scan using iw (fallback method)"""
        try:
            result = subprocess.run(
                ['sudo', 'iw', self.interface, 'scan'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"[-] Scan failed: {result.stderr}")
                return []

            return self._parse_iw_output(result.stdout)

        except subprocess.TimeoutExpired:
            print("[-] Scan timed out")
            return []
        except Exception as e:
            print(f"[-] Error during scan: {e}")
            return []

    def _parse_iw_output(self, output: str) -> List[WiFiNetwork]:
        """Parse iw scan output"""
        networks = []
        current_network = None

        bssid = None
        freq = None
        channel = None
        signal = -100
        ssid = ""
        encryption = "Open"

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('BSS '):
                # Save previous network
                if bssid:
                    network = WiFiNetwork(
                        bssid=bssid,
                        channel=channel or 0,
                        essid=ssid or f"Hidden-{bssid}",
                        power=signal,
                        encryption=encryption,
                        cipher="",
                        authentication=""
                    )
                    networks.append(network)

                # Start new network
                bssid = line.split()[1].rstrip('(on')
                signal = -100
                ssid = ""
                encryption = "Open"
                channel = None

            elif 'freq:' in line:
                freq = int(line.split(':')[1].strip())
                # Convert freq to channel (approximate)
                if 2412 <= freq <= 2484:
                    channel = (freq - 2412) // 5 + 1
                elif 5180 <= freq <= 5825:
                    channel = (freq - 5180) // 5 + 36

            elif 'signal:' in line:
                try:
                    signal = int(float(line.split(':')[1].strip().split()[0]))
                except:
                    signal = -100

            elif 'SSID:' in line:
                ssid = line.split(':', 1)[1].strip()

            elif 'RSN:' in line or 'WPA:' in line:
                encryption = "WPA/WPA2"

        # Save last network
        if bssid:
            network = WiFiNetwork(
                bssid=bssid,
                channel=channel or 0,
                essid=ssid or f"Hidden-{bssid}",
                power=signal,
                encryption=encryption,
                cipher="",
                authentication=""
            )
            networks.append(network)

        return networks

    def get_network_clients(self, bssid: str, duration: int = 10) -> List[str]:
        """
        Monitor a specific network for connected clients

        Args:
            bssid: Target network BSSID
            duration: Monitor duration in seconds

        Returns:
            List of client MAC addresses
        """
        if bssid in self.networks:
            network = self.networks[bssid]
            if network.clients:
                return network.clients

        print(f"[*] Monitoring {bssid} for clients...")

        # Need to rescan with focus on this AP
        networks = self.scan(duration=duration, channel=self.networks.get(bssid, WiFiNetwork(
            bssid=bssid, channel=0, essid="", power=0,
            encryption="", cipher="", authentication=""
        )).channel)

        for net in networks:
            if net.bssid == bssid:
                return net.clients

        return []

    def stop_scan(self):
        """Stop ongoing scan"""
        if self.scan_process:
            try:
                import os
                os.killpg(os.getpgid(self.scan_process.pid), signal.SIGTERM)
            except:
                pass
            self.scan_process = None
