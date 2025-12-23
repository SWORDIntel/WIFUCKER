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

    def scan(self, duration: int = 10, channel: Optional[int] = None, progress_callback=None) -> List[WiFiNetwork]:
        """
        Scan for networks

        Args:
            duration: Scan duration in seconds
            channel: Specific channel to scan (None for all channels)
            progress_callback: Optional callback function for progress updates
                Called with (phase, progress, message) parameters

        Returns:
            List of discovered networks
        """
        if progress_callback:
            progress_callback("starting", 0, f"Scanning on {self.interface}...")
        else:
            print(f"[*] Scanning for networks on {self.interface}...")

        if channel:
            msg = f"Locked to channel {channel}"
            if progress_callback:
                progress_callback("channel_lock", 0, msg)
            else:
                print(f"[*] {msg}")
        else:
            msg = "Hopping across all channels"
            if progress_callback:
                progress_callback("channel_hop", 0, msg)
            else:
                print(f"[*] {msg}")

        # Try airodump-ng first (best option)
        if self._command_exists('airodump-ng'):
            return self._scan_with_airodump(duration, channel, progress_callback)

        # Fallback to iw scan
        if progress_callback:
            progress_callback("fallback", 0, "Using iw scan (airodump-ng not found)")
        else:
            print("[!] airodump-ng not found, using iw scan (less detailed)")
        return self._scan_with_iw(progress_callback)

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

    def _scan_with_airodump(self, duration: int, channel: Optional[int] = None, progress_callback=None) -> List[WiFiNetwork]:
        """Scan using airodump-ng"""
        import tempfile
        import os

        # Check if running as root (airodump-ng requires root)
        if os.geteuid() != 0:
            print("[!] airodump-ng requires root privileges")
            print("[!] Falling back to iw scan (may be less detailed)")
            return self._scan_with_iw()

        # Validate interface is in monitor mode
        try:
            result = subprocess.run(
                ['iw', 'dev', self.interface, 'info'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                is_monitor = False
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('type '):
                        iface_type = line.split()[1]
                        is_monitor = (iface_type == 'monitor')
                        break
                
                if not is_monitor:
                    print(f"[!] Warning: Interface {self.interface} is not in monitor mode")
                    print("[!] airodump-ng requires monitor mode. Attempting to enable...")
                    # Try to enable monitor mode
                    from .monitor_mode import MonitorMode
                    monitor = MonitorMode()
                    success, message, mon_iface = monitor.enable_monitor_mode(self.interface)
                    if success:
                        self.interface = mon_iface
                        print(f"[+] {message}")
                    else:
                        print(f"[-] Failed to enable monitor mode: {message}")
                        print("[-] Falling back to iw scan")
                        return self._scan_with_iw()
        except Exception as e:
            print(f"[!] Could not verify monitor mode: {e}")
            print("[!] Continuing with scan attempt...")

        # Verify interface is up
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', self.interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                if 'state DOWN' in result.stdout:
                    print(f"[!] Interface {self.interface} is down, bringing it up...")
                    subprocess.run(
                        ['ip', 'link', 'set', self.interface, 'up'],
                        capture_output=True,
                        timeout=5
                    )
        except Exception as e:
            print(f"[!] Could not verify interface state: {e}")

        # Create temporary file for output
        # airodump-ng writes to current working directory, so use absolute path
        temp_dir = tempfile.gettempdir()
        temp_dir = os.path.abspath(temp_dir)
        temp_prefix = os.path.join(temp_dir, f'wifucker_scan_{os.getpid()}')
        
        # Change to temp directory so airodump-ng writes there
        original_cwd = os.getcwd()
        try:
            os.chdir(temp_dir)
        except:
            pass  # If we can't change dir, airodump-ng will write to current dir

        # Build command - use just the filename, not full path (airodump-ng adds suffix)
        base_name = os.path.basename(temp_prefix)
        cmd = ['airodump-ng', self.interface, '-w', base_name, '--output-format', 'csv']

        if channel:
            cmd.extend(['-c', str(channel)])

        process = None
        try:
            # Start airodump-ng
            # Don't capture stderr so we can see errors, but redirect stdout to avoid terminal mess
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,  # Suppress terminal output
                stderr=subprocess.PIPE,  # Capture errors
                preexec_fn=os.setsid,
                cwd=temp_dir  # Run in temp directory
            )

            self.scan_process = process
            
            # Check if process started successfully (wait a moment to see if it crashes immediately)
            time.sleep(0.5)
            if process.poll() is not None:
                # Process exited immediately, likely an error
                stdout, stderr = process.communicate()
                error_msg = stderr.decode('utf-8', errors='ignore') if stderr else stdout.decode('utf-8', errors='ignore')
                if 'monitor mode' in error_msg.lower() or 'monitor' in error_msg.lower():
                    print("[-] Error: Interface must be in monitor mode for airodump-ng")
                    print("[-] Falling back to iw scan")
                    return self._scan_with_iw()
                elif 'permission' in error_msg.lower() or 'denied' in error_msg.lower():
                    print("[-] Permission denied. airodump-ng requires root privileges.")
                    print("[-] Falling back to iw scan")
                    return self._scan_with_iw()
                else:
                    print(f"[-] airodump-ng failed to start: {error_msg[:200]}")
                    print("[-] Falling back to iw scan")
                    return self._scan_with_iw()

            # Let it run for specified duration
            if progress_callback:
                progress_callback("scanning", 0, f"Scanning for {duration} seconds...")
            else:
                print(f"[*] Scanning for {duration} seconds...")

            networks_found = 0
            best_signal = -100

            for i in range(duration):
                time.sleep(1)
                progress_percent = (i + 1) / duration * 100

                # Try to get intermediate results (if CSV file exists and has content)
                try:
                    if os.path.exists(temp_prefix + "-01.csv"):
                        intermediate_networks = self._parse_airodump_csv(temp_prefix + "-01.csv")
                        networks_found = len(intermediate_networks)
                        if intermediate_networks:
                            best_signal = max(n.power for n in intermediate_networks)
                except:
                    pass  # Ignore errors in intermediate parsing

                # Create enhanced progress message
                if networks_found > 0:
                    status_msg = f"Found {networks_found} networks (best: {best_signal}dBm) - {i+1}/{duration}s"
                else:
                    status_msg = f"Scanning... {i+1}/{duration}s"

                if progress_callback:
                    progress_callback("scanning", progress_percent, status_msg)
                elif (i + 1) % 2 == 0:  # Update every 2 seconds
                    print(f"\r[*] {status_msg}", end='', flush=True)

            if not progress_callback:
                print()

            # Stop process
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                process.wait(timeout=5)
            except ProcessLookupError:
                pass  # Process already terminated
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except:
                    pass

        except PermissionError:
            print("[-] Permission denied. airodump-ng requires root privileges.")
            print("[-] Falling back to iw scan")
            return self._scan_with_iw()
        except Exception as e:
            print(f"[-] Error during scan: {e}")
            if process:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except:
                    pass

        finally:
            self.scan_process = None
            # Restore original directory
            try:
                os.chdir(original_cwd)
            except:
                pass

        # Parse results - wait for file to be written and find the correct file
        import glob
        
        # Wait a moment for file to be written (airodump-ng needs time)
        time.sleep(2.0)
        
        # Try to find the CSV file (airodump-ng creates files with -01, -02, etc.)
        # airodump-ng writes to current working directory (which we changed to temp_dir)
        base_name = os.path.basename(temp_prefix)
        patterns = [
            os.path.join(temp_dir, f"{base_name}-*.csv"),  # In temp dir (where we chdir'd)
            f"{temp_prefix}-*.csv",  # Original pattern
            os.path.join(original_cwd, f"{base_name}-*.csv"),  # In original cwd (fallback)
        ]
        
        csv_files = []
        for pattern in patterns:
            csv_files.extend(glob.glob(pattern))
        
        # Remove duplicates and sort
        csv_files = sorted(list(set(csv_files)))
        
        if csv_files:
            # Use the most recent file (highest number, or by modification time)
            csv_file = max(csv_files, key=lambda f: (os.path.getmtime(f) if os.path.exists(f) else 0, f))
            
            # Wait a bit more if file is very small (might still be writing)
            max_wait = 3
            wait_count = 0
            while os.path.getsize(csv_file) < 100 and wait_count < max_wait:
                time.sleep(1.0)
                wait_count += 1
            
            try:
                # Debug: check file size and content
                file_size = os.path.getsize(csv_file)
                if file_size < 50:
                    print(f"[!] CSV file is very small ({file_size} bytes), may be incomplete")
                
                networks = self._parse_airodump_csv(csv_file)
                
                # Clean up temp files
                try:
                    for f in os.listdir(temp_dir):
                        if f.startswith(os.path.basename(temp_prefix)):
                            try:
                                os.remove(os.path.join(temp_dir, f))
                            except:
                                pass
                except:
                    pass
                
                if networks:
                    return networks
                else:
                    # Debug: check if file has content
                    with open(csv_file, 'r', errors='ignore') as f:
                        content = f.read()
                        if len(content) > 100:
                            print(f"[!] CSV file has content ({len(content)} bytes) but no networks parsed")
                            # Try to see what went wrong
                            lines = content.split('\n')
                            print(f"[!] File has {len(lines)} lines")
                            if len(lines) > 1:
                                print(f"[!] First line: {lines[0][:100]}")
                                print(f"[!] Second line: {lines[1][:100] if len(lines) > 1 else 'N/A'}")
            except Exception as e:
                print(f"[-] Error parsing CSV file: {e}")
        else:
            print(f"[-] No CSV file found matching pattern: {pattern}")

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
        import os
        
        # Try without sudo first (if already root)
        cmd = ['iw', self.interface, 'scan']
        if os.geteuid() != 0:
            # Not root, try with sudo
            cmd = ['sudo', 'iw', self.interface, 'scan']
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                if 'Operation not permitted' in error_msg or 'Permission denied' in error_msg:
                    print("[-] Permission denied. iw scan requires root privileges.")
                    print("[-] Try running with: sudo -E ./wifucker")
                else:
                    print(f"[-] Scan failed: {error_msg}")
                return []

            return self._parse_iw_output(result.stdout)

        except FileNotFoundError:
            print("[-] 'iw' command not found. Install with: sudo apt install iw")
            return []
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
