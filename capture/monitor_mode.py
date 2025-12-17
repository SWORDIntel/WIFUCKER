#!/usr/bin/env python3
"""
WiFi Monitor Mode Manager
=========================

Handles putting WiFi adapters into monitor mode and interface detection.
"""

import subprocess
import re
import os
from typing import List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class WirelessInterface:
    """Wireless interface information"""
    name: str
    phy: str
    driver: str
    chipset: str
    monitor_capable: bool
    in_monitor_mode: bool

    def __str__(self):
        mode = "Monitor" if self.in_monitor_mode else "Managed"
        status = "✓" if self.monitor_capable else "✗"
        return f"{self.name} [{mode}] {status} {self.chipset} ({self.driver})"


class MonitorMode:
    """WiFi monitor mode manager"""

    def __init__(self):
        self.original_interfaces = {}

    def _run_command(self, cmd: List[str], check_root: bool = True) -> Tuple[int, str, str]:
        """Run command and return exit code, stdout, stderr"""
        if check_root and os.geteuid() != 0:
            # Try with sudo
            cmd = ['sudo'] + cmd

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def detect_interfaces(self) -> List[WirelessInterface]:
        """Detect wireless interfaces"""
        interfaces = []

        # Try using iwconfig first
        returncode, stdout, _ = self._run_command(['iwconfig'], check_root=False)

        if returncode == 0:
            # Parse iwconfig output
            current_iface = None
            for line in stdout.split('\n'):
                if line and not line.startswith(' '):
                    # New interface
                    match = re.match(r'^(\w+)\s+', line)
                    if match:
                        iface_name = match.group(1)

                        # Check if it's a wireless interface
                        if 'IEEE 802.11' in line or 'ESSID' in line:
                            # Get interface details
                            phy, driver, chipset = self._get_interface_details(iface_name)
                            in_monitor = 'Mode:Monitor' in line

                            interfaces.append(WirelessInterface(
                                name=iface_name,
                                phy=phy,
                                driver=driver,
                                chipset=chipset,
                                monitor_capable=True,  # Assume capable if wireless
                                in_monitor_mode=in_monitor
                            ))

        # Fallback: Try using iw dev
        if not interfaces:
            returncode, stdout, _ = self._run_command(['iw', 'dev'], check_root=False)

            if returncode == 0:
                current_iface = None
                for line in stdout.split('\n'):
                    line = line.strip()

                    if line.startswith('Interface '):
                        iface_name = line.split()[1]
                        current_iface = iface_name
                    elif line.startswith('type ') and current_iface:
                        iface_type = line.split()[1]
                        in_monitor = iface_type == 'monitor'

                        phy, driver, chipset = self._get_interface_details(current_iface)

                        interfaces.append(WirelessInterface(
                            name=current_iface,
                            phy=phy,
                            driver=driver,
                            chipset=chipset,
                            monitor_capable=True,
                            in_monitor_mode=in_monitor
                        ))
                        current_iface = None

        return interfaces

    def is_in_monitor_mode(self, interface: str) -> bool:
        """
        Check if an interface is currently in monitor mode
        
        Args:
            interface: Interface name to check
            
        Returns:
            True if interface is in monitor mode, False otherwise
        """
        # Method 1: Try using iw dev info
        returncode, stdout, _ = self._run_command(['iw', 'dev', interface, 'info'], check_root=False)
        if returncode == 0:
            for line in stdout.split('\n'):
                line = line.strip()
                if line.startswith('type '):
                    iface_type = line.split()[1]
                    return iface_type == 'monitor'
        
        # Method 2: Try using iwconfig
        returncode, stdout, _ = self._run_command(['iwconfig', interface], check_root=False)
        if returncode == 0:
            return 'Mode:Monitor' in stdout
        
        # Method 3: Try using iw dev (list all interfaces)
        returncode, stdout, _ = self._run_command(['iw', 'dev'], check_root=False)
        if returncode == 0:
            current_iface = None
            for line in stdout.split('\n'):
                line = line.strip()
                if line.startswith('Interface '):
                    iface_name = line.split()[1]
                    current_iface = iface_name
                elif line.startswith('type ') and current_iface == interface:
                    iface_type = line.split()[1]
                    return iface_type == 'monitor'
        
        # If we can't determine, assume not in monitor mode
        return False

    def _get_interface_details(self, iface: str) -> Tuple[str, str, str]:
        """Get PHY, driver, and chipset for interface"""
        phy = "unknown"
        driver = "unknown"
        chipset = "unknown"

        # Get PHY
        returncode, stdout, _ = self._run_command(['iw', 'dev', iface, 'info'], check_root=False)
        if returncode == 0:
            for line in stdout.split('\n'):
                if 'wiphy' in line:
                    match = re.search(r'wiphy (\d+)', line)
                    if match:
                        phy = f"phy{match.group(1)}"

        # Get driver
        driver_path = f"/sys/class/net/{iface}/device/driver"
        if os.path.exists(driver_path):
            try:
                driver = os.path.basename(os.path.realpath(driver_path))
            except:
                pass

        # Get chipset from lspci or lsusb
        chipset = self._detect_chipset(iface)

        return phy, driver, chipset

    def _detect_chipset(self, iface: str) -> str:
        """Detect chipset using lspci/lsusb"""
        # Try lspci for PCI devices
        returncode, stdout, _ = self._run_command(['lspci'], check_root=False)
        if returncode == 0:
            for line in stdout.split('\n'):
                if 'Network controller' in line or 'Wireless' in line:
                    # Extract chipset info
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        return parts[1].strip()

        # Try lsusb for USB devices
        returncode, stdout, _ = self._run_command(['lsusb'], check_root=False)
        if returncode == 0:
            for line in stdout.split('\n'):
                if 'Wireless' in line or '802.11' in line or 'WiFi' in line:
                    parts = line.split(':', 2)
                    if len(parts) > 2:
                        return parts[2].strip()

        return "Unknown chipset"

    def enable_monitor_mode(self, interface: str) -> Tuple[bool, str, Optional[str]]:
        """
        Enable monitor mode on interface

        Returns:
            (success, message, monitor_interface_name)
        """
        # Store original interface
        self.original_interfaces[interface] = interface

        # Method 1: Try airmon-ng (if available)
        returncode, _, _ = self._run_command(['which', 'airmon-ng'], check_root=False)
        if returncode == 0:
            # Kill interfering processes
            self._run_command(['airmon-ng', 'check', 'kill'])

            # Start monitor mode
            returncode, stdout, stderr = self._run_command(['airmon-ng', 'start', interface])

            if returncode == 0:
                # Parse output to get monitor interface name
                match = re.search(r'monitor mode (?:enabled|vif enabled) on (\w+)', stdout + stderr)
                if match:
                    mon_iface = match.group(1)
                    return True, f"Monitor mode enabled on {mon_iface}", mon_iface
                else:
                    # Assume interface name with 'mon' suffix
                    mon_iface = f"{interface}mon"
                    return True, f"Monitor mode enabled (assumed {mon_iface})", mon_iface

        # Method 2: Manual method using iw/ip
        monitor_iface = f"{interface}mon"

        # Bring interface down
        returncode, _, _ = self._run_command(['ip', 'link', 'set', interface, 'down'])
        if returncode != 0:
            returncode, _, _ = self._run_command(['ifconfig', interface, 'down'])
            if returncode != 0:
                return False, f"Failed to bring {interface} down", None

        # Try using iw to set monitor mode
        returncode, stdout, stderr = self._run_command(['iw', interface, 'set', 'monitor', 'none'])

        if returncode == 0:
            # Bring interface back up
            self._run_command(['ip', 'link', 'set', interface, 'up'])
            return True, f"Monitor mode enabled on {interface}", interface

        # Try using iwconfig (older method)
        returncode, _, _ = self._run_command(['iwconfig', interface, 'mode', 'monitor'])

        if returncode == 0:
            self._run_command(['ip', 'link', 'set', interface, 'up'])
            return True, f"Monitor mode enabled on {interface}", interface

        return False, f"Failed to enable monitor mode on {interface}", None

    def disable_monitor_mode(self, interface: str) -> Tuple[bool, str]:
        """
        Disable monitor mode and restore managed mode

        Returns:
            (success, message)
        """
        # Method 1: Try airmon-ng
        returncode, _, _ = self._run_command(['which', 'airmon-ng'], check_root=False)
        if returncode == 0:
            returncode, stdout, stderr = self._run_command(['airmon-ng', 'stop', interface])

            if returncode == 0:
                return True, f"Monitor mode disabled on {interface}"

        # Method 2: Manual method
        self._run_command(['ip', 'link', 'set', interface, 'down'])

        # Set managed mode
        returncode, _, _ = self._run_command(['iw', interface, 'set', 'type', 'managed'])

        if returncode != 0:
            # Try iwconfig
            returncode, _, _ = self._run_command(['iwconfig', interface, 'mode', 'managed'])

        self._run_command(['ip', 'link', 'set', interface, 'up'])

        # Restart NetworkManager if it was stopped
        self._run_command(['systemctl', 'start', 'NetworkManager'])

        if returncode == 0:
            return True, f"Monitor mode disabled on {interface}"

        return False, f"Failed to disable monitor mode on {interface}"

    def check_requirements(self) -> Tuple[bool, List[str]]:
        """
        Check if required tools are installed

        Returns:
            (all_present, missing_tools)
        """
        required_tools = ['iw', 'iwconfig', 'ip']
        optional_tools = ['airmon-ng', 'airodump-ng', 'aireplay-ng']

        missing = []

        for tool in required_tools:
            returncode, _, _ = self._run_command(['which', tool], check_root=False)
            if returncode != 0:
                missing.append(tool)

        optional_missing = []
        for tool in optional_tools:
            returncode, _, _ = self._run_command(['which', tool], check_root=False)
            if returncode != 0:
                optional_missing.append(tool)

        return (len(missing) == 0, missing, optional_missing)
