#!/usr/bin/env python3
"""
WiFi Adapter Optimizer
======================

Automatically configures WiFi adapter for maximum performance:
- Sets maximum TX power
- Enables packet injection
- Optimizes antenna configuration
- Sets optimal channel width
- Disables power saving
- Enables monitor mode features
"""

import subprocess
import re
from typing import Tuple, Dict, List, Optional
from dataclasses import dataclass


@dataclass
class AdapterCapabilities:
    """WiFi adapter capabilities"""
    interface: str
    driver: str
    chipset: str
    max_tx_power: int  # dBm
    current_tx_power: int  # dBm
    supports_monitor: bool
    supports_injection: bool
    supports_ap: bool
    antenna_count: int
    supported_bands: List[str]  # ['2.4GHz', '5GHz', '6GHz']
    current_channel: Optional[int]
    current_frequency: Optional[int]


class AdapterOptimizer:
    """WiFi adapter performance optimizer"""

    def __init__(self, interface: str):
        self.interface = interface

    def _run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Run command and return exit code, stdout, stderr"""
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

    def detect_capabilities(self) -> AdapterCapabilities:
        """Detect adapter capabilities"""

        # Get basic info
        returncode, stdout, stderr = self._run_command(['iw', 'dev', self.interface, 'info'])

        if returncode != 0:
            raise RuntimeError(f"Failed to get adapter info: {stderr}")

        # Parse output
        driver = "unknown"
        chipset = "unknown"
        current_channel = None
        current_freq = None

        for line in stdout.split('\n'):
            line = line.strip()

            if 'channel' in line.lower():
                match = re.search(r'channel (\d+)', line)
                if match:
                    current_channel = int(match.group(1))

                match = re.search(r'(\d+) MHz', line)
                if match:
                    current_freq = int(match.group(1))

        # Get PHY info for capabilities
        returncode, stdout, stderr = self._run_command(['iw', 'phy'])

        max_tx_power = 20  # Default
        supports_monitor = False
        supports_injection = False
        supports_ap = False
        antenna_count = 1
        supported_bands = []

        if returncode == 0:
            # Parse PHY info
            if 'monitor' in stdout.lower():
                supports_monitor = True

            if 'AP' in stdout or 'AP/VLAN' in stdout:
                supports_ap = True

            # TX power
            match = re.search(r'(\d+\.\d+) dBm', stdout)
            if match:
                max_tx_power = int(float(match.group(1)))

            # Bands
            if '2.4 GHz' in stdout or '2412 MHz' in stdout:
                supported_bands.append('2.4GHz')
            if '5 GHz' in stdout or '5180 MHz' in stdout:
                supported_bands.append('5GHz')
            if '6 GHz' in stdout or '5955 MHz' in stdout:
                supported_bands.append('6GHz')

            # Antennas
            match = re.search(r'Available Antennas:.*?(\d+)', stdout)
            if match:
                antenna_count = int(match.group(1))

        # Get current TX power
        returncode, stdout, stderr = self._run_command(['iw', 'dev', self.interface, 'info'])

        current_tx_power = 20  # Default
        if returncode == 0:
            match = re.search(r'txpower ([\d.]+) dBm', stdout)
            if match:
                current_tx_power = int(float(match.group(1)))

        # Get driver info
        driver_path = f"/sys/class/net/{self.interface}/device/driver"
        try:
            import os
            if os.path.exists(driver_path):
                driver = os.path.basename(os.path.realpath(driver_path))
        except:
            pass

        # Detect chipset
        chipset = self._detect_chipset()

        # Assume injection support for monitor-capable adapters
        supports_injection = supports_monitor

        return AdapterCapabilities(
            interface=self.interface,
            driver=driver,
            chipset=chipset,
            max_tx_power=max_tx_power,
            current_tx_power=current_tx_power,
            supports_monitor=supports_monitor,
            supports_injection=supports_injection,
            supports_ap=supports_ap,
            antenna_count=antenna_count,
            supported_bands=supported_bands,
            current_channel=current_channel,
            current_frequency=current_freq
        )

    def _detect_chipset(self) -> str:
        """Detect WiFi chipset"""
        # Try lspci for PCI devices
        returncode, stdout, _ = self._run_command(['lspci'])
        if returncode == 0:
            for line in stdout.split('\n'):
                if 'Network controller' in line or 'Wireless' in line:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        return parts[1].strip()

        # Try lsusb for USB devices
        returncode, stdout, _ = self._run_command(['lsusb'])
        if returncode == 0:
            for line in stdout.split('\n'):
                if 'Wireless' in line or '802.11' in line or 'WiFi' in line:
                    parts = line.split(':', 2)
                    if len(parts) > 2:
                        return parts[2].strip()

        return "Unknown chipset"

    def optimize(self, aggressive: bool = False) -> Dict[str, bool]:
        """
        Optimize adapter for maximum performance

        Args:
            aggressive: Enable aggressive optimizations (may be unstable)

        Returns:
            Dictionary of optimization results
        """
        results = {}

        print(f"[*] Optimizing {self.interface} for maximum performance...")

        # Get capabilities first
        try:
            caps = self.detect_capabilities()
            print(f"[*] Chipset: {caps.chipset}")
            print(f"[*] Driver: {caps.driver}")
            print(f"[*] Bands: {', '.join(caps.supported_bands)}")
            print(f"[*] Antennas: {caps.antenna_count}")
            print(f"[*] Current TX Power: {caps.current_tx_power} dBm")
            print(f"[*] Max TX Power: {caps.max_tx_power} dBm")
        except Exception as e:
            print(f"[-] Failed to detect capabilities: {e}")
            return results

        # 1. Set maximum TX power
        print(f"\n[*] Setting TX power to maximum ({caps.max_tx_power} dBm)...")
        returncode, _, _ = self._run_command([
            'sudo', 'iw', 'dev', self.interface,
            'set', 'txpower', 'fixed', str(caps.max_tx_power * 100)
        ])
        results['tx_power'] = (returncode == 0)

        if results['tx_power']:
            print(f"[+] TX power set to {caps.max_tx_power} dBm")
        else:
            print(f"[-] Failed to set TX power")

        # 2. Disable power saving
        print("\n[*] Disabling power saving...")
        returncode, _, _ = self._run_command([
            'sudo', 'iw', 'dev', self.interface, 'set', 'power_save', 'off'
        ])
        results['power_save'] = (returncode == 0)

        if results['power_save']:
            print("[+] Power saving disabled")
        else:
            print("[-] Failed to disable power saving")

        # 3. Set optimal antenna configuration
        if caps.antenna_count > 1:
            print(f"\n[*] Configuring {caps.antenna_count} antennas for TX/RX...")

            # Enable all antennas for both TX and RX
            antenna_mask = (1 << caps.antenna_count) - 1  # All antennas

            returncode, _, _ = self._run_command([
                'sudo', 'iw', 'phy',
                f'phy{self.interface}' if not self.interface.startswith('phy') else self.interface,
                'set', 'antenna', str(antenna_mask), str(antenna_mask)
            ])
            results['antenna'] = (returncode == 0)

            if results['antenna']:
                print(f"[+] Configured {caps.antenna_count} antennas")
            else:
                print("[-] Failed to configure antennas")

        # 4. Optimize for monitor mode
        if caps.supports_monitor:
            print("\n[*] Enabling monitor mode flags...")

            # These flags improve packet capture
            flags = ['fcsfail', 'control', 'otherbss']

            for flag in flags:
                returncode, _, _ = self._run_command([
                    'sudo', 'iw', 'dev', self.interface,
                    'set', 'monitor', flag
                ])

                if returncode == 0:
                    print(f"[+] Enabled {flag} flag")
                    results[f'flag_{flag}'] = True
                else:
                    results[f'flag_{flag}'] = False

        # 5. Set regulatory domain for maximum power (if aggressive)
        if aggressive:
            print("\n[!] Aggressive mode: Setting regulatory domain...")
            print("[!] Warning: This may violate local regulations")

            # BO (Bolivia) allows high TX power
            returncode, _, _ = self._run_command([
                'sudo', 'iw', 'reg', 'set', 'BO'
            ])
            results['regulatory'] = (returncode == 0)

            if results['regulatory']:
                print("[+] Regulatory domain set (use with caution!)")
            else:
                print("[-] Failed to set regulatory domain")

        # 6. Disable hardware encryption (better packet injection)
        if caps.driver in ['ath9k', 'ath9k_htc', 'rt2800usb', 'rtl8xxxu']:
            print("\n[*] Disabling hardware encryption for better injection...")

            driver_param = None
            if 'ath9k' in caps.driver:
                driver_param = 'nohwcrypt=1'
            elif 'rt2800' in caps.driver:
                driver_param = 'nohwcrypt=1'

            if driver_param:
                returncode, _, _ = self._run_command([
                    'sudo', 'modprobe', '-r', caps.driver
                ])

                returncode, _, _ = self._run_command([
                    'sudo', 'modprobe', caps.driver, driver_param
                ])
                results['hwcrypt'] = (returncode == 0)

                if results['hwcrypt']:
                    print("[+] Hardware encryption disabled")
                else:
                    print("[-] Failed to disable hardware encryption")

        # Print summary
        print("\n" + "="*60)
        print("OPTIMIZATION SUMMARY")
        print("="*60)

        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)

        print(f"Successful: {success_count}/{total_count}")

        for key, value in results.items():
            status = "✓" if value else "✗"
            print(f"  {status} {key}")

        print("="*60)

        return results

    def show_info(self):
        """Display detailed adapter information"""
        try:
            caps = self.detect_capabilities()

            print("\n" + "="*60)
            print("WIFI ADAPTER INFORMATION")
            print("="*60)
            print(f"Interface:       {caps.interface}")
            print(f"Driver:          {caps.driver}")
            print(f"Chipset:         {caps.chipset}")
            print(f"")
            print(f"Current TX Power: {caps.current_tx_power} dBm")
            print(f"Maximum TX Power: {caps.max_tx_power} dBm")
            print(f"")
            print(f"Monitor Mode:    {'Yes' if caps.supports_monitor else 'No'}")
            print(f"Packet Injection: {'Yes' if caps.supports_injection else 'No'}")
            print(f"AP Mode:         {'Yes' if caps.supports_ap else 'No'}")
            print(f"")
            print(f"Antennas:        {caps.antenna_count}")
            print(f"Supported Bands: {', '.join(caps.supported_bands) if caps.supported_bands else 'Unknown'}")
            print(f"")

            if caps.current_channel:
                print(f"Current Channel: {caps.current_channel}")
            if caps.current_frequency:
                print(f"Current Frequency: {caps.current_frequency} MHz")

            print("="*60)

        except Exception as e:
            print(f"[-] Error: {e}")


def main():
    """CLI interface"""
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description='Optimize WiFi adapter for maximum performance'
    )

    parser.add_argument('interface', help='Wireless interface name')
    parser.add_argument('--info', action='store_true', help='Show adapter information')
    parser.add_argument('--optimize', action='store_true', help='Optimize adapter')
    parser.add_argument('--aggressive', action='store_true',
                       help='Enable aggressive optimizations (use with caution)')

    args = parser.parse_args()

    optimizer = AdapterOptimizer(args.interface)

    if args.info:
        optimizer.show_info()
    elif args.optimize:
        results = optimizer.optimize(aggressive=args.aggressive)

        if all(results.values()):
            print("\n[+] All optimizations successful!")
            sys.exit(0)
        else:
            print("\n[!] Some optimizations failed")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
