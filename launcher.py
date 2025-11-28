#!/usr/bin/env python3
"""
WIFUCKER - Unified Launcher
===========================

Single command to:
1. Compile AVX-512 module
2. Detect and optimize WiFi adapter
3. Enable monitor mode
4. Launch interactive TUI

Usage:
    sudo wifucker-launch
    sudo wifucker-launch --interface wlan0
"""

import sys
import os
import subprocess
import time
from pathlib import Path
from typing import Optional, List, Tuple
from rich.console import Console
from rich.panel import Panel
from hw_detection import detect_accelerators
from install_builder import check_and_build_runtimes
from rich.text import Text
from rich.theme import Theme
import argparse

# Add current directory to sys.path for local module imports
sys.path.insert(0, str(Path(__file__).parent))

# TEMPEST Theme
tempest_theme = Theme(
    {
        "info": "cyan",
        "warning": "bold yellow",
        "error": "bold red",
        "success": "bold green",
        "header": "bold #ff9500",  # Amber
        "border": "#2d3640",
        "classification": "bold white on #ff0844",
    }
)

console = Console(theme=tempest_theme)


def print_banner():
    """Print launch banner"""
    banner_text = """
    WIFUCKER - TEMPEST CLASS C
    UNIFIED WARFARE LAUNCHER
    """

    console.print(
        Panel(
            Text(banner_text, justify="center", style="header"),
            border_style="header",
            subtitle="[bold #00ff41]🚀 COMPILE[/] │ [bold #00ffff]⚡ OPTIMIZE[/] │ [bold #ff9500]📡 MONITOR[/] │ [bold #ff0844]🎮 TUI[/]",
            subtitle_align="center",
        )
    )
    console.print(
        "[classification]  CLASSIFICATION: AUTHORIZED SECURITY PERSONNEL ONLY  [/]",
        justify="center",
    )
    console.print()


def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        console.print("[error]❌ FATAL: ROOT PRIVILEGES REQUIRED[/]")
        console.print("[info]ℹ Run with: sudo wifucker-launch[/]")
        sys.exit(1)


def run_command(cmd: List[str], silent: bool = False) -> Tuple[int, str, str]:
    """Run command and return result"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if not silent and result.returncode != 0 and result.stderr:
            console.print(f"[warning]⚠ COMMAND WARNING: {result.stderr.strip()}[/]")
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def detect_wireless_interfaces() -> List[str]:
    """Detect wireless interfaces"""
    console.print("\n[header][1/5] 📡 DETECTING WIRELESS INTERFACES...[/]")

    interfaces = []

    # Use iw dev
    returncode, stdout, _ = run_command(["iw", "dev"], silent=True)

    if returncode == 0:
        for line in stdout.split("\n"):
            if "Interface" in line:
                iface = line.split()[1]
                interfaces.append(iface)

    # Fallback: check /sys/class/net
    if not interfaces:
        try:
            for iface in os.listdir("/sys/class/net"):
                if iface.startswith("wlan") or iface.startswith("wlp"):
                    interfaces.append(iface)
        except:
            pass

    if interfaces:
        console.print(f"[success]✓ FOUND {len(interfaces)} INTERFACE(S):[/]")
        for iface in interfaces:
            console.print(f"    [info]➤ {iface}[/]")
        return interfaces
    else:
        console.print("[error]❌ NO WIRELESS INTERFACES FOUND[/]")
        sys.exit(1)


def select_interface(interfaces: list[str], specified: Optional[str] = None) -> str:
    """Select wireless interface"""
    if specified:
        if specified in interfaces:
            console.print(f"[success]✓ USING SPECIFIED INTERFACE: {specified}[/]")
            return specified
        else:
            console.print(f"[error]❌ SPECIFIED INTERFACE '{specified}' NOT FOUND[/]")
            sys.exit(1)

    if len(interfaces) == 1:
        console.print(f"[success]✓ USING INTERFACE: {interfaces[0]}[/]")
        return interfaces[0]

    # Let user select
    console.print(f"\n[info]SELECT WIRELESS INTERFACE:[/]")
    for i, iface in enumerate(interfaces, 1):
        console.print(f"  [bold]{i}.[/] {iface}")

    while True:
        try:
            choice = console.input(f"\n[info]ENTER CHOICE (1-{len(interfaces)}): [/]")
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
        except (ValueError, KeyboardInterrupt):
            console.print(f"\n[error]❌ CANCELLED[/]")
            sys.exit(1)


def compile_avx512_module():
    """Compile AVX-512 cracker module"""
    console.print(f"\n[header][2/5] 🚀 COMPILING AVX-512 MODULE...[/]")

    # Find crackers directory
    module_dir = Path(__file__).parent / "crackers"

    if not module_dir.exists():
        # Try relative paths
        possible_paths = [
            Path("/usr/local/lib/python*/dist-packages/davbest/wifi/crackers"),
            Path.home() / ".local/lib/python*/site-packages/davbest/wifi/crackers",
            Path(__file__).parent.parent / "crackers",
        ]

        for path in possible_paths:
            matches = list(Path("/").glob(str(path).lstrip("/")))
            if matches:
                module_dir = matches[0]
                break

    if not module_dir.exists() or not (module_dir / "Makefile").exists():
        console.print(f"[warning]⚠ AVX-512 MODULE NOT FOUND, SKIPPING[/]")
        return False

    # Check if already compiled
    so_file = module_dir / "avx512_cracker.so"
    if so_file.exists():
        console.print(f"[success]✓ AVX-512 MODULE READY[/]")
        return True

    # Check for build tools
    returncode, _, _ = run_command(["which", "gcc"], silent=True)
    if returncode != 0:
        console.print(f"[warning]⚠ GCC NOT FOUND, SKIPPING COMPILATION[/]")
        console.print(f"[info]ℹ Install with: sudo apt install build-essential libssl-dev[/]")
        return False

    # Compile
    console.print(f"[info]⚙ Compiling (this may take a minute)...[/]")
    returncode, stdout, stderr = run_command(["make", "-C", str(module_dir)])

    if returncode == 0 and so_file.exists():
        console.print(f"[success]✓ COMPILATION SUCCESSFUL[/]")
        console.print(f"[success]✓ PERFORMANCE: 200,000-500,000 H/s[/]")
        return True
    else:
        console.print(f"[warning]⚠ COMPILATION FAILED (NON-CRITICAL)[/]")
        if stderr:
            console.print(f"[dim]{stderr.strip()[:100]}[/]")
        return False


def optimize_adapter(interface: str):
    """Optimize WiFi adapter"""
    console.print(f"\n[header][3/5] ⚡ OPTIMIZING ADAPTER...[/]")

    try:
        # Import optimizer
        from capture.adapter_optimizer import AdapterOptimizer

        optimizer = AdapterOptimizer(interface)

        # Get capabilities
        try:
            caps = optimizer.detect_capabilities()
            console.print(f"[info]➤ CHIPSET:[/] {caps.chipset}")
            console.print(f"[info]➤ DRIVER:[/] {caps.driver}")
            console.print(
                f"[info]➤ TX POWER:[/] {caps.current_tx_power} dBm → {caps.max_tx_power} dBm"
            )
        except Exception:
            pass

        # Optimize
        results = optimizer.optimize(aggressive=False)

        success_count = sum(1 for v in results.values() if v)
        if success_count > 0:
            console.print(
                f"[success]✓ OPTIMIZATION COMPLETE: {success_count}/{len(results)} SUCCESSFUL[/]"
            )
        else:
            console.print(f"[warning]⚠ LIMITED OPTIMIZATION SUCCESS[/]")

        return True

    except Exception as e:
        console.print(f"[warning]⚠ OPTIMIZATION FAILED: {e}[/]")
        return False


def enable_monitor_mode(interface: str) -> str:
    """Enable monitor mode and return monitor interface name"""
    try:
        from capture.monitor_mode import MonitorMode

        monitor = MonitorMode()

        # Kill interfering processes
        console.print(f"[info]➤ KILLING INTERFERING PROCESSES...[/]")
        run_command(["airmon-ng", "check", "kill"], silent=True)

        # Enable monitor mode
        success, message, mon_iface = monitor.enable_monitor_mode(interface)

        if success and mon_iface:
            console.print(f"[success]✓ MONITOR MODE ENABLED: {mon_iface}[/]")

            # Optimize monitor interface too
            time.sleep(1)
            console.print(f"[info]➤ OPTIMIZING MONITOR INTERFACE...[/]")
            optimize_adapter(mon_iface)

            return mon_iface
        else:
            console.print(f"[error]❌ FAILED TO ENABLE MONITOR MODE: {message}[/]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[error]❌ ERROR: {e}[/]")
        sys.exit(1)


def launch_tui(interface: str, accelerators: Optional[list[str]] = None):
    """Launch the interactive TUI"""
    if accelerators is None:
        accelerators = []
    console.print(f"\n[header][5/5] 🎮 LAUNCHING TUI...[/]")
    console.print(f"[success]✓ INTERFACE: {interface}[/]")
    console.print(f"[success]✓ SYSTEMS ARMED AND READY[/]")
    console.print(f"[info]✓ ACCELERATORS: {', '.join(accelerators) if accelerators else 'None'}[/]")

    time.sleep(2)
    try:
        # Try to import and launch TUI
        from wifi_tui import TempestWiFiTUI as WiFiTUI

        app = WiFiTUI(interface, accelerators=accelerators)
        app.run()

    except ImportError as e:
        # Fallback: launch via command
        console.print(f"[warning]⚠ LAUNCHING VIA COMMAND LINE (import failed: {e})...[/]")
        tui_path = Path(__file__).parent / "wifi_tui.py"
        if tui_path.exists():
            os.execvp(sys.executable, [sys.executable, str(tui_path), "--interface", interface])
        else:
            console.print(f"[error]❌ TUI SCRIPT NOT FOUND AT {tui_path}[/]")
            sys.exit(1)


def cleanup(interface: str):
    """Cleanup on exit"""
    console.print(f"\n[info]🧹 CLEANING UP...[/]")

    try:
        from capture.monitor_mode import MonitorMode

        monitor = MonitorMode()
        success, message = monitor.disable_monitor_mode(interface)

        if success:
            console.print(f"[success]✓ {message}[/]")
        else:
            console.print(f"[warning]⚠ {message}[/]")
    except Exception:
        pass

    # Restart NetworkManager
    console.print(f"[info]➤ RESTARTING NETWORKMANAGER...[/]")
    run_command(["systemctl", "start", "NetworkManager"], silent=True)


def main():
    """Main function to run the WiFi cracker setup and TUI."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Launch the Tempest WiFi Cracker TUI.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        help="Specify the wireless interface to use (e.g., wlan0).",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode for detailed error messages."
    )
    args = parser.parse_args()

    try:
        # Step 1: Check for root privileges
        check_root()

        # Step 2: Select wireless interface
        interfaces = detect_wireless_interfaces()
        interface = select_interface(interfaces, args.interface)

        # Step 3: Compile AVX-512 module
        compile_avx512_module()

        # Step 4: Optimize adapter
        optimize_adapter(interface)

        # Step 5: Enable monitor mode
        mon_interface = enable_monitor_mode(interface)

        # Step 6: Detect hardware accelerators
        accelerators = detect_accelerators()
        console.print(
            f"[info]✓ DETECTED ACCELERATORS: {', '.join(accelerators) if accelerators else 'None'}"
        )

        # Step 7: Launch TUI with accelerators
        launch_tui(mon_interface, accelerators=accelerators)

    except KeyboardInterrupt:
        console.print(f"\n\n[warning]⚠ INTERRUPTED BY USER[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[error]❌ ERROR: {e}[/]")
        if args.debug:
            raise
        sys.exit(1)
    finally:
        # Cleanup will be handled by TUI exit routine
        pass


if __name__ == "__main__":
    main()
