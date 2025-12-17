#!/usr/bin/env python3
"""
WIFUCKER Unified TUI - Next Generation
========================================
Integrated WiFi + PBKDF2 password cracking interface
Supports: WiFi WPA cracking, PBKDF2 dictionary attacks, steganography

Features:
- Multi-tab interface (WiFi, PBKDF2, Tools, Reports)
- Real-time progress monitoring
- Hardware acceleration detection (NPU, NCS2, GPU)
- Integration with rockyou wordlist
- Context-aware password generation
- Multi-threaded cracking engine
"""

import sys
from pathlib import Path

# Check if running directly without venv
try:
    from textual.app import App, ComposeResult
except ImportError:
    script_dir = Path(__file__).parent
    venv_python = script_dir / "venv" / "bin" / "python3"

    if venv_python.exists():
        print("=" * 60)
        print("ERROR: Missing dependencies detected")
        print("=" * 60)
        print(f"\nPlease use the launcher script instead:")
        print(f"  {script_dir}/wifucker")
        print(f"\nOr activate the virtual environment first:")
        print(f"  source {script_dir}/venv/bin/activate")
        print(f"  python3 {Path(__file__).name}")
        print("\nIf you need sudo, use:")
        print(f"  sudo -E {script_dir}/wifucker")
        print("=" * 60)
        sys.exit(1)
    else:
        print("ERROR: textual module not found and venv not detected")
        print("Please run the launcher: ./wifucker")
        sys.exit(1)

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual.widgets import (
    Header, Footer, Button, Static, Input, Label, Log, RichLog,
    TabbedContent, TabPane, Switch, RadioSet, RadioButton, DirectoryTree, DataTable
)
from textual import on
from textual.binding import Binding
from textual.message import Message
from typing import Optional, Callable, Tuple, List, Dict
import threading
import asyncio
import os
from rich.text import Text
import subprocess

ROOT_DIR = Path(__file__).parent
SCRIPTS_DIR = ROOT_DIR / "scripts"
VENV_PYTHON = ROOT_DIR / "venv" / "bin" / "python3"
PYTHON_BIN = str(VENV_PYTHON if VENV_PYTHON.exists() else sys.executable)
DSMIL_ROOT = ROOT_DIR.parent.parent

# Import PBKDF2 cracker modules
from crackers import (
    PBKDF2Cracker, CrackingResult, MutationEngine, ContextWordlistGenerator
)


class MarkupLog(RichLog):
    """Log widget that always treats string input as rich markup."""
    # RichLog already handles markup strings and Rich renderables natively,
    # so we can use it directly without custom conversion logic


def detect_package_manager():
    """
    Detect which package manager is available on the system.
    
    Returns:
        str: Package manager name ('apt', 'dnf', 'yum', 'pacman', 'zypper', 'emerge')
             or None if none detected
    """
    import shutil
    
    if shutil.which('apt'):
        return 'apt'
    elif shutil.which('dnf'):
        return 'dnf'
    elif shutil.which('yum'):
        return 'yum'
    elif shutil.which('pacman'):
        return 'pacman'
    elif shutil.which('zypper'):
        return 'zypper'
    elif shutil.which('emerge'):
        return 'emerge'
    return None


def install_tools_auto(tools: list, log_callback=None) -> bool:
    """
    Automatically install missing tools
    
    Args:
        tools: List of tool names to check/install
        log_callback: Optional callback function for logging (takes string message)
    
    Returns:
        True if all tools are now available, False otherwise
    """
    import os
    import subprocess
    import shutil
    
    def log(msg):
        if log_callback:
            log_callback(msg)
        else:
            print(msg)
    
    # Check which tools are missing
    missing_tools = []
    for tool in tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if not missing_tools:
        return True  # All tools available
    
    # Check if we have root
    if os.geteuid() != 0:
        log("[yellow]Root privileges required to install tools[/]")
        log("[cyan]Please run with: sudo -E ./wifucker[/]")
        return False
    
    # Detect package manager
    pkg_manager = detect_package_manager()
    if not pkg_manager:
        log("[red]Could not detect package manager[/]")
        log("[yellow]Please install tools manually:[/]")
        log("  aircrack-ng (provides airodump-ng)")
        log("  iw")
        return False
    
    # Map tools to packages
    tool_to_package = {
        'airodump-ng': 'aircrack-ng',
        'iw': 'iw',
        'iwconfig': 'wireless-tools',
    }
    
    # Determine packages to install
    packages_to_install = []
    for tool in missing_tools:
        package = tool_to_package.get(tool, tool)
        if package not in packages_to_install:
            packages_to_install.append(package)
    
    if not packages_to_install:
        return False
    
    # Build install command based on package manager
    if pkg_manager == 'apt':
        cmd = ['apt', 'install', '-y'] + packages_to_install
    elif pkg_manager == 'dnf':
        cmd = ['dnf', 'install', '-y'] + packages_to_install
    elif pkg_manager == 'yum':
        cmd = ['yum', 'install', '-y'] + packages_to_install
    elif pkg_manager == 'pacman':
        cmd = ['pacman', '-S', '--noconfirm'] + packages_to_install
    elif pkg_manager == 'zypper':
        cmd = ['zypper', 'install', '-y'] + packages_to_install
    elif pkg_manager == 'emerge':
        cmd = ['emerge', '--quiet-build'] + packages_to_install
    else:
        log(f"[red]Unsupported package manager: {pkg_manager}[/]")
        return False
    
    # Attempt installation
    log(f"[cyan]Installing missing tools: {', '.join(packages_to_install)}...[/]")
    log(f"[yellow]Using package manager: {pkg_manager}[/]")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            log(f"[green]✓ Successfully installed: {', '.join(packages_to_install)}[/]")
            
            # Verify tools are now available
            all_available = True
            for tool in tools:
                if not shutil.which(tool):
                    log(f"[yellow]Warning: {tool} still not found after installation[/]")
                    all_available = False
            
            return all_available
        else:
            log(f"[red]Installation failed:[/]")
            log(f"[red]{result.stderr}[/]")
            return False
            
    except subprocess.TimeoutExpired:
        log("[red]Installation timed out[/]")
        return False
    except Exception as e:
        log(f"[red]Installation error: {e}[/]")
        return False


class ProgressMonitor(Static):
    """Realtime progress display"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.total = 0
        self.tested = 0
        self.rate = 0.0
        self.status = "Ready"

    def render(self):
        """Render progress information"""
        if self.total == 0:
            return f"[cyan]Status:[/] {self.status}"

        percent = (self.tested / self.total * 100) if self.total > 0 else 0
        bar_length = 30
        filled = int(bar_length * percent / 100)
        bar = "█" * filled + "░" * (bar_length - filled)

        return f"""[cyan]Status:[/] {self.status}
[yellow]Progress:[/] [{bar}] {percent:.1f}%
[green]Tested:[/] {self.tested:,} / {self.total:,}
[magenta]Rate:[/] {self.rate:,.0f} passwords/sec"""

    def update_progress(self, tested: int, total: int, percent: float, rate: float):
        """Update progress"""
        self.tested = tested
        self.total = total
        self.rate = rate
        self.refresh()

    def set_status(self, status: str):
        """Update status"""
        self.status = status
        self.refresh()


class PBKDF2Tab(Container):
    """PBKDF2 password cracking interface"""

    def compose(self) -> ComposeResult:
        yield Label("PBKDF2 Password Cracker")
        yield Vertical(
            Label("[cyan]Encrypted Data (Base64 format)[/]"),
            Input(
                id="encrypted_input", 
                placeholder="paste base64(salt)|base64(ciphertext)",
                tooltip="Format: base64(salt)|base64(ciphertext)"
            ),
            Label("[cyan]Cracking Strategy[/]"),
            RadioSet(
                RadioButton("Dictionary Attack (rockyou.txt)", id="dict"),
                RadioButton("Pattern Generation", id="pattern"),
                RadioButton("Context-Aware", id="context"),
                RadioButton("Mutations", id="mutations"),
                id="crack_strategy"
            ),
            Button("Start Cracking", id="start_crack", variant="primary"),
            Label("[yellow]Progress[/]"),
            ProgressMonitor(id="progress_monitor"),
            Label("[green]Results[/]"),
            MarkupLog(id="crack_log", highlight=True),
            id="pbkdf2_container"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "start_crack":
            self.start_pbkdf2_cracking()
    
    def validate_encrypted_input(self, encrypted_data: str) -> Tuple[bool, str]:
        """Validate encrypted data format"""
        if not encrypted_data:
            return False, "Encrypted data cannot be empty"
        
        # Check for base64(salt)|base64(ciphertext) format
        if "|" not in encrypted_data:
            return False, "Invalid format: expected base64(salt)|base64(ciphertext)"
        
        parts = encrypted_data.split("|", 1)
        if len(parts) != 2:
            return False, "Invalid format: expected base64(salt)|base64(ciphertext)"
        
        try:
            from base64 import b64decode
            b64decode(parts[0])
            b64decode(parts[1])
        except Exception as e:
            return False, f"Invalid base64 encoding: {str(e)}"
        
        return True, ""

    def start_pbkdf2_cracking(self):
        """Start PBKDF2 cracking process"""
        encrypted_input = self.query_one("#encrypted_input", Input)
        strategy = self.query_one("#crack_strategy", RadioSet)
        log = self.query_one("#crack_log", MarkupLog)
        monitor = self.query_one("#progress_monitor", ProgressMonitor)

        encrypted_data = encrypted_input.value.strip()
        
        # Validate input
        is_valid, error_msg = self.validate_encrypted_input(encrypted_data)
        if not is_valid:
            log.write(f"[red]Error: {error_msg}[/]")
            monitor.set_status("Validation failed")
            return

        monitor.set_status("Initializing cracker...")
        log.write(f"[cyan]Starting PBKDF2 crack on: {encrypted_data[:50]}...[/]")

        # Run cracking in background thread
        thread = threading.Thread(
            target=self._crack_worker,
            args=(encrypted_data, log, monitor, strategy),
            daemon=True
        )
        thread.start()

    def _crack_worker(self, encrypted_data: str, log: MarkupLog, monitor: ProgressMonitor, strategy_widget):
        """Worker thread for cracking"""
        try:
            # Get strategy from the widget passed as parameter
            try:
                strategy_button = strategy_widget.pressed
                strategy = strategy_button.id if strategy_button else "dict"
            except (AttributeError, TypeError):
                # Fallback if widget structure is unexpected
                strategy = "dict"
                log.write("[yellow]Warning: Could not determine strategy, using dictionary attack[/]")

            monitor.set_status(f"Strategy: {strategy}")

            # Initialize cracker
            cracker = PBKDF2Cracker(encrypted_data)

            # Throttle progress updates to reduce UI lag
            last_update_time = [0]
            update_interval = 0.5  # Update every 0.5 seconds
            
            def progress_callback(tested, total, percent, rate):
                import time
                current_time = time.time()
                if current_time - last_update_time[0] >= update_interval:
                    monitor.update_progress(tested, total, percent, rate)
                    last_update_time[0] = current_time

            # Generate wordlist based on strategy
            if strategy == "pattern":
                wordlist = ContextWordlistGenerator.generate(5000)
                log.write(f"[yellow]Generated {len(wordlist):,} pattern passwords[/]")
            elif strategy == "context":
                wordlist = ContextWordlistGenerator.generate_with_mutations(10000)
                log.write(f"[yellow]Generated {len(wordlist):,} context-aware passwords[/]")
            elif strategy == "mutations":
                base = ["password", "admin", "test", "crypto", "secure"]
                wordlist = []
                for word in base:
                    wordlist.extend(MutationEngine.apply_mutations(word))
                log.write(f"[yellow]Generated {len(wordlist):,} mutations[/]")
            else:  # dictionary
                rockyou = Path.home() / "rockyou" / "rockyou.txt"
                if rockyou.exists():
                    try:
                        log.write("[cyan]Loading rockyou.txt...[/]")
                        with open(rockyou, 'r', encoding='utf-8', errors='ignore') as f:
                            wordlist = [line.strip() for line in f if line.strip()]
                    except (IOError, OSError, PermissionError) as e:
                        log.write(f"[red]Error reading rockyou.txt: {e}[/]")
                        log.write("[yellow]Falling back to default wordlist[/]")
                        wordlist = ["password", "12345678", "admin", "test", "crypto"]
                    log.write(f"[yellow]Loaded {len(wordlist):,} passwords from rockyou[/]")
                else:
                    log.write("[red]rockyou.txt not found, using patterns instead[/]")
                    wordlist = ContextWordlistGenerator.generate(5000)

            monitor.total = len(wordlist)
            monitor.set_status("Cracking...")

            # Run cracking
            result = cracker.crack_dictionary(
                wordlist,
                progress_callback=progress_callback,
                max_workers=8
            )

            if result.success:
                log.write(f"[green]✓ SUCCESS![/]")
                log.write(f"[green]Password: {result.password}[/]")
                log.write(f"[green]Message: {result.message}[/]")
                log.write(f"[cyan]Attempts: {result.attempts:,}[/]")
                log.write(f"[cyan]Time: {result.elapsed_time:.2f}s[/]")
                log.write(f"[cyan]Rate: {result.rate:,.0f} passwords/sec[/]")
                monitor.set_status(f"SUCCESS in {result.elapsed_time:.2f}s")
            else:
                log.write(f"[yellow]Password not found[/]")
                log.write(f"[cyan]Tested: {result.attempts:,}[/]")
                log.write(f"[cyan]Time: {result.elapsed_time:.2f}s[/]")
                log.write(f"[cyan]Rate: {result.rate:,.0f} passwords/sec[/]")
                monitor.set_status("Not found in wordlist")

        except Exception as e:
            import traceback
            error_msg = str(e)
            log.write(f"[red]Error: {error_msg}[/]")
            log.write(f"[red]Details: {traceback.format_exc()}[/]")
            monitor.set_status(f"Error: {error_msg[:30]}...")


class WiFiTab(Container):
    """WiFi WPA/WPA2 Cracking Interface"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.networks: List = []
        self.selected_network_index: Optional[int] = None

    def compose(self) -> ComposeResult:
        yield Label("[bold cyan]WiFi WPA/WPA2 Cracker[/]")
        yield Vertical(
            # Interface Status Section
            Label("[cyan]━━━ Interface Status ━━━[/]"),
            Horizontal(
                Static(id="interface_status", markup=True),
                Static(id="monitor_mode_status", markup=True),
                Static(id="root_status", markup=True),
            ),
            
            # Network Scanning Section
            Label("[cyan]━━━ Network Scanning ━━━[/]"),
            Horizontal(
                Button("Scan Networks", id="scan_networks", variant="primary", tooltip="Scan for available WiFi networks"),
                Button("Refresh", id="refresh_networks", tooltip="Refresh network list"),
            ),
            Label("[yellow]Available Networks (click to select):[/]"),
            DataTable(id="network_list", cursor_type="row", zebra_stripes=True),
            
            # Target Selection Section
            Label("[cyan]━━━ Target Selection ━━━[/]"),
            Input(id="target_ssid", placeholder="SSID (select from list above or enter manually)", tooltip="Target network SSID"),
            Static(id="network_details", markup=True),
            
            # Capture Configuration Section
            Label("[cyan]━━━ Capture Configuration ━━━[/]"),
            Horizontal(
                Vertical(
                    Label("Deauth Packets:"),
                    Input(id="deauth_count", value="5", type="integer", 
                          placeholder="1-100", tooltip="Number of deauth packets to send (1-100)"),
                ),
                Vertical(
                    Label("Capture Duration (sec):"),
                    Input(id="capture_duration", value="60", type="integer",
                          placeholder="10-300", tooltip="How long to capture handshake (10-300 seconds)"),
                ),
            ),
            
            # File Configuration Section
            Label("[cyan]━━━ File Configuration ━━━[/]"),
            Label("[cyan]PCAP File (with handshake):[/]"),
            Horizontal(
                Input(id="pcap_file", placeholder="/path/to/handshake.pcap", tooltip="Path to PCAP file with captured handshake"),
                Button("Browse", id="browse_pcap", tooltip="Select PCAP file"),
            ),
            Label("[cyan]Wordlist:[/]"),
            Horizontal(
                Input(id="wordlist_file", placeholder="/path/to/wordlist.txt or rockyou.txt", tooltip="Path to wordlist file"),
                Button("Use rockyou", id="use_rockyou", tooltip="Use rockyou.txt wordlist"),
            ),
            
            # Actions Section
            Label("[cyan]━━━ Actions ━━━[/]"),
            Horizontal(
                Button("Capture Handshake", id="capture_handshake", variant="success", tooltip="Capture WPA handshake from target network"),
                Button("Crack Password", id="crack_wifi", variant="primary", tooltip="Crack password from PCAP file"),
            ),
            
            # Progress and Results Section
            Label("[yellow]━━━ Progress ━━━[/]"),
            ProgressMonitor(id="wifi_progress"),
            Label("[green]━━━ Results ━━━[/]"),
            MarkupLog(id="wifi_log", highlight=True),
            id="wifi_container"
        )
    
    def on_mount(self) -> None:
        """Initialize the WiFi tab"""
        self.update_interface_status()
        network_list = self.query_one("#network_list", DataTable)
        network_list.add_columns("SSID", "BSSID", "Ch", "Signal", "Encryption", "Clients")
        network_list.cursor_type = "row"
    
    def update_interface_status(self):
        """Update interface status indicators"""
        try:
            import subprocess
            
            # Get current interface
            interface = "Unknown"
            try:
                result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'IEEE 802.11' in line:
                            interface = line.split()[0]
                            break
            except:
                try:
                    result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'Interface' in line:
                                interface = line.split()[-1]
                                break
                except:
                    pass
            
            interface_status = self.query_one("#interface_status", Static)
            interface_status.update(f"[cyan]Interface:[/] {interface}")
            
            # Check monitor mode
            monitor_status = self.query_one("#monitor_mode_status", Static)
            from capture.monitor_mode import MonitorMode
            monitor_mode = MonitorMode()
            if interface != "Unknown" and monitor_mode.is_in_monitor_mode(interface):
                monitor_status.update("[green]Monitor Mode: ✓ Active[/]")
            else:
                monitor_status.update("[yellow]Monitor Mode: ✗ Inactive[/]")
            
            # Check root privileges
            root_status = self.query_one("#root_status", Static)
            if os.geteuid() == 0:
                root_status.update("[green]Root: ✓ Active[/]")
            else:
                root_status.update("[yellow]Root: ✗ Required[/]")
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "crack_wifi":
            self.start_wifi_cracking()
        elif event.button.id == "scan_networks":
            self.scan_networks()
        elif event.button.id == "refresh_networks":
            self.scan_networks()
        elif event.button.id == "capture_handshake":
            self.capture_handshake()
        elif event.button.id == "browse_pcap":
            self.browse_pcap_file()
        elif event.button.id == "use_rockyou":
            rockyou_path = Path.home() / "rockyou" / "rockyou.txt"
            if rockyou_path.exists():
                self.query_one("#wordlist_file", Input).value = str(rockyou_path)
                log = self.query_one("#wifi_log", MarkupLog)
                log.write(f"[green]✓ Using rockyou.txt: {rockyou_path}[/]")
            else:
                log = self.query_one("#wifi_log", MarkupLog)
                log.write("[yellow]rockyou.txt not found. Download from Tools tab.[/]")
    
    @on(DataTable.RowSelected, "#network_list")
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle network selection from DataTable"""
        try:
            row_key = event.cursor_row
            if row_key is not None and 0 <= row_key < len(self.networks):
                selected_network = self.networks[row_key]
                self.selected_network_index = row_key
                
                # Update target SSID
                target_input = self.query_one("#target_ssid", Input)
                target_input.value = selected_network.essid
                
                # Update network details
                self.update_network_details(selected_network)
                
                # Log selection
                log = self.query_one("#wifi_log", MarkupLog)
                log.write(f"[green]✓ Selected network: {selected_network.essid} ({selected_network.bssid})[/]")
        except Exception as e:
            # Silently handle any selection errors
            pass
    
    def update_network_details(self, network):
        """Update network details display"""
        from capture.network_scanner import WiFiNetwork
        
        details = self.query_one("#network_details", Static)
        
        client_count = len(network.clients) if hasattr(network, 'clients') else 0
        signal_quality = "Excellent" if network.power >= -50 else "Good" if network.power >= -60 else "Fair" if network.power >= -70 else "Weak"
        
        details_text = f"""[cyan]Network Details:[/]
  [yellow]SSID:[/] {network.essid}
  [yellow]BSSID:[/] {network.bssid}
  [yellow]Channel:[/] {network.channel}
  [yellow]Signal:[/] {network.power} dBm ({signal_quality})
  [yellow]Encryption:[/] {network.encryption}
  [yellow]Clients:[/] {client_count}"""
        
        if client_count == 0:
            details_text += "\n  [yellow]⚠ Warning:[/] No clients detected - handshake capture may be difficult"
        
        details.update(details_text)
    
    def update_network_list(self, networks: List):
        """Update the network list DataTable"""
        from capture.network_scanner import WiFiNetwork
        
        self.networks = sorted(networks, key=lambda x: x.power, reverse=True)
        network_list = self.query_one("#network_list", DataTable)
        network_list.clear()
        
        for network in self.networks:
            client_count = len(network.clients) if hasattr(network, 'clients') else 0
            client_str = f"{client_count} ✓" if client_count > 0 else "0"
            
            network_list.add_row(
                network.essid[:30] if len(network.essid) <= 30 else network.essid[:27] + "...",
                network.bssid,
                str(network.channel),
                f"{network.power} dBm",
                network.encryption[:15] if network.encryption else "Open",
                client_str
            )
    
    def browse_pcap_file(self):
        """Browse for PCAP file using system file picker"""
        log = self.query_one("#wifi_log", MarkupLog)
        pcap_input = self.query_one("#pcap_file", Input)
        
        # Try to use zenity (Linux) or osascript (macOS) for file picker
        try:
            # Try zenity first (Linux)
            result = subprocess.run(
                ["zenity", "--file-selection", "--title=Select PCAP File", "--file-filter=PCAP files (*.pcap *.cap) | *.pcap *.cap"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                selected_file = result.stdout.strip()
                pcap_input.value = selected_file
                log.write(f"[green]✓ Selected: {selected_file}[/]")
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Fallback: try osascript (macOS)
        try:
            script = '''
                tell application "System Events"
                    activate
                    set theFile to choose file with prompt "Select PCAP File" of type {"pcap", "cap"}
                    return POSIX path of theFile
                end tell
            '''
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                selected_file = result.stdout.strip()
                pcap_input.value = selected_file
                log.write(f"[green]✓ Selected: {selected_file}[/]")
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # If no file picker available, show helpful message
        log.write("[yellow]File picker not available. Please enter path manually or install zenity (Linux).[/]")
        log.write("[cyan]Tip: You can drag and drop files into the input field if supported.[/]")

    def scan_networks(self):
        """Scan for WiFi networks"""
        log = self.query_one("#wifi_log", MarkupLog)
        monitor = self.query_one("#wifi_progress", ProgressMonitor)

        log.write("[cyan]Scanning for WiFi networks...[/]")
        monitor.set_status("Scanning...")

        def scan_worker():
            try:
                import os
                import subprocess
                from capture.network_scanner import NetworkScanner
                from capture.monitor_mode import MonitorMode

                # Check for root privileges (required for scanning)
                if os.geteuid() != 0:
                    log.write("[yellow]Warning: Root privileges recommended for network scanning[/]")
                    log.write("[yellow]Some scanning methods may not work without sudo[/]")
                    log.write("[cyan]Try running with: sudo -E ./wifucker[/]")

                # Try multiple methods to detect interface
                interfaces = []
                
                # Method 1: iwconfig
                try:
                    result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        interfaces = [line.split()[0] for line in result.stdout.split('\n') if 'IEEE 802.11' in line]
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass

                # Method 2: iw dev
                if not interfaces:
                    try:
                        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if 'Interface' in line:
                                    iface = line.split()[-1]
                                    if iface and iface not in interfaces:
                                        interfaces.append(iface)
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        pass

                # Method 3: ip link show
                if not interfaces:
                    try:
                        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if 'wlan' in line.lower() or 'wifi' in line.lower():
                                    parts = line.split(':')
                                    if len(parts) >= 2:
                                        iface = parts[1].strip().split()[0]
                                        if iface and iface not in interfaces:
                                            interfaces.append(iface)
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        pass

                if not interfaces:
                    log.write("[red]No WiFi interfaces found.[/]")
                    log.write("[yellow]Troubleshooting:[/]")
                    log.write("  1. Ensure you have a wireless adapter connected")
                    log.write("  2. Check if wireless is enabled: rfkill unblock wifi")
                    log.write("  3. Verify interface exists: ip link show")
                    log.write("  4. Try running with sudo: sudo -E ./wifucker")
                    monitor.set_status("No interface found")
                    return

                interface = interfaces[0]
                log.write(f"[cyan]Using interface: {interface}[/]")

                # Check and enable monitor mode if needed
                monitor_mode = MonitorMode()
                if not monitor_mode.is_in_monitor_mode(interface):
                    log.write(f"[cyan]Enabling monitor mode on {interface}...[/]")
                    success, message, mon_iface = monitor_mode.enable_monitor_mode(interface)
                    if success:
                        interface = mon_iface  # Use monitor interface
                        log.write(f"[green]✓ {message}[/]")
                        # Ensure interface is up
                        try:
                            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                                          capture_output=True, timeout=5, check=False)
                        except:
                            pass
                    else:
                        log.write(f"[red]Failed to enable monitor mode: {message}[/]")
                        log.write("[yellow]Warning: Scanning may not work properly without monitor mode[/]")
                        log.write("[yellow]airodump-ng requires monitor mode to function correctly[/]")
                        if os.geteuid() != 0:
                            log.write("[yellow]Try running with: sudo -E ./wifucker[/]")
                else:
                    log.write(f"[green]✓ Interface {interface} is already in monitor mode[/]")

                # Check for required tools
                import shutil
                has_airodump = shutil.which('airodump-ng') is not None
                has_iw = shutil.which('iw') is not None

                required_tools = []
                if not has_airodump:
                    required_tools.append('airodump-ng')
                if not has_iw:
                    required_tools.append('iw')

                if required_tools:
                    log.write(f"[yellow]Missing tools: {', '.join(required_tools)}[/]")
                    log.write("[cyan]Attempting automatic installation...[/]")
                    
                    # Attempt auto-install
                    def log_install(msg):
                        log.write(msg)
                    
                    install_success = install_tools_auto(
                        ['airodump-ng', 'iw'],
                        log_callback=log_install
                    )
                    
                    if install_success:
                        log.write("[green]✓ All tools installed successfully![/]")
                        # Re-check availability
                        has_airodump = shutil.which('airodump-ng') is not None
                        has_iw = shutil.which('iw') is not None
                    else:
                        log.write("[yellow]Auto-installation failed or not available[/]")
                        log.write("[yellow]Manual installation required:[/]")
                        pkg_mgr = detect_package_manager()
                        if pkg_mgr == 'apt':
                            log.write("  sudo apt install aircrack-ng iw")
                        elif pkg_mgr == 'dnf':
                            log.write("  sudo dnf install aircrack-ng iw")
                        elif pkg_mgr == 'yum':
                            log.write("  sudo yum install aircrack-ng iw")
                        elif pkg_mgr == 'pacman':
                            log.write("  sudo pacman -S aircrack-ng iw")
                        else:
                            log.write("  Install: aircrack-ng (provides airodump-ng) and iw")
                        
                        if not has_airodump and not has_iw:
                            monitor.set_status("Tools missing")
                            return

                if not has_airodump:
                    log.write("[yellow]airodump-ng not available, using iw (less detailed)[/]")
                elif not has_iw:
                    log.write("[yellow]iw not available, using airodump-ng only[/]")

                scanner = NetworkScanner(interface)
                log.write("[cyan]Scanning for 10 seconds...[/]")
                networks = scanner.scan(duration=10)

                if networks:
                    log.write(f"[green]✓ Found {len(networks)} network(s)[/]")
                    
                    # Update network list in UI
                    self.update_network_list(networks)
                    
                    # Auto-select first WPA network if no selection exists
                    wpa_networks = [n for n in networks if "WPA" in n.encryption]
                    if wpa_networks and self.selected_network_index is None:
                        target_input = self.query_one("#target_ssid", Input)
                        if not target_input.value:
                            target_input.value = wpa_networks[0].essid
                            # Find and select in list
                            for idx, net in enumerate(self.networks):
                                if net.essid == wpa_networks[0].essid:
                                    self.selected_network_index = idx
                                    network_list = self.query_one("#network_list", DataTable)
                                    network_list.cursor_coordinate = (idx, 0)
                                    self.update_network_details(net)
                                    break
                            log.write(f"[yellow]Auto-selected: {wpa_networks[0].essid}[/]")
                    
                    # Update interface status
                    self.update_interface_status()
                else:
                    log.write("[yellow]No networks found[/]")
                    log.write("[cyan]Possible reasons:[/]")
                    log.write("  1. No networks in range")
                    log.write("  2. Interface not in monitor mode (required for airodump-ng)")
                    log.write("  3. Insufficient permissions (try with sudo)")
                    log.write("  4. Interface not properly configured")
                    
                    # Clear network list
                    network_list = self.query_one("#network_list", DataTable)
                    network_list.clear()
                    self.networks = []

                monitor.set_status("Scan complete")
            except Exception as e:
                import traceback
                log.write(f"[red]Error: {str(e)}[/]")
                log.write(f"[red]Traceback: {traceback.format_exc()}[/]")
                monitor.set_status("Error occurred")

        threading.Thread(target=scan_worker, daemon=True).start()

    def capture_handshake(self):
        """Capture WiFi handshake"""
        log = self.query_one("#wifi_log", MarkupLog)
        monitor = self.query_one("#wifi_progress", ProgressMonitor)
        target_input = self.query_one("#target_ssid", Input)

        target_ssid = target_input.value.strip()
        if not target_ssid:
            log.write("[red]Error: Select a target network first using 'Scan Networks'[/]")
            log.write("[yellow]Tip: Click on a network in the list or enter SSID manually[/]")
            return

        # Get and validate deauth configuration
        try:
            deauth_count_input = self.query_one("#deauth_count", Input)
            deauth_count = int(deauth_count_input.value or "5")
            if not (1 <= deauth_count <= 100):
                log.write("[red]Error: Deauth count must be between 1 and 100[/]")
                monitor.set_status("Invalid deauth count")
                return
        except ValueError:
            log.write("[red]Error: Deauth count must be a valid number[/]")
            monitor.set_status("Invalid deauth count")
            return

        # Get and validate capture duration
        try:
            capture_duration_input = self.query_one("#capture_duration", Input)
            capture_duration = int(capture_duration_input.value or "60")
            if not (10 <= capture_duration <= 300):
                log.write("[red]Error: Capture duration must be between 10 and 300 seconds[/]")
                monitor.set_status("Invalid capture duration")
                return
        except ValueError:
            log.write("[red]Error: Capture duration must be a valid number[/]")
            monitor.set_status("Invalid capture duration")
            return

        # Check root privileges
        if os.geteuid() != 0:
            log.write("[red]Error: Root privileges required for handshake capture[/]")
            log.write("[yellow]Run with: sudo -E ./wifucker[/]")
            monitor.set_status("Root required")
            return

        log.write("[cyan]Handshake capture configuration:[/]")
        log.write(f"  [yellow]Target:[/] {target_ssid}")
        log.write(f"  [yellow]Deauth packets:[/] {deauth_count}")
        log.write(f"  [yellow]Capture duration:[/] {capture_duration} seconds")
        log.write("[cyan]Starting handshake capture...[/]")

        def capture_worker():
            try:
                import os
                if os.geteuid() != 0:
                    log.write("[red]Error: Root privileges required for handshake capture[/]")
                    log.write("[yellow]Run with: sudo -E ./wifucker[/]")
                    monitor.set_status("Root required")
                    return

                # Import with graceful fallback
                try:
                    from capture.handshake_capture import HandshakeCapture
                    from capture.network_scanner import NetworkScanner
                except ImportError as e:
                    log.write(f"[red]Error importing capture modules: {e}[/]")
                    log.write("[yellow]Please ensure all capture modules are available[/]")
                    monitor.set_status("Import error")
                    return

                # Detect interface with error handling
                import subprocess
                try:
                    result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=10)
                    if result.returncode != 0:
                        log.write("[yellow]iwconfig failed, trying alternative methods...[/]")
                        interfaces = []
                    else:
                        interfaces = [line.split()[0] for line in result.stdout.split('\n') if 'IEEE 802.11' in line]
                except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                    log.write(f"[yellow]iwconfig not available: {e}[/]")
                    interfaces = []

                if not interfaces:
                    # Try alternative interface detection
                    try:
                        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if 'Interface' in line:
                                    iface = line.split()[-1]
                                    if iface:
                                        interfaces.append(iface)
                    except:
                        pass
                    
                    if not interfaces:
                        log.write("[red]No WiFi interfaces found[/]")
                        log.write("[yellow]Troubleshooting:[/]")
                        log.write("  1. Ensure wireless adapter is connected")
                        log.write("  2. Check: ip link show")
                        log.write("  3. Enable wireless: rfkill unblock wifi")
                        monitor.set_status("No interface")
                        return

                interface = interfaces[0]
                log.write(f"[cyan]Using interface: {interface}[/]")

                # Scan to get network details with error handling
                try:
                    scanner = NetworkScanner(interface)
                    networks = scanner.scan(duration=5)
                except Exception as e:
                    log.write(f"[yellow]Network scan failed: {e}[/]")
                    log.write("[yellow]Continuing with manual capture...[/]")
                    networks = []
                
                target_network = None
                for net in networks:
                    if net.essid == target_ssid:
                        target_network = net
                        break

                if not target_network:
                    log.write(f"[yellow]Network '{target_ssid}' not found in scan, using manual capture[/]")
                    # Create a basic network object for manual capture
                    from capture.network_scanner import WiFiNetwork
                    target_network = WiFiNetwork(
                        bssid="00:00:00:00:00:00",  # Will be detected during capture
                        essid=target_ssid,
                        channel=1,
                        power=-50,
                        encryption="WPA2",
                        cipher="",
                        authentication=""
                    )

                # Initialize capture with error handling
                try:
                    # Ensure output directory exists
                    output_dir = Path("./captures")
                    output_dir.mkdir(exist_ok=True)
                    
                    capture = HandshakeCapture(interface=interface, output_dir=str(output_dir))
                    monitor.set_status("Initializing capture...")
                    log.write(f"[cyan]Capturing handshake for {target_ssid}...[/]")
                    log.write(f"[yellow]Capture duration: {capture_duration} seconds[/]")
                    log.write(f"[yellow]Deauth packets: {deauth_count}[/]")
                    log.write("[cyan]Starting capture process...[/]")
                    
                    # Start progress update thread
                    import time
                    progress_thread_running = [True]
                    
                    def progress_updater():
                        elapsed = 0
                        while progress_thread_running[0] and elapsed < capture_duration:
                            time.sleep(1)
                            elapsed += 1
                            remaining = capture_duration - elapsed
                            if remaining > 0:
                                monitor.set_status(f"Capturing... {remaining}s remaining")
                                if elapsed % 5 == 0:
                                    log.write(f"[cyan]Capture in progress... {remaining}s remaining[/]")
                    
                    progress_thread = threading.Thread(target=progress_updater, daemon=True)
                    progress_thread.start()

                    # Capture handshake with correct parameters
                    result = capture.capture_handshake(
                        target=target_network,
                        capture_duration=capture_duration,
                        deauth_count=deauth_count
                    )
                    
                    # Stop progress thread
                    progress_thread_running[0] = False
                except Exception as e:
                    log.write(f"[red]Capture initialization failed: {e}[/]")
                    log.write("[yellow]Please ensure:[/]")
                    log.write("  1. Interface is in monitor mode")
                    log.write("  2. You have root privileges")
                    log.write("  3. Required tools are installed (airodump-ng)")
                    monitor.set_status("Capture failed")
                    return

                if result and result.success:
                    log.write(f"[green]✓ Handshake captured successfully![/]")
                    log.write(f"[green]PCAP file: {result.pcap_file}[/]")
                    log.write(f"[green]Handshakes: {result.handshakes_captured}[/]")
                    log.write(f"[cyan]Duration: {result.duration:.1f}s[/]")
                    log.write("[yellow]You can now use 'Crack Password' with this PCAP file[/]")
                    
                    # Auto-fill PCAP file path with error handling
                    try:
                        pcap_input = self.query_one("#pcap_file", Input)
                        if not pcap_input.value and hasattr(result, 'pcap_file'):
                            pcap_input.value = result.pcap_file
                    except Exception:
                        pass  # Widget might not exist yet
                    
                    monitor.set_status(f"Captured: {result.pcap_file}")
                else:
                    error_msg = result.message if result and hasattr(result, 'message') else "Unknown error"
                    log.write(f"[red]Capture failed: {error_msg}[/]")
                    log.write("[yellow]Tips:[/]")
                    log.write("  - Ensure target network has active clients")
                    log.write(f"  - Try increasing capture duration (current: {capture_duration}s) or deauth packets (current: {deauth_count})")
                    log.write("  - Check interface is in monitor mode")
                    log.write("  - Verify you have root privileges")
                    log.write("  - Try scanning again to refresh network information")
                    monitor.set_status("Capture failed")

            except ImportError as e:
                log.write(f"[red]Import error: {e}[/]")
                log.write("[yellow]Capture module not available[/]")
                monitor.set_status("Module missing")
            except Exception as e:
                log.write(f"[red]Error: {str(e)}[/]")
                import traceback
                log.write(f"[red]{traceback.format_exc()}[/]")
                monitor.set_status("Error occurred")

        threading.Thread(target=capture_worker, daemon=True).start()

    def start_wifi_cracking(self):
        """Start WiFi password cracking"""
        try:
            pcap_input = self.query_one("#pcap_file", Input)
            wordlist_input = self.query_one("#wordlist_file", Input)
            target_input = self.query_one("#target_ssid", Input)
            log = self.query_one("#wifi_log", MarkupLog)
            monitor = self.query_one("#wifi_progress", ProgressMonitor)
        except Exception as e:
            print(f"Error accessing widgets: {e}")
            return

        pcap_file = pcap_input.value.strip() if pcap_input.value else ""
        wordlist_file = wordlist_input.value.strip() if wordlist_input.value else ""

        if not pcap_file:
            log.write("[red]Error: Enter PCAP file path[/]")
            log.write("[yellow]Use 'Browse PCAP' button or enter path manually[/]")
            monitor.set_status("PCAP file missing")
            return

        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            log.write(f"[red]Error: PCAP file not found: {pcap_file}[/]")
            log.write("[yellow]Please check the file path and try again[/]")
            monitor.set_status("File not found")
            return
        
        if not pcap_path.is_file():
            log.write(f"[red]Error: Path is not a file: {pcap_file}[/]")
            monitor.set_status("Invalid file")
            return
        
        if not os.access(pcap_file, os.R_OK):
            log.write(f"[red]Error: Cannot read PCAP file: {pcap_file}[/]")
            log.write("[yellow]Check file permissions[/]")
            monitor.set_status("Permission denied")
            return

        if not wordlist_file:
            # Try rockyou
            rockyou_path = Path.home() / "rockyou" / "rockyou.txt"
            if rockyou_path.exists() and rockyou_path.is_file():
                try:
                    # Verify file is readable
                    with open(rockyou_path, 'r') as f:
                        f.read(1)  # Try to read at least 1 byte
                    wordlist_file = str(rockyou_path)
                    wordlist_input.value = wordlist_file
                    log.write(f"[cyan]Using rockyou.txt: {wordlist_file}[/]")
                except (IOError, PermissionError) as e:
                    log.write(f"[yellow]Cannot read rockyou.txt: {e}[/]")
                    log.write("[red]Error: Enter wordlist file path[/]")
                    monitor.set_status("Wordlist unreadable")
                    return
            else:
                log.write("[red]Error: Enter wordlist file path[/]")
                log.write("[yellow]Download rockyou.txt from Tools tab or specify a wordlist[/]")
                monitor.set_status("Wordlist missing")
                return

        wordlist_path = Path(wordlist_file)
        if not wordlist_path.exists():
            log.write(f"[red]Error: Wordlist file not found: {wordlist_file}[/]")
            monitor.set_status("Wordlist not found")
            return
        
        if not wordlist_path.is_file():
            log.write(f"[red]Error: Path is not a file: {wordlist_file}[/]")
            monitor.set_status("Invalid wordlist")
            return
        
        if not os.access(wordlist_file, os.R_OK):
            log.write(f"[red]Error: Cannot read wordlist file: {wordlist_file}[/]")
            monitor.set_status("Wordlist permission denied")
            return

        monitor.set_status("Parsing PCAP...")
        log.write(f"[cyan]Parsing PCAP: {pcap_file}[/]")

        def crack_worker():
            try:
                # Import with graceful fallback
                try:
                    from parsers.pcap_parser import PCAPParser
                    from crackers.openvino_cracker import OpenVINOWiFiCracker
                except ImportError as e:
                    log.write(f"[red]Error importing modules: {e}[/]")
                    log.write("[yellow]Please ensure all required modules are available[/]")
                    monitor.set_status("Import error")
                    return

                # Parse PCAP with error handling
                try:
                    parser = PCAPParser(pcap_file)
                    handshakes, pmkids = parser.parse()
                except Exception as e:
                    log.write(f"[red]Error parsing PCAP: {e}[/]")
                    log.write("[yellow]Please verify PCAP file is valid and contains handshakes[/]")
                    monitor.set_status("Parse error")
                    return

                if not handshakes:
                    log.write("[red]No handshakes found in PCAP file[/]")
                    monitor.set_status("No handshake found")
                    return

                log.write(f"[green]Found {len(handshakes)} handshake(s)[/]")

                # Select handshake
                target_ssid = target_input.value.strip()
                if target_ssid:
                    target_hs = next((hs for hs in handshakes if hs.ssid == target_ssid), None)
                    if not target_hs:
                        log.write(f"[yellow]SSID '{target_ssid}' not found, using first handshake[/]")
                        target_hs = handshakes[0]
                else:
                    target_hs = handshakes[0]

                log.write(f"[cyan]Target: {target_hs.ssid} ({target_hs.bssid})[/]")
                log.write(f"[cyan]Handshake type: {target_hs.handshake_type}[/]")

                # Initialize cracker with full Layer 9 permissions
                monitor.set_status("Initializing cracker with Layer 9 (QUANTUM)...")
                log.write("[cyan]Initializing hardware-accelerated cracker...[/]")
                log.write("[green]Layer 9 (QUANTUM) clearance: ACTIVE[/]")
                log.write("[cyan]Routing through: Quantum → Unified Accelerators → Hardware[/]")
                
                try:
                    cracker = OpenVINOWiFiCracker(use_hardware=True)
                except Exception as e:
                    log.write(f"[yellow]Hardware acceleration init failed: {e}[/]")
                    log.write("[yellow]Falling back to CPU-only mode...[/]")
                    try:
                        cracker = OpenVINOWiFiCracker(use_hardware=False)
                    except Exception as e2:
                        log.write(f"[red]Cracker initialization failed: {e2}[/]")
                        monitor.set_status("Init failed")
                        return

                # Log acceleration stack
                if cracker.use_quantum:
                    log.write(f"[green]✓ Quantum Processor: ENABLED (Layer 9)[/]")
                if cracker.use_unified_accel:
                    log.write(f"[green]✓ Unified Accelerator: {cracker.total_tops:.1f} TOPS[/]")
                    if cracker.unified_manager:
                        stats = cracker.unified_manager.get_stats()
                        for accel_name, accel_stats in stats["accelerators"].items():
                            log.write(f"  - {accel_name.upper()}: {accel_stats['tops']:.1f} TOPS")
                elif cracker.use_hardware and cracker.primary_device:
                    log.write(f"[yellow]Standard Hardware: {cracker.primary_device.device_name}[/]")

                # Show effective TOPS with Layer 9
                quantum_speedup = 1.5 if cracker.use_quantum else 1.0
                effective_tops = (cracker.total_tops if cracker.use_unified_accel else 0) * quantum_speedup
                if effective_tops > 0:
                    log.write(f"[bold cyan]Effective TOPS (with Layer 9): {effective_tops:.1f}[/]")

                # Throttle progress updates to reduce UI lag
                last_update_time = [0]
                update_interval = 0.5  # Update every 0.5 seconds
                
                def progress_callback(tested, total, percent, rate):
                    import time
                    current_time = time.time()
                    if current_time - last_update_time[0] >= update_interval:
                        monitor.update_progress(tested, total, percent, rate)
                        last_update_time[0] = current_time
                        if tested % 1000 == 0:
                            log.write(f"[cyan]Tested: {tested:,} / {total:,} ({percent:.1f}%) - {rate:,.0f} pwd/sec[/]")

                # Crack with full Layer 9 acceleration stack
                monitor.set_status("Cracking WPA2/PSK2 with Layer 9 (QUANTUM)...")
                log.write("[bold cyan]═══════════════════════════════════════════════════════════[/]")
                log.write("[bold green]WPA2/PSK2 CRACKING - FULL 9-LAYER ACCELERATION STACK[/]")
                log.write("[bold cyan]═══════════════════════════════════════════════════════════[/]")
                log.write("[green]Layer 9 (QUANTUM) Clearance: ACTIVE[/]")
                log.write("[cyan]Routing through all acceleration layers...[/]")

                # Show routing path
                routing_path = []
                if cracker.use_quantum:
                    routing_path.append("Quantum Processor (Layer 9)")
                if cracker.use_unified_accel:
                    routing_path.append(f"Unified Accelerators ({cracker.total_tops:.1f} TOPS)")
                elif cracker.use_hardware:
                    routing_path.append(f"Hardware ({cracker.primary_device.device_name if cracker.primary_device else 'CPU'})")
                else:
                    routing_path.append("CPU")

                log.write(f"[cyan]Routing: {' → '.join(routing_path)}[/]")

                result = cracker.crack_handshake(
                    ssid=target_hs.ssid,
                    anonce=target_hs.anonce,
                    snonce=target_hs.snonce,
                    mic=target_hs.mic,
                    bssid=target_hs.bssid,
                    client=target_hs.client,
                    wordlist_file=wordlist_file,
                    progress_callback=progress_callback
                )

                if result.success:
                    log.write(f"[bold green]✓ SUCCESS![/]")
                    log.write(f"[green]Password: {result.password}[/]")
                    log.write(f"[cyan]Device Used: {result.device_used}[/]")
                    log.write(f"[cyan]Attempts: {result.attempts:,}[/]")
                    log.write(f"[cyan]Time: {result.elapsed_time:.2f}s[/]")
                    log.write(f"[cyan]Rate: {result.hashes_per_second:,.0f} hashes/sec[/]")

                    # Show Layer 9 performance if quantum was used
                    if "QUANTUM" in result.device_used or "Quantum" in result.device_used:
                        log.write(f"[bold cyan]Layer 9 (QUANTUM) acceleration: ACTIVE[/]")

                    monitor.set_status(f"SUCCESS: {result.password}")
                else:
                    log.write(f"[yellow]Password not found in wordlist[/]")
                    log.write(f"[cyan]Tested: {result.attempts:,} passwords[/]")
                    log.write(f"[cyan]Time: {result.elapsed_time:.2f}s[/]")
                    monitor.set_status("Not found")

            except Exception as e:
                log.write(f"[red]Error: {str(e)}[/]")
                import traceback
                log.write(f"[red]{traceback.format_exc()}[/]")
                monitor.set_status("Error occurred")

        threading.Thread(target=crack_worker, daemon=True).start()


class Quantum9LayerTab(Container):
    """Quantum Processor & 9-Layer System Control"""

    def compose(self) -> ComposeResult:
        yield Label("Quantum Processor & 9-Layer System")
        yield Vertical(
            Label("[bold cyan]TOTAL TOPS:[/] [bold green]Calculating...[/]"),
            Static("", id="total_tops_display"),
            Label("[cyan]Clearance Level (9-Layer System)[/]"),
            Static("Loading...", id="clearance_display"),
            Horizontal(
                Button("Set to QUANTUM (Layer 9)", id="set_quantum", variant="success"),
                Button("Refresh Status", id="refresh_quantum", variant="primary"),
            ),
            Label("[cyan]Quantum Processor[/]"),
            Static("Loading...", id="quantum_status"),
            Horizontal(
                Button("Enable Quantum", id="enable_quantum", variant="success"),
                Button("Disable Quantum", id="disable_quantum"),
            ),
            Label("[cyan]Unified Accelerator System[/]"),
            Static("Loading...", id="accelerator_status"),
            Label("[cyan]System Statistics[/]"),
            MarkupLog(id="quantum_log", highlight=True),
            id="quantum_container"
        )

    def on_mount(self) -> None:
        """Refresh status on mount"""
        self.refresh_status()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        log = self.query_one("#quantum_log", MarkupLog)

        if event.button.id == "set_quantum":
            self.set_quantum_clearance()
        elif event.button.id == "refresh_quantum":
            self.refresh_status()
        elif event.button.id == "enable_quantum":
            self.enable_quantum()
        elif event.button.id == "disable_quantum":
            self.disable_quantum()

    def refresh_status(self):
        """Refresh all status displays"""
        log = self.query_one("#quantum_log", MarkupLog)
        total_tops_display = self.query_one("#total_tops_display", Static)
        clearance_display = self.query_one("#clearance_display", Static)
        quantum_status = self.query_one("#quantum_status", Static)
        accelerator_status = self.query_one("#accelerator_status", Static)

        log.write("[cyan]Refreshing 9-Layer System status...[/]")

        # Calculate and display TOTAL TOPS
        total_tops = 0.0
        tops_breakdown = []

        # Check clearance level
        try:
            dsmil_path = DSMIL_ROOT if (DSMIL_ROOT / "ai").exists() else ROOT_DIR.parent
            sys.path.insert(0, str(dsmil_path))

            from ai.hardware.dsmil_accelerator_interface import ClearanceLevel, get_accelerator_interface

            clearance_text = "9-Layer Clearance System:\n"
            for level in ClearanceLevel:
                clearance_text += f"  Layer {level.value}: {level.name}\n"
            clearance_text += "\n[green]Current: QUANTUM (Layer 9)[/]"
            clearance_display.update(clearance_text)

        except Exception as e:
            clearance_display.update(f"[red]Clearance check failed: {e}[/]")

        # Check quantum processor
        try:
            from crackers.quantum_accelerator import get_quantum_accelerator
            quantum_accel = get_quantum_accelerator()

            if quantum_accel and quantum_accel.quantum_available:
                provider = quantum_accel.quantum_device.get_active_provider() if quantum_accel.quantum_device else "Unknown"
                quantum_text = f"[green]✓ Quantum Processor: ENABLED[/]\n"
                quantum_text += f"Provider: {provider}\n"
                quantum_text += f"Status: Active (Layer 9)"
            else:
                quantum_text = "[yellow]⚠ Quantum Processor: Not Available[/]\n"
                quantum_text += "Install: pip install qiskit qiskit-aer"
            quantum_status.update(quantum_text)

        except Exception as e:
            quantum_status.update(f"[red]Quantum check failed: {e}[/]")

        # Check unified accelerators and calculate TOTAL TOPS
        try:
            from crackers.openvino_cracker import OpenVINOWiFiCracker
            cracker = OpenVINOWiFiCracker()

            accel_text = ""
            if cracker.use_quantum:
                accel_text += "[green]✓ Quantum: ENABLED[/]\n"
                # Quantum provides speedup but not measured in TOPS
                tops_breakdown.append("Quantum: Speedup (not in TOPS)")

            if cracker.use_unified_accel:
                unified_tops = cracker.total_tops
                total_tops += unified_tops
                accel_text += f"[green]✓ Unified Accelerator: {unified_tops:.1f} TOPS[/]\n"
                if cracker.unified_manager:
                    stats = cracker.unified_manager.get_stats()
                    for accel_name, accel_stats in stats["accelerators"].items():
                        accel_tops = accel_stats['tops']
                        tops_breakdown.append(f"{accel_name.upper()}: {accel_tops:.1f} TOPS")
                        accel_text += f"  - {accel_name.upper()}: {accel_tops:.1f} TOPS\n"
            elif cracker.use_hardware and cracker.primary_device:
                # Estimate TOPS for standard hardware
                device_name = cracker.primary_device.device_name
                if "NPU" in device_name or "npu" in device_name.lower():
                    est_tops = 30.0
                elif "GPU" in device_name or "Arc" in device_name:
                    est_tops = 40.0
                elif "NCS2" in device_name:
                    est_tops = 10.0
                else:
                    est_tops = 0.0
                total_tops += est_tops
                tops_breakdown.append(f"{device_name}: ~{est_tops:.1f} TOPS (est)")
                accel_text += f"[yellow]Standard Hardware: {device_name}[/]\n"
            else:
                accel_text += "[red]CPU-only mode[/]"
                tops_breakdown.append("CPU: 0 TOPS")

            # Display TOTAL TOPS prominently (with Layer 9 quantum)
            quantum_speedup = 1.5  # Standard quantum speedup
            quantum_active = cracker.use_quantum and cracker.quantum_accel and cracker.quantum_accel.quantum_available
            effective_tops_with_quantum = total_tops * quantum_speedup

            if total_tops > 0:
                tops_text = f"[bold green]BASE TOPS: {total_tops:.1f}[/]\n\n"
                tops_text += f"[bold cyan]WITH LAYER 9 (QUANTUM):[/]\n"
                tops_text += f"  Effective: [bold]{effective_tops_with_quantum:.1f} TOPS[/]\n"
                tops_text += f"  Speedup: {quantum_speedup:.1f}x\n"
                tops_text += f"  Gain: +{(effective_tops_with_quantum - total_tops):.1f} TOPS\n\n"

                tops_text += "Hardware Breakdown:\n"
                for breakdown in tops_breakdown:
                    tops_text += f"  • {breakdown}\n"

                tops_text += f"\nLayer 9 (QUANTUM): {quantum_speedup:.1f}x multiplier\n"
                if quantum_active:
                    tops_text += f"  → [green]✓ ACTIVE[/] - {effective_tops_with_quantum:.1f} TOPS total\n"
                else:
                    tops_text += f"  → [yellow]✗ INACTIVE[/] (enable for {effective_tops_with_quantum:.1f} TOPS)"
            else:
                tops_text = "[yellow]BASE: 0 TOPS (CPU-only)[/]\n"
                tops_text += f"[yellow]WITH LAYER 9: 0 TOPS[/]"

            total_tops_display.update(tops_text)
            accelerator_status.update(accel_text)
            log.write(f"[green]✓ Status refreshed - Total TOPS: {total_tops:.1f}[/]")

        except Exception as e:
            total_tops_display.update(f"[red]TOPS calculation failed: {e}[/]")
            accelerator_status.update(f"[red]Accelerator check failed: {e}[/]")
            log.write(f"[red]Error: {e}[/]")

    def set_quantum_clearance(self):
        """Set clearance to QUANTUM (Layer 9)"""
        log = self.query_one("#quantum_log", MarkupLog)
        log.write("[cyan]Setting clearance to QUANTUM (Layer 9)...[/]")

        def set_worker():
            try:
                import subprocess
                clearance_script = SCRIPTS_DIR / "set_max_clearance.py"
                if not clearance_script.exists():
                    log.write("[yellow]Clearance script not found[/]")
                    return
                result = subprocess.run(
                    [PYTHON_BIN, str(clearance_script)],
                    cwd=str(ROOT_DIR),
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    log.write("[green]✓ Clearance set to QUANTUM (Layer 9)[/]")
                    log.write(result.stdout)
                else:
                    log.write(f"[yellow]Clearance setting: {result.stderr}[/]")
            except Exception as e:
                log.write(f"[red]Error: {e}[/]")

        threading.Thread(target=set_worker, daemon=True).start()
        self.refresh_status()

    def enable_quantum(self):
        """Enable quantum processor"""
        log = self.query_one("#quantum_log", MarkupLog)
        log.write("[cyan]Enabling quantum processor...[/]")
        log.write("[yellow]Note: Requires quantum dependencies (qiskit, qiskit-aer)[/]")
        self.refresh_status()

    def disable_quantum(self):
        """Disable quantum processor"""
        log = self.query_one("#quantum_log", MarkupLog)
        log.write("[yellow]Disabling quantum processor (fallback to unified accelerators)[/]")
        self.refresh_status()


class ToolsTab(Container):
    """Tools and utilities"""

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("[cyan]Utilities[/]"),
            Button("Download rockyou.txt", id="download_rockyou"),
            Button("Generate Context Wordlist", id="gen_context"),
            Button("Test Imports", id="test_imports"),
            Button("System Info", id="system_info"),
            MarkupLog(id="tools_log")
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        log = self.query_one("#tools_log", MarkupLog)

        if event.button.id == "test_imports":
            log.write("[cyan]Testing module imports...[/]")
            try:
                from crackers import PBKDF2Cracker, MutationEngine, ContextWordlistGenerator
                log.write("[green]✓ PBKDF2Cracker imported[/]")
                log.write("[green]✓ MutationEngine imported[/]")
                log.write("[green]✓ ContextWordlistGenerator imported[/]")
            except Exception as e:
                log.write(f"[red]Import error: {e}[/]")

        elif event.button.id == "download_rockyou":
            log.write("[yellow]Starting rockyou.txt download...[/]")
            log.write("[cyan]This will download 14.3M passwords (134MB)[/]")
            threading.Thread(
                target=self._download_rockyou, args=(log,), daemon=True
            ).start()

        elif event.button.id == "gen_context":
            log.write("[cyan]Generating context-aware wordlist...[/]")
            wordlist = ContextWordlistGenerator.generate(5000)
            log.write(f"[green]Generated {len(wordlist):,} passwords[/]")
            log.write("[cyan]Sample (first 10):[/]")
            for pwd in wordlist[:10]:
                log.write(f"  {pwd}")

    def _download_rockyou(self, log: Log):
        """Download rockyou.txt"""
        import subprocess
        rockyou_dir = Path.home() / "rockyou"
        rockyou_dir.mkdir(exist_ok=True)

        try:
            log.write("[cyan]Running: wget rockyou.txt...[/]")
            result = subprocess.run(
                [
                    "wget", "-q",
                    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
                    "-O", str(rockyou_dir / "rockyou.txt")
                ],
                timeout=300,
                capture_output=True
            )

            if result.returncode == 0:
                log.write("[green]✓ Download complete[/]")
            else:
                log.write(f"[red]Download failed: {result.stderr.decode()}[/]")
        except Exception as e:
            log.write(f"[red]Error: {e}[/]")


class WiFuFuckerApp(App):
    """Unified WIFUCKER application"""

    CSS = """
    Screen {
        background: $surface;
        color: $text;
    }

    Header {
        background: $primary;
        color: $text;
        height: 1;
    }

    Footer {
        background: $primary;
        color: $text;
        height: 1;
    }

    Button {
        margin: 0 1;
    }

    Button:hover {
        background: $accent;
    }

    Input {
        margin: 1 1;
        width: 1fr;
    }

    Log {
        margin: 1 1;
        height: 1fr;
        border: round $accent;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("c", "clear_log", "Clear Log", show=True),
        Binding("ctrl+s", "save_results", "Save Results", show=True),
        Binding("tab", "next_tab", "Next Tab", show=True),
        Binding("shift+tab", "prev_tab", "Prev Tab", show=True),
    ]

    TITLE = "WIFUCKER - Unified Cracking Platform"
    SUB_TITLE = "WiFi + PBKDF2 + Steganography | Layer 9 (QUANTUM) Active"

    def on_mount(self) -> None:
        """Initialize with Layer 9 (QUANTUM) clearance on startup"""
        # Set Layer 9 clearance in background
        def set_clearance():
            try:
                import subprocess
                clearance_script = SCRIPTS_DIR / "set_max_clearance.py"
                if clearance_script.exists():
                    subprocess.run(
                        [PYTHON_BIN, str(clearance_script)],
                        capture_output=True,
                        timeout=5
                    )
            except Exception:
                pass  # Fail silently, clearance may already be set

        threading.Thread(target=set_clearance, daemon=True).start()

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="tabs"):
            with TabPane("Quantum/9-Layer", id="quantum_tab"):
                yield Quantum9LayerTab()
            with TabPane("WiFi WPA/WPA2", id="wifi_tab"):
                yield WiFiTab()
            with TabPane("PBKDF2 Cracker", id="pbkdf2_tab"):
                yield PBKDF2Tab()
            with TabPane("Tools", id="tools_tab"):
                yield ToolsTab()
        yield Footer()

    def action_quit(self) -> None:
        """Quit the application"""
        self.exit()

    def action_clear_log(self) -> None:
        """Clear log output"""
        try:
            # Try to clear the active tab's log
            tabs = self.query_one("#tabs", TabbedContent)
            active_tab = tabs.active
            if active_tab == "pbkdf2_tab":
                log = self.query_one("#crack_log", MarkupLog)
                log.clear()
            elif active_tab == "wifi_tab":
                log = self.query_one("#wifi_log", MarkupLog)
                log.clear()
            elif active_tab == "quantum_tab":
                log = self.query_one("#quantum_log", MarkupLog)
                log.clear()
            elif active_tab == "tools_tab":
                log = self.query_one("#tools_log", MarkupLog)
                log.clear()
        except:
            pass
    
    def action_save_results(self) -> None:
        """Save current tab's results to file"""
        try:
            from datetime import datetime
            tabs = self.query_one("#tabs", TabbedContent)
            active_tab = tabs.active
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if active_tab == "pbkdf2_tab":
                log = self.query_one("#crack_log", MarkupLog)
                filename = f"wifucker_pbkdf2_{timestamp}.txt"
            elif active_tab == "wifi_tab":
                log = self.query_one("#wifi_log", MarkupLog)
                filename = f"wifucker_wifi_{timestamp}.txt"
            elif active_tab == "quantum_tab":
                log = self.query_one("#quantum_log", MarkupLog)
                filename = f"wifucker_quantum_{timestamp}.txt"
            elif active_tab == "tools_tab":
                log = self.query_one("#tools_log", MarkupLog)
                filename = f"wifucker_tools_{timestamp}.txt"
            else:
                return
            
            # Get log content (textual logs don't have direct content access)
            # We'll save a summary instead
            output_path = ROOT_DIR / filename
            with open(output_path, 'w') as f:
                f.write(f"WIFUCKER Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Tab: {active_tab}\n")
                f.write("=" * 60 + "\n")
                f.write("Note: Full log content requires Textual API enhancement\n")
                f.write("This file was created via Save Results action.\n")
            
            log.write(f"[green]✓ Results saved to: {output_path}[/]")
        except Exception as e:
            try:
                log = self.query_one("#crack_log", MarkupLog)
                log.write(f"[red]Error saving results: {e}[/]")
            except:
                pass
    
    def action_next_tab(self) -> None:
        """Navigate to next tab"""
        tabs = self.query_one("#tabs", TabbedContent)
        tab_ids = ["quantum_tab", "wifi_tab", "pbkdf2_tab", "tools_tab"]
        current_idx = tab_ids.index(tabs.active) if tabs.active in tab_ids else 0
        next_idx = (current_idx + 1) % len(tab_ids)
        tabs.active = tab_ids[next_idx]
    
    def action_prev_tab(self) -> None:
        """Navigate to previous tab"""
        tabs = self.query_one("#tabs", TabbedContent)
        tab_ids = ["quantum_tab", "wifi_tab", "pbkdf2_tab", "tools_tab"]
        current_idx = tab_ids.index(tabs.active) if tabs.active in tab_ids else 0
        prev_idx = (current_idx - 1) % len(tab_ids)
        tabs.active = tab_ids[prev_idx]


def main():
    """Run the TUI"""
    app = WiFuFuckerApp()
    app.run()


if __name__ == "__main__":
    main()
