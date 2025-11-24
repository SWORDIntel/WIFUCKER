#!/usr/bin/env python3
"""
WiFi Security Suite - Terminal User Interface
==============================================

Interactive TUI for hardware-accelerated WiFi cracking.

Features:
- Real-time hardware detection
- Interactive PCAP parsing
- Live cracking progress
- AI wordlist generation
- Wordlist management
- Beautiful progress visualization
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Button, Static, Input, Label,
    DataTable, ProgressBar, Log, TabbedContent, TabPane,
    Select, Switch, RadioSet, RadioButton
)
from textual.binding import Binding
from textual.reactive import reactive
from rich.text import Text
from rich.panel import Panel
from rich.table import Table as RichTable
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
import asyncio
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from .parsers.pcap_parser import PCAPParser, HandshakeData
from .crackers.openvino_cracker import OpenVINOWiFiCracker
from .crackers.hardware_detector import HardwareDetector, DeviceInfo
from .ai_models.wordlist_generator import AIWordlistGenerator, WordlistConfig
from .utils.wordlist_downloader import WordlistDownloader


class DeviceCard(Static):
    """Display card for hardware device"""

    def __init__(self, device: DeviceInfo, **kwargs):
        super().__init__(**kwargs)
        self.device = device

    def compose(self) -> ComposeResult:
        status_icon = "✓" if self.device.is_available else "✗"
        status_color = "green" if self.device.is_available else "red"

        content = f"""[bold]{self.device.device_name}[/bold]

[cyan]Type:[/cyan] {self.device.device_type.value}
[cyan]Status:[/cyan] [{status_color}]{status_icon} {'Available' if self.device.is_available else 'Unavailable'}[/{status_color}]
[cyan]Precision:[/cyan] {self.device.inference_precision}
[cyan]Batch Size:[/cyan] {self.device.max_batch_size}
[cyan]Performance:[/cyan] {self.device.performance_hint}
"""
        yield Static(content, classes="device-card")


class HandshakeRow(Static):
    """Row displaying handshake information"""

    def __init__(self, hs: HandshakeData, index: int, **kwargs):
        super().__init__(**kwargs)
        self.handshake = hs
        self.index = index

    def compose(self) -> ComposeResult:
        complete_icon = "✓" if self.handshake.is_complete else "✗"
        complete_color = "green" if self.handshake.is_complete else "yellow"

        content = f"""[bold]#{self.index}[/bold] [{complete_color}]{complete_icon}[/{complete_color}] [cyan]{self.handshake.ssid}[/cyan]
    BSSID: {self.handshake.bssid} | Client: {self.handshake.client}
    Type: {self.handshake.handshake_type} | Time: {self.handshake.timestamp.strftime('%H:%M:%S')}
"""
        yield Static(content, classes="handshake-row")


class CrackingProgress(Static):
    """Real-time cracking progress display"""

    progress = reactive(0.0)
    speed = reactive(0)
    attempts = reactive(0)
    elapsed = reactive(0.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("Cracking Progress", classes="progress-title")
        yield ProgressBar(total=100, show_eta=True, id="crack-progress")
        yield Static(id="progress-stats")

    def watch_progress(self, progress: float):
        """Update progress bar"""
        bar = self.query_one("#crack-progress", ProgressBar)
        bar.update(progress=progress)

        # Update stats
        stats = self.query_one("#progress-stats", Static)
        eta = self._estimate_eta()

        stats.update(f"""[cyan]Progress:[/cyan] {progress:.1f}%
[cyan]Attempts:[/cyan] {self.attempts:,}
[cyan]Speed:[/cyan] {self.speed:,} H/s
[cyan]Elapsed:[/cyan] {self.elapsed:.1f}s
[cyan]ETA:[/cyan] {eta}
""")

    def _estimate_eta(self) -> str:
        """Estimate time remaining"""
        if self.progress > 0 and self.speed > 0:
            remaining = (100 - self.progress) / 100
            total_passwords = self.attempts / (self.progress / 100) if self.progress > 0 else 0
            remaining_passwords = total_passwords * remaining
            eta_seconds = remaining_passwords / self.speed if self.speed > 0 else 0

            if eta_seconds < 60:
                return f"{eta_seconds:.0f}s"
            elif eta_seconds < 3600:
                return f"{eta_seconds/60:.1f}m"
            else:
                return f"{eta_seconds/3600:.1f}h"
        return "Calculating..."


class WiFiCrackerTUI(App):
    """Main TUI application for WiFi cracking"""

    CSS = """
    Screen {
        background: $surface;
    }

    .device-card {
        border: solid $primary;
        padding: 1;
        margin: 1;
        background: $panel;
    }

    .handshake-row {
        border: solid $secondary;
        padding: 1;
        margin: 1;
        background: $panel;
    }

    .progress-title {
        text-align: center;
        text-style: bold;
        color: $accent;
    }

    #progress-stats {
        padding: 1;
        border: solid $primary;
        margin-top: 1;
    }

    .success-panel {
        border: solid green;
        padding: 2;
        background: $success;
    }

    .error-panel {
        border: solid red;
        padding: 2;
        background: $error;
    }

    Log {
        border: solid $primary;
        height: 15;
    }

    Button {
        margin: 1;
    }

    Input {
        margin: 1;
    }

    Select {
        margin: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "show_devices", "Devices"),
        Binding("p", "parse_pcap", "Parse"),
        Binding("c", "crack", "Crack"),
        Binding("g", "generate", "Generate"),
    ]

    TITLE = "DavBest WiFi Security Suite - OpenVINO Accelerated"

    def __init__(self):
        super().__init__()
        self.hardware_detector = HardwareDetector()
        self.devices: List[DeviceInfo] = []
        self.handshakes: List[HandshakeData] = []
        self.selected_handshake: Optional[HandshakeData] = None
        self.cracker: Optional[OpenVINOWiFiCracker] = None

    def compose(self) -> ComposeResult:
        """Create child widgets"""
        yield Header(show_clock=True)

        with TabbedContent(initial="devices"):
            # Devices Tab
            with TabPane("🖥️  Hardware", id="devices"):
                yield Button("🔍 Detect Devices", id="btn-detect", variant="primary")
                yield ScrollableContainer(id="devices-container")

            # Parse Tab
            with TabPane("📡 Parse PCAP", id="parse"):
                yield Label("PCAP File Path:")
                yield Input(placeholder="/path/to/capture.pcap", id="input-pcap")
                yield Horizontal(
                    Button("📂 Parse PCAP", id="btn-parse", variant="success"),
                    Button("💾 Export Hashcat", id="btn-export-hc"),
                    Button("💾 Export John", id="btn-export-john"),
                )
                yield ScrollableContainer(id="handshakes-container")

            # Crack Tab
            with TabPane("🔓 Crack", id="crack"):
                yield Label("Select Handshake:")
                yield Select([], id="select-handshake")
                yield Label("Wordlist Path:")
                yield Input(placeholder="/path/to/wordlist.txt", id="input-wordlist")
                yield Horizontal(
                    Label("Device:"),
                    Select([
                        ("Auto", "auto"),
                        ("NPU", "NPU"),
                        ("NCS2", "NCS2"),
                        ("GPU", "GPU"),
                        ("CPU", "CPU")
                    ], value="auto", id="select-device")
                )
                yield Horizontal(
                    Static("Enable Rules:"),
                    Switch(id="switch-rules")
                )
                yield Button("🚀 Start Cracking", id="btn-crack", variant="primary")
                yield CrackingProgress(id="crack-progress-widget")
                yield Static(id="crack-result")

            # Generate Tab
            with TabPane("🤖 Generate Wordlist", id="generate"):
                yield Label("Target SSID:")
                yield Input(placeholder="NetworkName", id="input-ssid")
                yield Horizontal(
                    Label("Max Passwords:"),
                    Input(value="10000", id="input-max-passwords")
                )
                yield Horizontal(
                    Label("Min Length:"),
                    Input(value="8", id="input-min-length")
                )
                yield Horizontal(
                    Label("Max Length:"),
                    Input(value="63", id="input-max-length")
                )
                yield Button("🎯 Generate", id="btn-generate", variant="success")
                yield Static(id="generate-result")

            # Download Tab
            with TabPane("📥 Download Wordlists", id="download"):
                yield Label("Popular Wordlist Sources from GitHub:")
                yield Horizontal(
                    Button("📦 Download All", id="btn-dl-all", variant="primary"),
                    Button("📋 SecLists WiFi", id="btn-dl-seclists"),
                    Button("📋 Berzerk0", id="btn-dl-berzerk0"),
                )
                yield Label("Download Directory:")
                yield Input(value="./wordlists", id="input-dl-dir")
                yield Static(id="download-result")

            # Log Tab
            with TabPane("📜 Logs", id="logs"):
                yield Log(id="log-output")

        yield Footer()

    async def on_mount(self) -> None:
        """Initialize application"""
        self.log_message("WiFi Security Suite Started")
        self.log_message("⚠️  For authorized security testing only!")

        # Auto-detect devices on startup
        await self.detect_devices()

    def log_message(self, message: str):
        """Add message to log"""
        log = self.query_one("#log-output", Log)
        timestamp = datetime.now().strftime("%H:%M:%S")
        log.write_line(f"[{timestamp}] {message}")

    async def detect_devices(self):
        """Detect available hardware"""
        self.log_message("Detecting hardware accelerators...")

        container = self.query_one("#devices-container", ScrollableContainer)
        await container.remove_children()

        self.devices = self.hardware_detector.detect_devices()

        for device in self.devices:
            card = DeviceCard(device)
            await container.mount(card)

        self.log_message(f"Found {len(self.devices)} device(s)")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks"""
        button_id = event.button.id

        if button_id == "btn-detect":
            self.run_worker(self.detect_devices())
        elif button_id == "btn-parse":
            self.run_worker(self.parse_pcap())
        elif button_id == "btn-crack":
            self.run_worker(self.crack_password())
        elif button_id == "btn-generate":
            self.run_worker(self.generate_wordlist())
        elif button_id == "btn-dl-all":
            self.run_worker(self.download_wordlists("all"))
        elif button_id == "btn-dl-seclists":
            self.run_worker(self.download_wordlists("seclists_wifi"))
        elif button_id == "btn-dl-berzerk0":
            self.run_worker(self.download_wordlists("berzerk0_probable"))

    async def parse_pcap(self):
        """Parse PCAP file"""
        pcap_input = self.query_one("#input-pcap", Input)
        pcap_file = pcap_input.value

        if not pcap_file or not Path(pcap_file).exists():
            self.log_message(f"❌ PCAP file not found: {pcap_file}")
            return

        self.log_message(f"📡 Parsing PCAP: {pcap_file}")

        try:
            parser = PCAPParser(pcap_file)
            handshakes, pmkids = parser.parse()

            self.handshakes = handshakes

            # Display handshakes
            container = self.query_one("#handshakes-container", ScrollableContainer)
            await container.remove_children()

            for i, hs in enumerate(handshakes, 1):
                row = HandshakeRow(hs, i)
                await container.mount(row)

            # Update handshake selector
            select = self.query_one("#select-handshake", Select)
            select.set_options([
                (f"{hs.ssid} ({hs.bssid})", str(i))
                for i, hs in enumerate(handshakes)
            ])

            self.log_message(f"✅ Found {len(handshakes)} handshake(s)")

        except Exception as e:
            self.log_message(f"❌ Error parsing PCAP: {e}")

    async def crack_password(self):
        """Start cracking process"""
        if not self.handshakes:
            self.log_message("❌ No handshakes available. Parse PCAP first.")
            return

        # Get selected handshake
        select = self.query_one("#select-handshake", Select)
        if select.value == Select.BLANK:
            self.log_message("❌ Please select a handshake")
            return

        hs_index = int(select.value)
        target_hs = self.handshakes[hs_index]

        # Get wordlist
        wordlist_input = self.query_one("#input-wordlist", Input)
        wordlist_file = wordlist_input.value

        if not wordlist_file or not Path(wordlist_file).exists():
            self.log_message(f"❌ Wordlist not found: {wordlist_file}")
            return

        # Get device preference
        device_select = self.query_one("#select-device", Select)
        device_pref = None if device_select.value == "auto" else device_select.value

        # Get rules setting
        rules_switch = self.query_one("#switch-rules", Switch)
        use_rules = rules_switch.value

        self.log_message(f"🚀 Starting crack: {target_hs.ssid}")
        self.log_message(f"   Wordlist: {wordlist_file}")
        self.log_message(f"   Device: {device_pref or 'Auto'}")
        self.log_message(f"   Rules: {'Enabled' if use_rules else 'Disabled'}")

        # Initialize cracker
        if not self.cracker:
            self.cracker = OpenVINOWiFiCracker(
                use_hardware=True,
                device_preference=device_pref
            )

        # Progress callback
        progress_widget = self.query_one("#crack-progress-widget", CrackingProgress)

        def progress_callback(current, total, percent, speed):
            progress_widget.progress = percent
            progress_widget.attempts = current
            progress_widget.speed = int(speed)

        # Run cracking
        try:
            result = self.cracker.crack_handshake(
                ssid=target_hs.ssid,
                anonce=target_hs.anonce,
                snonce=target_hs.snonce,
                mic=target_hs.mic,
                bssid=target_hs.bssid,
                client=target_hs.client,
                wordlist_file=wordlist_file,
                progress_callback=progress_callback,
                use_rules=use_rules
            )

            # Show result
            result_widget = self.query_one("#crack-result", Static)

            if result.success:
                result_text = f"""[bold green]🎉 SUCCESS![/bold green]

[cyan]SSID:[/cyan] {target_hs.ssid}
[cyan]Password:[/cyan] [bold yellow]{result.password}[/bold yellow]
[cyan]Attempts:[/cyan] {result.attempts:,}
[cyan]Time:[/cyan] {result.elapsed_time:.2f}s
[cyan]Speed:[/cyan] {result.hashes_per_second:,.0f} H/s
[cyan]Device:[/cyan] {result.device_used}
"""
                result_widget.update(result_text)
                result_widget.add_class("success-panel")
                self.log_message(f"✅ Password cracked: {result.password}")
            else:
                result_text = f"""[bold red]❌ Password Not Found[/bold red]

[cyan]SSID:[/cyan] {target_hs.ssid}
[cyan]Attempts:[/cyan] {result.attempts:,}
[cyan]Time:[/cyan] {result.elapsed_time:.2f}s

💡 Try a larger wordlist or enable rules
"""
                result_widget.update(result_text)
                result_widget.add_class("error-panel")
                self.log_message("❌ Password not found in wordlist")

        except Exception as e:
            self.log_message(f"❌ Cracking error: {e}")

    async def generate_wordlist(self):
        """Generate AI-powered wordlist"""
        ssid_input = self.query_one("#input-ssid", Input)
        ssid = ssid_input.value

        if not ssid:
            self.log_message("❌ Please enter an SSID")
            return

        max_pwd_input = self.query_one("#input-max-passwords", Input)
        min_len_input = self.query_one("#input-min-length", Input)
        max_len_input = self.query_one("#input-max-length", Input)

        try:
            max_passwords = int(max_pwd_input.value)
            min_length = int(min_len_input.value)
            max_length = int(max_len_input.value)
        except ValueError:
            self.log_message("❌ Invalid number format")
            return

        self.log_message(f"🤖 Generating wordlist for: {ssid}")

        config = WordlistConfig(
            min_length=min_length,
            max_length=max_length,
            max_generated=max_passwords
        )

        generator = AIWordlistGenerator(config)
        passwords = generator.generate(ssid, max_passwords=max_passwords)

        # Save to file
        output_file = f"wordlist_{ssid}.txt"
        with open(output_file, 'w') as f:
            f.write('\n'.join(passwords))

        result_widget = self.query_one("#generate-result", Static)
        result_widget.update(f"""[bold green]✅ Wordlist Generated[/bold green]

[cyan]SSID:[/cyan] {ssid}
[cyan]Passwords:[/cyan] {len(passwords):,}
[cyan]File:[/cyan] {output_file}

Sample passwords:
{'  '.join(passwords[:10])}
""")

        self.log_message(f"✅ Generated {len(passwords):,} passwords → {output_file}")

    async def download_wordlists(self, source: str):
        """Download wordlists"""
        dl_dir_input = self.query_one("#input-dl-dir", Input)
        dl_dir = dl_dir_input.value

        self.log_message(f"📥 Downloading wordlists to: {dl_dir}")

        downloader = WordlistDownloader(download_dir=dl_dir)

        try:
            if source == "all":
                downloader.download_all()
            else:
                downloader.download_wordlist(source)

            result_widget = self.query_one("#download-result", Static)
            result_widget.update(f"""[bold green]✅ Download Complete[/bold green]

[cyan]Source:[/cyan] {source}
[cyan]Directory:[/cyan] {dl_dir}

Check the log tab for details.
""")

            self.log_message("✅ Download complete")

        except Exception as e:
            self.log_message(f"❌ Download error: {e}")


def main():
    """Run TUI application"""
    app = WiFiCrackerTUI()
    app.run()


if __name__ == '__main__':
    main()
