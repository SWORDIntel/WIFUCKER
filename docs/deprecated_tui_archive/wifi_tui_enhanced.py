#!/usr/bin/env python3
"""
DavBest WiFi Suite - Polished Enhanced TUI
===========================================

Beautiful, easy-to-use interface with live feedback.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Button, Static, Input, Label,
    DataTable, ProgressBar, Log, TabbedContent, TabPane,
    Switch, RadioSet, RadioButton, ListView, ListItem, Rule
)
from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import Screen
from rich.text import Text
from rich.panel import Panel
from rich.table import Table as RichTable
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import asyncio
from pathlib import Path
from typing import Optional, List
from datetime import datetime
import threading
import time

from .capture.network_scanner import NetworkScanner, WiFiNetwork
from .capture.deauth_attack import DeauthAttacker, DeauthResult
from .capture.handshake_capture import HandshakeCapture


class NetworkListItem(ListItem):
    """Polished network list item"""

    def __init__(self, network: WiFiNetwork, **kwargs):
        self.network = network
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        """Create beautiful network display"""
        net = self.network

        # Signal strength with color and bars
        if net.power >= -60:
            signal_bar = "▰▰▰▰▰"
            signal_color = "green"
        elif net.power >= -70:
            signal_bar = "▰▰▰▰▱"
            signal_color = "yellow"
        elif net.power >= -80:
            signal_bar = "▰▰▰▱▱"
            signal_color = "orange"
        else:
            signal_bar = "▰▱▱▱▱"
            signal_color = "red"

        # Client indicator with icon
        if net.has_clients:
            client_display = f"[green]👥 {len(net.clients)}[/green]"
        else:
            client_display = "[dim]👥 0[/dim]"

        # Security icon
        if "WPA3" in net.encryption:
            sec_icon = "🔒"
        elif "WPA2" in net.encryption or "WPA" in net.encryption:
            sec_icon = "🔐"
        else:
            sec_icon = "🔓"

        content = (
            f"[bold cyan]{net.essid[:30]:30s}[/bold cyan] │ "
            f"[dim]{net.bssid}[/dim] │ "
            f"[bold]Ch {net.channel:2d}[/bold] │ "
            f"[{signal_color}]{signal_bar} {net.power:3d}dBm[/{signal_color}] │ "
            f"{sec_icon} {net.encryption:8s} │ "
            f"{client_display}"
        )

        yield Static(content, classes="network-item")


class ScanScreen(Screen):
    """Polished network scanning screen"""

    CSS = """
    ScanScreen {
        background: $surface;
    }

    #scan-header {
        background: $primary;
        color: $text;
        padding: 1;
        border: solid $accent;
        margin-bottom: 1;
    }

    #scan-controls {
        background: $panel;
        padding: 1;
        border: solid $accent;
        margin: 1 0;
    }

    #scan-status {
        padding: 1;
        background: $panel;
        border-left: thick $accent;
        margin: 1 0;
    }

    .network-item {
        padding: 1 2;
        border-bottom: solid $panel;
    }

    .network-item:hover {
        background: $boost;
    }

    #action-buttons {
        padding: 1;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("s", "start_scan", "🔍 Scan", show=True),
        Binding("r", "rescan", "🔄 Rescan", show=True),
        Binding("escape", "app.pop_screen", "◀ Back", show=True),
    ]

    def __init__(self, interface: str, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.scanner = NetworkScanner(interface)
        self.networks: List[WiFiNetwork] = []
        self.selected_network: Optional[WiFiNetwork] = None
        self.scanning = False

    def compose(self) -> ComposeResult:
        yield Header()

        with Container():
            yield Static(
                f"[bold]📡 Network Scanner[/bold]\n"
                f"Interface: [cyan]{self.interface}[/cyan] │ "
                f"Status: [green]● Ready[/green]\n"
                f"[dim]Press 'S' to scan for networks[/dim]",
                id="scan-header"
            )

            with Horizontal(id="scan-controls"):
                yield Button("🔍 Start Scan", id="btn-scan", variant="primary")
                yield Button("⏹ Stop", id="btn-stop", variant="error", disabled=True)
                yield Label("Duration:")
                yield Input(value="10", id="scan-duration", type="integer", placeholder="seconds")
                yield Label("sec")

            yield Static("", id="scan-status")

            yield ProgressBar(total=100, show_eta=True, id="scan-progress", classes="hidden")

            yield Static("[bold]📋 Networks Found:[/bold]", classes="section-title")

            with ScrollableContainer(id="network-list-container"):
                yield ListView(id="network-list")

            with Horizontal(id="action-buttons"):
                yield Button("✓ Select", id="btn-select", variant="success", disabled=True)
                yield Button("💥 Deauth", id="btn-deauth", variant="warning", disabled=True)
                yield Button("📦 Capture", id="btn-capture", variant="primary", disabled=True)

        yield Footer()

    async def on_mount(self) -> None:
        """Show help on mount"""
        status = self.query_one("#scan-status", Static)
        status.update("[dim]💡 Tip: Select a network with many clients for best results[/dim]")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "btn-scan":
            await self.action_start_scan()
        elif event.button.id == "btn-stop":
            self.action_stop_scan()
        elif event.button.id == "btn-select":
            await self.action_select_network()
        elif event.button.id == "btn-deauth":
            await self.action_deauth_attack()
        elif event.button.id == "btn-capture":
            await self.action_capture_handshake()

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle network selection"""
        network_list = self.query_one("#network-list", ListView)
        selected_idx = network_list.index

        if 0 <= selected_idx < len(self.networks):
            self.selected_network = self.networks[selected_idx]

            # Enable action buttons
            self.query_one("#btn-select", Button).disabled = False
            self.query_one("#btn-deauth", Button).disabled = False
            self.query_one("#btn-capture", Button).disabled = False

            # Show selection feedback
            net = self.selected_network
            status = self.query_one("#scan-status", Static)
            status.update(
                f"[green]✓[/green] Selected: [bold]{net.essid}[/bold] │ "
                f"Channel {net.channel} │ "
                f"{net.power} dBm │ "
                f"{len(net.clients)} client(s)"
            )

    async def action_start_scan(self) -> None:
        """Start network scan with live feedback"""
        if self.scanning:
            return

        self.scanning = True
        scan_btn = self.query_one("#btn-scan", Button)
        stop_btn = self.query_one("#btn-stop", Button)
        status = self.query_one("#scan-status", Static)
        progress = self.query_one("#scan-progress", ProgressBar)

        scan_btn.disabled = True
        stop_btn.disabled = False
        progress.remove_class("hidden")

        # Get scan duration
        duration_input = self.query_one("#scan-duration", Input)
        try:
            duration = int(duration_input.value)
        except:
            duration = 10

        # Animate scanning
        status.update(f"[yellow]🔍 Scanning for networks...[/yellow]")

        # Run scan in background with progress
        def scan_worker():
            for i in range(duration):
                if not self.scanning:
                    break
                progress.update(progress=int((i / duration) * 100))
                time.sleep(1)

            self.networks = self.scanner.scan(duration=1)  # Final capture
            progress.update(progress=100)

        await asyncio.get_event_loop().run_in_executor(None, scan_worker)

        # Update UI
        await self.update_network_list()

        if len(self.networks) > 0:
            status.update(
                f"[green]✓ Found {len(self.networks)} network(s)[/green] │ "
                f"[dim]Select one to continue[/dim]"
            )
        else:
            status.update("[red]✗ No networks found[/red] │ [dim]Try scanning longer[/dim]")

        scan_btn.disabled = False
        stop_btn.disabled = True
        progress.add_class("hidden")
        self.scanning = False

    def action_stop_scan(self) -> None:
        """Stop scanning"""
        self.scanning = False
        self.scanner.stop_scan()

        status = self.query_one("#scan-status", Static)
        status.update("[yellow]⏹ Scan stopped by user[/yellow]")

    def action_rescan(self) -> None:
        """Quick rescan"""
        asyncio.create_task(self.action_start_scan())

    async def update_network_list(self) -> None:
        """Update network list display"""
        network_list = self.query_one("#network-list", ListView)
        await network_list.clear()

        if not self.networks:
            await network_list.append(
                ListItem(Static("[dim]No networks found yet. Click 'Start Scan'.[/dim]"))
            )
            return

        for net in sorted(self.networks, key=lambda x: x.power, reverse=True):
            item = NetworkListItem(net)
            await network_list.append(item)

    async def action_select_network(self) -> None:
        """Select network and return to main"""
        if self.selected_network:
            self.app.selected_network = self.selected_network  # type: ignore
            self.app.pop_screen()

    async def action_deauth_attack(self) -> None:
        """Launch deauth attack screen"""
        if self.selected_network:
            self.app.push_screen(DeauthScreen(self.interface, self.selected_network))

    async def action_capture_handshake(self) -> None:
        """Launch capture screen"""
        if self.selected_network:
            self.app.push_screen(CaptureScreen(self.interface, self.selected_network))


class DeauthScreen(Screen):
    """Polished deauth attack screen"""

    CSS = """
    DeauthScreen {
        background: $surface;
    }

    #deauth-header {
        background: $error;
        color: $text;
        padding: 1 2;
        border: solid $accent;
        margin-bottom: 1;
    }

    #deauth-controls {
        background: $panel;
        padding: 1 2;
        border: solid $accent;
        margin: 1 0;
    }

    #client-list-container {
        background: $panel;
        border: solid $accent;
        padding: 1;
        margin: 1 0;
        max-height: 15;
    }

    .client-item {
        padding: 0 2;
        border-left: thick $success;
    }

    #attack-stats {
        background: $panel;
        padding: 1 2;
        border-left: thick $warning;
        margin: 1 0;
    }

    #deauth-log {
        border: solid $accent;
        margin-top: 1;
        max-height: 20;
    }
    """

    BINDINGS = [
        Binding("d", "start_deauth", "💥 Start", show=True),
        Binding("s", "stop_deauth", "⏹ Stop", show=True),
        Binding("escape", "app.pop_screen", "◀ Back", show=True),
    ]

    def __init__(self, interface: str, network: WiFiNetwork, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.network = network
        self.deauther = DeauthAttacker(interface)
        self.attack_active = False
        self.attack_thread: Optional[threading.Thread] = None
        self.packets_sent = 0
        self.start_time = 0

    def compose(self) -> ComposeResult:
        yield Header()

        with Container():
            yield Static(
                f"[bold]💥 Deauthentication Attack[/bold]\n"
                f"Target: [cyan]{self.network.essid}[/cyan] ({self.network.bssid})\n"
                f"Channel: [yellow]{self.network.channel}[/yellow] │ "
                f"Power: [green]{self.network.power} dBm[/green] │ "
                f"Clients: [cyan]{len(self.network.clients)}[/cyan]",
                id="deauth-header"
            )

            with Vertical(id="deauth-controls"):
                yield Label("[bold]⚙️ Attack Configuration:[/bold]")
                yield Rule()

                with RadioSet(id="attack-mode"):
                    yield RadioButton("💣 Broadcast (Deauth ALL clients - Fast)", value=True)
                    yield RadioButton("🎯 Targeted (Specific clients - Precise)", value=False)

                with Horizontal():
                    yield Label("📤 Packets/burst:")
                    yield Input(value="10", id="deauth-count", type="integer")
                    yield Label("⏱️ Interval:")
                    yield Input(value="1.0", id="deauth-interval")
                    yield Label("sec")

                with Horizontal():
                    yield Switch(value=False, id="continuous-mode")
                    yield Label("🔄 Continuous mode (keeps attacking)")

            yield Static("", id="attack-stats")

            with Vertical(id="client-list-container"):
                yield Label(f"[bold]👥 Connected Clients ({len(self.network.clients)}):[/bold]")
                yield Rule()

                if self.network.clients:
                    for i, client in enumerate(self.network.clients, 1):
                        yield Static(
                            f"[green]●[/green] Device {i}: [cyan]{client}[/cyan]",
                            classes="client-item"
                        )
                else:
                    yield Static("[dim]⚠️ No clients detected - broadcast recommended[/dim]")

            with Horizontal(id="deauth-buttons"):
                yield Button("💥 Start Attack", id="btn-start", variant="error")
                yield Button("⏹ Stop Attack", id="btn-stop", variant="success", disabled=True)

            yield Log(id="deauth-log", auto_scroll=True, highlight=True)

        yield Footer()

    async def on_mount(self) -> None:
        """Show initial stats"""
        stats = self.query_one("#attack-stats", Static)
        stats.update(
            "[dim]Ready to attack │ "
            "Configure settings above and press 'Start Attack'[/dim]"
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "btn-start":
            await self.action_start_deauth()
        elif event.button.id == "btn-stop":
            await self.action_stop_deauth()

    async def action_start_deauth(self) -> None:
        """Start deauth attack with live feedback"""
        if self.attack_active:
            return

        start_btn = self.query_one("#btn-start", Button)
        stop_btn = self.query_one("#btn-stop", Button)
        log = self.query_one("#deauth-log", Log)
        stats = self.query_one("#attack-stats", Static)

        start_btn.disabled = True
        stop_btn.disabled = False

        # Get parameters
        mode = self.query_one("#attack-mode", RadioSet)
        broadcast_mode = mode.pressed_index == 0

        count_input = self.query_one("#deauth-count", Input)
        try:
            count = int(count_input.value)
        except:
            count = 10

        interval_input = self.query_one("#deauth-interval", Input)
        try:
            interval = float(interval_input.value)
        except:
            interval = 1.0

        continuous = self.query_one("#continuous-mode", Switch).value

        self.attack_active = True
        self.packets_sent = 0
        self.start_time = time.time()

        log.write_line("[bold yellow]⚡ Starting deauth attack...[/bold yellow]")

        mode_icon = "💣" if broadcast_mode else "🎯"
        mode_text = "BROADCAST (all clients)" if broadcast_mode else f"TARGETED ({len(self.network.clients)} clients)"
        log.write_line(f"{mode_icon} Mode: [cyan]{mode_text}[/cyan]")
        log.write_line(f"📤 Packets: [yellow]{count}[/yellow] per burst")

        if continuous:
            log.write_line(f"[red]🔄 Continuous mode enabled - will loop every {interval}s[/red]")

        if broadcast_mode:
            def broadcast_attack():
                burst = 0
                while self.attack_active:
                    burst += 1
                    result = self.deauther.deauth_network(
                        self.network.bssid,
                        None,
                        count=count
                    )

                    self.packets_sent += count
                    elapsed = time.time() - self.start_time
                    rate = self.packets_sent / elapsed if elapsed > 0 else 0

                    if result.success:
                        log.write_line(
                            f"[green]✓ Burst {burst}:[/green] Sent {count} packets │ "
                            f"Total: {self.packets_sent} │ Rate: {rate:.1f} pkt/s"
                        )

                        # Update stats
                        stats.update(
                            f"[green]● ATTACKING[/green] │ "
                            f"Bursts: {burst} │ "
                            f"Packets: {self.packets_sent} │ "
                            f"Rate: {rate:.1f} pkt/s │ "
                            f"Duration: {int(elapsed)}s"
                        )
                    else:
                        log.write_line(f"[red]✗ Burst {burst} failed:[/red] {result.message}")

                    if not continuous:
                        break

                    time.sleep(interval)

                self.attack_active = False

            self.attack_thread = threading.Thread(target=broadcast_attack, daemon=True)
            self.attack_thread.start()

        else:
            # Targeted attack
            if not self.network.clients:
                log.write_line("[yellow]⚠️ No clients to target![/yellow]")
                self.attack_active = False
                start_btn.disabled = False
                stop_btn.disabled = True
                return

            def targeted_attack():
                burst = 0
                while self.attack_active:
                    burst += 1
                    log.write_line(f"[cyan]━━━ Burst {burst} ━━━[/cyan]")

                    for idx, client in enumerate(self.network.clients, 1):
                        if not self.attack_active:
                            break

                        result = self.deauther.deauth_network(
                            self.network.bssid,
                            client,
                            count=count
                        )

                        self.packets_sent += count
                        elapsed = time.time() - self.start_time
                        rate = self.packets_sent / elapsed if elapsed > 0 else 0

                        if result.success:
                            log.write_line(
                                f"  [green]✓ Device {idx}:[/green] {client} │ "
                                f"{count} packets sent"
                            )
                        else:
                            log.write_line(f"  [red]✗ Device {idx}:[/red] {client} failed")

                        # Update stats
                        stats.update(
                            f"[green]● ATTACKING[/green] │ "
                            f"Burst: {burst}/{len(self.network.clients)} │ "
                            f"Packets: {self.packets_sent} │ "
                            f"Rate: {rate:.1f} pkt/s"
                        )

                    if not continuous:
                        break

                    time.sleep(interval)

                self.attack_active = False

            self.attack_thread = threading.Thread(target=targeted_attack, daemon=True)
            self.attack_thread.start()

        # Monitor completion
        def monitor_completion():
            while self.attack_active:
                time.sleep(0.5)

            # Attack finished
            start_btn.disabled = False
            stop_btn.disabled = True

            elapsed = time.time() - self.start_time
            log.write_line(
                f"\n[bold green]✓ Attack complete[/bold green] │ "
                f"Total packets: {self.packets_sent} │ "
                f"Duration: {elapsed:.1f}s"
            )

            stats.update(
                f"[yellow]⏹ STOPPED[/yellow] │ "
                f"Packets sent: {self.packets_sent} │ "
                f"Duration: {int(elapsed)}s"
            )

        threading.Thread(target=monitor_completion, daemon=True).start()

    async def action_stop_deauth(self) -> None:
        """Stop deauth attack"""
        self.attack_active = False

        log = self.query_one("#deauth-log", Log)
        log.write_line("[yellow]⏹ Stopping attack...[/yellow]")


class CaptureScreen(Screen):
    """Polished handshake capture screen"""

    CSS = """
    CaptureScreen {
        background: $surface;
    }

    #capture-header {
        background: $success;
        color: $text;
        padding: 1 2;
        border: solid $accent;
        margin-bottom: 1;
    }

    #capture-controls {
        background: $panel;
        padding: 1 2;
        border: solid $accent;
        margin: 1 0;
    }

    #capture-progress-container {
        padding: 1;
        border: solid $accent;
        margin: 1 0;
    }

    #capture-log {
        border: solid $accent;
        margin-top: 1;
        max-height: 25;
    }
    """

    BINDINGS = [
        Binding("c", "start_capture", "📦 Capture", show=True),
        Binding("escape", "app.pop_screen", "◀ Back", show=True),
    ]

    def __init__(self, interface: str, network: WiFiNetwork, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.network = network
        self.capture = HandshakeCapture(interface)

    def compose(self) -> ComposeResult:
        yield Header()

        with Container():
            yield Static(
                f"[bold]📦 Handshake Capture[/bold]\n"
                f"Target: [cyan]{self.network.essid}[/cyan] ({self.network.bssid})\n"
                f"Channel: [yellow]{self.network.channel}[/yellow] │ "
                f"Clients: [cyan]{len(self.network.clients)}[/cyan] │ "
                f"Signal: [green]{self.network.power} dBm[/green]",
                id="capture-header"
            )

            with Vertical(id="capture-controls"):
                yield Label("[bold]⚙️ Capture Configuration:[/bold]")
                yield Rule()

                with Horizontal():
                    yield Label("💥 Deauth count:")
                    yield Input(value="10", id="capture-deauth-count", type="integer")
                    yield Label("⏱️ Timeout:")
                    yield Input(value="30", id="capture-timeout", type="integer")
                    yield Label("sec")

                with Horizontal():
                    yield Label("📁 Output directory:")
                    yield Input(value="./captures", id="capture-output-dir")

            with Vertical(id="capture-progress-container"):
                yield Static("", id="capture-status")
                yield ProgressBar(total=100, show_eta=True, id="capture-progress")

            with Horizontal():
                yield Button("📦 Start Capture", id="btn-capture-start", variant="primary")

            yield Log(id="capture-log", auto_scroll=True, highlight=True)

        yield Footer()

    async def on_mount(self) -> None:
        """Show initial status"""
        status = self.query_one("#capture-status", Static)
        status.update(
            "[dim]Ready to capture │ "
            f"Will deauth to force handshake from {len(self.network.clients)} client(s)[/dim]"
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "btn-capture-start":
            await self.action_start_capture()

    async def action_start_capture(self) -> None:
        """Start handshake capture with live feedback"""
        log = self.query_one("#capture-log", Log)
        progress = self.query_one("#capture-progress", ProgressBar)
        status = self.query_one("#capture-status", Static)
        btn = self.query_one("#btn-capture-start", Button)

        btn.disabled = True

        # Get parameters
        deauth_input = self.query_one("#capture-deauth-count", Input)
        try:
            deauth_count = int(deauth_input.value)
        except:
            deauth_count = 10

        timeout_input = self.query_one("#capture-timeout", Input)
        try:
            timeout = int(timeout_input.value)
        except:
            timeout = 30

        output_dir = self.query_one("#capture-output-dir", Input).value

        log.write_line(f"[bold cyan]🚀 Starting handshake capture...[/bold cyan]")
        log.write_line(f"📡 Target: [cyan]{self.network.essid}[/cyan] ({self.network.bssid})")
        log.write_line(f"📋 Channel: [yellow]{self.network.channel}[/yellow]")
        log.write_line(f"💥 Deauth packets: [yellow]{deauth_count}[/yellow]")
        log.write_line(f"⏱️ Timeout: [yellow]{timeout}s[/yellow]")
        log.write_line(f"📁 Output: [dim]{output_dir}[/dim]")
        log.write_line("")

        # Simulate progress
        progress.update(total=timeout, progress=0)
        status.update("[yellow]📡 Scanning for target...[/yellow]")

        # Run capture
        def capture_worker():
            result = self.capture.capture_handshake(
                target=self.network,
                deauth_count=deauth_count,
                capture_duration=timeout,
                verify=True
            )
            return result

        # Start capture
        start_time = time.time()

        # Update progress in parallel
        async def update_progress():
            for i in range(timeout):
                await asyncio.sleep(1)
                progress.update(progress=i + 1)

                elapsed = i + 1
                if elapsed < 5:
                    status.update(f"[yellow]📡 Initializing capture... ({elapsed}s)[/yellow]")
                elif elapsed < 8:
                    status.update(f"[yellow]💥 Sending deauth packets... ({elapsed}s)[/yellow]")
                else:
                    status.update(f"[cyan]📦 Waiting for handshake... ({elapsed}s / {timeout}s)[/cyan]")

        # Run both in parallel
        progress_task = asyncio.create_task(update_progress())

        try:
            result = await asyncio.get_event_loop().run_in_executor(None, capture_worker)

            if result.success:
                log.write_line("")
                log.write_line("[bold green]═══════════════════════════════════════[/bold green]")
                log.write_line("[bold green]        ✓ HANDSHAKE CAPTURED!        [/bold green]")
                log.write_line("[bold green]═══════════════════════════════════════[/bold green]")
                log.write_line(f"✓ Handshakes: [green bold]{result.handshakes_captured}[/green bold]")
                log.write_line(f"✓ Duration: [cyan]{result.duration:.1f}s[/cyan]")
                log.write_line(f"✓ File: [cyan]{result.pcap_file}[/cyan]")
                log.write_line("")
                log.write_line("[bold]📋 Next steps:[/bold]")
                log.write_line(f"  1. Crack: [cyan]davbest-wifi crack {result.pcap_file} wordlist.txt[/cyan]")
                log.write_line(f"  2. Parse: [cyan]davbest-wifi parse {result.pcap_file}[/cyan]")

                status.update(f"[green]✓ SUCCESS! Captured {result.handshakes_captured} handshake(s)[/green]")
            else:
                log.write_line("")
                log.write_line("[bold red]═══════════════════════════════════════[/bold red]")
                log.write_line("[bold red]        ✗ CAPTURE FAILED              [/bold red]")
                log.write_line("[bold red]═══════════════════════════════════════[/bold red]")
                log.write_line(f"[yellow]⚠️ {result.message}[/yellow]")
                log.write_line("")
                log.write_line("[bold]💡 Troubleshooting:[/bold]")
                log.write_line("  • Ensure clients are connected to the network")
                log.write_line("  • Try increasing deauth count")
                log.write_line("  • Try increasing timeout duration")
                log.write_line("  • Move closer to the target")

                status.update(f"[red]✗ Failed: {result.message}[/red]")

        except Exception as e:
            log.write_line(f"[red]✗ Error: {e}[/red]")
            status.update(f"[red]✗ Error occurred[/red]")

        finally:
            progress_task.cancel()
            btn.disabled = False


class WiFiTUI(App):
    """Main polished WiFi TUI"""

    CSS = """
    Screen {
        background: $surface;
    }

    #main-container {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }

    #title-card {
        background: $primary;
        color: $text;
        padding: 2;
        border: heavy $accent;
        margin-bottom: 2;
        text-align: center;
    }

    #info-panel {
        background: $panel;
        border: solid $accent;
        padding: 1 2;
        margin-bottom: 2;
    }

    #main-menu {
        padding: 1;
    }

    .menu-button {
        width: 100%;
        margin: 1 0;
        height: 3;
    }

    .section-divider {
        margin: 1 0;
    }

    .hidden {
        display: none;
    }
    """

    BINDINGS = [
        Binding("1", "scan_networks", "🔍 Scan", show=True),
        Binding("2", "deauth_attack", "💥 Deauth", show=True),
        Binding("3", "capture_handshake", "📦 Capture", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, interface: str, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.selected_network: Optional[WiFiNetwork] = None

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="main-container"):
            yield Static(
                "[bold]🚀 DavBest WiFi Security Suite[/bold]\n"
                "[dim]Hardware-Accelerated WiFi Pentesting[/dim]",
                id="title-card"
            )

            yield Static(
                f"📡 Interface: [cyan bold]{self.interface}[/cyan bold]\n"
                f"🟢 Status: [green]Ready[/green]\n"
                f"🎯 Target: [dim]None selected - Press '1' to scan[/dim]",
                id="info-panel"
            )

            with Vertical(id="main-menu"):
                yield Label("[bold]📋 Main Menu:[/bold]")
                yield Rule(classes="section-divider")

                yield Button("🔍 1. Scan Networks", id="btn-scan", variant="primary", classes="menu-button")
                yield Button("💥 2. Deauth Attack", id="btn-deauth", variant="warning", classes="menu-button")
                yield Button("📦 3. Capture Handshake", id="btn-capture", variant="success", classes="menu-button")

                yield Rule(classes="section-divider")

                yield Button("🚀 4. Crack Password", id="btn-crack", classes="menu-button")
                yield Button("📝 5. Generate Wordlist", id="btn-generate", classes="menu-button")

                yield Rule(classes="section-divider")

                yield Button("❌ Q. Quit", id="btn-quit", variant="error", classes="menu-button")

        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "btn-scan":
            await self.action_scan_networks()
        elif event.button.id == "btn-deauth":
            await self.action_deauth_attack()
        elif event.button.id == "btn-capture":
            await self.action_capture_handshake()
        elif event.button.id == "btn-quit":
            self.exit()

    async def action_scan_networks(self) -> None:
        """Launch network scanner"""
        self.push_screen(ScanScreen(self.interface))

    async def action_deauth_attack(self) -> None:
        """Launch deauth attack"""
        if self.selected_network:
            self.push_screen(DeauthScreen(self.interface, self.selected_network))
        else:
            # Need to scan first
            await self.action_scan_networks()

    async def action_capture_handshake(self) -> None:
        """Launch capture"""
        if self.selected_network:
            self.push_screen(CaptureScreen(self.interface, self.selected_network))
        else:
            await self.action_scan_networks()

    def on_screen_resume(self) -> None:
        """Update info panel when returning"""
        info = self.query_one("#info-panel", Static)

        if self.selected_network:
            net = self.selected_network
            info.update(
                f"📡 Interface: [cyan bold]{self.interface}[/cyan bold]\n"
                f"🟢 Status: [green]Ready[/green]\n"
                f"🎯 Target: [cyan bold]{net.essid}[/cyan bold] │ "
                f"Ch {net.channel} │ {net.power} dBm │ {len(net.clients)} clients"
            )
        else:
            info.update(
                f"📡 Interface: [cyan bold]{self.interface}[/cyan bold]\n"
                f"🟢 Status: [green]Ready[/green]\n"
                f"🎯 Target: [dim]None selected - Press '1' to scan[/dim]"
            )


def main():
    """Run polished TUI"""
    import sys

    if len(sys.argv) > 2 and sys.argv[1] == '--interface':
        interface = sys.argv[2]
    else:
        interface = "wlan0mon"

    app = WiFiTUI(interface)
    app.run()


if __name__ == '__main__':
    main()
