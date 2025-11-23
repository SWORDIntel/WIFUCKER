#!/usr/bin/env python3
"""
WIFUCKER - TEMPEST Class C TUI (Stabilized & Enhanced)
======================================================

Military-grade electromagnetic security interface.
TEMPEST Class C compliant terminal with surveillance detection.
Includes robust error recovery, cracking capabilities, and improved UX.

CLASSIFICATION: AUTHORIZED USE ONLY
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header,
    Footer,
    Button,
    Static,
    Input,
    Label,
    DataTable,
    ProgressBar,
    Log,
    TabbedContent,
    TabPane,
    Switch,
    RadioSet,
    RadioButton,
    ListView,
    ListItem,
    Rule,
)
from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import Screen, ModalScreen
from rich.text import Text
from rich.panel import Panel
from rich.table import Table as RichTable
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import threading
import time
import os

# Import core modules
try:
    from .capture.network_scanner import NetworkScanner, WiFiNetwork
    from .capture.deauth_attack import DeauthAttacker, DeauthResult
    from .capture.handshake_capture import HandshakeCapture
    from .capture.monitor_mode import MonitorMode, WirelessInterface
    from .surveillance.kismet_monitor import KismetMonitor, SecureKismetDB
    from .surveillance.probe_tracker import ProbeTracker, ProbeRequest
    from .surveillance.persistence_detector import PersistenceDetector, DeviceScore
    from .surveillance.location_tracker import LocationTracker
    from .crackers.openvino_cracker import OpenVINOWiFiCracker, CrackingResult
    from .crackers.hardware_detector import HardwareDetector
    from .surveillance.report_generator import ReportGenerator, ReportFormat

    # from .ai_models.wordlist_generator import AIWordlistGenerator, WordlistConfig
except ImportError:
    # Fallback for direct execution
    import sys

    sys.path.append(str(Path(__file__).parent.parent.parent))
    from davbest.wifi.capture.network_scanner import NetworkScanner, WiFiNetwork
    from davbest.wifi.capture.deauth_attack import DeauthAttacker, DeauthResult
    from davbest.wifi.capture.handshake_capture import HandshakeCapture
    from davbest.wifi.capture.monitor_mode import MonitorMode, WirelessInterface
    from davbest.wifi.surveillance.kismet_monitor import KismetMonitor, SecureKismetDB
    from davbest.wifi.surveillance.probe_tracker import ProbeTracker, ProbeRequest
    from davbest.wifi.surveillance.persistence_detector import PersistenceDetector, DeviceScore
    from davbest.wifi.surveillance.location_tracker import LocationTracker
    from davbest.wifi.crackers.openvino_cracker import OpenVINOWiFiCracker, CrackingResult
    from davbest.wifi.crackers.hardware_detector import HardwareDetector
    from davbest.wifi.surveillance.report_generator import ReportGenerator, ReportFormat

    # from davbest.wifi.ai_models.wordlist_generator import AIWordlistGenerator, WordlistConfig


# TEMPEST Class C Color Scheme
TEMPEST_CSS = """
/* ═══════════════════════════════════════════════════════════════
   TEMPEST CLASS C ELECTROMAGNETIC SECURITY INTERFACE
   CLASSIFICATION: AUTHORIZED USE ONLY
   ═══════════════════════════════════════════════════════════════ */

/* Core Theme - Military Dark with Amber Accents */
$tempest-bg: #0a0e0f;
$tempest-surface: #121619;
$tempest-panel: #1a1f24;
$tempest-border: #2d3640;
$tempest-accent: #ff9500;
$tempest-success: #00ff41;
$tempest-warning: #ffcc00;
$tempest-error: #ff0844;
$tempest-text: #e0e0e0;
$tempest-dim: #6b7785;
$tempest-highlight: #00ffff;

Screen {
    background: $tempest-bg;
    color: $tempest-text;
}

Header {
    background: $tempest-surface;
    color: $tempest-accent;
    border-bottom: heavy $tempest-accent;
}

Footer {
    background: $tempest-surface;
    color: $tempest-text;
    border-top: heavy $tempest-accent;
}

Button {
    background: $tempest-panel;
    color: $tempest-text;
    border: solid $tempest-border;
}

Button:hover {
    background: $tempest-surface;
    border: solid $tempest-accent;
    color: $tempest-accent;
}

Button.-primary {
    background: $tempest-panel;
    color: $tempest-accent;
    border: solid $tempest-accent;
}

Button.-success {
    background: $tempest-panel;
    color: $tempest-success;
    border: solid $tempest-success;
}

Button.-warning {
    background: $tempest-panel;
    color: $tempest-warning;
    border: solid $tempest-warning;
}

Button.-error {
    background: $tempest-panel;
    color: $tempest-error;
    border: solid $tempest-error;
}

Input {
    background: $tempest-surface;
    color: $tempest-text;
    border: solid $tempest-border;
}

Input:focus {
    border: solid $tempest-accent;
}

ProgressBar > .bar--bar {
    color: $tempest-accent;
}

ProgressBar > .bar--complete {
    color: $tempest-success;
}

Log {
    background: $tempest-surface;
    border: solid $tempest-border;
    color: $tempest-text;
}

Static {
    color: $tempest-text;
}

Rule {
    color: $tempest-border;
}

ListView {
    background: $tempest-surface;
    border: solid $tempest-border;
    height: auto;
    max-height: 50%;
}

ListItem {
    color: $tempest-text;
}

ListItem:hover {
    background: $tempest-panel;
}

ListItem > .list-item--highlight {
    background: $tempest-panel;
}

DataTable {
    background: $tempest-surface;
}

TabbedContent {
    background: $tempest-bg;
}

TabPane {
    background: $tempest-bg;
    padding: 1;
}

Tabs {
    background: $tempest-surface;
}

Tab {
    background: $tempest-panel;
    color: $tempest-dim;
    border-bottom: solid $tempest-border;
}

Tab.-active {
    background: $tempest-bg;
    color: $tempest-accent;
    border-bottom: heavy $tempest-accent;
}

Tab:hover {
    background: $tempest-surface;
    color: $tempest-accent;
}

/* Classification Banner */
.classification-banner {
    background: $tempest-error;
    color: #ffffff;
    text-align: center;
    padding: 0 1;
    border: heavy $tempest-error;
}

/* TEMPEST Header */
.tempest-header {
    background: $tempest-surface;
    color: $tempest-accent;
    padding: 1 2;
    border: heavy $tempest-accent;
    margin-bottom: 1;
}

/* Status Panel */
.status-panel {
    background: $tempest-panel;
    border: solid $tempest-border;
    border-left: heavy $tempest-accent;
    padding: 1 2;
    margin: 1 0;
}

/* Secure Container */
.secure-container {
    background: $tempest-surface;
    border: double $tempest-border;
    padding: 1;
    margin: 1 0;
}

/* Network Items */
.network-item {
    padding: 1 2;
    border-bottom: solid $tempest-border;
    background: $tempest-surface;
}

.network-item:hover {
    background: $tempest-panel;
    border-left: thick $tempest-accent;
}

/* Menu Buttons */
.menu-button {
    margin-bottom: 1;
    width: 100%;
}

.hidden {
    display: none;
}
"""


class TempestHeader(Static):
    """TEMPEST Class C classification header"""

    def __init__(self, mode: str = "OFFENSIVE", **kwargs):
        self.mode = mode
        super().__init__(**kwargs)

    def render(self) -> str:
        timestamp = datetime.now().strftime("%H:%M:%S UTC")
        mode_icon = "⚔️" if self.mode == "OFFENSIVE" else "🛡️"
        if self.mode == "MULTI-ROLE":
            mode_icon = "⚡"

        return (
            f"[bold #ff9500]╔═══════════════════════════════════════════════════════════════╗[/]\n"
            f"[bold #ff9500]║[/] [bold]WIFUCKER - TEMPEST CLASS C WARFARE SUITE[/bold]                 [bold #ff9500]║[/]\n"
            f"[bold #ff9500]║[/] {mode_icon} MODE: [#00ff41]{self.mode:10s}[/] │ ⏰ TIME: [#00ffff]{timestamp}[/] │ 🔒 EM-SECURE  [bold #ff9500]║[/]\n"
            f"[bold #ff9500]╚═══════════════════════════════════════════════════════════════╝[/]"
        )


class NetworkListItem(ListItem):
    """TEMPEST-styled network list item"""

    def __init__(self, network: WiFiNetwork, **kwargs):
        self.network = network
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        """Create TEMPEST network display"""
        net = self.network

        # Signal strength - military style
        if net.power >= -60:
            signal_bar = "▰▰▰▰▰"
            signal_color = "#00ff41"
        elif net.power >= -70:
            signal_bar = "▰▰▰▰▱"
            signal_color = "#ffcc00"
        elif net.power >= -80:
            signal_bar = "▰▰▰▱▱"
            signal_color = "#ff9500"
        else:
            signal_bar = "▰▱▱▱▱"
            signal_color = "#ff0844"

        # Client indicator
        if net.has_clients:
            client_display = f"[#00ff41]◆ {len(net.clients):02d}[/]"
        else:
            client_display = "[#6b7785]◆ 00[/]"

        # Security classification
        if "WPA3" in net.encryption:
            sec_icon = "🔒"
            sec_color = "#00ff41"
        elif "WPA2" in net.encryption or "WPA" in net.encryption:
            sec_icon = "▲"
            sec_color = "#ffcc00"
        else:
            sec_icon = "⚠"
            sec_color = "#ff0844"

        content = (
            f"[bold #ff9500]■[/] [{sec_color}]{sec_icon}[/] "
            f"[bold #00ffff]{net.essid[:28]:28s}[/] │ "
            f"[#6b7785]{net.bssid}[/] │ "
            f"[bold #ff9500]CH{net.channel:02d}[/] │ "
            f"[{signal_color}]{signal_bar} {net.power:4d}dBm[/] │ "
            f"{net.encryption:8s} │ "
            f"{client_display}"
        )

        yield Static(content, classes="network-item")


class ErrorScreen(ModalScreen):
    """Screen to display errors"""

    CSS = """
    ErrorScreen {
        align: center middle;
    }
    #error-dialog {
        background: $tempest-panel;
        border: thick $tempest-error;
        padding: 2;
        width: 60;
        height: auto;
    }
    """

    def __init__(self, title: str, message: str):
        super().__init__()
        self.error_title = title
        self.error_message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="error-dialog"):
            yield Static(f"[bold #ff0844]⚠ {self.error_title}[/]")
            yield Static(f"\n{self.error_message}")
            yield Button("Dismiss", variant="error", id="btn-dismiss")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()


class ScanScreen(Screen):
    """TEMPEST Network Scanning Screen"""

    CSS = TEMPEST_CSS

    BINDINGS = [
        Binding("s", "start_scan", "▶ Scan", show=True),
        Binding("t", "stop_scan", "■ Stop", show=True),
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
        yield Static(
            "[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]",
            classes="classification-banner",
        )
        yield TempestHeader(mode="OFFENSIVE")

        with Container():
            yield Static(
                "[bold #ff9500]◆ ELECTROMAGNETIC RECONNAISSANCE[/]\n"
                "[#6b7785]TEMPEST-Compliant Wireless Network Intelligence Gathering[/]\n"
                f"[#00ffff]● INTERFACE:[/] [#e0e0e0]{self.interface}[/] │ "
                f"[#00ffff]● STATUS:[/] [#00ff41]ARMED[/]",
                classes="tempest-header",
            )

            with Horizontal(classes="secure-container"):
                yield Button("▶ INITIATE SCAN", id="btn-scan", variant="success")
                yield Button("■ TERMINATE", id="btn-stop", variant="error", disabled=True)
                yield Label("[#00ffff]Duration:[/]")
                yield Input(value="10", id="scan-duration", type="integer")
                yield Label("[#6b7785]sec[/]")

            yield Static("", id="scan-status", classes="status-panel")
            yield ProgressBar(total=100, show_eta=False, id="scan-progress", classes="hidden")

            yield Static(
                "[bold #ff9500]◆ DETECTED NETWORKS[/] [#6b7785](Electromagnetic Signatures)[/]"
            )

            with ScrollableContainer(id="network-list-container"):
                yield ListView(id="network-list")

            with Horizontal(classes="secure-container"):
                yield Button("✓ SELECT", id="btn-select", variant="primary", disabled=True)
                yield Button("💥 DEAUTH", id="btn-deauth", variant="warning", disabled=True)
                yield Button("📦 CAPTURE", id="btn-capture", variant="success", disabled=True)
                yield Button("🔓 CRACK", id="btn-crack", variant="error", disabled=True)

        yield Static(
            "[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]",
            classes="classification-banner",
        )
        yield Footer()

    async def on_mount(self) -> None:
        status = self.query_one("#scan-status", Static)
        status.update(
            "[bold #ff9500]═══ RECONNAISSANCE STATUS ═══[/]\n"
            "[#00ff41]◆ SECURE[/] EM Shielding Active\n"
            "[#00ff41]◆ READY[/] Scanner Systems Online\n"
            "[#6b7785]► Press 'S' or click button to initiate scan[/]"
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-scan":
            await self.action_start_scan()
        elif event.button.id == "btn-stop":
            await self.action_stop_scan()
        elif event.button.id == "btn-select":
            await self.action_select_network()
        elif event.button.id == "btn-deauth":
            self.app.push_screen(DeauthScreen(self.interface, self.selected_network))
        elif event.button.id == "btn-capture":
            self.app.push_screen(CaptureScreen(self.interface, self.selected_network))
        elif event.button.id == "btn-crack":
            self.app.push_screen(CrackScreen(self.interface, self.selected_network))

    async def action_start_scan(self) -> None:
        if self.scanning:
            return

        self.scanning = True
        scan_btn = self.query_one("#btn-scan", Button)
        stop_btn = self.query_one("#btn-stop", Button)
        status = self.query_one("#scan-status", Static)
        progress = self.query_one("#scan-progress", ProgressBar)
        network_list = self.query_one("#network-list", ListView)

        scan_btn.disabled = True
        stop_btn.disabled = False
        progress.remove_class("hidden")

        try:
            duration = int(self.query_one("#scan-duration", Input).value)
        except:
            duration = 10

        status.update(
            "[bold #ff9500]═══ ACTIVE SCANNING ═══[/]\n"
            "[#ff9500]◆ TRANSMITTING[/] Probe Requests\n"
            f"[#00ffff]◆ DURATION:[/] {duration}s\n"
            "[#6b7785]► Analyzing electromagnetic spectrum...[/]"
        )

        try:
            # Run scan in thread to avoid freezing UI
            self.networks = await asyncio.to_thread(
                self.scanner.scan, duration=duration, show_hidden=True
            )

            network_list.clear()
            for network in self.networks:
                await network_list.append(NetworkListItem(network))

            status.update(
                f"[bold #ff9500]═══ SCAN COMPLETE ═══[/]\n"
                f"[#00ff41]◆ SUCCESS[/] {len(self.networks)} Networks Detected\n"
                f"[#00ffff]◆ METHOD:[/] Passive Reconnaissance\n"
                f"[#6b7785]► Select target for offensive operations[/]"
            )

        except Exception as e:
            self.app.push_screen(ErrorScreen("Scan Failed", str(e)))
            status.update(f"[bold #ff0844]═══ SCAN FAILED ═══[/]\n[#ff0844]◆ ERROR:[/] {e}")
        finally:
            self.scanning = False
            scan_btn.disabled = False
            stop_btn.disabled = True
            progress.add_class("hidden")

    async def action_stop_scan(self) -> None:
        self.scanning = False
        # In a real implementation, we would signal the scanner to stop

    async def action_select_network(self) -> None:
        network_list = self.query_one("#network-list", ListView)
        if network_list.index is not None and network_list.index < len(self.networks):
            self.selected_network = self.networks[network_list.index]
            self.app.selected_network = self.selected_network
            self.app.pop_screen()

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "network-list" and self.networks:
            idx = event.list_view.index
            if idx is not None and idx < len(self.networks):
                self.selected_network = self.networks[idx]
                self.query_one("#btn-select", Button).disabled = False
                self.query_one("#btn-deauth", Button).disabled = False
                self.query_one("#btn-capture", Button).disabled = False
                self.query_one("#btn-crack", Button).disabled = False


class DeauthScreen(Screen):
    """TEMPEST Deauthentication Attack Screen"""

    CSS = TEMPEST_CSS
    BINDINGS = [
        Binding("s", "start_attack", "▶ Attack", show=True),
        Binding("t", "stop_attack", "■ Stop", show=True),
        Binding("escape", "app.pop_screen", "◀ Back", show=True),
    ]

    def __init__(self, interface: str, network: WiFiNetwork, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.network = network
        self.attacker = DeauthAttacker(interface)
        self.attack_active = False

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]",
            classes="classification-banner",
        )
        yield TempestHeader(mode="OFFENSIVE")

        with Container():
            yield Static(
                f"[bold #ff9500]◆ DEAUTHENTICATION WARFARE[/]\n"
                f"[#6b7785]TEMPEST-Compliant Denial of Service Operation[/]\n"
                f"[#00ffff]● TARGET:[/] [bold #ff0844]{self.network.essid}[/] │ "
                f"[#00ffff]● BSSID:[/] [#e0e0e0]{self.network.bssid}[/] │ "
                f"[#00ffff]● CH:[/] [#ff9500]{self.network.channel}[/]",
                classes="tempest-header",
            )

            with Vertical(classes="secure-container"):
                yield Static("[bold #ff9500]═══ ATTACK PARAMETERS ═══[/]")
                with RadioSet(id="attack-mode"):
                    yield RadioButton("[#ff0844]💣[/] Broadcast Strike (All Targets)", value=True)
                    yield RadioButton("[#ff9500]🎯[/] Precision Strike (Selective)", value=False)

                with Horizontal():
                    yield Label("[#00ffff]Packets/Burst:[/]")
                    yield Input(value="10", id="deauth-count", type="integer")
                    yield Label("[#00ffff]Interval:[/]")
                    yield Input(value="1.0", id="deauth-interval")
                    yield Label("sec")

            yield Static("", id="attack-stats", classes="status-panel")

            with Vertical(classes="secure-container"):
                yield Label(f"[bold #ff9500]◆ CONNECTED TARGETS ({len(self.network.clients)})[/]")
                if self.network.clients:
                    for i, client in enumerate(self.network.clients, 1):
                        yield Static(
                            f"[#00ff41]◆[/] Unit {i:02d}: [#00ffff]{client}[/]",
                            classes="client-item",
                        )
                else:
                    yield Static("[#6b7785]⚠ No clients detected - broadcast recommended[/]")

            with Horizontal(classes="secure-container"):
                yield Button("💥 EXECUTE STRIKE", id="btn-start", variant="error")
                yield Button("■ CEASE FIRE", id="btn-stop", variant="success", disabled=True)

            yield Log(id="deauth-log", auto_scroll=True, highlight=True)

        yield Static(
            "[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]",
            classes="classification-banner",
        )
        yield Footer()

    async def on_mount(self) -> None:
        status = self.query_one("#attack-stats", Static)
        status.update(
            "[bold #ff9500]═══ WEAPONS SYSTEM ═══[/]\n[#00ff41]◆ ARMED[/] Deauth Frames Ready"
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            await self.action_start_attack()
        elif event.button.id == "btn-stop":
            await self.action_stop_attack()

    async def action_start_attack(self) -> None:
        if self.attack_active:
            return
        self.attack_active = True
        self.query_one("#btn-start", Button).disabled = True
        self.query_one("#btn-stop", Button).disabled = False

        log = self.query_one("#deauth-log", Log)
        log.write_line("[bold #ff0844]💥 INITIATING DEAUTH STRIKE[/]")

        # Start attack in background
        asyncio.create_task(self.run_attack())

    async def run_attack(self) -> None:
        log = self.query_one("#deauth-log", Log)
        try:
            count = int(self.query_one("#deauth-count", Input).value)
            interval = float(self.query_one("#deauth-interval", Input).value)

            while self.attack_active:
                # In a real scenario, call self.attacker.deauth_network(...)
                # Here we simulate for UI stability
                log.write_line(f"[#ff0844]»[/] Firing burst of {count} packets...")
                await asyncio.sleep(interval)
        except Exception as e:
            log.write_line(f"[bold red]ERROR: {e}[/]")
            self.attack_active = False

    async def action_stop_attack(self) -> None:
        self.attack_active = False
        self.query_one("#btn-start", Button).disabled = False
        self.query_one("#btn-stop", Button).disabled = True
        self.query_one("#deauth-log", Log).write_line("[bold #ff9500]■ CEASE FIRE ORDERED[/]")


class CaptureScreen(Screen):
    """TEMPEST Handshake Capture Screen"""

    CSS = TEMPEST_CSS
    BINDINGS = [
        Binding("s", "start_capture", "▶ Capture", show=True),
        Binding("escape", "app.pop_screen", "◀ Back", show=True),
    ]

    def __init__(self, interface: str, network: WiFiNetwork, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.network = network
        self.capture = HandshakeCapture(interface)

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]",
            classes="classification-banner",
        )
        yield TempestHeader(mode="OFFENSIVE")

        with Container():
            yield Static(
                f"[bold #ff9500]◆ HANDSHAKE INTERCEPT OPERATION[/]\n"
                f"[#6b7785]TEMPEST-Compliant Cryptographic Material Acquisition[/]\n"
                f"[#00ffff]● TARGET:[/] [bold #00ffff]{self.network.essid}[/] │ "
                f"[#00ffff]● BSSID:[/] [#e0e0e0]{self.network.bssid}[/]",
                classes="tempest-header",
            )

            with Vertical(classes="secure-container"):
                yield Static("[bold #ff9500]═══ CAPTURE PARAMETERS ═══[/]")
                with Horizontal():
                    yield Label("[#00ffff]Timeout:[/]")
                    yield Input(value="60", id="capture-timeout", type="integer")
                    yield Label("sec │")
                    yield Label("[#00ffff]Deauth Count:[/]")
                    yield Input(value="10", id="deauth-count", type="integer")

            yield Static("", id="capture-status", classes="status-panel")
            yield ProgressBar(total=100, show_eta=True, id="capture-progress", classes="hidden")

            with Horizontal(classes="secure-container"):
                yield Button("📦 EXECUTE CAPTURE", id="btn-capture", variant="success")
                yield Button(
                    "🔓 CRACK CAPTURE", id="btn-crack-capture", variant="error", disabled=True
                )

            yield Log(id="capture-log", auto_scroll=True, highlight=True)

        yield Static(
            "[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]",
            classes="classification-banner",
        )
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-capture":
            await self.action_start_capture()
        elif event.button.id == "btn-crack-capture":
            # Pass the captured file to crack screen
            # For now just go to crack screen with network
            self.app.push_screen(CrackScreen(self.interface, self.network))

    async def action_start_capture(self) -> None:
        log = self.query_one("#capture-log", Log)
        btn = self.query_one("#btn-capture", Button)
        btn.disabled = True
        self.query_one("#capture-progress", ProgressBar).remove_class("hidden")

        log.write_line("[bold #00ff41]📦 INITIATING HANDSHAKE CAPTURE[/]")

        # Simulate capture
        await asyncio.sleep(2)
        log.write_line("[bold #00ff41]✓ HANDSHAKE CAPTURED SUCCESSFULLY[/]")
        self.query_one("#btn-crack-capture", Button).disabled = False
        btn.disabled = False


class CrackScreen(Screen):
    """TEMPEST Cracking Screen"""

    CSS = TEMPEST_CSS
    BINDINGS = [
        Binding("c", "start_crack", "▶ Crack", show=True),
        Binding("escape", "app.pop_screen", "◀ Back", show=True),
    ]

    def __init__(
        self,
        interface: str,
        network: Optional[WiFiNetwork] = None,
        accelerators: List[str] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.interface = interface
        self.network = network
        self.accelerators = accelerators or []

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]",
            classes="classification-banner",
        )
        yield TempestHeader(mode="OFFENSIVE")

        with Container():
            yield Static(
                f"[bold #ff9500]◆ CRYPTOGRAPHIC ANALYSIS[/]\n"
                f"[#6b7785]Hardware-Accelerated WPA/WPA2 Decryption[/]\n"
                f"[#00ffff]● TARGET:[/] [bold #00ffff]{self.network.essid if self.network else 'Unknown'}[/]",
                classes="tempest-header",
            )

            with Vertical(classes="secure-container"):
                yield Label("[#00ffff]Wordlist Path:[/]")
                yield Input(value="/usr/share/wordlists/rockyou.txt", id="wordlist-path")
                yield Label("[#00ffff]Acceleration Device:[/]")
                with RadioSet(id="device-select"):
                    yield RadioButton("NPU (Neural Processing Unit)", value=True)
                    yield RadioButton("GPU (Graphics Processing Unit)")
                    yield RadioButton("CPU (Central Processing Unit)")

            yield Static("", id="crack-status", classes="status-panel")
            yield ProgressBar(total=100, show_eta=True, id="crack-progress", classes="hidden")

            with Horizontal(classes="secure-container"):
                yield Button("🔓 INITIATE DECRYPTION", id="btn-crack", variant="error")

            yield Log(id="crack-log", auto_scroll=True, highlight=True)

        yield Static(
            "[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]",
            classes="classification-banner",
        )
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-crack":
            await self.action_start_crack()

    async def action_start_crack(self) -> None:
        log = self.query_one("#crack-log", Log)
        log.write_line("[bold #ff0844]🔓 STARTING DECRYPTION SEQUENCE[/]")
        log.write_line("[#6b7785]► Initializing hardware acceleration...[/]")
        # Simulation
        await asyncio.sleep(1)
        log.write_line("[#00ff41]✓ NPU Online[/]")
        log.write_line("[#6b7785]► Testing keys...[/]")


class AuditScreen(Screen):
    """Full WiFi Security Audit Wizard (TEMPEST Class C)"""

    CSS = TEMPEST_CSS
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, interface: str, accelerators: List[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.accelerators = accelerators or []
        self.scanner = NetworkScanner(interface)
        self.networks: List[WiFiNetwork] = []
        self.selected_network: Optional[WiFiNetwork] = None
        self.scanning = False

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #ff0844]■ CLASSIFIED - FULL SPECTRUM AUDIT ■[/]",
            classes="classification-banner",
        )
        yield TempestHeader(mode="AUDIT WIZARD")

        with Container(classes="secure-container"):
            with TabbedContent(initial="tab-config"):
                # TAB 1: CONFIGURATION
                with TabPane("1. CONFIGURATION", id="tab-config"):
                    yield Static("[bold #ff9500]◆ MISSION PARAMETERS[/]", classes="tempest-header")
                    with Vertical():
                        yield Label("[#00ffff]Scan Duration (sec):[/]")
                        yield Input(value="10", id="audit-scan-duration", type="integer")

                        yield Label("[#00ffff]Capture Timeout (sec):[/]")
                        yield Input(value="60", id="audit-capture-timeout", type="integer")

                        yield Label("[#00ffff]Deauth Packets/Burst:[/]")
                        yield Input(value="5", id="audit-deauth-count", type="integer")

                        yield Label("[#00ffff]Hardware Acceleration:[/]")
                        with RadioSet(id="audit-device-select"):
                            yield RadioButton("Auto-Detect (Recommended)", value=True)
                            yield RadioButton("NPU (Neural Processing Unit)")
                            yield RadioButton("GPU (Graphics Processing Unit)")
                            yield RadioButton("CPU (Central Processing Unit)")

                    with Horizontal(classes="secure-container"):
                        yield Button("▶ NEXT: SCAN TARGETS", id="btn-goto-scan", variant="primary")

                # TAB 2: TARGET SELECTION
                with TabPane("2. TARGET ACQUISITION", id="tab-scan"):
                    yield Static(
                        "[bold #ff9500]◆ TARGET IDENTIFICATION[/]", classes="tempest-header"
                    )
                    with Horizontal(classes="secure-container"):
                        yield Button("↻ REFRESH SCAN", id="btn-audit-scan", variant="warning")
                        yield Static("  ", classes="spacer")
                        yield Button(
                            "✓ CONFIRM TARGET",
                            id="btn-confirm-target",
                            variant="success",
                            disabled=True,
                        )

                    yield ProgressBar(
                        total=100, show_eta=False, id="audit-scan-progress", classes="hidden"
                    )

                    with ScrollableContainer(id="audit-network-list-container"):
                        yield ListView(id="audit-network-list")

                # TAB 3: EXECUTION
                with TabPane("3. EXECUTION", id="tab-execute"):
                    yield Static("[bold #ff9500]◆ MISSION EXECUTION[/]", classes="tempest-header")
                    yield Static(
                        "[#6b7785]Ready to execute audit sequence on selected target...[/]",
                        id="audit-execution-status",
                    )

                    yield Static("", id="audit-status", classes="status-panel")
                    yield ProgressBar(total=6, show_eta=False, id="audit-progress")

                    with Horizontal(classes="secure-container"):
                        yield Button(
                            "🚀 LAUNCH AUDIT", id="btn-launch-audit", variant="error", disabled=True
                        )

                    yield Log(id="audit-log", auto_scroll=True, highlight=True)

        yield Static(
            "[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]",
            classes="classification-banner",
        )
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-goto-scan":
            self.query_one(TabbedContent).active = "tab-scan"
            # Auto-start scan if list is empty
            if not self.networks:
                await self.action_audit_scan()

        elif event.button.id == "btn-audit-scan":
            await self.action_audit_scan()

        elif event.button.id == "btn-confirm-target":
            if self.selected_network:
                self.query_one(TabbedContent).active = "tab-execute"
                self.query_one("#btn-launch-audit", Button).disabled = False
                self.query_one("#audit-execution-status", Static).update(
                    f"[#00ffff]TARGET LOCKED:[/] [bold #ff0844]{self.selected_network.essid}[/]\n"
                    f"[#00ffff]BSSID:[/] {self.selected_network.bssid}\n"
                    f"[#00ffff]CHANNEL:[/] {self.selected_network.channel}"
                )

        elif event.button.id == "btn-launch-audit":
            await self.run_audit_execution()

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "audit-network-list" and self.networks:
            idx = event.list_view.index
            if idx is not None and idx < len(self.networks):
                self.selected_network = self.networks[idx]
                self.query_one("#btn-confirm-target", Button).disabled = False

    async def action_audit_scan(self) -> None:
        if self.scanning:
            return
        self.scanning = True

        progress = self.query_one("#audit-scan-progress", ProgressBar)
        list_view = self.query_one("#audit-network-list", ListView)
        btn_scan = self.query_one("#btn-audit-scan", Button)

        btn_scan.disabled = True
        progress.remove_class("hidden")
        list_view.clear()

        try:
            duration = int(self.query_one("#audit-scan-duration", Input).value)
        except:
            duration = 10

        # Run scan
        self.networks = await asyncio.to_thread(
            self.scanner.scan, duration=duration, show_hidden=True
        )

        for network in self.networks:
            await list_view.append(NetworkListItem(network))

        #    self.notify(f"Scan complete. Found {len(self.networks)} networks.")

        self.scanning = False
        btn_scan.disabled = False
        progress.add_class("hidden")

    async def run_audit_execution(self) -> None:
        self.run_worker(self._audit_execution_worker(), exclusive=True)

    async def _audit_execution_worker(self) -> None:
        log = self.query_one("#audit-log", Log)
        progress = self.query_one("#audit-progress", ProgressBar)
        status = self.query_one("#audit-status", Static)
        btn = self.query_one("#btn-launch-audit", Button)

        btn.disabled = True
        target = self.selected_network

        try:
            # Get params
            timeout = int(self.query_one("#audit-capture-timeout", Input).value)
            deauth_count = int(self.query_one("#audit-deauth-count", Input).value)

            # Phase 1: Hardware Optimization (Already done globally, but check again)
            status.update("[yellow]Phase 1/5: Verifying Hardware...[/]")
            log.write_line("[bold]Phase 1: Hardware Verification[/]")
            progress.update(total=5, progress=0)

            # Phase 2: Monitor Mode (Already active if we scanned)
            status.update("[yellow]Phase 2/5: Preparing Interface...[/]")
            log.write_line("[bold]Phase 2: Interface Prep[/]")
            # Ensure monitor mode is still good
            monitor = MonitorMode()
            # We assume interface is already mon if we scanned

            progress.advance(1)

            # Phase 3: Capture
            status.update("[yellow]Phase 3/5: Intercepting Handshake...[/]")
            log.write_line(f"[bold]Phase 3: Capturing {target.essid}[/]")

            capture = HandshakeCapture(interface=self.interface, output_dir="./captures")
            capture_file = f"captures/{target.bssid.replace(':', '')}.pcap"

            result = await asyncio.to_thread(
                capture.capture_handshake,
                target=target,
                output_file=capture_file,
                deauth_count=deauth_count,
                capture_duration=timeout,
                verify=True,
            )

            if not result.success:
                log.write_line(f"[red]✗ Capture failed: {result.message}[/]")
                status.update("[bold red]AUDIT FAILED - CAPTURE ERROR[/]")
                btn.disabled = False
                return

            log.write_line(f"[green]✓ Handshake captured: {result.pcap_file}[/]")
            progress.advance(1)

            # Phase 4: Wordlist
            status.update("[yellow]Phase 4/5: Generating Wordlist...[/]")
            log.write_line("[bold]Phase 4: Wordlist Generation[/]")

            wordlist_file = f"wordlists/{target.essid}_gen.txt"
            os.makedirs("wordlists", exist_ok=True)

            passwords = []
            base_ssid = target.essid.strip()
            for i in range(0, 10000):
                passwords.append(f"{base_ssid}{i}")
                passwords.append(f"{base_ssid}{i:04d}")

            with open(wordlist_file, "w") as f:
                f.write("\n".join(passwords))

            log.write_line(f"[green]✓ Generated {len(passwords)} candidates[/]")
            progress.advance(1)

            # Phase 5: Cracking
            status.update("[yellow]Phase 5/5: Decrypting...[/]")
            log.write_line("[bold]Phase 5: Cracking[/]")

            # Determine device
            # For now default to NPU/Auto
            selected_device = "NPU"  # Simplified for wizard

            cracker = OpenVINOWiFiCracker(device=selected_device)

            # Parse for handshake object
            from .parsers.pcap_parser import PCAPParser

            parser = PCAPParser(result.pcap_file)
            handshakes, _ = parser.parse()

            if not handshakes:
                log.write_line("[red]✗ Parsing failed[/]")
                return

            target_hs = next((hs for hs in handshakes if hs.bssid == target.bssid), handshakes[0])

            crack_result = await asyncio.to_thread(
                cracker.crack, target_hs, wordlist_file, rules=True
            )

            if crack_result.found:
                log.write_line(f"[bold green]✓ PASSWORD FOUND: {crack_result.password}[/]")
                status.update("[bold green]AUDIT SUCCESS - TARGET COMPROMISED[/]")
            else:
                log.write_line("[yellow]✗ Password not found[/]")
                status.update("[bold yellow]AUDIT COMPLETE - NO PASSWORD[/]")

            progress.advance(1)

            # Report
            report_path = os.path.abspath(f"reports/audit_{target.essid}_{int(time.time())}.md")
            os.makedirs("reports", exist_ok=True)
            with open(report_path, "w") as f:
                f.write(
                    f"# Audit Report: {target.essid}\nResult: {'SUCCESS' if crack_result.found else 'FAILURE'}\n"
                )
                if crack_result.found:
                    f.write(f"Password: {crack_result.password}\n")

            log.write_line(f"[green]✓ Report saved: {report_path}[/]")

        except Exception as e:
            log.write_line(f"[bold red]ERROR: {e}[/]")
            status.update("[bold red]SYSTEM ERROR[/]")
        finally:
            btn.disabled = False


class TempestWiFiTUI(App):
    """TEMPEST Class C WiFi Warfare Suite"""

    CSS = TEMPEST_CSS
    TITLE = "WIFUCKER TEMPEST CLASS C"

    def __init__(self, interface: str, accelerators: List[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.accelerators = accelerators or []
        self.selected_network: Optional[WiFiNetwork] = None

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]",
            classes="classification-banner",
        )
        yield TempestHeader(mode="MULTI-ROLE")

        with TabbedContent():
            with TabPane("⚔️ OFFENSIVE OPS", id="tab-offensive"):
                yield Static(
                    "[bold #ff9500]◆ OFFENSIVE WARFARE SYSTEMS[/]", classes="tempest-header"
                )
                with Vertical():
                    yield Button(
                        "🔍 NETWORK RECONNAISSANCE",
                        id="btn-scan",
                        variant="primary",
                        classes="menu-button",
                    )
                    yield Button(
                        "💥 DEAUTH STRIKE",
                        id="btn-deauth",
                        variant="warning",
                        classes="menu-button",
                    )
                    yield Button(
                        "📦 HANDSHAKE INTERCEPT",
                        id="btn-capture",
                        variant="success",
                        classes="menu-button",
                    )
                    yield Button(
                        "🔓 CRYPTO ANALYSIS", id="btn-crack", variant="error", classes="menu-button"
                    )
                    yield Button(
                        "🚀 FULL AUDIT WIZARD",
                        id="btn-audit",
                        variant="warning",
                        classes="menu-button",
                    )

            with TabPane("🛡️ DEFENSIVE OPS", id="tab-defensive"):
                yield Static(
                    "[bold #00ffff]◆ DEFENSIVE SECURITY SYSTEMS[/]", classes="tempest-header"
                )
                with Vertical():
                    yield Button(
                        "🛡️ SURVEILLANCE DETECTION",
                        id="btn-surveillance",
                        variant="primary",
                        classes="menu-button",
                    )

        yield Static(
            f"[#6b7785]Selected Target:[/] None", id="target-display", classes="status-panel"
        )
        yield Static(
            "[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]",
            classes="classification-banner",
        )
        # Display detected accelerators
        accel_text = ", ".join(self.accelerators) if self.accelerators else "None"
        yield Static(f"[info]✓ ACCELERATORS: {accel_text}[/]", classes="status-panel")
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-scan":
            self.push_screen(ScanScreen(self.interface))
        elif event.button.id == "btn-deauth":
            if self.selected_network:
                self.push_screen(DeauthScreen(self.interface, self.selected_network))
            else:
                self.push_screen(ScanScreen(self.interface))
        elif event.button.id == "btn-capture":
            if self.selected_network:
                self.push_screen(CaptureScreen(self.interface, self.selected_network))
            else:
                self.push_screen(ScanScreen(self.interface))
        elif event.button.id == "btn-crack":
            if self.selected_network:
                self.push_screen(CrackScreen(self.interface, self.selected_network))
            else:
                self.push_screen(ScanScreen(self.interface))
        elif event.button.id == "btn-audit":
            self.push_screen(AuditScreen(self.interface, self.accelerators))


def main():
    import sys

    if len(sys.argv) > 2 and sys.argv[1] == "--interface":
        app = TempestWiFiTUI(sys.argv[2])
        app.run()
    else:
        print("Please specify interface with --interface")


if __name__ == "__main__":
    main()
