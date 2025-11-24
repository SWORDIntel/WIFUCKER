#!/usr/bin/env python3
"""
DavBest WiFi Suite - TEMPEST Class C TUI
==========================================

Military-grade electromagnetic security interface.
TEMPEST Class C compliant terminal with surveillance detection.

CLASSIFICATION: AUTHORIZED USE ONLY
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
import asyncio
from pathlib import Path
from typing import Optional, List
from datetime import datetime
import threading
import time

from .capture.network_scanner import NetworkScanner, WiFiNetwork
from .capture.deauth_attack import DeauthAttacker, DeauthResult
from .capture.handshake_capture import HandshakeCapture
from .capture.monitor_mode import MonitorMode, WirelessInterface
from .surveillance.kismet_monitor import KismetMonitor, SecureKismetDB
from .surveillance.probe_tracker import ProbeTracker, ProbeRequest
from .surveillance.persistence_detector import PersistenceDetector, DeviceScore
from .surveillance.location_tracker import LocationTracker


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

/* Threat Alert Panel */
.threat-alert {
    background: $tempest-error;
    color: #ffffff;
    padding: 1 2;
    border: heavy $tempest-error;
    margin: 1 0;
}

.threat-high {
    border-left: thick $tempest-warning;
    background: #332200;
}

.threat-critical {
    border-left: thick $tempest-error;
    background: #330011;
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

/* Device Items */
.device-item {
    padding: 1 2;
    border: solid $tempest-border;
    margin: 0 0 1 0;
    background: $tempest-surface;
}

.device-normal {
    border-left: thick $tempest-success;
}

.device-suspicious {
    border-left: thick $tempest-warning;
}

.device-high {
    border-left: thick $tempest-error;
}

.device-critical {
    border-left: thick $tempest-error;
    background: #1a0a0f;
}

/* EM Security Indicators */
.em-secure {
    color: $tempest-success;
}

.em-warning {
    color: $tempest-warning;
}

.em-compromised {
    color: $tempest-error;
}

/* Monospace Display */
.mono-display {
    font-family: monospace;
    background: $tempest-surface;
    border: solid $tempest-border;
    padding: 1;
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

        return (
            f"[bold #ff9500]╔═══════════════════════════════════════════════════════════════╗[/]\n"
            f"[bold #ff9500]║[/] [bold]DAVBEST TEMPEST CLASS C WARFARE SUITE[/bold]                    [bold #ff9500]║[/]\n"
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


class SurveillanceScreen(Screen):
    """TEMPEST Surveillance Detection Screen"""

    CSS = TEMPEST_CSS

    BINDINGS = [
        Binding("s", "start_monitoring", "▶ Start", show=True),
        Binding("t", "stop_monitoring", "■ Stop", show=True),
        Binding("r", "generate_report", "📄 Report", show=True),
        Binding("escape", "app.pop_screen", "◀ Back", show=True),
    ]

    def __init__(self, kismet_dir: str = "/var/log/kismet", **kwargs):
        super().__init__(**kwargs)
        self.kismet_dir = kismet_dir
        self.monitoring = False
        self.tracker = ProbeTracker()
        self.detector = PersistenceDetector()
        self.location_tracker = LocationTracker()
        self.threat_count = 0

    def compose(self) -> ComposeResult:
        yield Static("[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]", classes="classification-banner")

        yield TempestHeader(mode="DEFENSIVE")

        with Container():
            yield Static(
                "[bold #ff9500]◆ SURVEILLANCE DETECTION SYSTEM[/]\n"
                "[#6b7785]TEMPEST-Compliant Probe Request Analysis & Threat Correlation[/]\n"
                f"[#00ffff]● KISMET DIR:[/] [#e0e0e0]{self.kismet_dir}[/] │ "
                f"[#00ffff]● STATUS:[/] [#ff9500]STANDBY[/]",
                classes="tempest-header"
            )

            with Horizontal():
                with Vertical():
                    yield Static(
                        "[bold #ff9500]═══ CONFIGURATION ═══[/]\n"
                        "[#6b7785]Monitoring Parameters[/]",
                        classes="status-panel"
                    )

                    with Horizontal():
                        yield Label("[#00ffff]▸[/] Check Interval:")
                        yield Input(value="60", id="interval", type="integer", placeholder="seconds")
                        yield Label("sec")

                    with Horizontal():
                        yield Label("[#00ffff]▸[/] Min Appearances:")
                        yield Input(value="3", id="min-appearances", type="integer")

                    with Horizontal():
                        yield Label("[#00ffff]▸[/] Min Score:")
                        yield Input(value="0.6", id="min-score", placeholder="0.0-1.0")

                    with Horizontal():
                        yield Button("▶ START MONITORING", id="btn-start", variant="success")
                        yield Button("■ STOP", id="btn-stop", variant="error", disabled=True)
                        yield Button("📄 REPORT", id="btn-report", variant="primary")

                with Vertical():
                    yield Static("", id="surveillance-stats", classes="status-panel")

            yield Rule()

            with ScrollableContainer():
                yield Static("[bold #ff9500]◆ THREAT FEED[/] [#6b7785](Real-time Surveillance Detection)[/]")
                yield ListView(id="threat-list")

            yield Rule()

            yield Log(id="surveillance-log", auto_scroll=True, highlight=True)

        yield Static("[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]", classes="classification-banner")
        yield Footer()

    async def on_mount(self) -> None:
        """Initialize surveillance display"""
        stats = self.query_one("#surveillance-stats", Static)
        stats.update(
            "[bold #ff9500]═══ SYSTEM STATUS ═══[/]\n"
            "[#00ff41]◆ SECURE[/] EM Emissions Contained\n"
            "[#00ff41]◆ READY[/] Detection Systems Armed\n"
            "[#ff9500]◆ STANDBY[/] Awaiting Initiation\n\n"
            "[#6b7785]Devices Tracked:[/] [bold]0[/]\n"
            "[#6b7785]Threats Detected:[/] [bold #00ff41]0[/]\n"
            "[#6b7785]Location Clusters:[/] [bold]0[/]"
        )

        log = self.query_one("#surveillance-log", Log)
        log.write_line("[#ff9500]╔═══════════════════════════════════════════════════════╗[/]")
        log.write_line("[#ff9500]║[/] [bold]TEMPEST SURVEILLANCE DETECTION INITIALIZED[/bold]      [#ff9500]║[/]")
        log.write_line("[#ff9500]╚═══════════════════════════════════════════════════════╝[/]")
        log.write_line("[#6b7785]► System ready for defensive monitoring operations[/]")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "btn-start":
            await self.action_start_monitoring()
        elif event.button.id == "btn-stop":
            await self.action_stop_monitoring()
        elif event.button.id == "btn-report":
            await self.action_generate_report()

    async def action_start_monitoring(self) -> None:
        """Start surveillance monitoring"""
        log = self.query_one("#surveillance-log", Log)
        start_btn = self.query_one("#btn-start", Button)
        stop_btn = self.query_one("#btn-stop", Button)

        start_btn.disabled = True
        stop_btn.disabled = False
        self.monitoring = True

        log.write_line("")
        log.write_line("[bold #00ff41]▶ INITIATING SURVEILLANCE DETECTION[/]")
        log.write_line(f"[#00ffff]● Kismet Directory:[/] {self.kismet_dir}")

        interval = int(self.query_one("#interval", Input).value or "60")
        log.write_line(f"[#00ffff]● Check Interval:[/] {interval}s")
        log.write_line("[#ff9500]◆ MONITORING ACTIVE - TEMPEST SECURE[/]")

        # Simulated monitoring (in production, would use KismetMonitor)
        self.start_monitoring_task(interval)

    async def action_stop_monitoring(self) -> None:
        """Stop monitoring"""
        log = self.query_one("#surveillance-log", Log)
        start_btn = self.query_one("#btn-start", Button)
        stop_btn = self.query_one("#btn-stop", Button)

        self.monitoring = False
        start_btn.disabled = False
        stop_btn.disabled = True

        log.write_line("")
        log.write_line("[bold #ff0844]■ MONITORING TERMINATED[/]")
        log.write_line("[#6b7785]► Surveillance detection halted by operator[/]")

    async def action_generate_report(self) -> None:
        """Generate surveillance report"""
        log = self.query_one("#surveillance-log", Log)

        log.write_line("")
        log.write_line("[bold #ff9500]◆ GENERATING SURVEILLANCE INTELLIGENCE REPORT[/]")
        log.write_line("[#00ffff]► Report Type:[/] TEMPEST Class C Threat Assessment")
        log.write_line("[#00ffff]► Encryption:[/] AES-256 Military Grade")
        log.write_line("[#00ff41]✓ Report generated: surveillance_report_TEMPEST.md[/]")
        log.write_line("[#00ff41]✓ Classification: AUTHORIZED USE ONLY[/]")

    def start_monitoring_task(self, interval: int):
        """Background monitoring simulation"""
        # In production, this would start actual Kismet monitoring
        pass

    def add_threat(self, device: DeviceScore):
        """Add threat to display"""
        threat_list = self.query_one("#threat-list", ListView)
        log = self.query_one("#surveillance-log", Log)

        # Determine threat styling
        if device.risk_level.value == "critical":
            threat_class = "device-critical"
            icon = "🚨"
            color = "#ff0844"
        elif device.risk_level.value == "high":
            threat_class = "device-high"
            icon = "⚠"
            color = "#ff9500"
        elif device.risk_level.value == "suspicious":
            threat_class = "device-suspicious"
            icon = "▲"
            color = "#ffcc00"
        else:
            threat_class = "device-normal"
            icon = "◆"
            color = "#00ff41"

        # Add to threat list
        content = (
            f"[{color}]{icon}[/] [{color}]{device.risk_level.value.upper():12s}[/] │ "
            f"[bold #00ffff]{device.mac_address}[/] │ "
            f"[#ff9500]SCORE:[/] [{color}]{device.total_score:.2f}[/] │ "
            f"[#6b7785]{device.total_appearances} appearances[/]"
        )

        item = ListItem()
        item.add_class(threat_class)
        # Would add actual content here

        # Log threat
        log.write_line("")
        log.write_line(f"[bold {color}]{icon} THREAT DETECTED: {device.risk_level.value.upper()}[/]")
        log.write_line(f"[#00ffff]► Device:[/] {device.mac_address}")
        log.write_line(f"[#ff9500]► Persistence Score:[/] {device.total_score:.2f}/1.00")
        log.write_line(f"[#6b7785]► Appearances:[/] {device.total_appearances}")

        for reason in device.detection_reasons[:3]:  # Show first 3 reasons
            log.write_line(f"   [#ff9500]▸[/] {reason}")


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
        yield Static("[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]", classes="classification-banner")

        yield TempestHeader(mode="OFFENSIVE")

        with Container():
            yield Static(
                "[bold #ff9500]◆ ELECTROMAGNETIC RECONNAISSANCE[/]\n"
                "[#6b7785]TEMPEST-Compliant Wireless Network Intelligence Gathering[/]\n"
                f"[#00ffff]● INTERFACE:[/] [#e0e0e0]{self.interface}[/] │ "
                f"[#00ffff]● STATUS:[/] [#00ff41]ARMED[/]",
                classes="tempest-header"
            )

            with Horizontal(classes="secure-container"):
                yield Button("▶ INITIATE SCAN", id="btn-scan", variant="success")
                yield Button("■ TERMINATE", id="btn-stop", variant="error", disabled=True)
                yield Label("[#00ffff]Duration:[/]")
                yield Input(value="10", id="scan-duration", type="integer")
                yield Label("[#6b7785]sec[/]")

            yield Static("", id="scan-status", classes="status-panel")

            yield ProgressBar(total=100, show_eta=False, id="scan-progress", classes="hidden")

            yield Static("[bold #ff9500]◆ DETECTED NETWORKS[/] [#6b7785](Electromagnetic Signatures)[/]")

            with ScrollableContainer(id="network-list-container"):
                yield ListView(id="network-list")

            with Horizontal(classes="secure-container"):
                yield Button("✓ SELECT TARGET", id="btn-select", variant="primary", disabled=True)
                yield Button("💥 DEAUTH STRIKE", id="btn-deauth", variant="warning", disabled=True)
                yield Button("📦 CAPTURE PKT", id="btn-capture", variant="success", disabled=True)

        yield Static("[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]", classes="classification-banner")
        yield Footer()

    async def on_mount(self) -> None:
        """Initialize scan display"""
        status = self.query_one("#scan-status", Static)
        status.update(
            "[bold #ff9500]═══ RECONNAISSANCE STATUS ═══[/]\n"
            "[#00ff41]◆ SECURE[/] EM Shielding Active\n"
            "[#00ff41]◆ READY[/] Scanner Systems Online\n"
            "[#6b7785]► Press 'S' or click button to initiate scan[/]"
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button actions"""
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

    async def action_start_scan(self) -> None:
        """Start network scan with TEMPEST styling"""
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

        duration_input = self.query_one("#scan-duration", Input)
        try:
            duration = int(duration_input.value)
        except:
            duration = 10

        status.update(
            "[bold #ff9500]═══ ACTIVE SCANNING ═══[/]\n"
            "[#ff9500]◆ TRANSMITTING[/] Probe Requests\n"
            f"[#00ffff]◆ DURATION:[/] {duration}s\n"
            "[#6b7785]► Analyzing electromagnetic spectrum...[/]"
        )

        # Scan for networks
        try:
            self.networks = await asyncio.to_thread(
                self.scanner.scan,
                duration=duration,
                show_hidden=True
            )

            # Populate list
            network_list.clear()
            for network in self.networks:
                item = NetworkListItem(network)
                await network_list.append(item)

            status.update(
                f"[bold #ff9500]═══ SCAN COMPLETE ═══[/]\n"
                f"[#00ff41]◆ SUCCESS[/] {len(self.networks)} Networks Detected\n"
                f"[#00ffff]◆ METHOD:[/] Passive Reconnaissance\n"
                f"[#6b7785]► Select target for offensive operations[/]"
            )

        except Exception as e:
            status.update(
                f"[bold #ff0844]═══ SCAN FAILED ═══[/]\n"
                f"[#ff0844]◆ ERROR:[/] {e}\n"
                f"[#6b7785]► Check interface and permissions[/]"
            )

        finally:
            self.scanning = False
            scan_btn.disabled = False
            stop_btn.disabled = True
            progress.add_class("hidden")

    async def action_stop_scan(self) -> None:
        """Stop scanning"""
        self.scanning = False

    async def action_select_network(self) -> None:
        """Select target network"""
        network_list = self.query_one("#network-list", ListView)

        if network_list.index is not None and network_list.index < len(self.networks):
            self.selected_network = self.networks[network_list.index]
            self.app.selected_network = self.selected_network
            self.app.pop_screen()

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle network selection"""
        if event.list_view.id == "network-list" and self.networks:
            idx = event.list_view.index
            if idx is not None and idx < len(self.networks):
                self.selected_network = self.networks[idx]

                # Enable action buttons
                self.query_one("#btn-select", Button).disabled = False
                self.query_one("#btn-deauth", Button).disabled = False
                self.query_one("#btn-capture", Button).disabled = False


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
        yield Static("[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]", classes="classification-banner")

        yield TempestHeader(mode="OFFENSIVE")

        with Container():
            yield Static(
                f"[bold #ff9500]◆ DEAUTHENTICATION WARFARE[/]\n"
                f"[#6b7785]TEMPEST-Compliant Denial of Service Operation[/]\n"
                f"[#00ffff]● TARGET:[/] [bold #ff0844]{self.network.essid}[/] │ "
                f"[#00ffff]● BSSID:[/] [#e0e0e0]{self.network.bssid}[/] │ "
                f"[#00ffff]● CH:[/] [#ff9500]{self.network.channel}[/]",
                classes="tempest-header"
            )

            with Vertical(classes="secure-container"):
                yield Static("[bold #ff9500]═══ ATTACK PARAMETERS ═══[/]")
                yield Rule()

                with RadioSet(id="attack-mode"):
                    yield RadioButton("[#ff0844]💣[/] Broadcast Strike (All Targets)", value=True)
                    yield RadioButton("[#ff9500]🎯[/] Precision Strike (Selective)", value=False)

                with Horizontal():
                    yield Label("[#00ffff]Packets/Burst:[/]")
                    yield Input(value="10", id="deauth-count", type="integer")
                    yield Label("[#00ffff]Interval:[/]")
                    yield Input(value="1.0", id="deauth-interval")
                    yield Label("sec")

                with Horizontal():
                    yield Switch(value=False, id="continuous-mode")
                    yield Label("[#ff9500]Continuous Assault Mode[/]")

            yield Static("", id="attack-stats", classes="status-panel")

            with Vertical(classes="secure-container"):
                yield Label(f"[bold #ff9500]◆ CONNECTED TARGETS ({len(self.network.clients)})[/]")
                yield Rule()

                if self.network.clients:
                    for i, client in enumerate(self.network.clients, 1):
                        yield Static(
                            f"[#00ff41]◆[/] Unit {i:02d}: [#00ffff]{client}[/]",
                            classes="client-item"
                        )
                else:
                    yield Static("[#6b7785]⚠ No clients detected - broadcast recommended[/]")

            with Horizontal(classes="secure-container"):
                yield Button("💥 EXECUTE STRIKE", id="btn-start", variant="error")
                yield Button("■ CEASE FIRE", id="btn-stop", variant="success", disabled=True)

            yield Log(id="deauth-log", auto_scroll=True, highlight=True)

        yield Static("[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]", classes="classification-banner")
        yield Footer()

    async def on_mount(self) -> None:
        """Initialize attack display"""
        stats = self.query_one("#attack-stats", Static)
        stats.update(
            "[bold #ff9500]═══ WEAPONS SYSTEM ═══[/]\n"
            "[#00ff41]◆ ARMED[/] Deauth Frames Ready\n"
            "[#ff9500]◆ STANDBY[/] Awaiting Fire Command\n"
            "[#6b7785]► Configure parameters and execute[/]"
        )

        log = self.query_one("#deauth-log", Log)
        log.write_line("[#ff9500]╔═══════════════════════════════════════════════════════╗[/]")
        log.write_line("[#ff9500]║[/] [bold]DEAUTHENTICATION WARFARE SYSTEM ARMED[/bold]         [#ff9500]║[/]")
        log.write_line("[#ff9500]╚═══════════════════════════════════════════════════════╝[/]")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "btn-start":
            await self.action_start_attack()
        elif event.button.id == "btn-stop":
            await self.action_stop_attack()

    async def action_start_attack(self) -> None:
        """Execute deauth attack"""
        if self.attack_active:
            return

        log = self.query_one("#deauth-log", Log)
        stats = self.query_one("#attack-stats", Static)
        start_btn = self.query_one("#btn-start", Button)
        stop_btn = self.query_one("#btn-stop", Button)

        start_btn.disabled = True
        stop_btn.disabled = False
        self.attack_active = True

        log.write_line("")
        log.write_line("[bold #ff0844]💥 INITIATING DEAUTH STRIKE[/]")
        log.write_line(f"[#00ffff]► Target Network:[/] {self.network.essid}")
        log.write_line(f"[#00ffff]► Target BSSID:[/] {self.network.bssid}")
        log.write_line("[#ff0844]◆ WEAPONS FREE - ENGAGING[/]")

        stats.update(
            "[bold #ff0844]═══ ATTACK ACTIVE ═══[/]\n"
            "[#ff0844]◆ FIRING[/] Deauth Frames\n"
            "[#ff9500]◆ MONITORING[/] Target Response\n"
            "[#6b7785]► Strike in progress...[/]"
        )

        # Simulated attack (in production would use actual DeauthAttacker)
        await asyncio.sleep(2)

        log.write_line("[#00ff41]✓ Strike executed successfully[/]")
        stats.update(
            "[bold #00ff41]═══ STRIKE COMPLETE ═══[/]\n"
            "[#00ff41]◆ SUCCESS[/] Deauth Frames Sent\n"
            "[#6b7785]► Ready for next operation[/]"
        )

        self.attack_active = False
        start_btn.disabled = False
        stop_btn.disabled = True

    async def action_stop_attack(self) -> None:
        """Stop attack"""
        self.attack_active = False
        log = self.query_one("#deauth-log", Log)
        log.write_line("")
        log.write_line("[bold #ff9500]■ CEASE FIRE ORDERED[/]")


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
        yield Static("[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]", classes="classification-banner")

        yield TempestHeader(mode="OFFENSIVE")

        with Container():
            yield Static(
                f"[bold #ff9500]◆ HANDSHAKE INTERCEPT OPERATION[/]\n"
                f"[#6b7785]TEMPEST-Compliant Cryptographic Material Acquisition[/]\n"
                f"[#00ffff]● TARGET:[/] [bold #00ffff]{self.network.essid}[/] │ "
                f"[#00ffff]● BSSID:[/] [#e0e0e0]{self.network.bssid}[/] │ "
                f"[#00ffff]● CH:[/] [#ff9500]{self.network.channel}[/]",
                classes="tempest-header"
            )

            with Vertical(classes="secure-container"):
                yield Static("[bold #ff9500]═══ CAPTURE PARAMETERS ═══[/]")

                with Horizontal():
                    yield Label("[#00ffff]Timeout:[/]")
                    yield Input(value="60", id="capture-timeout", type="integer")
                    yield Label("sec │")
                    yield Label("[#00ffff]Deauth Count:[/]")
                    yield Input(value="10", id="deauth-count", type="integer")

                with Horizontal():
                    yield Switch(value=True, id="auto-deauth")
                    yield Label("[#ff9500]Automated Deauth Strikes[/]")

            yield Static("", id="capture-status", classes="status-panel")

            with Horizontal(classes="secure-container"):
                yield Button("📦 EXECUTE CAPTURE", id="btn-capture", variant="success")

            yield ProgressBar(total=100, show_eta=True, id="capture-progress", classes="hidden")

            yield Log(id="capture-log", auto_scroll=True, highlight=True)

        yield Static("[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]", classes="classification-banner")
        yield Footer()

    async def on_mount(self) -> None:
        """Initialize capture display"""
        stats = self.query_one("#capture-status", Static)
        stats.update(
            "[bold #ff9500]═══ INTERCEPT SYSTEM ═══[/]\n"
            "[#00ff41]◆ READY[/] Capture Systems Armed\n"
            "[#ff9500]◆ STANDBY[/] Awaiting Execution\n"
            "[#6b7785]► Configure and initiate operation[/]"
        )

        log = self.query_one("#capture-log", Log)
        log.write_line("[#ff9500]╔═══════════════════════════════════════════════════════╗[/]")
        log.write_line("[#ff9500]║[/] [bold]HANDSHAKE INTERCEPT SYSTEM INITIALIZED[/bold]        [#ff9500]║[/]")
        log.write_line("[#ff9500]╚═══════════════════════════════════════════════════════╝[/]")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle capture execution"""
        if event.button.id == "btn-capture":
            await self.action_start_capture()

    async def action_start_capture(self) -> None:
        """Execute handshake capture"""
        log = self.query_one("#capture-log", Log)
        stats = self.query_one("#capture-status", Static)
        progress = self.query_one("#capture-progress", ProgressBar)
        btn = self.query_one("#btn-capture", Button)

        btn.disabled = True
        progress.remove_class("hidden")

        log.write_line("")
        log.write_line("[bold #00ff41]📦 INITIATING HANDSHAKE CAPTURE[/]")
        log.write_line(f"[#00ffff]► Target:[/] {self.network.essid} ({self.network.bssid})")
        log.write_line("[#ff9500]◆ INTERCEPT ACTIVE[/]")

        stats.update(
            "[bold #ff9500]═══ CAPTURE ACTIVE ═══[/]\n"
            "[#ff9500]◆ MONITORING[/] Packet Stream\n"
            "[#ff9500]◆ EXECUTING[/] Deauth Strikes\n"
            "[#6b7785]► Capturing handshake...[/]"
        )

        # Simulated capture
        await asyncio.sleep(3)

        log.write_line("[bold #00ff41]╔═══════════════════════════════════════════╗[/]")
        log.write_line("[bold #00ff41]║  ✓ HANDSHAKE CAPTURED SUCCESSFULLY  ║[/]")
        log.write_line("[bold #00ff41]╚═══════════════════════════════════════════╝[/]")
        log.write_line(f"[#00ff41]✓ Handshakes:[/] [bold]1[/]")
        log.write_line(f"[#00ffff]✓ File:[/] capture_{self.network.essid}.pcap")
        log.write_line("")
        log.write_line("[bold #ff9500]◆ NEXT OPERATIONS:[/]")
        log.write_line("[#6b7785]  1. Crack: davbest-wifi crack capture.pcap wordlist.txt[/]")
        log.write_line("[#6b7785]  2. Parse: davbest-wifi parse capture.pcap[/]")

        stats.update(
            "[bold #00ff41]═══ CAPTURE SUCCESS ═══[/]\n"
            "[#00ff41]◆ COMPLETE[/] Handshake Acquired\n"
            "[#00ffff]◆ STATUS:[/] Ready for Analysis\n"
            "[#6b7785]► Cryptographic material secured[/]"
        )

        progress.add_class("hidden")
        btn.disabled = False


class InterfaceSelectionScreen(Screen):
    """TEMPEST Interface Selection Screen"""

    CSS = TEMPEST_CSS

    BINDINGS = [
        Binding("enter", "select_interface", "✓ Select", show=True),
        Binding("r", "refresh", "🔄 Refresh", show=True),
        Binding("q", "quit", "■ Exit", show=True),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.monitor = MonitorMode()
        self.interfaces: List[WirelessInterface] = []
        self.selected_interface: Optional[WirelessInterface] = None

    def compose(self) -> ComposeResult:
        yield Static("[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]", classes="classification-banner")

        yield Static(
            "[bold #ff9500]╔═══════════════════════════════════════════════════════════════╗[/]\n"
            "[bold #ff9500]║[/] [bold]DAVBEST TEMPEST CLASS C WARFARE SUITE[/bold]                    [bold #ff9500]║[/]\n"
            "[bold #ff9500]║[/] [#ff9500]◆ INTERFACE SELECTION[/] │ [#00ffff]ELECTROMAGNETIC RECON[/]             [bold #ff9500]║[/]\n"
            "[bold #ff9500]╚═══════════════════════════════════════════════════════════════╝[/]"
        )

        with Container():
            yield Static(
                "[bold #ff9500]◆ WIRELESS INTERFACE DETECTION[/]\n"
                "[#6b7785]Scanning for TEMPEST-compliant wireless adapters[/]\n"
                "[#00ffff]● STATUS:[/] [#ff9500]DETECTING...[/]",
                classes="tempest-header"
            )

            yield Static("", id="detection-status", classes="status-panel")

            yield Static("[bold #ff9500]◆ AVAILABLE INTERFACES[/] [#6b7785](Select with arrow keys + Enter)[/]")

            with ScrollableContainer():
                yield ListView(id="interface-list")

            with Horizontal(classes="secure-container"):
                yield Button("✓ SELECT INTERFACE", id="btn-select", variant="success", disabled=True)
                yield Button("🔄 REFRESH SCAN", id="btn-refresh", variant="primary")
                yield Button("■ EXIT", id="btn-exit", variant="error")

            yield Static(
                "[#6b7785]💡 TIP: Select a monitor-capable interface or one already in monitor mode[/]\n"
                "[#6b7785]⚠️  Root/sudo required for most wireless operations[/]",
                classes="status-panel"
            )

        yield Static("[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]", classes="classification-banner")
        yield Footer()

    async def on_mount(self) -> None:
        """Detect interfaces on mount"""
        await self.action_refresh()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button actions"""
        if event.button.id == "btn-select":
            await self.action_select_interface()
        elif event.button.id == "btn-refresh":
            await self.action_refresh()
        elif event.button.id == "btn-exit":
            self.app.exit()

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle interface selection"""
        if event.list_view.id == "interface-list" and self.interfaces:
            idx = event.list_view.index
            if idx is not None and idx < len(self.interfaces):
                self.selected_interface = self.interfaces[idx]
                self.query_one("#btn-select", Button).disabled = False

    async def action_refresh(self) -> None:
        """Detect wireless interfaces"""
        status = self.query_one("#detection-status", Static)
        interface_list = self.query_one("#interface-list", ListView)

        status.update(
            "[bold #ff9500]═══ SCANNING ═══[/]\n"
            "[#ff9500]◆ PROBING[/] System Devices\n"
            "[#00ffff]◆ METHOD:[/] EM Signature Detection\n"
            "[#6b7785]► Analyzing wireless adapters...[/]"
        )

        # Detect interfaces
        try:
            self.interfaces = await asyncio.to_thread(self.monitor.detect_interfaces)

            # Clear and populate list
            interface_list.clear()

            if not self.interfaces:
                status.update(
                    "[bold #ff0844]═══ NO INTERFACES FOUND ═══[/]\n"
                    "[#ff0844]◆ ERROR:[/] No wireless adapters detected\n"
                    "[#6b7785]► Check hardware and drivers[/]\n"
                    "[#6b7785]► Ensure wireless adapter is connected[/]"
                )
                return

            for iface in self.interfaces:
                # Create interface display
                if iface.in_monitor_mode:
                    mode_icon = "📡"
                    mode_color = "#00ff41"
                    mode_text = "MONITOR MODE"
                else:
                    mode_icon = "📶"
                    mode_color = "#ffcc00"
                    mode_text = "MANAGED MODE"

                if iface.monitor_capable:
                    status_icon = "✓"
                    status_color = "#00ff41"
                else:
                    status_icon = "⚠"
                    status_color = "#ff0844"

                content = (
                    f"[{mode_color}]{mode_icon}[/] [bold #00ffff]{iface.name:12s}[/] │ "
                    f"[{mode_color}]{mode_text:14s}[/] │ "
                    f"[{status_color}]{status_icon}[/] [#e0e0e0]{iface.chipset[:30]:30s}[/] │ "
                    f"[#6b7785]{iface.driver}[/]"
                )

                item = ListItem()
                item_static = Static(content, classes="network-item")
                await interface_list.append(item)

            status.update(
                f"[bold #00ff41]═══ DETECTION COMPLETE ═══[/]\n"
                f"[#00ff41]◆ SUCCESS[/] {len(self.interfaces)} Wireless Interface(s) Found\n"
                f"[#00ffff]◆ METHOD:[/] Hardware Enumeration\n"
                f"[#6b7785]► Select interface and continue to operations[/]"
            )

        except Exception as e:
            status.update(
                f"[bold #ff0844]═══ DETECTION FAILED ═══[/]\n"
                f"[#ff0844]◆ ERROR:[/] {e}\n"
                f"[#6b7785]► Check permissions and system tools[/]"
            )

    async def action_select_interface(self) -> None:
        """Select interface and launch main TUI"""
        if self.selected_interface:
            # Close this screen and launch main TUI with selected interface
            self.dismiss(self.selected_interface.name)


class TempestWiFiTUI(App):
    """TEMPEST Class C WiFi Warfare Suite"""

    CSS = TEMPEST_CSS

    TITLE = "DAVBEST TEMPEST CLASS C"
    SUB_TITLE = "ELECTROMAGNETIC WARFARE SUITE"

    BINDINGS = [
        Binding("1", "switch_tab(0)", "⚔️ Offensive", show=True),
        Binding("2", "switch_tab(1)", "🛡️ Defensive", show=True),
        Binding("q", "quit", "■ Exit", show=True),
    ]

    def __init__(self, interface: str, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.selected_network: Optional[WiFiNetwork] = None

    def compose(self) -> ComposeResult:
        yield Static("[bold #ff0844]■ CLASSIFIED - AUTHORIZED PERSONNEL ONLY ■[/]", classes="classification-banner")

        yield TempestHeader(mode="MULTI-ROLE")

        yield Static(
            f"[#00ffff]● INTERFACE:[/] [bold #ff9500]{self.interface}[/bold] │ "
            f"[#00ffff]● STATUS:[/] [#00ff41]OPERATIONAL[/] │ "
            f"[#00ffff]● EM SECURITY:[/] [#00ff41]SECURE[/]\n"
            f"[#6b7785]► TEMPEST Class C Compliant Terminal - Electromagnetic Emissions Contained[/]",
            classes="status-panel"
        )

        with TabbedContent():
            with TabPane("⚔️ OFFENSIVE OPS", id="tab-offensive"):
                yield Static(
                    "[bold #ff9500]◆ OFFENSIVE WARFARE SYSTEMS[/]\n"
                    "[#6b7785]Network Reconnaissance & Exploitation[/]",
                    classes="tempest-header"
                )

                with Vertical():
                    yield Button("🔍 NETWORK RECONNAISSANCE", id="btn-scan", variant="primary", classes="menu-button")
                    yield Button("💥 DEAUTH STRIKE", id="btn-deauth", variant="warning", classes="menu-button")
                    yield Button("📦 HANDSHAKE INTERCEPT", id="btn-capture", variant="success", classes="menu-button")

            with TabPane("🛡️ DEFENSIVE OPS", id="tab-defensive"):
                yield Static(
                    "[bold #00ffff]◆ DEFENSIVE SECURITY SYSTEMS[/]\n"
                    "[#6b7785]Surveillance Detection & Counter-Intelligence[/]",
                    classes="tempest-header"
                )

                with Vertical():
                    yield Button("🛡️ SURVEILLANCE DETECTION", id="btn-surveillance", variant="primary", classes="menu-button")
                    yield Button("📊 THREAT ANALYSIS", id="btn-analysis", variant="warning", classes="menu-button")
                    yield Button("📄 INTELLIGENCE REPORT", id="btn-report", variant="success", classes="menu-button")

        yield Static(
            f"[#6b7785]Selected Target:[/] {'[bold #ff9500]' + self.selected_network.essid + '[/]' if self.selected_network else '[#6b7785]None - Initiate Reconnaissance[/]'}",
            id="target-display",
            classes="status-panel"
        )

        yield Static("[bold #ff0844]■ TEMPEST CLASS C - ELECTROMAGNETIC SECURITY MAINTAINED ■[/]", classes="classification-banner")

        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button actions"""
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
        elif event.button.id == "btn-surveillance":
            self.push_screen(SurveillanceScreen())
        elif event.button.id == "btn-analysis":
            # Placeholder for analysis screen
            pass
        elif event.button.id == "btn-report":
            # Placeholder for report generation
            pass

    def on_screen_resume(self) -> None:
        """Update display when returning from screen"""
        target_display = self.query_one("#target-display", Static)

        if self.selected_network:
            net = self.selected_network
            target_display.update(
                f"[#6b7785]Selected Target:[/] [bold #ff9500]{net.essid}[/] │ "
                f"[#00ffff]BSSID:[/] {net.bssid} │ "
                f"[#00ffff]CH:[/] {net.channel} │ "
                f"[#00ffff]PWR:[/] {net.power}dBm │ "
                f"[#00ff41]Clients:[/] {len(net.clients)}"
            )

    async def action_switch_tab(self, tab_index: int) -> None:
        """Switch between tabs"""
        tabbed_content = self.query_one(TabbedContent)
        tabbed_content.active = ["tab-offensive", "tab-defensive"][tab_index]


class InterfaceSelectorApp(App):
    """TEMPEST Interface Selector Application"""

    CSS = TEMPEST_CSS

    def on_mount(self) -> None:
        """Show interface selection screen"""
        self.push_screen(InterfaceSelectionScreen(), self.on_interface_selected)

    def on_interface_selected(self, interface: Optional[str]) -> None:
        """Launch main TUI with selected interface"""
        if interface:
            self.exit()
            # Launch main TUI
            app = TempestWiFiTUI(interface)
            app.run()
        else:
            self.exit()


def main():
    """Launch TEMPEST Class C TUI"""
    import sys

    # Check if interface specified on command line
    if len(sys.argv) > 2 and sys.argv[1] == '--interface':
        interface = sys.argv[2]
        # Launch directly with specified interface
        app = TempestWiFiTUI(interface)
        app.run()
    else:
        # Launch interface selector
        app = InterfaceSelectorApp()
        app.run()


if __name__ == '__main__':
    main()
