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

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual.widgets import (
    Header, Footer, Button, Static, Input, Label, Log,
    TabbedContent, TabPane, Switch, RadioSet, RadioButton
)
from textual.binding import Binding
from pathlib import Path
from typing import Optional, Callable
import threading
import asyncio

# Import PBKDF2 cracker modules
from crackers import (
    PBKDF2Cracker, CrackingResult, MutationEngine, ContextWordlistGenerator
)


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
            Input(id="encrypted_input", placeholder="paste base64(salt)|base64(ciphertext)"),
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
            Log(id="crack_log", highlight=True),
            id="pbkdf2_container"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "start_crack":
            self.start_pbkdf2_cracking()

    def start_pbkdf2_cracking(self):
        """Start PBKDF2 cracking process"""
        encrypted_input = self.query_one("#encrypted_input", Input)
        strategy = self.query_one("#crack_strategy", RadioSet)
        log = self.query_one("#crack_log", Log)
        monitor = self.query_one("#progress_monitor", ProgressMonitor)

        encrypted_data = encrypted_input.value.strip()
        if not encrypted_data:
            log.write("[red]Error: Enter encrypted data[/]")
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

    def _crack_worker(self, encrypted_data: str, log: Log, monitor: ProgressMonitor, strategy_widget):
        """Worker thread for cracking"""
        try:
            strategy_button = self.query_one("#crack_strategy", RadioSet).pressed
            strategy = strategy_button.id if strategy_button else "dict"

            monitor.set_status(f"Strategy: {strategy}")

            # Initialize cracker
            cracker = PBKDF2Cracker(encrypted_data)

            def progress_callback(tested, total, percent, rate):
                monitor.update_progress(tested, total, percent, rate)

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
                    log.write("[cyan]Loading rockyou.txt...[/]")
                    with open(rockyou, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip()]
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
            log.write(f"[red]Error: {str(e)}[/]")
            monitor.set_status("Error occurred")


class ToolsTab(Container):
    """Tools and utilities"""

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("[cyan]Utilities[/]"),
            Button("Download rockyou.txt", id="download_rockyou"),
            Button("Generate Context Wordlist", id="gen_context"),
            Button("Test Imports", id="test_imports"),
            Button("System Info", id="system_info"),
            Log(id="tools_log")
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        log = self.query_one("#tools_log", Log)

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
        Binding("c", "clear_log", "Clear", show=False),
    ]

    TITLE = "WIFUCKER - Unified Cracking Platform"
    SUB_TITLE = "WiFi + PBKDF2 + Steganography"

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="tabs"):
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
            log = self.query_one("#crack_log", Log)
            log.clear()
        except:
            pass


def main():
    """Run the TUI"""
    app = WiFuFuckerApp()
    app.run()


if __name__ == "__main__":
    main()
