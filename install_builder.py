#!/usr/bin/env python3
"""
install_builder.py
===================

Utility script that ensures required hardware acceleration runtimes (OpenVINO, optional TensorRT) are compiled from source.
It is invoked by the launcher before any other steps.
"""

import os
import sys
import subprocess
from pathlib import Path
import json
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import the compile_runtimes module which contains the actual build logic
from .compile_runtimes import main as compile_runtimes_main

console = Console()

BUILD_DIR = Path.home() / "davbest_builds"
FLAG_FILE = BUILD_DIR / "openvino_built.flag"


def check_and_build_runtimes(force: bool = False) -> None:
    """Check if the OpenVINO runtime is already built; if not, build it.

    Args:
        force: If True, force a rebuild even if the flag file exists.
    """
    # Ensure the build directory exists
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    if FLAG_FILE.exists() and not force:
        console.print("[bold green]✓ OpenVINO runtime already built – skipping compilation.[/]")
        return

    console.print("[cyan]🔧 Starting hardware acceleration runtime compilation...[/]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task(description="Compiling runtimes...", total=None)

            # Run the compile_runtimes main function which handles download, configure, build
            # We run this in a way that it doesn't interfere with our spinner if possible,
            # but compile_runtimes_main likely prints to stdout.
            # Ideally we would capture output or integrate tighter, but for now we wrap the call.
            compile_runtimes_main()

            progress.update(task, completed=1)

        # Write flag file on success
        FLAG_FILE.touch()

        # Check for Kitty
        kitty_installed = check_kitty_installation()

        # Write manifest
        manifest = {
            "openvino": True,
            "tensorrt": False,  # Placeholder
            "kitty_installed": kitty_installed,
            "build_date": str(os.path.getmtime(FLAG_FILE)),
            "devices": ["CPU", "GPU", "NPU"],  # Placeholder detection
        }
        with open(BUILD_DIR / "runtime_manifest.json", "w") as f:
            json.dump(manifest, f, indent=2)

        console.print("[bold green]✓ Runtime build completed and manifest recorded.[/]")
    except Exception as e:
        console.print(f"[bold red]❌ Failed to build runtimes: {e}")
        sys.exit(1)


def check_kitty_installation() -> bool:
    """Check if Kitty terminal is installed."""
    try:
        # Check if kitty is in PATH
        subprocess.run(
            ["which", "kitty"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        console.print("[green]✓ Kitty terminal detected (Recommended for best experience)[/]")
        return True
    except subprocess.CalledProcessError:
        console.print(
            "[yellow]⚠ Kitty terminal not found. Recommended for accelerated TUI features.[/]"
        )
        console.print(
            "  Install with: curl -L https://sw.kovidgoyal.net/kitty/installer.sh | sh /dev/stdin"
        )
        return False


if __name__ == "__main__":
    # Allow optional --force flag from command line
    force_rebuild = "--force" in sys.argv
    check_and_build_runtimes(force=force_rebuild)
