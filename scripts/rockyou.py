# rockyou.py
"""Utility to ensure rockyou wordlist repositories are available.
Uses aria2c for high-speed downloading of large wordlists (like rockyou2024.txt).
"""
import subprocess
import shutil
from pathlib import Path

DEFAULT_ROCKYOU_PATH = Path.home() / "rockyou"
ROCKYOU_TXT = DEFAULT_ROCKYOU_PATH / "rockyou.txt"
ROCKYOU2024_TXT = DEFAULT_ROCKYOU_PATH / "rockyou2024.txt"

# Direct download links (examples - replace with stable mirrors if needed)
ROCKYOU_URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
ROCKYOU2024_URL = "https://github.com/zacheller/rockyou/raw/master/rockyou2024.txt"  # Placeholder URL, user implies it's too big for repo


def _check_aria2c():
    """Check if aria2c is installed."""
    if not shutil.which("aria2c"):
        raise RuntimeError(
            "aria2c is required for downloading wordlists. Please install it (sudo apt install aria2c)."
        )


def _download_file(url: str, dest_path: Path):
    """Download a file using aria2c."""
    _check_aria2c()
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # aria2c command: -x16 (16 connections), -s16 (16 split), -k1M (1M split size)
    cmd = [
        "aria2c",
        "-x16",
        "-s16",
        "-k1M",
        "--dir",
        str(dest_path.parent),
        "--out",
        dest_path.name,
        url,
    ]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to download {url}: {e}")


def ensure_rockyou(path: Path = DEFAULT_ROCKYOU_PATH) -> Path:
    """Make sure the classic rockyou.txt wordlist exists.

    Args:
        path: Desired location for the rockyou repo. Defaults to ~/rockyou.
    Returns:
        Path to the rockyou.txt file.
    """
    target_file = path / "rockyou.txt"
    if not target_file.exists():
        # Try downloading the classic rockyou.txt
        try:
            _download_file(ROCKYOU_URL, target_file)
        except Exception as e:
            raise RuntimeError(f"Failed to download rockyou.txt: {e}")

    return target_file


def ensure_rockyou2024(path: Path = DEFAULT_ROCKYOU_PATH) -> Path:
    """Make sure the rockyou2024.txt wordlist exists.

    Args:
        path: Desired location for the rockyou repo. Defaults to ~/rockyou.
    Returns:
        Path to the rockyou2024.txt file.
    """
    target_file = path / "rockyou2024.txt"
    if not target_file.exists():
        # Try downloading the 2024 version
        # NOTE: RockYou2024 wordlist is large and not included in repository.
        # User must provide download URL or download manually.
        # Common sources: GitHub releases, security research repositories, or torrents.
        print(f"[!] RockYou2024 wordlist not found at {target_file}")
        print("[!] Please download rockyou2024.txt manually or provide download URL")
        print("[!] The file is typically several GB in size")
        raise FileNotFoundError(f"RockYou2024 wordlist not found. Please download to: {target_file}")

    return target_file
