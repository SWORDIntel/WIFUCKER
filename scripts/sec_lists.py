# sec_lists.py
"""Utility to ensure SecLists wordlist repository is available.
If the repository is not present in the expected location, it will be cloned using git.
The function returns the absolute path to the SecLists directory.
"""
import os
import subprocess
from pathlib import Path

DEFAULT_SECLISTS_PATH = Path.home() / "SecLists"


def ensure_seclists(path: Path = DEFAULT_SECLISTS_PATH) -> Path:
    """Make sure the SecLists repository exists.

    Args:
        path: Desired location for the SecLists repo. Defaults to ~/SecLists.
    Returns:
        Path to the SecLists directory.
    """
    if not path.exists():
        # Clone the repository (shallow clone for speed)
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "https://github.com/danielmiessler/SecLists",
                    str(path),
                ],
                check=True,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to clone SecLists repository: {e}")
    return path
