#!/usr/bin/env python3
"""
Wordlist Downloader for WiFi Cracking
======================================

Downloads popular password lists from GitHub and other sources.

Popular sources:
- SecLists (danielmiessler/SecLists)
- weakpass.com
- CrackStation
- RockYou
- WiFi-specific wordlists

Features:
- Automatic download from GitHub
- Progress tracking
- Deduplication
- Format conversion
"""

import os
import requests
import gzip
import shutil
from typing import List, Optional, Dict
from pathlib import Path
from tqdm import tqdm


class WordlistDownloader:
    """
    Downloads and manages password wordlists from various sources.
    """

    # Popular GitHub wordlist repositories
    GITHUB_SOURCES = {
        'seclists_wifi': {
            'name': 'SecLists WiFi Passwords',
            'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt',
            'filename': 'seclists_wifi_top4800.txt',
            'description': 'Top 4800 probable WiFi passwords from SecLists'
        },
        'seclists_common': {
            'name': 'SecLists Common Passwords',
            'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
            'filename': 'seclists_common_1m.txt',
            'description': 'Top 1 million common passwords from SecLists'
        },
        'berzerk0_probable': {
            'name': 'Probable Wordlists WiFi',
            'url': 'https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/WPA-Length/Top1575-probable-v2-wpa-length.txt',
            'filename': 'berzerk0_wifi_top1575.txt',
            'description': 'Top 1575 WPA-length passwords'
        },
        'weakpass_online': {
            'name': 'WeakPass Online Top 100',
            'url': 'https://weakpass.com/wordlist/90',  # Example URL
            'filename': 'weakpass_top100.txt',
            'description': 'Top 100 most common passwords'
        }
    }

    def __init__(self, download_dir: str = "./wordlists"):
        """
        Initialize wordlist downloader.

        Args:
            download_dir: Directory to store downloaded wordlists
        """
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)

        print(f"[*] Wordlist directory: {self.download_dir}")

    def download_all(self, force: bool = False):
        """
        Download all available wordlists.

        Args:
            force: Force re-download even if file exists
        """
        print("\n[*] Downloading popular wordlists from GitHub...")

        for key, source in self.GITHUB_SOURCES.items():
            self.download_wordlist(key, force=force)

    def download_wordlist(self, source_key: str, force: bool = False) -> Optional[str]:
        """
        Download a specific wordlist.

        Args:
            source_key: Key from GITHUB_SOURCES
            force: Force re-download

        Returns:
            Path to downloaded file or None on failure
        """
        if source_key not in self.GITHUB_SOURCES:
            print(f"[-] Unknown source: {source_key}")
            return None

        source = self.GITHUB_SOURCES[source_key]
        output_path = self.download_dir / source['filename']

        # Check if already exists
        if output_path.exists() and not force:
            print(f"[*] {source['name']} already exists: {output_path}")
            return str(output_path)

        print(f"\n[*] Downloading {source['name']}...")
        print(f"    URL: {source['url']}")
        print(f"    Description: {source['description']}")

        try:
            # Download with progress bar
            response = requests.get(source['url'], stream=True)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))

            with open(output_path, 'wb') as f, tqdm(
                total=total_size,
                unit='B',
                unit_scale=True,
                desc=source['filename']
            ) as pbar:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))

            # Count lines
            with open(output_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)

            print(f"[+] Downloaded: {output_path}")
            print(f"[+] Passwords: {line_count:,}")

            return str(output_path)

        except requests.exceptions.RequestException as e:
            print(f"[-] Download failed: {e}")
            return None

    def download_rockyou(self, force: bool = False) -> Optional[str]:
        """
        Download RockYou wordlist.

        Note: RockYou is very large (~14GB uncompressed).
        This provides information on how to obtain it.

        Args:
            force: Not used, kept for interface consistency

        Returns:
            Path if available locally, None otherwise
        """
        rockyou_path = self.download_dir / "rockyou.txt"

        if rockyou_path.exists():
            print(f"[+] RockYou found: {rockyou_path}")
            return str(rockyou_path)

        print("\n[*] RockYou Wordlist Information:")
        print("    RockYou is a 14GB wordlist with 14 million+ passwords")
        print("    It's not automatically downloaded due to its size")
        print("\n    To obtain RockYou:")
        print("    1. On Kali Linux: /usr/share/wordlists/rockyou.txt.gz")
        print("    2. Download from: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
        print("    3. Or use: wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
        print(f"    4. Place in: {self.download_dir}/rockyou.txt")

        return None

    def create_combined_list(
        self,
        sources: List[str],
        output_name: str = "combined.txt",
        deduplicate: bool = True
    ) -> str:
        """
        Combine multiple wordlists into one.

        Args:
            sources: List of source keys or file paths
            output_name: Name of combined output file
            deduplicate: Remove duplicates

        Returns:
            Path to combined wordlist
        """
        print(f"\n[*] Creating combined wordlist: {output_name}")

        output_path = self.download_dir / output_name

        if deduplicate:
            passwords = set()
        else:
            passwords = []

        # Read all sources
        for source in sources:
            # Check if it's a source key or file path
            if source in self.GITHUB_SOURCES:
                file_path = self.download_dir / self.GITHUB_SOURCES[source]['filename']
            else:
                file_path = Path(source)

            if not file_path.exists():
                print(f"[!] Warning: {file_path} not found, skipping")
                continue

            print(f"[*] Reading: {file_path}")

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password:
                        if deduplicate:
                            passwords.add(password)
                        else:
                            passwords.append(password)

        # Write combined list
        print(f"[*] Writing combined list...")

        if deduplicate:
            passwords = sorted(passwords)  # Sort for consistency

        with open(output_path, 'w', encoding='utf-8') as f:
            for password in passwords:
                f.write(password + '\n')

        print(f"[+] Combined wordlist created: {output_path}")
        print(f"[+] Total passwords: {len(passwords):,}")

        return str(output_path)

    def list_available(self):
        """List all available wordlist sources"""
        print("\n" + "="*70)
        print("AVAILABLE WORDLIST SOURCES")
        print("="*70)

        for i, (key, source) in enumerate(self.GITHUB_SOURCES.items(), 1):
            output_path = self.download_dir / source['filename']
            status = "✓ Downloaded" if output_path.exists() else "✗ Not downloaded"

            print(f"\n{i}. {source['name']}")
            print(f"   Key: {key}")
            print(f"   Description: {source['description']}")
            print(f"   Status: {status}")
            print(f"   File: {source['filename']}")

        print("\n" + "="*70 + "\n")

    def get_wordlist_info(self, wordlist_path: str) -> Dict:
        """
        Get information about a wordlist.

        Args:
            wordlist_path: Path to wordlist file

        Returns:
            Dictionary with wordlist statistics
        """
        path = Path(wordlist_path)

        if not path.exists():
            return {'error': 'File not found'}

        # Count lines and get size
        line_count = 0
        min_length = float('inf')
        max_length = 0
        total_length = 0

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if password:
                    line_count += 1
                    length = len(password)
                    min_length = min(min_length, length)
                    max_length = max(max_length, length)
                    total_length += length

        avg_length = total_length / line_count if line_count > 0 else 0
        file_size = path.stat().st_size

        info = {
            'path': str(path),
            'filename': path.name,
            'passwords': line_count,
            'file_size': file_size,
            'file_size_mb': file_size / (1024 * 1024),
            'min_length': min_length if min_length != float('inf') else 0,
            'max_length': max_length,
            'avg_length': avg_length
        }

        print(f"\n[*] Wordlist Information: {path.name}")
        print(f"    Total passwords: {info['passwords']:,}")
        print(f"    File size: {info['file_size_mb']:.2f} MB")
        print(f"    Password length: {info['min_length']}-{info['max_length']} (avg: {info['avg_length']:.1f})")

        return info


def main():
    """Example usage"""
    print("""
╔════════════════════════════════════════════════════════════╗
║        Wordlist Downloader for WiFi Cracking              ║
║      Downloads popular password lists from GitHub         ║
╚════════════════════════════════════════════════════════════╝
    """)

    downloader = WordlistDownloader()

    # List available sources
    downloader.list_available()

    # Download all wordlists
    response = input("\nDownload all wordlists? (y/n): ")
    if response.lower() == 'y':
        downloader.download_all()

        # Create combined list
        print("\n[*] Creating combined WiFi wordlist...")
        combined = downloader.create_combined_list(
            ['seclists_wifi', 'berzerk0_probable'],
            output_name='wifi_combined.txt',
            deduplicate=True
        )

        # Show info
        downloader.get_wordlist_info(combined)

    # RockYou info
    downloader.download_rockyou()


if __name__ == '__main__':
    main()
