#!/usr/bin/env python3
"""
WiGLE API Integration
=====================

Integration with WiGLE (Wireless Geographic Logging Engine) for
SSID geolocation lookups and network intelligence gathering.
"""

import requests
import time
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path
import json
from cryptography.fernet import Fernet


@dataclass
class SSIDLocation:
    """Represents a WiFi network location from WiGLE."""
    ssid: str
    bssid: str
    latitude: float
    longitude: float
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    encryption: Optional[str] = None

    def __str__(self):
        location_str = f"{self.city}, {self.region}, {self.country}" if self.city else "Unknown"
        return f"{self.ssid} ({self.bssid}): {location_str} @ ({self.latitude:.6f}, {self.longitude:.6f})"


class WiGLEAPI:
    """
    WiGLE API client for WiFi network geolocation.

    Requires WiGLE API credentials (free account available at https://wigle.net)
    """

    API_BASE_URL = "https://api.wigle.net/api/v2"

    def __init__(
        self,
        api_name: Optional[str] = None,
        api_token: Optional[str] = None,
        credentials_file: Optional[str] = None,
        rate_limit_delay: float = 1.0
    ):
        """
        Initialize WiGLE API client.

        Args:
            api_name: WiGLE API name (username)
            api_token: WiGLE API token
            credentials_file: Path to encrypted credentials file
            rate_limit_delay: Delay between API calls (seconds)
        """
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = 0

        # Load credentials
        if credentials_file:
            self.api_name, self.api_token = self._load_encrypted_credentials(credentials_file)
        elif api_name and api_token:
            self.api_name = api_name
            self.api_token = api_token
        else:
            self.api_name = None
            self.api_token = None

        self.session = requests.Session()
        if self.api_name and self.api_token:
            self.session.auth = (self.api_name, self.api_token)

    def _rate_limit(self):
        """Enforce rate limiting between API calls."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    def _get_encryption_key(self) -> bytes:
        """
        Get or generate encryption key for Fernet.
        
        Uses a key file in the same directory as credentials, or generates one.
        
        Returns:
            Fernet encryption key
        """
        import os
        import base64
        
        # Key file path: same directory as credentials, named .wigle_key
        key_file = Path.home() / ".wigle_key"
        
        if key_file.exists():
            # Load existing key
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            # Save key file with restricted permissions
            key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Read/write for owner only
            return key

    def _load_encrypted_credentials(self, file_path: str) -> tuple:
        """
        Load encrypted WiGLE credentials from file using Fernet encryption.

        Args:
            file_path: Path to encrypted credentials file

        Returns:
            Tuple of (api_name, api_token)
        """
        try:
            cred_path = Path(file_path)
            if not cred_path.exists():
                raise FileNotFoundError(f"Credentials file not found: {file_path}")

            # Load encrypted data
            with open(cred_path, 'rb') as f:
                encrypted_data = f.read()

            # Try Fernet decryption first
            try:
                key = self._get_encryption_key()
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(encrypted_data)
                data = json.loads(decrypted_data.decode('utf-8'))
                return data.get('api_name'), data.get('api_token')
            except Exception:
                # Fallback: try plain JSON (for backward compatibility with unencrypted files)
                try:
                    data = json.loads(encrypted_data.decode('utf-8'))
                    return data.get('api_name'), data.get('api_token')
                except (json.JSONDecodeError, UnicodeDecodeError):
                    raise ValueError("Credentials file format not recognized - expected Fernet-encrypted or JSON")

        except Exception as e:
            print(f"[!] Error loading credentials: {e}")
            return None, None

    def save_encrypted_credentials(
        self,
        file_path: str,
        api_name: str,
        api_token: str
    ):
        """
        Save WiGLE credentials in encrypted format using Fernet encryption.

        Args:
            file_path: Path to save credentials
            api_name: WiGLE API name
            api_token: WiGLE API token
        """
        import os
        
        data = {
            'api_name': api_name,
            'api_token': api_token
        }

        cred_path = Path(file_path)
        cred_path.parent.mkdir(parents=True, exist_ok=True)

        # Encrypt using Fernet
        key = self._get_encryption_key()
        fernet = Fernet(key)
        json_data = json.dumps(data).encode('utf-8')
        encrypted_data = fernet.encrypt(json_data)

        # Write encrypted data
        with open(cred_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Set restrictive permissions
        os.chmod(cred_path, 0o600)  # Read/write for owner only

        print(f"[+] Encrypted credentials saved to: {file_path}")

    def search_ssid(self, ssid: str, max_results: int = 10) -> List[SSIDLocation]:
        """
        Search for WiFi network by SSID.

        Args:
            ssid: Network SSID to search for
            max_results: Maximum number of results

        Returns:
            List of SSIDLocation objects
        """
        if not self.api_name or not self.api_token:
            print("[!] WiGLE API credentials not configured")
            return []

        self._rate_limit()

        endpoint = f"{self.API_BASE_URL}/network/search"
        params = {
            'ssid': ssid,
            'first': 0,
            'freenet': 'false',
            'paynet': 'false',
            'resultsPerPage': max_results
        }

        try:
            response = self.session.get(endpoint, params=params)
            response.raise_for_status()

            data = response.json()

            if not data.get('success'):
                print(f"[!] WiGLE API error: {data.get('message', 'Unknown error')}")
                return []

            results = []
            for result in data.get('results', []):
                location = SSIDLocation(
                    ssid=result.get('ssid', ''),
                    bssid=result.get('netid', ''),
                    latitude=result.get('trilat', 0.0),
                    longitude=result.get('trilong', 0.0),
                    country=result.get('country', None),
                    region=result.get('region', None),
                    city=result.get('city', None),
                    first_seen=result.get('firsttime', None),
                    last_seen=result.get('lasttime', None),
                    encryption=result.get('encryption', None)
                )
                results.append(location)

            return results

        except requests.exceptions.RequestException as e:
            print(f"[!] WiGLE API request failed: {e}")
            return []

    def search_bssid(self, bssid: str) -> Optional[SSIDLocation]:
        """
        Search for WiFi network by BSSID (MAC address).

        Args:
            bssid: Network BSSID to search for

        Returns:
            SSIDLocation object or None
        """
        if not self.api_name or not self.api_token:
            print("[!] WiGLE API credentials not configured")
            return None

        self._rate_limit()

        endpoint = f"{self.API_BASE_URL}/network/detail"
        params = {'netid': bssid}

        try:
            response = self.session.get(endpoint, params=params)
            response.raise_for_status()

            data = response.json()

            if not data.get('success'):
                return None

            results = data.get('results', [])
            if not results:
                return None

            result = results[0]
            location = SSIDLocation(
                ssid=result.get('ssid', ''),
                bssid=result.get('netid', ''),
                latitude=result.get('trilat', 0.0),
                longitude=result.get('trilong', 0.0),
                country=result.get('country', None),
                region=result.get('region', None),
                city=result.get('city', None),
                first_seen=result.get('firsttime', None),
                last_seen=result.get('lasttime', None),
                encryption=result.get('encryption', None)
            )

            return location

        except requests.exceptions.RequestException as e:
            print(f"[!] WiGLE API request failed: {e}")
            return None

    def search_location(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 1.0,
        max_results: int = 100
    ) -> List[SSIDLocation]:
        """
        Search for WiFi networks near a location.

        Args:
            latitude: Center latitude
            longitude: Center longitude
            radius_km: Search radius in kilometers
            max_results: Maximum number of results

        Returns:
            List of SSIDLocation objects
        """
        if not self.api_name or not self.api_token:
            print("[!] WiGLE API credentials not configured")
            return []

        self._rate_limit()

        endpoint = f"{self.API_BASE_URL}/network/search"
        params = {
            'latrange1': latitude - (radius_km / 111.0),  # ~111km per degree
            'latrange2': latitude + (radius_km / 111.0),
            'longrange1': longitude - (radius_km / 111.0),
            'longrange2': longitude + (radius_km / 111.0),
            'freenet': 'false',
            'paynet': 'false',
            'resultsPerPage': max_results
        }

        try:
            response = self.session.get(endpoint, params=params)
            response.raise_for_status()

            data = response.json()

            if not data.get('success'):
                return []

            results = []
            for result in data.get('results', []):
                location = SSIDLocation(
                    ssid=result.get('ssid', ''),
                    bssid=result.get('netid', ''),
                    latitude=result.get('trilat', 0.0),
                    longitude=result.get('trilong', 0.0),
                    country=result.get('country', None),
                    region=result.get('region', None),
                    city=result.get('city', None),
                    first_seen=result.get('firsttime', None),
                    last_seen=result.get('lasttime', None),
                    encryption=result.get('encryption', None)
                )
                results.append(location)

            return results

        except requests.exceptions.RequestException as e:
            print(f"[!] WiGLE API request failed: {e}")
            return []

    def get_api_status(self) -> Dict:
        """
        Get WiGLE API account status and usage.

        Returns:
            Dictionary with account statistics
        """
        if not self.api_name or not self.api_token:
            return {"error": "Credentials not configured"}

        self._rate_limit()

        endpoint = f"{self.API_BASE_URL}/profile/user"

        try:
            response = self.session.get(endpoint)
            response.raise_for_status()

            data = response.json()

            if data.get('success'):
                user_data = data.get('user', {})
                return {
                    'username': user_data.get('userid', ''),
                    'rank': user_data.get('rank', ''),
                    'monthly_queries': user_data.get('monthcount', 0),
                    'monthly_limit': user_data.get('monthlimit', 0),
                    'daily_queries': user_data.get('dailycount', 0),
                    'daily_limit': user_data.get('dailylimit', 0),
                }
            else:
                return {"error": data.get('message', 'Unknown error')}

        except requests.exceptions.RequestException as e:
            return {"error": str(e)}


# Example usage
if __name__ == "__main__":
    # Example: Search for SSID
    wigle = WiGLEAPI()

    # Check if credentials are configured
    status = wigle.get_api_status()
    if "error" in status:
        print(f"[!] {status['error']}")
        print("\n[*] To use WiGLE API:")
        print("    1. Create free account at https://wigle.net")
        print("    2. Generate API token in account settings")
        print("    3. Configure credentials:")
        print("       wigle.save_encrypted_credentials('~/.wigle_creds.json', 'API_NAME', 'API_TOKEN')")
    else:
        print(f"[+] WiGLE Account: {status['username']}")
        print(f"[+] Daily queries: {status['daily_queries']}/{status['daily_limit']}")
        print(f"[+] Monthly queries: {status['monthly_queries']}/{status['monthly_limit']}")

        # Example search
        results = wigle.search_ssid("Starbucks", max_results=5)
        print(f"\n[+] Found {len(results)} results:")
        for loc in results:
            print(f"  {loc}")
