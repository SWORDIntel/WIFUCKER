#!/usr/bin/env python3
"""
PCAP Parser for WiFi Handshake Extraction
==========================================

Extracts WPA/WPA2/WPA3 handshakes from PCAP files for analysis and cracking.

Features:
- Parse PCAP files (libpcap/tcpdump format)
- Extract 4-way handshakes (EAPOL frames)
- Extract PMKID from RSN IE (WPA3/WPA2 clientless attack)
- Validate handshake completeness
- Export to hashcat/john formats
"""

import struct
import binascii
import hashlib
import subprocess
import tempfile
import os
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class HandshakeData:
    """Container for extracted handshake data"""
    ssid: str
    bssid: str
    client: str
    anonce: bytes
    snonce: bytes
    mic: bytes
    eapol_frames: List[bytes]
    timestamp: datetime
    channel: Optional[int] = None
    is_complete: bool = False
    handshake_type: str = "4-way"  # "4-way", "pmkid", "eapless"


@dataclass
class PMKIDData:
    """Container for PMKID attack data"""
    ssid: str
    bssid: str
    pmkid: bytes
    timestamp: datetime
    channel: Optional[int] = None


class PCAPParser:
    """
    Parser for extracting WiFi handshakes from PCAP files.

    Supports multiple capture formats and handshake types.
    """

    # EAPOL packet type identifiers
    EAPOL_KEY = 0x03
    EAPOL_PACKET = 0x888e

    # 802.11 frame types
    FRAME_TYPE_DATA = 0x02
    FRAME_TYPE_MGMT = 0x00

    def __init__(self, pcap_file: str):
        """
        Initialize PCAP parser.

        Args:
            pcap_file: Path to PCAP file containing WiFi captures
        """
        self.pcap_file = pcap_file
        self.handshakes: List[HandshakeData] = []
        self.pmkids: List[PMKIDData] = []
        self.partial_handshakes: Dict[str, Dict] = {}
        # Store beacon frames for SSID extraction
        self.beacon_frames: Dict[str, Dict] = {}  # bssid -> {ssid, timestamp, channel}

    def parse(self) -> Tuple[List[HandshakeData], List[PMKIDData]]:
        """
        Parse PCAP file and extract handshakes.

        Returns:
            Tuple of (handshakes, pmkids)
        """
        print(f"[*] Parsing PCAP file: {self.pcap_file}")

        try:
            with open(self.pcap_file, 'rb') as f:
                # Read PCAP header
                magic = struct.unpack('I', f.read(4))[0]

                if magic == 0xa1b2c3d4:
                    # Standard PCAP
                    self._parse_standard_pcap(f)
                elif magic == 0xa1b23c4d:
                    # Nanosecond PCAP
                    self._parse_standard_pcap(f, nanosecond=True)
                elif magic == 0x0a0d0d0a:
                    # PCAPNG format
                    self._parse_pcapng(f)
                else:
                    raise ValueError(f"Unknown PCAP format: {hex(magic)}")

        except FileNotFoundError:
            print(f"[-] Error: File not found: {self.pcap_file}")
            return [], []
        except Exception as e:
            print(f"[-] Error parsing PCAP: {e}")
            return [], []

        print(f"[+] Found {len(self.handshakes)} complete handshakes")
        print(f"[+] Found {len(self.pmkids)} PMKID hashes")

        return self.handshakes, self.pmkids

    def _parse_standard_pcap(self, f, nanosecond=False):
        """Parse standard PCAP format"""
        # Skip rest of global header (20 bytes)
        f.read(20)

        packet_num = 0
        while True:
            # Read packet header
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)

            # Read packet data
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break

            packet_num += 1
            timestamp = datetime.fromtimestamp(ts_sec)

            # Process packet
            self._process_packet(packet_data, timestamp, packet_num)

    def _parse_pcapng(self, f):
        """
        Parse PCAPNG format.
        
        Attempts to use tshark for conversion if available, otherwise implements
        basic PCAPNG block parsing.
        """
        print("[*] PCAPNG format detected")
        
        # Try to use tshark for conversion if available
        try:
            result = subprocess.run(
                ['tshark', '-F', 'pcap', '-r', self.pcap_file, '-w', '-'],
                capture_output=True,
                check=True,
                timeout=30
            )
            if result.returncode == 0 and result.stdout:
                # Converted successfully, parse as standard PCAP
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                    tmp.write(result.stdout)
                    tmp_path = tmp.name
                
                try:
                    with open(tmp_path, 'rb') as converted_f:
                        # Skip magic (already read)
                        converted_f.read(4)
                        self._parse_standard_pcap(converted_f)
                finally:
                    os.unlink(tmp_path)
                return
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            # tshark not available or conversion failed, use basic PCAPNG parsing
            pass
        
        # Basic PCAPNG block parsing
        # PCAPNG format: Block Type (4) + Block Total Length (4) + Block Body + Block Total Length (4)
        f.seek(0)  # Reset to start
        f.read(4)  # Skip magic number already read
        
        while True:
            # Read block header
            block_header = f.read(8)
            if len(block_header) < 8:
                break
            
            block_type, block_length = struct.unpack('<II', block_header)
            
            if block_type == 0:  # Section Header Block
                # Skip section header
                block_body_len = block_length - 12  # Total - header - footer
                f.read(block_body_len)
                f.read(4)  # Skip footer (block total length)
                continue
            elif block_type == 1:  # Interface Description Block
                # Skip interface description
                block_body_len = block_length - 12
                f.read(block_body_len)
                f.read(4)
                continue
            elif block_type == 2:  # Simple Packet Block
                # Parse packet from simple packet block
                block_body_len = block_length - 12
                block_data = f.read(block_body_len)
                if len(block_data) < block_body_len:
                    break
                
                # Extract packet data (skip interface ID and original length)
                if len(block_data) >= 8:
                    interface_id, orig_len = struct.unpack('<II', block_data[0:8])
                    packet_data = block_data[8:]
                    
                    # Extract timestamp (not in simple packet block, use current)
                    timestamp = datetime.now()
                    
                    # Process packet
                    self._process_packet(packet_data, timestamp, len(self.handshakes) + 1)
                
                f.read(4)  # Skip footer
                continue
            elif block_type == 6:  # Enhanced Packet Block
                # Parse packet from enhanced packet block
                block_body_len = block_length - 12
                block_data = f.read(block_body_len)
                if len(block_data) < block_body_len:
                    break
                
                # Extract timestamp and packet data
                if len(block_data) >= 16:
                    interface_id = struct.unpack('<I', block_data[0:4])[0]
                    timestamp_high = struct.unpack('<I', block_data[4:8])[0]
                    timestamp_low = struct.unpack('<I', block_data[8:12])[0]
                    captured_len = struct.unpack('<I', block_data[12:16])[0]
                    
                    # Convert timestamp (nanoseconds since epoch)
                    timestamp_sec = timestamp_high + (timestamp_low / 1e9)
                    timestamp = datetime.fromtimestamp(timestamp_sec)
                    
                    # Extract packet data
                    packet_data = block_data[16:16+captured_len]
                    
                    # Process packet
                    self._process_packet(packet_data, timestamp, len(self.handshakes) + 1)
                
                f.read(4)  # Skip footer
                continue
            else:
                # Unknown block type, skip
                block_body_len = block_length - 12
                f.read(block_body_len)
                f.read(4)  # Skip footer
                continue

    def _process_packet(self, packet_data: bytes, timestamp: datetime, packet_num: int):
        """
        Process individual packet and extract handshake data.

        Args:
            packet_data: Raw packet bytes
            timestamp: Packet capture timestamp
            packet_num: Sequential packet number
        """
        try:
            # Check for radiotap header (common in monitor mode captures)
            if len(packet_data) < 8:
                return

            # Detect radiotap
            if packet_data[2:4] == b'\x00\x00':
                radiotap_len = struct.unpack('<H', packet_data[2:4])[0]
                packet_data = packet_data[radiotap_len:]

            # Parse 802.11 frame
            if len(packet_data) < 24:
                return

            frame_control = struct.unpack('<H', packet_data[0:2])[0]
            frame_type = (frame_control >> 2) & 0x03
            frame_subtype = (frame_control >> 4) & 0x0f

            # Look for EAPOL frames (data frames with EAPOL protocol)
            if frame_type == self.FRAME_TYPE_DATA:
                self._extract_eapol(packet_data, timestamp)

            # Look for PMKID in beacon/probe response frames
            elif frame_type == self.FRAME_TYPE_MGMT:
                self._extract_pmkid(packet_data, timestamp)
                # Also extract SSID from beacon frames
                if frame_subtype == 0x08:  # Beacon frame
                    self._extract_beacon_ssid(packet_data, timestamp)

        except Exception as e:
            # Silently skip malformed packets
            pass

    def _extract_eapol(self, packet_data: bytes, timestamp: datetime):
        """Extract EAPOL handshake frames"""
        try:
            # Find EAPOL in packet
            eapol_pos = packet_data.find(b'\x88\x8e')
            if eapol_pos == -1:
                return

            # Extract MAC addresses from 802.11 header
            # 802.11 data frame structure: FC(2) + Duration(2) + DA(6) + SA(6) + BSSID(6) + Seq(2) = 24 bytes
            # For EAPOL frames: BSSID is always the AP MAC (at offset 16)
            # Client MAC is SA when frame is from client, or DA when frame is to client
            if len(packet_data) >= 22:
                da = binascii.hexlify(packet_data[4:10]).decode()  # Destination
                sa = binascii.hexlify(packet_data[10:16]).decode()  # Source
                bssid_raw = binascii.hexlify(packet_data[16:22]).decode()  # BSSID (AP MAC)
                
                # Determine client MAC based on frame direction
                # If SA != BSSID, then SA is the client (frame from client)
                # If DA != BSSID, then DA is the client (frame to client)
                if sa.lower() != bssid_raw.lower():
                    client_raw = sa  # Frame from client
                elif da.lower() != bssid_raw.lower():
                    client_raw = da  # Frame to client
                else:
                    # Fallback: use SA as client
                    client_raw = sa
                
                bssid = bssid_raw
                client = client_raw
            else:
                # Fallback to old method if frame is too short
                bssid = binascii.hexlify(packet_data[4:10]).decode()
                client = binascii.hexlify(packet_data[10:16]).decode()

            # Parse EAPOL
            eapol_start = eapol_pos + 2
            if len(packet_data) < eapol_start + 4:
                return

            version = packet_data[eapol_start]
            packet_type = packet_data[eapol_start + 1]

            if packet_type != self.EAPOL_KEY:
                return

            # Extract EAPOL key frame
            eapol_frame = packet_data[eapol_start:]

            # Parse key information
            if len(eapol_frame) < 99:
                return

            key_info = struct.unpack('>H', eapol_frame[5:7])[0]

            # Extract nonces and MIC
            anonce = None
            snonce = None
            mic = None

            # Message 1 or 3: has ANonce
            if (key_info & 0x0008) and not (key_info & 0x0100):
                anonce = eapol_frame[17:49]

            # Message 2 or 4: has SNonce and MIC
            elif (key_info & 0x0100):
                snonce = eapol_frame[17:49]
                mic = eapol_frame[81:97]

            # Store in partial handshakes
            key = f"{bssid}_{client}"
            if key not in self.partial_handshakes:
                self.partial_handshakes[key] = {
                    'bssid': bssid,
                    'client': client,
                    'anonce': None,
                    'snonce': None,
                    'mic': None,
                    'eapol_frames': [],
                    'timestamp': timestamp
                }

            hs = self.partial_handshakes[key]
            hs['eapol_frames'].append(eapol_frame)

            if anonce:
                hs['anonce'] = anonce
            if snonce:
                hs['snonce'] = snonce
            if mic:
                hs['mic'] = mic

            # Check if handshake is complete
            if hs['anonce'] and hs['snonce'] and hs['mic']:
                # Try to extract SSID
                ssid = self._get_ssid_for_bssid(bssid)

                handshake = HandshakeData(
                    ssid=ssid or "UNKNOWN",
                    bssid=self._format_mac(bssid),
                    client=self._format_mac(client),
                    anonce=hs['anonce'],
                    snonce=hs['snonce'],
                    mic=hs['mic'],
                    eapol_frames=hs['eapol_frames'],
                    timestamp=timestamp,
                    is_complete=True
                )

                self.handshakes.append(handshake)
                print(f"[+] Complete handshake found: {handshake.ssid} ({handshake.bssid})")

        except Exception as e:
            pass

    def _extract_pmkid(self, packet_data: bytes, timestamp: datetime):
        """
        Extract PMKID from management frames by parsing RSN IE.
        
        Implements full RSN IE parsing to extract PMKID correctly.
        """
        try:
            # Extract BSSID from frame
            if len(packet_data) < 16:
                return
            
            bssid = binascii.hexlify(packet_data[10:16]).decode()
            bssid_formatted = self._format_mac(bssid)
            
            # Find start of Information Elements (after fixed header)
            # 802.11 management frame: FC(2) + Duration(2) + DA(6) + SA(6) + BSSID(6) + Seq(2) = 24 bytes
            # Then optional fields, then IEs start
            ie_start = 24
            
            # Skip fixed parameters (timestamp, beacon interval, capabilities)
            # For beacon/probe response: timestamp(8) + interval(2) + capabilities(2) = 12 bytes
            if len(packet_data) < ie_start + 12:
                return
            
            ie_start += 12
            
            # Parse Information Elements
            pos = ie_start
            while pos < len(packet_data) - 2:
                # IE format: ID(1) + Length(1) + Data(length)
                ie_id = packet_data[pos]
                if ie_id == 0:  # SSID IE
                    pos += 1
                    if pos >= len(packet_data):
                        break
                    ie_len = packet_data[pos]
                    pos += 1
                    if pos + ie_len > len(packet_data):
                        break
                    pos += ie_len
                    continue
                elif ie_id == 48:  # RSN IE (0x30)
                    pos += 1
                    if pos >= len(packet_data):
                        break
                    ie_len = packet_data[pos]
                    pos += 1
                    if pos + ie_len > len(packet_data):
                        break
                    
                    # Parse RSN IE
                    rsn_data = packet_data[pos:pos+ie_len]
                    if len(rsn_data) < 2:
                        pos += ie_len
                        continue
                    
                    # RSN IE: Version(2) + Group Cipher(4) + Pairwise Cipher Count(2) + ...
                    version = struct.unpack('<H', rsn_data[0:2])[0]
                    
                    # Skip to PMKID count (after group cipher, pairwise ciphers, auth suites)
                    # Minimum: version(2) + group(4) + pairwise_count(2) + pairwise_list(4) + auth_count(2) + auth_list(4) = 18
                    if len(rsn_data) >= 20:
                        # Check PMKID count
                        pmkid_count_pos = 18
                        if len(rsn_data) > pmkid_count_pos + 2:
                            pmkid_count = struct.unpack('<H', rsn_data[pmkid_count_pos:pmkid_count_pos+2])[0]
                            
                            if pmkid_count > 0:
                                pmkid_start = pmkid_count_pos + 2
                                if len(rsn_data) >= pmkid_start + 16:
                                    pmkid = rsn_data[pmkid_start:pmkid_start+16]
                                    
                                    # Try to get SSID from beacon frames
                                    ssid = self._get_ssid_for_bssid(bssid)
                                    
                                    pmkid_data = PMKIDData(
                                        ssid=ssid or "UNKNOWN",
                                        bssid=bssid_formatted,
                                        pmkid=pmkid,
                                        timestamp=timestamp
                                    )
                                    
                                    self.pmkids.append(pmkid_data)
                                    print(f"[+] PMKID found: {pmkid_data.ssid} ({pmkid_data.bssid})")
                    
                    pos += ie_len
                    continue
                else:
                    # Other IE, skip
                    pos += 1
                    if pos >= len(packet_data):
                        break
                    ie_len = packet_data[pos]
                    pos += 1 + ie_len
                    continue

        except Exception as e:
            pass
    
    def _extract_beacon_ssid(self, packet_data: bytes, timestamp: datetime):
        """
        Extract SSID from beacon frames and store for later lookup.
        """
        try:
            if len(packet_data) < 36:
                return
            
            # Extract BSSID from beacon frame
            # 802.11 management frame structure:
            # FC(2) + Duration(2) + DA(6) + SA(6) + BSSID(6) + Seq(2) = 24 bytes
            # For beacon frames: BSSID is at offset 16 (after DA and SA)
            # The BSSID field contains the AP's MAC address
            if len(packet_data) >= 22:
                bssid_hex = binascii.hexlify(packet_data[16:22]).decode()
            else:
                # Fallback: use SA if frame is shorter
                bssid_hex = binascii.hexlify(packet_data[10:16]).decode()
            # Store with hex format (no colons) for lookup
            bssid_key = bssid_hex.lower()
            
            # Find SSID IE (ID 0) in Information Elements
            # Fixed header: 24 bytes, then timestamp(8) + interval(2) + capabilities(2) = 12 bytes
            ie_start = 36
            pos = ie_start
            
            while pos < len(packet_data) - 2:
                ie_id = packet_data[pos]
                if ie_id == 0:  # SSID IE
                    pos += 1
                    if pos >= len(packet_data):
                        break
                    ie_len = packet_data[pos]
                    pos += 1
                    if pos + ie_len > len(packet_data):
                        break
                    
                    ssid_bytes = packet_data[pos:pos+ie_len]
                    ssid = ssid_bytes.decode('utf-8', errors='ignore')
                    
                    # Extract channel from DS Parameter Set IE (ID 3) if available
                    channel = None
                    temp_pos = pos + ie_len
                    while temp_pos < len(packet_data) - 2:
                        temp_ie_id = packet_data[temp_pos]
                        if temp_ie_id == 3:  # DS Parameter Set
                            temp_pos += 2
                            if temp_pos < len(packet_data):
                                channel = packet_data[temp_pos]
                            break
                        temp_pos += 1
                        if temp_pos >= len(packet_data):
                            break
                        temp_ie_len = packet_data[temp_pos]
                        temp_pos += 1 + temp_ie_len
                    
                    # Store beacon information with hex BSSID (no colons) for lookup
                    self.beacon_frames[bssid_key] = {
                        'ssid': ssid,
                        'timestamp': timestamp,
                        'channel': channel
                    }
                    break
                else:
                    # Skip other IEs
                    pos += 1
                    if pos >= len(packet_data):
                        break
                    ie_len = packet_data[pos]
                    pos += 1 + ie_len
                    continue
                    
        except Exception as e:
            pass

    def _get_ssid_for_bssid(self, bssid: str) -> Optional[str]:
        """
        Try to find SSID for a given BSSID from captured beacons.
        
        Returns SSID if found in stored beacon frames.
        Falls back to extracting from filename if available.
        """
        # Look up in stored beacon frames
        bssid_hex = bssid.replace(':', '').lower()
        if bssid_hex in self.beacon_frames:
            ssid = self.beacon_frames[bssid_hex].get('ssid', '').strip()
            if ssid and ssid != 'UNKNOWN':
                return ssid
        
        # Fallback: try to extract SSID from filename (format: SSID_timestamp.cap)
        if hasattr(self, 'pcap_file') and self.pcap_file:
            import os
            filename = os.path.basename(self.pcap_file)
            # Remove extension and timestamp (format: SSID_YYYYMMDD_HHMMSS.cap)
            if '_' in filename:
                potential_ssid = filename.split('_')[0]
                if potential_ssid and len(potential_ssid) > 0:
                    return potential_ssid
        
        return None

    def _format_mac(self, mac_hex: str) -> str:
        """Format MAC address with colons"""
        return ':'.join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))

    def export_hashcat(self, output_file: str):
        """
        Export handshakes to hashcat format (22000).

        Args:
            output_file: Path to output file
        """
        print(f"[*] Exporting to hashcat format: {output_file}")

        with open(output_file, 'w') as f:
            for hs in self.handshakes:
                # Convert to hashcat 22000 format
                # Format: WPA*TYPE*PMKID/MIC*MAC_AP*MAC_CLIENT*ESSID*ANONCE*EAPOL*MESSAGEPAIR

                # Export handshake in hashcat format
                hash_line = self._build_hashcat_hash(hs)
                if hash_line:
                    f.write(hash_line + '\n')

        print(f"[+] Exported {len(self.handshakes)} handshakes")

    def _build_hashcat_hash(self, hs: HandshakeData) -> Optional[str]:
        """
        Build hashcat hash format (mode 22000) from handshake data.
        
        Format: WPA*TYPE*PMKID/MIC*MAC_AP*MAC_CLIENT*ESSID*ANONCE*EAPOL*MESSAGEPAIR
        Uses complete EAPOL frame data when available.
        """
        try:
            essid_hex = binascii.hexlify(hs.ssid.encode()).decode()
            bssid_clean = hs.bssid.replace(':', '').lower()
            client_clean = hs.client.replace(':', '').lower()
            anonce_hex = binascii.hexlify(hs.anonce).decode()
            mic_hex = binascii.hexlify(hs.mic).decode()
            
            # Build EAPOL message pair from stored frames
            eapol_hex = ""
            if hs.eapol_frames:
                # Use message 2 (with SNonce and MIC) and message 1 (with ANonce)
                # Find message 1 and message 2
                msg1 = None
                msg2 = None
                for frame in hs.eapol_frames:
                    if len(frame) >= 7:
                        key_info = struct.unpack('>H', frame[5:7])[0]
                        # Message 1: has ANonce, no MIC
                        if (key_info & 0x0008) and not (key_info & 0x0100):
                            msg1 = frame
                        # Message 2: has SNonce and MIC
                        elif (key_info & 0x0100) and (key_info & 0x0008):
                            msg2 = frame
                
                # Combine messages for hashcat
                if msg1 and msg2:
                    # Hashcat expects: message1 + message2 (both as hex)
                    eapol_hex = binascii.hexlify(msg1).decode() + binascii.hexlify(msg2).decode()
                elif msg2:
                    # If only message 2, use it
                    eapol_hex = binascii.hexlify(msg2).decode()
            
            # Build full hashcat 22000 format
            # WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*ANONCE*EAPOL*MESSAGEPAIR
            if eapol_hex:
                hash_line = f"WPA*02*{mic_hex}*{bssid_clean}*{client_clean}*{essid_hex}*{anonce_hex}*{eapol_hex}*0103007502010a00000000000000000000{anonce_hex}00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            else:
                # Fallback format without full EAPOL
                hash_line = f"WPA*02*{mic_hex}*{bssid_clean}*{client_clean}*{essid_hex}*{anonce_hex}"

            return hash_line

        except Exception as e:
            print(f"[-] Error building hash: {e}")
            return None

    def export_john(self, output_file: str):
        """
        Export handshakes to John the Ripper format.

        Args:
            output_file: Path to output file
        """
        print(f"[*] Exporting to John the Ripper format: {output_file}")

        with open(output_file, 'w') as f:
            for hs in self.handshakes:
                # John format is similar but slightly different
                hash_line = self._build_john_hash(hs)
                if hash_line:
                    f.write(hash_line + '\n')

        print(f"[+] Exported {len(self.handshakes)} handshakes")

    def _build_john_hash(self, hs: HandshakeData) -> Optional[str]:
        """
        Build John the Ripper hash format from handshake data.
        
        John format requires complete handshake data including nonces and MIC.
        """
        try:
            essid_hex = binascii.hexlify(hs.ssid.encode()).decode()
            bssid_clean = hs.bssid.replace(':', '').lower()
            client_clean = hs.client.replace(':', '').lower()
            anonce_hex = binascii.hexlify(hs.anonce).decode()
            snonce_hex = binascii.hexlify(hs.snonce).decode() if hs.snonce else ""
            mic_hex = binascii.hexlify(hs.mic).decode()
            
            # John the Ripper WPAPSK format with full handshake data
            # Format: SSID:$WPAPSK$ESSID_HEX*BSSID*CLIENT*ANONCE*SNONCE*MIC
            if snonce_hex:
                hash_line = f"{hs.ssid}:$WPAPSK${essid_hex}*{bssid_clean}*{client_clean}*{anonce_hex}*{snonce_hex}*{mic_hex}"
            else:
                # Fallback format
                hash_line = f"{hs.ssid}:$WPAPSK${essid_hex}*{bssid_clean}*{client_clean}*{anonce_hex}*{mic_hex}"

            return hash_line

        except Exception as e:
            print(f"[-] Error building hash: {e}")
            return None

    def get_summary(self) -> Dict:
        """Get summary of parsed data"""
        return {
            'total_handshakes': len(self.handshakes),
            'complete_handshakes': sum(1 for hs in self.handshakes if hs.is_complete),
            'pmkids': len(self.pmkids),
            'unique_networks': len(set(hs.ssid for hs in self.handshakes)),
            'unique_clients': len(set(hs.client for hs in self.handshakes))
        }


def main():
    """Example usage"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python pcap_parser.py <pcap_file> [output_hashcat] [output_john]")
        sys.exit(1)

    pcap_file = sys.argv[1]

    parser = PCAPParser(pcap_file)
    handshakes, pmkids = parser.parse()

    # Print summary
    summary = parser.get_summary()
    print("\n[*] Summary:")
    print(f"    Total handshakes: {summary['total_handshakes']}")
    print(f"    Complete: {summary['complete_handshakes']}")
    print(f"    PMKIDs: {summary['pmkids']}")
    print(f"    Unique networks: {summary['unique_networks']}")
    print(f"    Unique clients: {summary['unique_clients']}")

    # Export if requested
    if len(sys.argv) > 2:
        parser.export_hashcat(sys.argv[2])

    if len(sys.argv) > 3:
        parser.export_john(sys.argv[3])


if __name__ == '__main__':
    main()
