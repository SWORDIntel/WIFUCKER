# WiFi Surveillance Detection Module

Advanced probe request monitoring and surveillance detection system based on the **Chasing-Your-Tail-NG** methodology, integrated into DavBest WiFi Security Suite.

## Overview

This module provides **defensive** WiFi security capabilities, allowing you to detect if you're being tracked or surveilled through wireless probe request analysis. It integrates with **Kismet** wireless monitoring and provides multi-factor persistence scoring to identify potential surveillance threats.

## Features

### Core Capabilities

- **Kismet Integration** - Secure database access to Kismet wireless monitoring data
- **Real-time Monitoring** - Continuous probe request tracking with configurable intervals
- **Multi-factor Persistence Scoring** - Advanced algorithms combining:
  - Appearance frequency analysis
  - Geographic distribution patterns
  - Temporal clustering detection
  - Multi-location correlation
- **GPS Location Tracking** - 100-meter clustering and movement pattern analysis
- **WiGLE API Integration** - SSID geolocation lookups for network intelligence
- **Multi-format Reporting** - Markdown, HTML, and KML (Google Earth) outputs

### Detection Methodology

The system uses a **4-level risk classification**:

- 🟢 **NORMAL** (0.0-0.5) - Typical wireless activity
- 🟡 **SUSPICIOUS** (0.6-0.7) - Unusual patterns detected
- ⚠️ **HIGH** (0.8-0.9) - Likely surveillance
- 🚨 **CRITICAL** (0.9-1.0) - Active tracking confirmed

### Time Window Analysis

Implements overlapping time windows for temporal persistence:

- **Recent**: 5 minutes
- **Medium**: 10 minutes
- **Old**: 15 minutes
- **Oldest**: 20 minutes

Devices appearing across multiple windows with regular intervals are flagged for investigation.

## Installation

### Prerequisites

1. **Kismet** wireless monitoring tool:
   ```bash
   sudo apt install kismet
   ```

2. **Python dependencies** (installed automatically):
   ```bash
   pip install -e .
   ```

### Optional: WiGLE API

For SSID geolocation features:

1. Create free account at https://wigle.net
2. Generate API token in account settings
3. Configure credentials:
   ```bash
   davbest-wifi surveillance wigle --setup
   ```

## Usage

### 1. Real-time Monitoring

Monitor Kismet databases in real-time for surveillance detection:

```bash
sudo davbest-wifi surveillance monitor \
    --kismet-dir /var/log/kismet \
    --interval 60 \
    --min-appearances 3 \
    --min-score 0.5 \
    --report \
    --report-dir ./reports
```

**Options:**
- `--kismet-dir` - Kismet database directory (default: /var/log/kismet)
- `--interval` - Check interval in seconds (default: 60)
- `--ignore-file` - File with MAC/SSID ignore list (one per line)
- `--min-appearances` - Minimum appearances for detection (default: 3)
- `--min-score` - Minimum persistence score 0.0-1.0 (default: 0.5)
- `--report` - Generate final report on exit
- `--report-dir` - Report output directory

**Example Output:**
```
[*] Starting Kismet surveillance monitoring
[*] Monitoring: /var/log/kismet
[*] Check interval: 60s
[*] Press Ctrl+C to stop

🚨 THREAT DETECTED: 🚨 AA:BB:CC:DD:EE:FF: Score=0.92 (12 appearances, 4.5h span)
    - High appearance rate: 2.67 times/hour
    - Multiple locations: 5 distinct areas
    - Regular timing: 22.5 min average intervals
    - Rapid movements: 3 quick location changes
```

### 2. Database Analysis

Analyze existing Kismet database for surveillance patterns:

```bash
davbest-wifi surveillance analyze /var/log/kismet/Kismet-20250115.kismet \
    --min-appearances 3 \
    --min-score 0.6 \
    --all-formats \
    --output-dir ./surveillance_reports
```

**Options:**
- `--min-appearances` - Minimum appearances (default: 3)
- `--min-score` - Minimum persistence score (default: 0.5)
- `--markdown` - Generate Markdown report
- `--html` - Generate HTML report
- `--kml` - Generate KML for Google Earth
- `--all-formats` - Generate all report formats
- `--output-dir` - Report output directory

**Example Output:**
```
======================================================================
SURVEILLANCE ANALYSIS RESULTS
======================================================================
  Total Devices:    156
  Suspicious:       8
  High Risk:        3
  Critical Threats: 1
  Location Clusters: 12
======================================================================

DETECTED THREATS:

🚨 AA:BB:CC:DD:EE:FF: Score=0.92 (12 appearances, 4.5h span)
  - High appearance rate: 2.67 times/hour
  - Multiple locations: 5 distinct areas
  - Regular timing: 22.5 min average intervals

[+] Markdown: ./surveillance_reports/surveillance_report_20250115_143022.md
[+] HTML: ./surveillance_reports/surveillance_report_20250115_143022.html
[+] KML: ./surveillance_reports/surveillance_report_20250115_143022.kml
```

### 3. WiGLE API Operations

#### Setup Credentials

```bash
davbest-wifi surveillance wigle --setup
```

#### Check Account Status

```bash
davbest-wifi surveillance wigle --status
```

**Output:**
```
[+] WiGLE Account Status:
  Username:       your_username
  Rank:           Explorer
  Daily Queries:  5/100
  Monthly Queries: 42/1000
```

#### Search for SSID

```bash
davbest-wifi surveillance wigle --search-ssid "Starbucks" --max-results 10
```

#### Search for BSSID

```bash
davbest-wifi surveillance wigle --search-bssid "AA:BB:CC:DD:EE:FF"
```

## Report Formats

### Markdown Reports

Human-readable text reports with:
- Executive summary
- Threat details with risk levels
- Detection reasons
- Location cluster information
- Recommendations

### HTML Reports

Interactive web reports with:
- Color-coded risk levels
- Summary cards with metrics
- Expandable device details
- Styled clusters and locations
- Professional formatting

### KML Reports (Google Earth)

Geographic visualization with:
- Color-coded placemarks by risk level
- Device tracking paths
- Location cluster markers
- Interactive descriptions
- Timeline support

## Ignore Lists

Create ignore lists to filter known devices/networks:

**ignore_list.txt:**
```
AA:BB:CC:DD:EE:01  # Your phone
AA:BB:CC:DD:EE:02  # Your laptop
HomeNetwork        # Your home WiFi
OfficeWiFi         # Your office
```

Usage:
```bash
sudo davbest-wifi surveillance monitor --ignore-file ignore_list.txt
```

## Detection Algorithms

### Persistence Scoring

**Base Score Calculation:**
```
appearance_rate = total_appearances / time_span_hours
base_score = min(appearance_rate / 2.0, 1.0)
```

**Geographic Bonus:**
- +0.3 if device appears in 2+ distinct locations (100m clustering)

**Total Score:**
```
total_score = min(base_score + geographic_bonus, 1.0)
```

### Detection Reasons

The system identifies specific patterns:

1. **High Appearance Rate** - Device appears frequently (>0.5 times/hour)
2. **Multiple Locations** - Device tracked across different areas
3. **Regular Timing** - Low variance in appearance intervals (<1 hour)
4. **Rapid Transitions** - Quick movements between locations (<30 min)
5. **Work Hours Activity** - High concentration during 9 AM - 5 PM
6. **Off-Hours Activity** - Significant late-night appearances (10 PM - 6 AM)
7. **Extended Tracking** - Long-term monitoring (>24 hours)
8. **Multiple SSID Probing** - Device searching for many networks (>5)

## Architecture

```
davbest/wifi/surveillance/
├── __init__.py                    # Module exports
├── kismet_monitor.py              # Kismet database integration
├── probe_tracker.py               # Probe request tracking + time windows
├── persistence_detector.py        # Scoring algorithms
├── location_tracker.py            # GPS correlation + clustering
├── wigle_api.py                   # WiGLE geolocation API
└── report_generator.py            # Multi-format reporting
```

## Integration with DavBest

The surveillance module is **fully integrated** into the main DavBest WiFi CLI:

```bash
davbest-wifi surveillance <command> [options]
```

Available alongside offensive capabilities:
- `capture` - Handshake capture (offensive)
- `crack` - Password cracking (offensive)
- `surveillance` - Threat detection (defensive) ← **NEW!**

## Example Workflow

### Complete Surveillance Detection Session

```bash
# 1. Start Kismet (in separate terminal)
sudo kismet -c wlan0

# 2. Create ignore list
cat > ignore.txt <<EOF
AA:BB:CC:DD:EE:01  # My phone
HomeNetwork
EOF

# 3. Monitor in real-time
sudo davbest-wifi surveillance monitor \
    --interval 30 \
    --ignore-file ignore.txt \
    --min-score 0.6 \
    --report \
    --report-dir ./reports

# Let it run for several hours...
# Press Ctrl+C when done

# 4. Review generated reports
firefox ./reports/surveillance_report_*.html

# Open KML in Google Earth
google-earth-pro ./reports/surveillance_report_*.kml

# 5. Investigate suspicious SSIDs with WiGLE
davbest-wifi surveillance wigle --search-ssid "SuspiciousNetwork"
```

## Best Practices

### For Accurate Detection

1. **Use GPS** - Enable GPS on Kismet for location tracking:
   ```bash
   sudo kismet -c wlan0 --override gps=gpsd:host=localhost,port=2947
   ```

2. **Run Long Sessions** - Longer monitoring periods (4-8 hours) improve accuracy

3. **Maintain Ignore Lists** - Filter out your own devices and known networks

4. **Multiple Locations** - Move around to identify persistent followers

5. **Review All Formats** - Check Markdown for details, HTML for overview, KML for geography

### Security Considerations

- **Authorized Use Only** - This is a defensive tool for personal security
- **Privacy** - Reports may contain sensitive location data - store securely
- **Kismet Permissions** - Kismet requires root, ensure proper system security
- **WiGLE Rate Limits** - Respect API limits (typically 100/day free tier)

## Troubleshooting

### "No Kismet databases found"

**Problem:** Monitor can't find Kismet database

**Solutions:**
- Check Kismet is running: `ps aux | grep kismet`
- Verify database location: `ls -la /var/log/kismet/`
- Specify custom directory: `--kismet-dir /path/to/kismet/logs`

### "No GPS data available"

**Problem:** Location features not working

**Solutions:**
- Enable GPS in Kismet configuration
- Check GPS daemon: `systemctl status gpsd`
- Verify GPS device connected
- Use network-based geolocation as fallback

### "WiGLE API credentials not configured"

**Problem:** WiGLE features unavailable

**Solutions:**
- Run setup: `davbest-wifi surveillance wigle --setup`
- Verify credentials file: `cat ~/.wigle_creds.json`
- Check account at https://wigle.net

### "ImportError" on startup

**Problem:** Missing dependencies

**Solutions:**
```bash
# Reinstall with dependencies
pip install -e .

# Or manually install missing package
pip install cryptography
```

## Credits

Based on the **Chasing-Your-Tail-NG** project by ArgeliusLabs:
- https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG

Integrated into **DavBest WiFi Security Suite** with enhancements:
- Streamlined CLI interface
- Enhanced reporting formats
- Production-ready error handling
- Secure database operations

## License

For authorized security testing and educational purposes only. Unauthorized surveillance is illegal.

---

**Need Help?**

- Report issues: https://github.com/SWORDIntel/DavBest/issues
- Main documentation: See main DavBest README.md
- WiGLE help: https://wigle.net/api
