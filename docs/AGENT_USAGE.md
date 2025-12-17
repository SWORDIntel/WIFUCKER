# WIFUCKER Agent Usage Guide

This guide provides comprehensive documentation for using WIFUCKER via automated agents (like AI assistants) with full JSON support and non-interactive operation.

## Table of Contents

1. [Overview](#overview)
2. [JSON Output Format](#json-output-format)
3. [Exit Codes](#exit-codes)
4. [Error Handling](#error-handling)
5. [Progress Tracking](#progress-tracking)
6. [Operation Management](#operation-management)
7. [Profiles](#profiles)
8. [Batch Operations](#batch-operations)
9. [Workflows](#workflows)
10. [Example Workflows](#example-workflows)

## Overview

WIFUCKER CLI is designed for full automation with:
- **JSON Output**: All commands support `--json` flag for structured output
- **Non-Interactive**: No prompts, all operations scriptable
- **Progress Tracking**: Real-time progress via `--progress-file`
- **Operation Management**: Track and control long-running operations
- **Profiles**: Save and reuse common configurations
- **Batch Operations**: Run multiple operations in sequence or parallel
- **Workflows**: Predefined and custom multi-step workflows

## JSON Output Format

All commands support `--json` flag for structured output:

```bash
wifucker scan wlan0 --json
```

### Success Response Format

```json
{
  "command": "scan",
  "success": true,
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "interface": "wlan0mon",
    "networks": [...],
    "count": 5
  }
}
```

### Error Response Format

```json
{
  "command": "scan",
  "success": false,
  "timestamp": "2024-01-01T12:00:00Z",
  "error": {
    "code": "MONITOR_MODE_FAILED",
    "message": "Failed to enable monitor mode",
    "suggestions": [
      "Ensure interface exists",
      "Check root privileges"
    ]
  },
  "exit_code": 1
}
```

## Exit Codes

Standardized exit codes across all commands:

- `0` - Success
- `1` - General error
- `2` - Invalid arguments
- `3` - Permission denied
- `4` - Not found
- `5` - Network error
- `6` - Cancelled

## Error Handling

All errors include:
- **Error Code**: Machine-readable error identifier
- **Message**: Human-readable error description
- **Suggestions**: Actionable troubleshooting steps
- **Exit Code**: Standard exit code

## Progress Tracking

Use `--progress-file` to track operation progress:

```bash
wifucker crack handshake.pcap wordlist.txt --progress-file /tmp/progress.json
```

Progress file format:

```json
{
  "operation": "crack",
  "status": "running",
  "progress": 45.5,
  "current": 45500,
  "total": 100000,
  "rate": 1250.5,
  "elapsed": 36.4,
  "estimated_remaining": 43.6
}
```

## Operation Management

### Create Operation

Operations are automatically tracked when using `--progress-file`:

```bash
wifucker capture wlan0mon --target-ssid "MyNetwork" --progress-file /tmp/capture.json
```

### Check Operation Status

```bash
wifucker operation status <operation_id> --json
```

### List Operations

```bash
wifucker operation list --status running --json
```

### Cancel Operation

```bash
wifucker operation cancel <operation_id> --json
```

## Profiles

Save and reuse common configurations:

### Save Profile

```bash
wifucker profile save my_scan --command scan --args '{"interface":"wlan0","duration":10}' --description "Quick scan profile"
```

### Load Profile

```bash
wifucker profile load my_scan --json
```

### List Profiles

```bash
wifucker profile list --json
```

### Delete Profile

```bash
wifucker profile delete my_scan --json
```

## Batch Operations

Run multiple operations from a JSON file:

### Batch File Format

```json
{
  "operations": [
    {
      "id": "op1",
      "command": "scan",
      "args": {
        "interface": "wlan0",
        "duration": 10,
        "json": true
      }
    },
    {
      "id": "op2",
      "command": "capture",
      "args": {
        "interface": "wlan0mon",
        "target_ssid": "MyNetwork",
        "json": true
      }
    }
  ]
}
```

### Execute Batch

Sequential execution:
```bash
wifucker batch --file batch.json --json
```

Parallel execution:
```bash
wifucker batch --file batch.json --parallel --max-parallel 4 --json
```

## Workflows

Predefined and custom multi-step workflows:

### List Workflows

```bash
wifucker workflow list --json
```

### Run Workflow

```bash
wifucker workflow run full_audit --args '{"interface":"wlan0","target_ssid":"MyNetwork"}' --json
```

### Create Custom Workflow

Create workflow file `my_workflow.json`:

```json
{
  "description": "Custom audit workflow",
  "default_args": {
    "interface": "wlan0",
    "target_ssid": "MyNetwork"
  },
  "steps": [
    {
      "type": "command",
      "command": "scan",
      "args": {
        "interface": "${interface}",
        "duration": 10
      }
    },
    {
      "type": "command",
      "command": "capture",
      "args": {
        "interface": "${interface}mon",
        "target_ssid": "${target_ssid}"
      },
      "stop_on_error": true
    }
  ]
}
```

Register workflow:
```bash
wifucker workflow create my_workflow --file my_workflow.json --description "Custom audit workflow"
```

## Example Workflows

### Complete Audit Workflow

```bash
# 1. Scan for networks
wifucker scan wlan0 --json > scan.json

# 2. Extract target network from scan
TARGET_SSID=$(jq -r '.data.networks[0].essid' scan.json)

# 3. Capture handshake
wifucker capture wlan0mon --target-ssid "$TARGET_SSID" --json > capture.json

# 4. Extract PCAP file
PCAP_FILE=$(jq -r '.data.pcap_file' capture.json)

# 5. Parse handshake
wifucker parse "$PCAP_FILE" --json > parse.json

# 6. Generate wordlist
wifucker generate "$TARGET_SSID" --json > generate.json

# 7. Extract wordlist file
WORDLIST=$(jq -r '.data.output_file' generate.json)

# 8. Crack password
wifucker crack "$PCAP_FILE" "$WORDLIST" --json > crack.json
```

### Using Workflow

```bash
wifucker workflow run full_audit \
  --args '{"interface":"wlan0","target_ssid":"MyNetwork"}' \
  --json \
  --progress-file /tmp/workflow.json
```

## Command Reference

### Scan Networks

```bash
wifucker scan <interface> [--duration N] [--min-power N] [--encryption TYPE] [--has-clients] [--json]
```

### Capture Handshake

```bash
wifucker capture <interface> [--target-ssid SSID] [--auto-select] [--capture-duration N] [--deauth-count N] [--json] [--progress-file FILE]
```

### Crack Password

```bash
wifucker crack <pcap> <wordlist> [--device DEVICE] [--rules] [--json] [--progress-file FILE]
```

### Parse PCAP

```bash
wifucker parse <pcap> [--export-hashcat FILE] [--export-john FILE] [--json]
```

### Generate Wordlist

```bash
wifucker generate <ssid> [--output FILE] [--max-passwords N] [--json]
```

### Full Audit

```bash
wifucker audit [--auto] [--interface IFACE] [--target-ssid SSID] [--capture-duration N] [--deauth-count N] [--json] [--progress-file FILE]
```

## Best Practices

1. **Always use `--json`** for agent automation
2. **Use `--progress-file`** for long-running operations
3. **Check exit codes** to determine success/failure
4. **Use profiles** for common configurations
5. **Use workflows** for multi-step operations
6. **Use batch operations** for parallel execution
7. **Handle errors** by checking JSON error responses
8. **Track operations** using operation management

## Error Recovery

When errors occur:

1. Check JSON error response for error code
2. Review suggestions in error response
3. Check operation status if using operation management
4. Retry with adjusted parameters
5. Use `--progress-file` to resume from last known state

## Integration Examples

### Python Integration

```python
import subprocess
import json

def run_wifucker(command, args, json_output=True):
    cmd = ["wifucker", command] + args
    if json_output:
        cmd.append("--json")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return json.loads(result.stdout)
    else:
        error = json.loads(result.stdout)
        raise Exception(error["error"]["message"])

# Example usage
networks = run_wifucker("scan", ["wlan0", "--duration", "10"])
print(f"Found {networks['data']['count']} networks")
```

### Shell Integration

```bash
#!/bin/bash

# Scan networks
SCAN_OUTPUT=$(wifucker scan wlan0 --json)
TARGET_SSID=$(echo "$SCAN_OUTPUT" | jq -r '.data.networks[0].essid')

# Capture handshake
CAPTURE_OUTPUT=$(wifucker capture wlan0mon --target-ssid "$TARGET_SSID" --json)
PCAP_FILE=$(echo "$CAPTURE_OUTPUT" | jq -r '.data.pcap_file')

# Crack password
CRACK_OUTPUT=$(wifucker crack "$PCAP_FILE" wordlist.txt --json)
if echo "$CRACK_OUTPUT" | jq -e '.data.found' > /dev/null; then
    PASSWORD=$(echo "$CRACK_OUTPUT" | jq -r '.data.password')
    echo "Password found: $PASSWORD"
fi
```

