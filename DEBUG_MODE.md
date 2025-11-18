# Debug Mode Documentation

## Overview

The debug mode provides verbose output and detailed inspection of tshark captures and jq processing. It's designed to help troubleshoot issues with packet capture, JSON parsing, and detection logic.

## Enabling Debug Mode

Use the `-D` or `--debug` flag:

```bash
sudo ./l2_monitor.sh -d 30 -D
```

## Debug Output

When debug mode is enabled, you'll see:

1. **Colored timestamped debug messages** in cyan text
2. **Detailed information** about each processing step
3. **Debug files** saved to `./debug/` directory

## Debug Directory Structure

The `debug/` directory contains:

```
debug/
├── debug.log                    # Complete debug log
├── session_info.txt             # Session metadata
├── tshark_raw_output.json       # Raw tshark JSON output (before processing)
├── tshark_stderr.log            # tshark error output (if any)
├── sample_packet.json           # First captured packet (for inspection)
├── protocol_breakdown.txt       # Packet counts by protocol
├── network_state_pretty.json    # Pretty-printed state file
└── jq_output_*.json             # Individual jq query outputs
```

## Debug Functions

### 1. `debug()`
Prints timestamped debug messages (only when DEBUG_MODE=true)

**Example output:**
```
[2025-11-18 10:15:32.123] [DEBUG] Starting packet capture...
[2025-11-18 10:15:32.456] [INFO] Found 15 ARP packets
```

### 2. `validate_json()`
Validates JSON files and shows sample data

**What it checks:**
- File exists
- File is not empty
- Valid JSON syntax
- Element count
- Sample of first element

**Example output:**
```
[DEBUG] Validating Protocol Data: /path/to/protocol_data.json
[INFO] Protocol Data validated: 42 elements
[DEBUG] Sample element from Protocol Data:
  frame.time_epoch: ["1637234567.123"]
  eth.src: ["aa:bb:cc:dd:ee:ff"]
  arp.opcode: ["1"]
```

### 3. `debug_tshark_fields()`
Analyzes available fields in captured packets

**What it shows:**
- All field names from first packet
- Packet distribution by protocol
- Saves sample packet to file

**Example output:**
```
[DEBUG] === TSHARK FIELD INSPECTION ===
[DEBUG] Extracting field names from first packet...
[DEBUG]   Available field: arp.dst.hw_mac
[DEBUG]   Available field: arp.dst.proto_ipv4
[DEBUG]   Available field: arp.opcode
[DEBUG]   Available field: eth.dst
[DEBUG]   Available field: eth.src
[DEBUG]   Available field: frame.protocols
[DEBUG]   Available field: frame.time_epoch
[DEBUG] Packet distribution:
[DEBUG]   eth:ethertype:arp: 35 packets
[DEBUG]   eth:ethertype:ip:udp:dhcp: 7 packets
```

### 4. `debug_protocol_extraction()`
Tests protocol-specific packet extraction

**What it tests:**
- ARP packet filtering
- DHCP packet filtering
- STP packet filtering
- CDP packet filtering
- LLDP packet filtering

**Example output:**
```
[DEBUG] === PROTOCOL EXTRACTION DEBUG ===
[DEBUG] Testing ARP packet extraction...
[INFO] Found 35 ARP packets
[DEBUG] Testing DHCP packet extraction...
[INFO] Found 7 DHCP packets
[DEBUG] Testing STP packet extraction...
[INFO] Found 0 STP packets
```

### 5. `debug_jq_query()`
Tests individual jq queries with error capture

**Usage:**
```bash
debug_jq_query "$input_file" "$query" "Description of query"
```

**What it provides:**
- Query execution status
- Error messages if query fails
- First 5 results on success
- Saves output to timestamped file

### 6. `debug_capture_summary()`
Comprehensive summary after capture

**What it includes:**
- JSON validation
- Field inspection
- Protocol extraction results
- Network state structure

## Use Cases

### 1. No Packets Captured

**Problem:** `capture_traffic()` returns 0 packets

**Debug steps:**
```bash
sudo ./l2_monitor.sh -i eth0 -d 30 -D
```

**Check:**
- `debug/tshark_stderr.log` - tshark errors
- `debug/tshark_raw_output.json` - raw capture data
- Debug log shows: "BPF Filter" used
- Verify interface has traffic: `tcpdump -i eth0 arp -c 5`

### 2. JSON Parsing Errors

**Problem:** jq fails to process captured data

**Debug steps:**
```bash
sudo ./l2_monitor.sh -d 30 -D
```

**Check:**
- `debug/sample_packet.json` - structure of captured packet
- `debug/jq_error.log` - jq syntax errors
- `debug/network_state_pretty.json` - final processed state
- Debug log shows field names found

### 3. Protocol Not Detected

**Problem:** Expected protocol packets not appearing in report

**Debug steps:**
```bash
sudo ./l2_monitor.sh -p arp,dhcp -d 60 -D
```

**Check:**
- `debug/protocol_breakdown.txt` - packet counts by protocol
- Debug log shows protocol extraction results
- Verify BPF filter includes the protocol
- Check if tshark fields are correctly named

### 4. Detection Rules Not Triggering

**Problem:** Attacks present but no alerts generated

**Debug steps:**
```bash
sudo ./l2_monitor.sh -d 60 -D -s MEDIUM
```

**Check:**
- `debug/network_state_pretty.json`:
  - `.arp_table` - check for `mac_count > 1`
  - `.dhcp_servers` - should show all DHCP servers
  - `.stp_roots` - check for multiple roots
- Debug log shows state summary with counts
- Verify thresholds in script match your scenario

### 5. Live Mode Not Analyzing

**Problem:** Live mode captures but doesn't trigger analysis

**Debug steps:**
```bash
sudo ./l2_monitor.sh -i eth0 -l -D
```

**Check:**
- Debug log shows packet counter incrementing
- Verify 50-packet threshold is reached
- Check if `debug/` files are being created every 50 packets

## Debug Log Example

Complete debug session output:

```
[2025-11-18 10:15:30.000] [INFO] Debug mode ENABLED - Output: /home/user/SecurityManLy2/debug/
[2025-11-18 10:15:30.001] [DEBUG] Session ID: 20251118_101530
[2025-11-18 10:15:30.002] [DEBUG] Working directory: /home/user/SecurityManLy2
[2025-11-18 10:15:30.003] [DEBUG] Enabled protocols: arp dhcp stp cdp lldp
[2025-11-18 10:15:30.100] [DEBUG] === STARTING PACKET CAPTURE ===
[2025-11-18 10:15:30.101] [DEBUG] Interface: eth0
[2025-11-18 10:15:30.102] [DEBUG] Duration: 30s
[2025-11-18 10:15:30.103] [DEBUG] BPF Filter: arp or (udp port 67 or udp port 68) or (ether proto 0x0026 or ether proto 0x0027) or (ether proto 0x2000) or (ether proto 0x88cc)
[2025-11-18 10:15:30.104] [DEBUG] Output file: /home/user/SecurityManLy2/protocol_data.json
[2025-11-18 10:16:00.200] [DEBUG] tshark exit code: 124
[2025-11-18 10:16:00.201] [DEBUG] Raw capture file size: 156789 bytes
[2025-11-18 10:16:00.202] [DEBUG] Converting newline-delimited JSON to array...
[2025-11-18 10:16:00.203] [DEBUG] Raw tshark output saved to: /home/user/SecurityManLy2/debug/tshark_raw_output.json
[2025-11-18 10:16:00.300] [DEBUG] JSON array conversion complete
[2025-11-18 10:16:00.400] [DEBUG] === CAPTURE SUMMARY ===
[2025-11-18 10:16:00.401] [DEBUG] Validating Protocol Data: /home/user/SecurityManLy2/protocol_data.json
[2025-11-18 10:16:00.500] [INFO] Protocol Data validated: 42 elements
[2025-11-18 10:16:00.600] [DEBUG] === TSHARK FIELD INSPECTION ===
[2025-11-18 10:16:00.700] [DEBUG] === PROTOCOL EXTRACTION DEBUG ===
[2025-11-18 10:16:00.800] [INFO] Found 35 ARP packets
[2025-11-18 10:16:00.900] [INFO] Found 7 DHCP packets
[2025-11-18 10:16:01.000] [DEBUG] === GENERATING NETWORK STATE ===
[2025-11-18 10:16:01.100] [INFO] State Summary:
[2025-11-18 10:16:01.101] [INFO]   ARP packets: 35
[2025-11-18 10:16:01.102] [INFO]   DHCP packets: 7
[2025-11-18 10:16:01.103] [INFO]   ARP table entries: 8
[2025-11-18 10:16:01.104] [INFO]   DHCP servers: 1
```

## Performance Impact

Debug mode adds minimal overhead:

- **Console output**: ~5% slower (colored formatting)
- **File I/O**: ~10-15% slower (saving debug files)
- **Memory**: +20-30MB (pretty-printed JSON files)

For performance-critical captures, disable debug mode.

## Tips

1. **Always use debug mode** when troubleshooting capture issues
2. **Inspect sample_packet.json** to understand tshark's JSON structure
3. **Check protocol_breakdown.txt** first for quick packet counts
4. **Compare raw vs processed** JSON to debug jq filters
5. **Share debug/ folder** when reporting bugs

## Cleanup

Debug files are preserved after script exits. To clean up:

```bash
rm -rf debug/
```

Or keep for later analysis - debug files contain complete capture details.

## Integration with Regular Logging

Debug mode complements (doesn't replace) the regular log file:

- `l2_monitor.log` - Always created, production events
- `debug/debug.log` - Only in debug mode, verbose details

Both logs are timestamped and can be analyzed together.

---

**Version**: 1.0
**Last Updated**: 2025-11-18
