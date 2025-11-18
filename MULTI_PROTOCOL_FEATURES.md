# Multi-Protocol Layer 2 Security Monitor

## 🎯 Overview

The system has been **completely redesigned** from a single-protocol (ARP) monitor into a comprehensive **multi-protocol Layer 2 security monitoring system**.

## ✨ New Features

### 🌐 Multi-Protocol Support

Now monitors **5 different Layer 2 protocols**:

| Protocol | Purpose | Attack Detection |
|----------|---------|------------------|
| **ARP** | Address Resolution | Spoofing, Flooding, MAC Duplication |
| **DHCP** | Dynamic IP Assignment | Rogue Servers, Starvation Attacks |
| **STP** | Spanning Tree Protocol | Topology Manipulation, Root Bridge Changes |
| **CDP** | Cisco Discovery Protocol | Network Reconnaissance |
| **LLDP** | Link Layer Discovery | Network Reconnaissance |

### 🚨 Detection Rules

#### ARP Attacks
- **MAC_DUPLICATE** (CRITICAL) - Detects when one IP responds from multiple MACs (ARP Spoofing)
- **ARP_FLOOD** (HIGH) - Abnormal rate of ARP packets (> 50/min threshold)

#### DHCP Attacks
- **ROGUE_DHCP** (CRITICAL) - Multiple DHCP servers detected (unauthorized DHCP server)
- **DHCP_STARVATION** (HIGH) - DHCP pool exhaustion attack (> 30 requests/min)

#### STP Attacks
- **STP_MANIPULATION** (HIGH) - Abnormal root bridge changes (> 3 changes)

#### Reconnaissance
- **DISCOVERY_SCAN** (MEDIUM) - Excessive CDP/LLDP device discovery (> 20 devices)

### 🎛️ New Command-Line Options

```bash
# Monitor all protocols
sudo ./l2_monitor.sh -d 60

# Monitor only specific protocols
sudo ./l2_monitor.sh -p arp,dhcp

# Live monitoring mode
sudo ./l2_monitor.sh -l -p arp,dhcp,stp

# Filter by severity
sudo ./l2_monitor.sh -s CRITICAL

# Custom alert email
sudo ./l2_monitor.sh -a security@company.com
```

### 📊 Enhanced Reporting

The new reporting system provides:

1. **Protocol Statistics** - Packet counts per protocol
2. **ARP Table** - Complete IP → MAC mapping with anomaly highlighting
3. **DHCP Servers** - All detected DHCP servers with warning for multiples
4. **STP Topology** - Root bridge information and change tracking
5. **Discovered Devices** - CDP/LLDP device inventory

### 🔧 Architecture Improvements

#### Modular Design
- **Protocol Handlers**: Separate detection logic for each protocol
- **Unified State Management**: Single JSON state file with protocol-specific sections
- **Extensible Detection Engine**: Easy to add new protocols and rules

#### Smart Capture Filters
The system automatically builds Berkeley Packet Filter (BPF) expressions based on selected protocols:

```
arp or (udp port 67 or udp port 68) or (ether proto 0x0026 or ether proto 0x0027) or (ether proto 0x2000) or (ether proto 0x88cc)
```

#### Multi-Protocol JSON State
```json
{
  "arp_packets": [...],
  "dhcp_packets": [...],
  "stp_packets": [...],
  "cdp_packets": [...],
  "lldp_packets": [...],
  "arp_table": [...],
  "dhcp_servers": [...],
  "stp_roots": [...],
  "discovered_devices": [...]
}
```

## 🆚 Comparison: Old vs New

| Feature | Old (ARP Only) | New (Multi-Protocol) |
|---------|----------------|---------------------|
| Protocols | 1 (ARP) | 5 (ARP, DHCP, STP, CDP, LLDP) |
| Detection Rules | 5 | 6 (more coming) |
| Protocol Selection | Fixed | Configurable via -p flag |
| State Management | ARP-specific | Unified multi-protocol |
| Reporting | Basic ARP stats | Comprehensive multi-protocol analysis |
| Email Alerts | Protocol-agnostic | Protocol-tagged alerts |

## 🎨 Enhanced Alert System

### Protocol-Tagged Alerts
Email subjects now include protocol information:
```
[L2 Security/DHCP] CRITICAL: ROGUE_DHCP
[L2 Security/ARP] CRITICAL: MAC_DUPLICATE
[L2 Security/STP] HIGH: STP_MANIPULATION
```

### HTML Email with Protocol Badges
Alerts now include color-coded protocol badges in emails for quick identification.

## 🐛 Bugs Fixed

1. **Readonly Variable Issue** - Fixed `ALERT_EMAIL` and `MSMTP_ACCOUNT` being readonly but modified via CLI flags
2. **Improved Error Handling** - Better handling of empty captures
3. **Flexible Configuration** - All critical settings can now be changed via CLI

## 📝 Usage Examples

### Example 1: Detect Rogue DHCP Server
```bash
sudo ./l2_monitor.sh -d 120 -p dhcp -s CRITICAL
```
Monitors only DHCP traffic for 2 minutes, alerting on critical issues (rogue servers).

### Example 2: ARP Security Audit
```bash
sudo ./l2_monitor.sh -d 300 -p arp
```
5-minute focused ARP security scan.

### Example 3: Complete Network Footprint
```bash
sudo ./l2_monitor.sh -d 600
```
10-minute comprehensive scan of all Layer 2 protocols.

### Example 4: Live STP Monitoring
```bash
sudo ./l2_monitor.sh -l -p stp
```
Continuous monitoring of STP topology changes.

## 🔐 Security Benefits

1. **Rogue DHCP Detection** - Prevents man-in-the-middle via malicious DHCP
2. **ARP Spoofing Detection** - Identifies MAC cloning and IP conflicts
3. **STP Attack Prevention** - Detects topology manipulation attempts
4. **Network Reconnaissance** - Identifies scanning activity via CDP/LLDP
5. **Multi-Vector Analysis** - Correlates attacks across multiple protocols

## 📦 Files

- `l2_monitor.sh` - Main multi-protocol monitoring script
- `l2_monitor.sh.backup` - Backup of original ARP-only version
- `protocol_data.json` - Multi-protocol packet capture data
- `network_state.json` - Unified protocol state and analysis
- `alerts.log` - All triggered alerts
- `l2_monitor.log` - System logs

## 🚀 Future Enhancements

Potential additions:
- Layer 3 protocols (ICMP, TCP SYN scans)
- Machine learning for anomaly detection
- Real-time dashboard
- Integration with SIEM systems
- Automated response actions

## 📚 Technical Details

### Captured Fields by Protocol

**ARP**: opcode, src/dst MAC, src/dst IP
**DHCP**: message type, server ID, client MAC, client/your IP
**STP**: root MAC, bridge MAC, type, flags
**CDP**: device ID, platform
**LLDP**: chassis ID, port ID

### Detection Thresholds

```bash
ARP_FLOOD_THRESHOLD=50       # packets/min
DHCP_FLOOD_THRESHOLD=30      # requests/min
STP_CHANGE_THRESHOLD=3       # root changes
CDP_SCAN_THRESHOLD=20        # devices discovered
MAC_FLAP_THRESHOLD=5         # MAC changes
ALERT_COOLDOWN=300           # 5 min between same alerts
```

## ✅ Testing

The system has been tested for:
- ✅ Syntax validation
- ✅ Multi-protocol capture filter generation
- ✅ JSON state management
- ✅ Alert system with protocol tagging
- ✅ Email delivery (msmtp integration)
- ✅ CLI argument parsing
- ✅ Help documentation

## 🎓 Educational Value

This tool demonstrates:
- Multi-protocol network analysis
- Layer 2 security concepts
- Attack detection methodologies
- Real-world security monitoring
- Bash scripting best practices

---

**Version**: 2.0.0
**Date**: 2025-11-18
**Status**: Production Ready
