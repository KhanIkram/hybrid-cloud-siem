# Technical Documentation

Complete deployment and configuration guide for the Hybrid Cloud SIEM.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Splunk Deployment](#splunk-deployment)
4. [Data Source Configuration](#data-source-configuration)
5. [Technology Add-ons](#technology-add-ons)
6. [Detection Deployment](#detection-deployment)
7. [MCP Server Setup](#mcp-server-setup)
8. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### Data Flow

```
Network Appliance                    SIEM
┌─────────────────┐                  ┌─────────────────┐
│                 │                  │                 │
│  Syslog Export  │──── UDP:5514 ───▶│  syslog index   │
│  (Firewall/DNS) │                  │                 │
│                 │                  │                 │
│  IPFIX/NetFlow  │──── UDP:2055 ───▶│  netflow index  │
│  (Flow Data)    │                  │                 │
│                 │                  │                 │
└─────────────────┘                  └─────────────────┘
```

### Components

| Component | Purpose |
|-----------|---------|
| Network Appliance | Exports syslog and flow data |
| Splunk Enterprise | SIEM platform for log aggregation and search |
| Technology Add-ons | Parse and normalize incoming data |
| Saved Searches | Detection queries |
| MCP Server | AI-assisted threat hunting interface |

---

## Prerequisites

### Hardware/Software

- **Splunk Enterprise** 9.0+ (Free tier: 500MB/day)
- **Python** 3.10+ (for MCP server)
- **Network device** with syslog and NetFlow/IPFIX export capability
- **nfdump** (for NetFlow processing)

### Network Requirements

| Traffic | Port | Protocol | Direction |
|---------|------|----------|-----------|
| Syslog | 5514 | UDP | Inbound to Splunk |
| NetFlow/IPFIX | 2055 | UDP | Inbound to collector |
| Splunk API | 8089 | TCP | MCP server to Splunk |
| VirusTotal API | 443 | TCP | MCP server outbound |
| AbuseIPDB API | 443 | TCP | MCP server outbound |

---

## Splunk Deployment

### 1. Install Splunk Enterprise

```bash
# Download from splunk.com
wget -O splunk.tgz "https://download.splunk.com/..."
tar xvzf splunk.tgz -C /opt
/opt/splunk/bin/splunk start --accept-license
```

### 2. Create Indexes

Copy `splunk/indexes.conf.example` to `$SPLUNK_HOME/etc/system/local/indexes.conf`:

```bash
cp indexes.conf.example /opt/splunk/etc/system/local/indexes.conf
```

Restart Splunk:
```bash
/opt/splunk/bin/splunk restart
```

### 3. Configure Firewall

Allow inbound traffic on required ports:

```bash
# Example: UFW
ufw allow 5514/udp  # Syslog
ufw allow 2055/udp  # NetFlow (if collector on same host)
ufw allow 8089/tcp  # Splunk API (restrict to trusted IPs)
```

---

## Data Source Configuration

### Syslog Export

Configure your network device to export syslog to Splunk:

| Setting | Value |
|---------|-------|
| Destination | Splunk IP |
| Port | 5514 |
| Protocol | UDP |
| Facility | Local0 (or as appropriate) |

### NetFlow/IPFIX Export

Configure flow export on your network device:

| Setting | Value |
|---------|-------|
| Destination | Collector IP |
| Port | 2055 |
| Version | IPFIX v10 or NetFlow v9 |
| Active Timeout | 60 seconds |
| Template Refresh | 60 seconds |

### NetFlow Processing Pipeline

Raw NetFlow is binary and requires conversion before Splunk ingestion:

```bash
# Install nfdump
apt-get install nfdump

# Create directories
mkdir -p /opt/netflow/{capture,processed}

# Start collector
nfcapd -w -D -l /opt/netflow/capture -p 2055

# Process flows (run via cron every 5 minutes)
# See scripts/process_flows.sh
```

The processing script converts binary flows to NDJSON format that Splunk can parse.

---

## Technology Add-ons

### TA-syslog

Parses syslog from network appliances with sourcetype routing.

```bash
cp -r splunk/apps/TA-syslog $SPLUNK_HOME/etc/apps/
```

**Key files:**
- `props.conf` - Field extractions and timestamp parsing
- `transforms.conf` - Sourcetype routing rules
- `inputs.conf` - UDP listener configuration

### TA-netflow

Parses NDJSON NetFlow data with CIM field mappings.

```bash
cp -r splunk/apps/TA-netflow $SPLUNK_HOME/etc/apps/
```

**Key files:**
- `props.conf` - JSON parsing and CIM aliases
- `inputs.conf` - File monitor for processed flows

### Customization

You will need to adjust field extractions based on your specific device's log format. The provided configurations are templates.

---

## Detection Deployment

### Import Saved Searches

Option 1: Copy configuration file
```bash
cp splunk/saved-searches/detections.conf \
   $SPLUNK_HOME/etc/apps/search/local/savedsearches.conf
```

Option 2: Import via Splunk Web
1. Settings > Searches, reports, and alerts
2. New Search
3. Paste SPL from detection catalog

### Enable Scheduled Alerts

The following detections are configured as scheduled alerts:

| Alert | Schedule | Purpose |
|-------|----------|---------|
| Pipeline Health Check | Every 15 min | Detect ingestion failures |
| License Usage Warning | Every 4 hours | Prevent license violations |

To enable:
1. Settings > Searches, reports, and alerts
2. Edit the alert
3. Set "Schedule" to enabled
4. Configure alert actions (email, webhook, etc.)

---

## MCP Server Setup

### 1. Install Dependencies

```bash
cd mcp-server
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.template .env
```

Edit `.env`:
```
SPLUNK_HOST=your-splunk-host
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your-password
SPLUNK_VERIFY_SSL=false

VIRUSTOTAL_API_KEY=your-vt-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

### 3. Get API Keys

| Service | URL | Free Tier |
|---------|-----|-----------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | 4 req/min, 500/day |
| AbuseIPDB | https://www.abuseipdb.com/account/api | 1000 checks/day |

### 4. Test Server

```bash
python test_server.py
```

### 5. Configure Claude Code

Add to Claude Desktop config:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "threat-hunter": {
      "command": "python",
      "args": ["/path/to/mcp-server/server.py"],
      "env": {
        "SPLUNK_HOST": "your-splunk-host",
        "SPLUNK_PORT": "8089",
        "SPLUNK_USERNAME": "admin",
        "SPLUNK_PASSWORD": "your-password",
        "VIRUSTOTAL_API_KEY": "your-key",
        "ABUSEIPDB_API_KEY": "your-key"
      }
    }
  }
}
```

Restart Claude Code after configuration changes.

---

## Troubleshooting

### No Data in Syslog Index

1. **Verify network connectivity**
   ```bash
   nc -ul 5514  # Listen for UDP
   # Send test from device, check if received
   ```

2. **Check Splunk inputs**
   ```bash
   /opt/splunk/bin/splunk list udp
   ```

3. **Verify firewall rules**
   ```bash
   iptables -L -n | grep 5514
   ```

### No Data in NetFlow Index

1. **Check nfcapd is running**
   ```bash
   ps aux | grep nfcapd
   ```

2. **Verify flows are being captured**
   ```bash
   ls -la /opt/netflow/capture/
   nfdump -r /opt/netflow/capture/nfcapd.current -c 5
   ```

3. **Check processing script**
   ```bash
   bash -x scripts/process_flows.sh
   ```

4. **Verify Splunk is monitoring the output directory**
   ```bash
   /opt/splunk/bin/splunk list monitor
   ```

### MCP Server Connection Errors

1. **Test Splunk API directly**
   ```bash
   curl -k -u admin:password https://splunk-host:8089/services/server/info
   ```

2. **Check credentials in .env**
   ```bash
   python -c "from dotenv import load_dotenv; import os; load_dotenv(); print(os.getenv('SPLUNK_HOST'))"
   ```

3. **Verify network path**
   ```bash
   nc -zv splunk-host 8089
   ```

### Rate Limiting

**VirusTotal**: 4 requests/minute on free tier
- Symptoms: HTTP 429 errors
- Solution: Space out enrichment calls, consider caching

**AbuseIPDB**: 1000 requests/day on free tier
- Symptoms: HTTP 429 errors
- Solution: Batch lookups, implement caching

### High License Usage

If approaching Splunk license limits:

1. **Enable sampling** in `scripts/process_flows.sh`
   ```bash
   SAMPLE_RATE=5  # Keep 1 in 5 flows
   ```

2. **Reduce retention** in `indexes.conf`
   ```
   frozenTimePeriodInSecs = 259200  # 3 days instead of 7
   ```

3. **Filter low-value traffic** in NetFlow processing
   ```bash
   # Exclude broadcast, multicast
   jq 'select(.dst4_addr | startswith("224.") | not)'
   ```

---

## Security Hardening

### Splunk API Access

Restrict API access to trusted IPs:

```bash
# In web.conf or via firewall
[settings]
trustedIP = 10.0.0.0/8,192.168.0.0/16
```

### Credential Management

- Never commit `.env` files
- Use Splunk's credential storage for production
- Rotate API keys periodically
- Use read-only Splunk accounts where possible

### Network Segmentation

- Place Splunk in a management VLAN
- Restrict inbound to required ports only
- Use VPN for remote API access

---

## Next Steps

1. Deploy and verify data ingestion
2. Run baseline queries to understand normal traffic
3. Tune detection thresholds based on your environment
4. Enable scheduled alerts
5. Configure MCP server for AI-assisted hunting
6. Document your baseline and tuning decisions

See [detection-catalog.md](detection-catalog.md) for detailed query documentation.
