# MCP Threat Hunter

AI-assisted threat hunting via Claude Code. Integrates Splunk, VirusTotal, and AbuseIPDB for security investigations using natural language.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![MCP](https://img.shields.io/badge/MCP-Compatible-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Overview

This MCP (Model Context Protocol) server enables Claude to:
- Execute Splunk SPL queries for threat hunting
- Enrich IOCs with VirusTotal and AbuseIPDB
- Hunt for C2 beaconing patterns using jitter analysis
- Detect volume anomalies and exfiltration
- Monitor data pipeline health

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLAUDE CODE (CLI)                         │
│  "Find beaconing patterns and enrich suspicious IPs"         │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    MCP THREAT HUNTER                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │search_splunk │  │  enrich_ip   │  │ hunt_beacons │       │
│  │hunt_ioc      │  │enrich_domain │  │hunt_volume   │       │
│  │get_summary   │  │ enrich_hash  │  │hunt_new_dest │       │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘       │
└─────────┼─────────────────┼─────────────────────────────────┘
          │                 │
          ▼                 ▼
   ┌────────────┐    ┌────────────┐    ┌────────────┐
   │   Splunk   │    │ VirusTotal │    │ AbuseIPDB  │
   │    API     │    │    API     │    │    API     │
   └────────────┘    └────────────┘    └────────────┘
```

---

## Available Tools

| Tool | Description |
|------|-------------|
| `search_splunk` | Execute any SPL query |
| `enrich_ip` | IP enrichment via VT + AbuseIPDB (combined verdict) |
| `enrich_domain` | Domain reputation from VirusTotal |
| `enrich_hash` | File hash lookup in VirusTotal |
| `hunt_beacons` | C2 detection using jitter analysis |
| `hunt_volume_anomaly` | Exfiltration detection via z-scores |
| `hunt_new_destinations` | Find new external connections |
| `hunt_ioc` | Combined search + enrichment |
| `get_network_summary` | Top talkers, destinations, ports |
| `check_pipeline_health` | Data ingestion status |

---

## Why Multiple Enrichment Sources?

Production SOAR playbooks query multiple threat intelligence sources because no single source has complete visibility.

### Source Comparison

| Source | Strength | Weakness |
|--------|----------|----------|
| **VirusTotal** | Broad coverage (files, domains, IPs), AV engine consensus | IP data is secondary; harsh rate limits |
| **AbuseIPDB** | IP-specific abuse reports, community-sourced, real-time | No file/hash analysis |

### How It Works

The server implements the same pattern used in production SOAR:

1. **Parallel Execution**: Both lookups run concurrently via `asyncio.gather()` (faster than sequential)
2. **Multi-Source Correlation**: No single source has complete visibility
3. **Verdict Synthesis**: Combined verdict from multiple inputs
4. **Graceful Degradation**: If one source fails, you still get data from the other

```python
# Concurrent lookups
vt_result, abuse_result = await asyncio.gather(
    vt_client.lookup_ip(ip),
    abuseipdb_client.check_ip(ip)
)

# Combined verdict logic
if any(verdict == "MALICIOUS" for verdict in verdicts):
    overall = "MALICIOUS"
```

### Example Output

```json
{
  "ip": "198.51.100.45",
  "overall_verdict": "MALICIOUS",
  "verdicts": {
    "VirusTotal": "MALICIOUS",
    "AbuseIPDB": "MALICIOUS"
  },
  "virustotal": {
    "malicious_votes": 12,
    "as_owner": "Suspicious Hosting LLC",
    "country": "RU"
  },
  "abuseipdb": {
    "abuse_confidence_score": 100,
    "total_reports": 847,
    "usage_type": "Data Center/Web Hosting"
  }
}
```

This architecture demonstrates understanding of security orchestration - not just "calling an API" but coordinating multiple tools and synthesizing actionable intelligence.

---

## Quick Start

### 1. Install Dependencies

```bash
cd mcp-server
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.template .env
# Edit .env with your credentials
```

Required settings:
```
SPLUNK_HOST=your-splunk-host
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your-password
VIRUSTOTAL_API_KEY=your-vt-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

### 3. Test Installation

```bash
python test_server.py
```

### 4. Configure Claude Code

Add to your Claude Desktop config:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Linux:** `~/.config/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "threat-hunter": {
      "command": "python",
      "args": ["/full/path/to/mcp-server/server.py"],
      "env": {
        "SPLUNK_HOST": "your-splunk-host",
        "SPLUNK_PORT": "8089",
        "SPLUNK_USERNAME": "admin",
        "SPLUNK_PASSWORD": "your-password",
        "VIRUSTOTAL_API_KEY": "your-vt-key",
        "ABUSEIPDB_API_KEY": "your-abuseipdb-key"
      }
    }
  }
}
```

### 5. Restart Claude Code

After updating config, restart Claude Code to load the MCP server.

---

## Example Prompts

### Threat Hunting

```
"Hunt for C2 beaconing patterns in the last 24 hours. 
Flag anything with less than 15% jitter."

"Check if we have any volume anomalies - hosts sending 
unusually high amounts of data."

"Find any new external destinations our hosts connected 
to in the last 4 hours."
```

### IOC Investigation

```
"I received an alert about 198.51.100.45. 
Hunt for this IP and tell me what you find."

"Check this hash against VirusTotal: 
d41d8cd98f00b204e9800998ecf8427e"

"Is evil-domain.com in our logs? What's the reputation?"
```

### Daily Operations

```
"Give me a network summary for the last 24 hours. 
Who are the top talkers?"

"Check if our data pipelines are healthy."

"Run this SPL query and explain the results:
index=netflow | stats count by dst_port | head 10"
```

### Combined Workflows

```
"Find beaconing patterns, then enrich any suspicious 
destination IPs with threat intelligence."

"Get me a threat report: 
1. Check pipeline health
2. Hunt for beacons
3. Look for volume anomalies
4. Enrich any suspicious IPs"
```

---

## Tool Details

### hunt_beacons

Detects C2 beaconing using statistical jitter analysis.

**How it works:**
- Calculates time intervals between repeated connections
- Computes jitter = stdev(interval) / avg(interval)
- Low jitter (<25%) indicates automated behavior

**Jitter Interpretation:**
| Jitter | Meaning |
|--------|---------|
| 0% | Perfect timing - automated (investigate!) |
| 1-10% | Very low - likely automated |
| 10-25% | Low - worth investigating |
| >25% | Normal variance - human activity |

**Example output:**
```json
{
  "results": [
    {
      "src4_addr": "192.0.2.10",
      "dst4_addr": "104.21.x.x",
      "dst_port": "443",
      "beacon_count": "79",
      "avg_interval_sec": "60.0",
      "jitter_pct": "0.0"
    }
  ],
  "analysis": {
    "description": "C2 beaconing detection via jitter analysis",
    "interpretation": {
      "0%": "Perfect timing - automated heartbeat or C2"
    }
  }
}
```

### enrich_ip

Enriches an IP using both VirusTotal and AbuseIPDB.

**Example output:**
```json
{
  "ip": "198.51.100.45",
  "overall_verdict": "MALICIOUS",
  "verdicts": {
    "VirusTotal": "MALICIOUS",
    "AbuseIPDB": "MALICIOUS"
  },
  "virustotal": {
    "malicious_votes": 12,
    "as_owner": "Suspicious Hosting LLC",
    "country": "RU"
  },
  "abuseipdb": {
    "abuse_confidence_score": 100,
    "total_reports": 847,
    "usage_type": "Data Center/Web Hosting"
  }
}
```

### hunt_volume_anomaly

Detects unusual data transfer using z-score analysis.

**How it works:**
- Bins traffic into hourly buckets
- Calculates mean and standard deviation per host
- Flags hours exceeding threshold (default: 2 standard deviations)

**MITRE Mapping:** T1041 - Exfiltration Over C2 Channel

---

## API Rate Limits

| Service | Free Tier Limit |
|---------|-----------------|
| VirusTotal | 4 requests/min, 500/day |
| AbuseIPDB | 1000 checks/day |
| Splunk | Depends on your license |

The server handles rate limiting gracefully and returns appropriate error messages.

---

## Troubleshooting

### "Connection refused" to Splunk

1. Verify Splunk is running: `curl -k https://splunk-host:8089`
2. Check firewall allows port 8089
3. Verify credentials in .env

### "VirusTotal API key not configured"

1. Get a free API key: https://www.virustotal.com/gui/my-apikey
2. Add to .env: `VIRUSTOTAL_API_KEY=your-key`

### "AbuseIPDB rate limit exceeded"

Free tier allows 1000 checks/day. Options:
- Wait until daily reset
- Upgrade to paid tier
- Cache results locally

### Claude Code doesn't see the tools

1. Check config file path is correct for your OS
2. Verify JSON syntax (use a JSON validator)
3. Restart Claude Code completely
4. Check server.py path is absolute, not relative

### Testing without live Splunk

Run the test script - it will test VT and AbuseIPDB independently:
```bash
python test_server.py
```

---

## Security Notes

- **Never commit .env files** - they contain credentials
- Use read-only Splunk credentials if possible
- Restrict Splunk API access by IP
- API keys should have minimum required permissions
- Consider using environment variables instead of .env in production

---

## Files

| File | Purpose |
|------|---------|
| `server.py` | Main MCP server implementation |
| `test_server.py` | Test script for validation |
| `requirements.txt` | Python dependencies |
| `.env.template` | Configuration template |

---

## Development

### Adding a New Tool

1. Add tool definition in `list_tools()`:
```python
Tool(
    name="my_new_tool",
    description="What this tool does",
    inputSchema={...}
)
```

2. Add handler in `call_tool()`:
```python
elif name == "my_new_tool":
    result = await my_function(arguments)
```

3. Test with `test_server.py`

### Logging

Enable debug logging:
```
LOG_LEVEL=DEBUG
```

Write to file:
```
LOG_FILE=/var/log/mcp-threat-hunter.log
```

---

## License

MIT License - See [LICENSE](../LICENSE) for details.

---

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [VirusTotal API](https://developers.virustotal.com/)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [Splunk REST API](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog)
