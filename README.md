# Hybrid Cloud SIEM with AI-Assisted Threat Hunting

A security monitoring platform demonstrating detection engineering, SOAR patterns, and AI-assisted threat hunting. Built to showcase practical security operations skills.

![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-5%20Tactics%20|%2010%20Techniques-red)
![Detections](https://img.shields.io/badge/Detections-15%20Queries-blue)
![Splunk](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-green)
![MCP](https://img.shields.io/badge/AI-MCP%20Server-purple)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)

---

## About This Project

This is a **portfolio project** demonstrating security engineering skills through a working home lab environment. It showcases:

- **Detection Engineering**: 15 SPL queries with statistical analysis (jitter, z-scores)
- **SOAR Patterns**: Multi-source threat intel orchestration with verdict synthesis
- **AI Integration**: MCP server enabling natural language threat hunting via Claude
- **Infrastructure**: Hybrid cloud architecture with dual data pipelines

> **Note**: All IP addresses, hostnames, and sensitive details have been sanitized. Example outputs use [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation addresses (192.0.2.x, 198.51.100.x, 203.0.113.x) or [REDACTED] placeholders.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HOME NETWORK                                    │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    Network Security Appliance                        │   │
│   │   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐    │   │
│   │   │ Firewall  │   │   DHCP    │   │    DNS    │   │  NetFlow  │    │   │
│   │   │   Logs    │   │  Leases   │   │  Queries  │   │  Export   │    │   │
│   │   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘    │   │
│   │         └───────────────┴───────────────┘               │          │   │
│   │                         │                               │          │   │
│   │                   Syslog (UDP)                    IPFIX v10        │   │
│   └─────────────────────────┼───────────────────────────────┼──────────┘   │
└─────────────────────────────┼───────────────────────────────┼───────────────┘
                              │                               │
                              │          INTERNET             │
                              │                               │
┌─────────────────────────────┼───────────────────────────────┼───────────────┐
│                          CLOUD                                               │
│   ┌─────────────────────────┴───────────────────────────────┴───────────┐   │
│   │                      Splunk Enterprise                               │   │
│   │                                                                      │   │
│   │   ┌─────────────────┐              ┌─────────────────┐              │   │
│   │   │  syslog index   │              │  netflow index  │              │   │
│   │   │  (Firewall/DNS) │              │  (Flow Data)    │              │   │
│   │   └────────┬────────┘              └────────┬────────┘              │   │
│   │            │                                │                        │   │
│   │            └────────────────┬───────────────┘                        │   │
│   │                             │                                        │   │
│   │                    ┌────────▼────────┐                               │   │
│   │                    │  15 Detection   │                               │   │
│   │                    │     Queries     │                               │   │
│   │                    └────────┬────────┘                               │   │
│   └─────────────────────────────┼────────────────────────────────────────┘   │
│                                 │                                            │
│   ┌─────────────────────────────▼────────────────────────────────────────┐   │
│   │                      MCP Threat Hunter                                │   │
│   │   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                │   │
│   │   │   Splunk    │   │ VirusTotal  │   │  AbuseIPDB  │                │   │
│   │   │     API     │   │     API     │   │     API     │                │   │
│   │   └─────────────┘   └─────────────┘   └─────────────┘                │   │
│   │                             │                                         │   │
│   │              Combined Verdict Synthesis                               │   │
│   └─────────────────────────────┼─────────────────────────────────────────┘   │
│                                 │                                            │
└─────────────────────────────────┼────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │      Claude Code        │
                    │  Natural Language       │
                    │   Threat Hunting        │
                    └─────────────────────────┘
```

---

## Skills Demonstrated

### Detection Engineering
| Skill | Implementation |
|-------|----------------|
| Statistical Analysis | Jitter-based C2 detection, z-score volume anomalies |
| MITRE ATT&CK Mapping | 5 tactics, 10 techniques covered |
| Threshold Tuning | Baseline analysis, false positive reduction |
| Query Optimization | Efficient SPL for large datasets |

### Security Orchestration (SOAR Patterns)
| Skill | Implementation |
|-------|----------------|
| Multi-Source Enrichment | VirusTotal + AbuseIPDB concurrent queries |
| Verdict Synthesis | Combined threat scoring from multiple sources |
| Async Execution | `asyncio.gather()` for parallel API calls |
| Graceful Degradation | Continues if one source fails |

### Infrastructure & Operations
| Skill | Implementation |
|-------|----------------|
| SIEM Administration | Splunk indexes, TAs, field extraction |
| Data Pipeline Design | Dual ingestion (syslog + IPFIX) |
| Cloud Architecture | Hybrid on-prem/cloud deployment |
| Monitoring | Pipeline health alerting |

### Software Development
| Skill | Implementation |
|-------|----------------|
| Python | Async/await, type hints, error handling |
| API Integration | REST APIs, authentication, rate limiting |
| MCP Protocol | Claude Code integration |
| Documentation | Technical writing, architecture diagrams |

---

## Detection Coverage

### MITRE ATT&CK Matrix

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| **Reconnaissance** | T1046 Network Service Discovery | Port scanning detection |
| **Initial Access** | T1200 Hardware Additions | New device detection |
| **Lateral Movement** | T1021 Remote Services | Internal admin port monitoring |
| **Command & Control** | T1071 Application Layer Protocol | Beaconing via jitter analysis |
| | T1571 Non-Standard Port | Unusual port detection |
| | T1573 Encrypted Channel | Long-duration flow analysis |
| | T1095 Non-Application Layer Protocol | ICMP tunnel detection |
| **Exfiltration** | T1041 Exfiltration Over C2 | Volume anomaly (z-score) |
| | T1029 Scheduled Transfer | After-hours activity |

### Flagship Detection: C2 Beaconing via Jitter Analysis

**Concept**: C2 implants beacon at regular intervals (low variance). Humans browse randomly (high variance). Jitter quantifies this difference.

```spl
index=netflow earliest=-24h
| search src_ip=192.0.2.* NOT dest_ip=192.0.2.*
| sort 0 src_ip, dest_ip, dest_port, _time
| streamstats current=f window=1 last(_time) as prev_time 
  by src_ip, dest_ip, dest_port
| eval interval = _time - prev_time
| where interval > 0 AND interval < 7200
| stats count as beacon_count, 
        avg(interval) as avg_interval, 
        stdev(interval) as stdev_interval 
  by src_ip, dest_ip, dest_port
| where beacon_count >= 10
| eval jitter_pct = round((stdev_interval / avg_interval) * 100, 1)
| where jitter_pct < 25
| sort jitter_pct
```

**Jitter Interpretation**:

| Jitter % | Meaning | Action |
|----------|---------|--------|
| 0% | Mathematically perfect timing | Investigate immediately |
| 1-10% | Very consistent - automated | Investigate |
| 10-25% | Low variance - worth checking | Review destination |
| >25% | Normal human variance | Likely benign |

**Example Output** (sanitized):

| Source | Destination | Port | Count | Interval | Jitter |
|--------|-------------|------|-------|----------|--------|
| 192.0.2.10 | 198.51.100.50 | 443 | 79 | 60.0s | **0.0%** |
| 192.0.2.10 | 198.51.100.51 | 8443 | 18 | 60.0s | **0.0%** |
| 192.0.2.10 | 203.0.113.25 | 443 | 292 | 30.1s | 1.2% |

> Investigation revealed: Gaming client heartbeat (legitimate). The detection surfaced the pattern correctly - disposition determined through enrichment and context.

---

## MCP Server: AI-Assisted Threat Hunting

The `mcp-server/` directory contains a complete MCP server enabling natural language security investigations through Claude.

### Why Multi-Source Enrichment?

| Approach | What It Demonstrates |
|----------|----------------------|
| Single API call | "I can call an API" |
| Multi-source + Verdict Synthesis | "I understand security orchestration" |

Production SOAR playbooks query multiple threat intelligence sources because no single source has complete visibility:

| Source | Strength | Limitation |
|--------|----------|------------|
| **VirusTotal** | Files, domains, broad coverage | IP intel is secondary |
| **AbuseIPDB** | IP abuse reports, community-sourced | No file analysis |

The server runs lookups **concurrently** and synthesizes a **combined verdict**:

```python
# Concurrent execution (not sequential)
vt_result, abuse_result = await asyncio.gather(
    vt_client.lookup_ip(ip),
    abuseipdb_client.check_ip(ip)
)

# Verdict synthesis
if any(verdict == "MALICIOUS" for verdict in verdicts):
    overall = "MALICIOUS"
```

### Available Tools

| Tool | Description |
|------|-------------|
| `search_splunk` | Execute arbitrary SPL queries |
| `enrich_ip` | VirusTotal + AbuseIPDB with combined verdict |
| `enrich_domain` | Domain reputation lookup |
| `enrich_hash` | File hash analysis |
| `hunt_beacons` | C2 detection via jitter analysis |
| `hunt_volume_anomaly` | Exfiltration detection via z-scores |
| `hunt_new_destinations` | First-seen external connections |
| `hunt_ioc` | Combined search + enrichment |
| `get_network_summary` | Top talkers, destinations, ports |
| `check_pipeline_health` | Data ingestion status |

### Example Interaction

```
User: "Hunt for beaconing patterns and enrich any suspicious destinations"

Claude: [Calls hunt_beacons → Calls enrich_ip for flagged IPs]

"Found 3 low-jitter patterns. Enrichment results:
 - 198.51.100.50: Gaming CDN (CLEAN) - Steam heartbeat
 - 198.51.100.51: Gaming CDN (CLEAN) - Steam heartbeat  
 - 203.0.113.25: Cloud provider (CLEAN) - App update check

 No malicious indicators. Recommend allowlisting known gaming infrastructure."
```

---

## Lessons Learned

### 1. Silent Failures Are the Worst Failures

Both data pipelines failed for 48 hours with zero alerts. Root causes:
- ISP changed WAN IP → cloud firewall blocked traffic
- Directory path changed after reorganization
- JSON format mismatch (arrays vs. newline-delimited)

**Solution**: Implemented "monitoring for the monitoring" - alerts if either pipeline goes silent for 30 minutes.

### 2. Baseline Before You Tune

Initial port scanning detection triggered constantly. Investigation revealed a typical workstation contacts 500+ unique destinations daily through normal browsing.

**Solution**: Established baselines first, then set thresholds above normal variance.

### 3. Two Data Sources Beat One

Perimeter logs showed 9,600+ blocked attacks. Internal flow data showed what traversed the network. Neither tells the complete story alone.

**Solution**: Correlate perimeter (what was blocked) with internal (what got through).

### 4. Statistical Methods Catch What Signatures Miss

Jitter analysis doesn't require IOCs or signatures. It detects behavioral patterns that would look identical whether from known or novel malware.

---

## Repository Structure

```
├── README.md                           # This file
├── LICENSE                             # MIT License
├── SECURITY.md                         # Security policy
│
├── docs/
│   ├── technical-documentation.md      # Deployment guide
│   ├── detection-catalog.md            # All 15 queries with MITRE mapping
│   ├── architecture.md                 # Detailed diagrams
│   └── ingestion-monitoring.md         # Pipeline health alerting
│
├── splunk/
│   ├── apps/
│   │   ├── TA-syslog/                  # Syslog Technology Add-on
│   │   └── TA-netflow/                 # NetFlow Technology Add-on
│   ├── indexes.conf.example            # Index configuration template
│   └── saved-searches/
│       └── detections.conf             # All detection queries
│
├── scripts/
│   ├── process_flows.sh                # NetFlow → NDJSON conversion
│   └── setup.sh                        # Installation helper
│
└── mcp-server/
    ├── server.py                       # MCP server implementation
    ├── test_server.py                  # Test harness
    ├── requirements.txt                # Python dependencies
    ├── .env.template                   # Configuration template
    ├── README.md                       # Setup instructions
    └── USAGE_EXAMPLES.md               # Example prompts
```

---

## Getting Started

### Prerequisites

- Splunk Enterprise (Free/Dev license sufficient)
- Python 3.10+
- Network device with syslog + NetFlow/IPFIX export
- Cloud instance or local server

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/KhanIkram/hybrid-cloud-siem.git
   cd hybrid-cloud-siem
   ```

2. **Review documentation**
   ```bash
   # Start with the technical guide
   cat docs/technical-documentation.md
   ```

3. **Deploy Splunk components**
   ```bash
   # Copy Technology Add-ons
   cp -r splunk/apps/TA-* $SPLUNK_HOME/etc/apps/
   ```

4. **Set up MCP server** (optional)
   ```bash
   cd mcp-server
   pip install -r requirements.txt
   cp .env.template .env
   # Edit .env with your credentials
   ```

See [docs/technical-documentation.md](docs/technical-documentation.md) for detailed instructions.

---

## Future Enhancements

- [ ] Splunk dashboards for visualization
- [ ] GreyNoise integration (benign scanner identification)
- [ ] Automated IOC blocklist updates
- [ ] Suricata IDS integration
- [ ] Sigma rule conversion

---

## Related Skills

This project demonstrates competencies relevant to:

- **Security Engineer** - Detection development, SIEM administration
- **Security Analyst** - Threat hunting, log analysis, triage
- **SOAR Engineer** - Multi-source orchestration, playbook patterns
- **Detection Engineer** - MITRE mapping, statistical analysis
- **SecOps/SOC** - Monitoring, alerting, incident response foundations

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Contact

Open to discussing this project, security engineering, or detection development opportunities.

- LinkedIn: https://www.linkedin.com/in/khanrikram/
- Email: ikramrkhan3@gmail.com


---

*Built for learning. Designed for detection. Ready to discuss.*
