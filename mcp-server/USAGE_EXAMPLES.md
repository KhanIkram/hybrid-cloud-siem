# Usage Examples

Real-world examples of using MCP Threat Hunter with Claude Code.

---

## Workflow 1: Daily Threat Hunt

### Prompt
```
Run a complete threat hunt for the last 24 hours:
1. First check if our data pipelines are healthy
2. Hunt for C2 beaconing patterns
3. Look for volume anomalies
4. Check for new destinations
5. Summarize your findings
```

### What Claude Does
1. Calls `check_pipeline_health` - verifies data is flowing
2. Calls `hunt_beacons` - finds low-jitter patterns
3. Calls `hunt_volume_anomaly` - finds z-score outliers
4. Calls `hunt_new_destinations` - finds first-seen IPs
5. Synthesizes findings into actionable report

### Example Response
```
## Daily Threat Hunt Summary - December 21, 2025

### Pipeline Status: HEALTHY
Both syslog and netflow indexes receiving data normally.

### C2 Beaconing Analysis
Found 3 low-jitter patterns:
- 192.0.2.10 → 104.21.x.x:443 - 0% jitter, 60s interval
  → Investigated: Steam game client heartbeat (benign)
- 192.0.2.10 → 172.67.x.x:8443 - 2.1% jitter, 30s interval
  → Cloudflare CDN, likely app update check

### Volume Anomalies
1 anomaly detected:
- 192.0.2.10 at 3:00 AM - 45MB (z-score: 3.2)
  → Coincides with scheduled backup window

### New Destinations
12 new external IPs in last 4 hours:
- All resolved to Microsoft, Google, Cloudflare infrastructure
- No suspicious indicators

### Verdict: No active threats detected
Recommend continuing normal monitoring.
```

---

## Workflow 2: Investigate an Alert

### Prompt
```
We got an IDS alert for traffic to 198.51.100.45. 
Hunt for this IP in our logs and enrich it with threat intel.
```

### What Claude Does
1. Calls `hunt_ioc` with IP type
2. Searches Splunk for all traffic to/from that IP
3. Enriches with VirusTotal + AbuseIPDB
4. Provides combined analysis

### Example Response
```
## IOC Investigation: 198.51.100.45

### Threat Intelligence

**Overall Verdict: MALICIOUS**

| Source | Verdict | Key Finding |
|--------|---------|-------------|
| VirusTotal | MALICIOUS | 12/90 vendors flagged |
| AbuseIPDB | MALICIOUS | 100% abuse score, 847 reports |

**Details:**
- Country: Russia
- ASN: AS12345 - Suspicious Hosting
- Usage Type: Data Center/Web Hosting
- Tags: tor-exit-node, malware, botnet-c2

### Splunk Findings

**Found in logs: YES**

| Source | Destination | Flows | Data | Ports |
|--------|-------------|-------|------|-------|
| 192.0.2.10 | 198.51.100.45 | 23 | 1.2 MB | 443, 8080 |

First seen: 2025-12-21 02:15:00
Last seen: 2025-12-21 02:47:00

### Recommendation
**IMMEDIATE ACTION REQUIRED**
1. Isolate 192.0.2.10 from network
2. Capture memory for forensic analysis
3. Review full connection timeline
4. Check for lateral movement from this host
```

---

## Workflow 3: Beaconing Deep Dive

### Prompt
```
I need to understand our beaconing patterns better.
Search with a very low threshold (5% jitter) and 
enrich any external IPs you find.
```

### What Claude Does
1. Calls `hunt_beacons` with jitter_threshold=5
2. For each external destination, calls `enrich_ip`
3. Correlates findings

### Example Response
```
## Low-Jitter Pattern Analysis (<5% threshold)

Found 5 patterns with very consistent timing:

### Pattern 1: BENIGN
- Source: 192.0.2.10
- Destination: 203.0.113.67 (Cloudflare)
- Port: 19314
- Interval: 60s, Jitter: 0.0%
- VT: CLEAN, AbuseIPDB: 0% abuse
- **Verdict:** Steam game client heartbeat

### Pattern 2: BENIGN  
- Source: 192.0.2.10
- Destination: 52.96.x.x (Microsoft)
- Port: 443
- Interval: 300s, Jitter: 0.3%
- VT: CLEAN, AbuseIPDB: 0% abuse
- **Verdict:** Microsoft Teams presence updates

### Pattern 3: INVESTIGATE
- Source: 192.0.2.25
- Destination: 45.33.x.x (Linode)
- Port: 8443
- Interval: 120s, Jitter: 1.2%
- VT: 2/90 vendors, AbuseIPDB: 15% abuse
- **Verdict:** Unknown - recommend investigation

### Summary
4/5 patterns confirmed benign (known apps)
1/5 pattern needs investigation (Pattern 3)
```

---

## Workflow 4: Custom SPL Query

### Prompt
```
Run this query and explain what it shows:
index=netflow 
| stats count by dst_port 
| sort -count 
| head 20
```

### What Claude Does
1. Calls `search_splunk` with the provided query
2. Interprets results

### Example Response
```
## Query Results: Top 20 Destination Ports

| Port | Count | Service |
|------|-------|---------|
| 443 | 125,847 | HTTPS |
| 80 | 23,456 | HTTP |
| 53 | 12,234 | DNS |
| 8443 | 8,901 | HTTPS-alt |
| 19314 | 7,234 | Steam |
| 123 | 3,456 | NTP |
| 8080 | 2,345 | HTTP Proxy |
| 5228 | 1,234 | Google Play |
| ... | ... | ... |

### Analysis
Traffic distribution looks normal:
- HTTPS (443) dominates as expected
- Gaming ports (19xxx) present - matches Steam client
- DNS queries reasonable volume
- No suspicious ports in top 20

**Notable:** Port 8443 usage is elevated. 
Consider investigating specific destinations.
```

---

## Workflow 5: Network Baseline

### Prompt
```
Give me a complete picture of network activity 
for the last 7 days. I need to understand 
what's normal in this environment.
```

### What Claude Does
1. Calls `get_network_summary` with hours=168
2. Calls `search_splunk` for additional metrics
3. Builds baseline profile

### Example Response
```
## Network Baseline Report (7 Days)

### Active Hosts
| Internal IP | Total Flows | Data (GB) | Unique Dests |
|-------------|-------------|-----------|--------------|
| 192.0.2.10 | 847,234 | 45.2 | 3,456 |
| 192.0.2.25 | 234,567 | 12.3 | 891 |

### Traffic Patterns
- Peak hours: 9 AM - 11 PM local
- Quiet hours: 2 AM - 6 AM
- Weekend traffic: ~40% of weekday volume

### Top Destinations
1. Cloudflare (104.x.x.x) - CDN traffic
2. Google (142.x.x.x) - Search, Gmail, Drive
3. Microsoft (52.x.x.x) - O365, Teams
4. Amazon (54.x.x.x) - AWS services
5. Steam (104.x.x.x) - Gaming

### Baseline Metrics
| Metric | Average | Std Dev | Anomaly Threshold |
|--------|---------|---------|-------------------|
| Daily flows | 154,000 | 23,000 | >200,000 |
| Daily data | 8.2 GB | 1.4 GB | >11 GB |
| Unique dests | 4,500 | 800 | >6,100 |

### Recommendations
- Normal: HTTPS to major cloud providers
- Normal: Gaming traffic evenings/weekends
- Investigate: Any traffic 2-6 AM
- Investigate: New IPs not in top destinations
```

---

## Quick Reference Commands

| Task | Prompt |
|------|--------|
| Health check | "Check pipeline health" |
| Hunt beacons | "Hunt for C2 beacons" |
| Volume anomaly | "Look for volume anomalies" |
| Enrich IP | "Enrich 8.8.8.8" |
| IOC hunt | "Hunt for this IP: x.x.x.x" |
| Network summary | "Give me a network summary" |
| Custom query | "Run this SPL: ..." |

---

## Tips for Effective Prompts

1. **Be specific about time ranges**
   - "Last 24 hours" vs "Last 7 days"
   
2. **Set thresholds when hunting**
   - "Jitter less than 10%"
   - "Z-score above 3"

3. **Chain investigations**
   - "Find beacons, then enrich suspicious IPs"
   
4. **Request context**
   - "Explain what you find"
   - "Summarize the risk"

5. **Use domain knowledge**
   - "Ignore known CDN traffic"
   - "Focus on non-standard ports"
