# Detection Catalog

15 detection queries mapped to MITRE ATT&CK framework.

---

## Coverage Summary

| Tactic | Techniques | Detections |
|--------|------------|------------|
| Reconnaissance | 1 | 1 |
| Initial Access | 1 | 1 |
| Lateral Movement | 1 | 1 |
| Command & Control | 5 | 7 |
| Exfiltration | 2 | 3 |
| **Operations** | - | 2 |

---

## Detection Index

| # | Name | MITRE | Data Source |
|---|------|-------|-------------|
| 01 | Device Inventory | Baseline | NetFlow |
| 02 | C2 Beaconing (Jitter) | T1071, T1573 | NetFlow |
| 03 | Port Scanning | T1046 | NetFlow |
| 04 | Volume Anomaly (Z-Score) | T1041 | NetFlow |
| 05 | New External Destinations | T1071 | NetFlow |
| 06 | Internal Admin Port Access | T1021 | NetFlow |
| 07 | Long Duration Flows | T1573 | NetFlow |
| 08 | Non-Standard Port Usage | T1571 | NetFlow |
| 09 | Large Transfers | T1041 | NetFlow |
| 10 | DNS to Non-Standard Resolver | T1071.004 | NetFlow |
| 11 | Unusual Protocol Usage | T1095 | NetFlow |
| 12 | After Hours Activity | T1029 | NetFlow |
| 13 | New Internal Device | T1200 | NetFlow |
| 14 | Known Suspicious Ports | T1571 | NetFlow |
| 15 | ICMP Tunnel Detection | T1095 | NetFlow |

---

## Detailed Detection Documentation

### Detection 01: Device Inventory (Baseline)

**Purpose**: Establish baseline of active internal hosts and their communication patterns.

**MITRE**: N/A (Baseline)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* OR src_ip=10.* OR src_ip=172.16.*
| stats dc(dest_ip) as unique_destinations, 
        sum(bytes) as bytes_total, 
        count as flows 
  by src_ip
| eval MB = round(bytes_total/1024/1024, 2)
| sort -flows
| table src_ip, flows, unique_destinations, MB
```

**Tuning**: Run weekly to track device inventory changes.

---

### Detection 02: C2 Beaconing via Jitter Analysis ⭐

**Purpose**: Detect automated C2 check-ins by measuring timing consistency.

**MITRE**: T1071 (Application Layer Protocol), T1573 (Encrypted Channel)

**Concept**: C2 implants beacon at regular intervals (low jitter). Human browsing is random (high jitter).

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* NOT (dest_ip=192.168.* OR dest_ip=10.* OR dest_ip=172.16.*)
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
| table src_ip, dest_ip, dest_port, beacon_count, avg_interval, jitter_pct
| sort jitter_pct
```

**Jitter Interpretation**:

| Jitter % | Meaning | Action |
|----------|---------|--------|
| 0% | Perfect timing (timer-based) | Investigate immediately |
| 1-10% | Very consistent | Likely automated, investigate |
| 10-25% | Low variance | Worth reviewing |
| >25% | Normal human variance | Likely benign |

**Tuning**:
- `beacon_count >= 10`: Minimum connections to establish pattern
- `jitter_pct < 25`: Threshold for flagging (adjust based on baseline)
- `interval < 7200`: Ignore intervals >2 hours

**False Positives**: Gaming clients, update services, monitoring tools

---

### Detection 03: Port Scanning

**Purpose**: Detect hosts scanning network ports or multiple targets.

**MITRE**: T1046 (Network Service Discovery)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* OR src_ip=10.*
| bin _time span=1h
| stats dc(dest_port) as unique_ports, 
        dc(dest_ip) as unique_targets, 
        count as flows 
  by _time, src_ip
| where unique_ports > 50 OR unique_targets > 200
| eval hour = strftime(_time, "%Y-%m-%d %H:%M")
| table hour, src_ip, unique_ports, unique_targets, flows
| sort -unique_ports
```

**Tuning**:
- `unique_ports > 50`: Normal browsing hits 20-40 ports/hour
- `unique_targets > 200`: Adjust based on network size

**False Positives**: Web browsers (many connections), vulnerability scanners (authorized)

---

### Detection 04: Volume Anomaly via Z-Score ⭐

**Purpose**: Detect unusual outbound data volumes indicating potential exfiltration.

**MITRE**: T1041 (Exfiltration Over C2 Channel)

**Concept**: Statistical anomaly detection using z-scores. Flags hours with traffic >2 standard deviations from the host's mean.

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* NOT (dest_ip=192.168.* OR dest_ip=10.*)
| bin _time span=1h
| stats sum(bytes) as hourly_bytes by _time, src_ip
| eventstats avg(hourly_bytes) as avg_bytes, 
             stdev(hourly_bytes) as stdev_bytes 
  by src_ip
| where stdev_bytes > 0
| eval zscore = round((hourly_bytes - avg_bytes) / stdev_bytes, 2)
| where zscore > 2
| eval MB = round(hourly_bytes/1024/1024, 2)
| eval hour = strftime(_time, "%Y-%m-%d %H:%M")
| table hour, src_ip, MB, zscore
| sort -zscore
```

**Tuning**:
- `zscore > 2`: 2 standard deviations (catches ~5% outliers)
- Increase to 3 for fewer, more significant alerts

**False Positives**: Backups, large downloads, video streaming

---

### Detection 05: New External Destinations

**Purpose**: Identify connections to previously unseen external IPs.

**MITRE**: T1071 (Application Layer Protocol)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* NOT (dest_ip=192.168.* OR dest_ip=10.*)
| stats earliest(_time) as first_seen, 
        count as flows, 
        sum(bytes) as bytes_total 
  by dest_ip
| where first_seen > relative_time(now(), "-4h")
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval MB = round(bytes_total/1024/1024, 2)
| sort -flows
| table dest_ip, first_seen, flows, MB
| head 20
```

**Tuning**:
- `-4h`: Window for "new" (adjust based on network activity)
- Combine with threat intel enrichment for triage

---

### Detection 06: Internal Admin Port Access

**Purpose**: Detect lateral movement via administrative protocols.

**MITRE**: T1021 (Remote Services)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* dest_ip=192.168.*
| search dest_port IN (22, 23, 135, 139, 445, 3389, 5985, 5986)
| stats dc(dest_ip) as unique_targets, 
        count as flows, 
        sum(bytes) as bytes_total 
  by src_ip, dest_port
| where unique_targets > 1
| eval MB = round(bytes_total/1024/1024, 2)
| table src_ip, dest_port, unique_targets, flows, MB
| sort -unique_targets
```

**Ports Monitored**:
| Port | Service |
|------|---------|
| 22 | SSH |
| 23 | Telnet |
| 135 | RPC |
| 139, 445 | SMB |
| 3389 | RDP |
| 5985, 5986 | WinRM |

**Tuning**: Whitelist known admin workstations

---

### Detection 07: Long Duration Flows

**Purpose**: Detect persistent connections that may indicate C2 or tunnels.

**MITRE**: T1573 (Encrypted Channel)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* NOT (dest_ip=192.168.* OR dest_ip=10.*)
| where duration > 3600
| stats count as flows, 
        sum(bytes) as bytes_total, 
        avg(duration) as avg_duration 
  by src_ip, dest_ip, dest_port
| where flows > 3
| eval hours = round(avg_duration/3600, 2)
| eval MB = round(bytes_total/1024/1024, 2)
| table src_ip, dest_ip, dest_port, flows, hours, MB
| sort -hours
```

**Tuning**:
- `duration > 3600`: Flows longer than 1 hour
- `flows > 3`: Multiple long flows to same destination

**False Positives**: VPN connections, streaming services, remote desktop

---

### Detection 08: Non-Standard Port Usage

**Purpose**: Detect traffic on unusual ports indicating protocol evasion.

**MITRE**: T1571 (Non-Standard Port)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* NOT (dest_ip=192.168.* OR dest_ip=10.*)
| where NOT dest_port IN (80, 443, 53, 123, 22, 25, 587, 993, 995, 8080, 8443)
| stats count as flows, 
        sum(bytes) as bytes_total, 
        dc(src_ip) as unique_sources 
  by dest_ip, dest_port
| where flows > 50
| eval MB = round(bytes_total/1024/1024, 2)
| table dest_ip, dest_port, flows, MB, unique_sources
| sort -flows
```

**Tuning**: Add legitimate ports to exclusion list as identified

---

### Detection 09: Large Transfers to Single Destination

**Purpose**: Detect potential data exfiltration via volume.

**MITRE**: T1041 (Exfiltration Over C2 Channel)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* NOT (dest_ip=192.168.* OR dest_ip=10.*)
| stats sum(bytes) as bytes_total, count as flows by src_ip, dest_ip
| where bytes_total > 5000000
| eval MB = round(bytes_total/1024/1024, 2)
| sort -MB
| head 20
| table src_ip, dest_ip, MB, flows
```

**Tuning**: Adjust `bytes_total > 5000000` (5MB) based on normal activity

---

### Detection 10: DNS to Non-Standard Resolver

**Purpose**: Detect DNS queries to unauthorized resolvers (potential tunneling).

**MITRE**: T1071.004 (DNS)

**Query**:
```spl
index=netflow earliest=-24h
| search dest_port=53 OR src_port=53
| where NOT (dest_ip="8.8.8.8" OR dest_ip="8.8.4.4" OR dest_ip="1.1.1.1" OR dest_ip="1.0.0.1")
| where NOT dest_ip LIKE "192.168.%" AND NOT dest_ip LIKE "10.%"
| stats count as flows, sum(bytes) as bytes_total by src_ip, dest_ip
| where flows > 10
| table src_ip, dest_ip, flows, bytes_total
| sort -flows
```

**Tuning**: Add your authorized DNS servers to exclusion list

---

### Detection 11: Unusual Protocol Usage

**Purpose**: Detect traffic using uncommon protocols (GRE, ESP tunnels).

**MITRE**: T1095 (Non-Application Layer Protocol)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.*
| where NOT protocol IN (6, 17, 1)
| stats count as flows, sum(bytes) as bytes_total by src_ip, dest_ip, protocol
| eval protocol_name = case(
    protocol=47, "GRE", 
    protocol=50, "ESP", 
    protocol=51, "AH", 
    protocol=41, "IPv6-tunnel", 
    1=1, tostring(protocol))
| table src_ip, dest_ip, protocol, protocol_name, flows, bytes_total
| sort -flows
```

**Protocol Reference**:
| Number | Name | Concern |
|--------|------|---------|
| 47 | GRE | Tunneling |
| 50 | ESP | VPN/encrypted |
| 51 | AH | Authentication |
| 41 | IPv6-in-IPv4 | Tunneling |

---

### Detection 12: After Hours Activity

**Purpose**: Detect network activity during unusual hours.

**MITRE**: T1029 (Scheduled Transfer)

**Query**:
```spl
index=netflow earliest=-7d
| search src_ip=192.168.* NOT (dest_ip=192.168.* OR dest_ip=10.*)
| eval hour_utc = tonumber(strftime(_time, "%H"))
| eval minute_utc = tonumber(strftime(_time, "%M"))
| eval time_decimal = hour_utc + (minute_utc / 60)
| where time_decimal >= 8.0 AND time_decimal < 13.5
| stats count as flows, 
        sum(bytes) as bytes_total, 
        dc(dest_ip) as unique_dests 
  by src_ip
| eval MB = round(bytes_total/1024/1024, 2)
| table src_ip, flows, unique_dests, MB
| sort -flows
```

**Tuning**: Adjust UTC hours for your timezone. Example shows 3:00-8:30 AM ET (UTC-5).

---

### Detection 13: New Internal Device

**Purpose**: Detect new devices appearing on the network.

**MITRE**: T1200 (Hardware Additions)

**Query**:
```spl
index=netflow earliest=-24h
| search src_ip=192.168.* OR src_ip=10.*
| stats earliest(_time) as first_seen, count as flows by src_ip
| where first_seen > relative_time(now(), "-4h")
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| table src_ip, first_seen, flows
| sort -flows
```

**Tuning**: Correlate with DHCP logs for MAC address context

---

### Detection 14: Known Suspicious Ports

**Purpose**: Detect traffic to ports associated with malware or anonymization.

**MITRE**: T1571 (Non-Standard Port)

**Query**:
```spl
index=netflow earliest=-24h
| search dest_port IN (4444, 5555, 6666, 1337, 31337, 8545, 3128, 9001, 9030, 9050, 9051)
| stats count as flows, sum(bytes) as bytes_total by src_ip, dest_ip, dest_port
| eval MB = round(bytes_total/1024/1024, 2)
| table src_ip, dest_ip, dest_port, flows, MB
| sort -flows
```

**Port Reference**:
| Port | Association |
|------|-------------|
| 4444 | Metasploit default |
| 5555 | Android ADB |
| 1337, 31337 | "Elite" backdoors |
| 8545 | Ethereum RPC |
| 3128 | Squid proxy |
| 9001, 9030, 9050, 9051 | Tor |

---

### Detection 15: ICMP Tunnel Detection

**Purpose**: Detect ICMP traffic with high data volume (potential tunneling).

**MITRE**: T1095 (Non-Application Layer Protocol)

**Query**:
```spl
index=netflow earliest=-24h
| search protocol=1
| stats count as flows, sum(bytes) as bytes_total by src_ip, dest_ip
| where bytes_total > 10000
| eval KB = round(bytes_total/1024, 2)
| table src_ip, dest_ip, flows, KB
| sort -KB
```

**Tuning**: Normal ICMP (ping) is small. High volume indicates data transfer.

---

## Operational Alerts

### Pipeline Health Check

**Purpose**: Alert when data stops flowing.

```spl
| tstats latest(_time) as last_event WHERE index=syslog OR index=netflow by index
| eval minutes_ago = round((now() - last_event) / 60, 1)
| where minutes_ago >= 30
| eval status = case(minutes_ago < 60, "Warning", 1=1, "Critical")
| table index, minutes_ago, status
```

**Schedule**: Every 15 minutes

---

### License Usage Warning

**Purpose**: Alert before hitting license limits.

```spl
| rest /services/licenser/pools
| stats sum(used_bytes) as used, sum(effective_quota) as quota
| eval pct_used = round((used/quota)*100, 1)
| where pct_used > 80
| table pct_used
```

**Schedule**: Every 4 hours

---

## Tuning Methodology

1. **Baseline first**: Run Detection 01 to understand normal activity
2. **Start loose**: Begin with high thresholds, reduce false positives
3. **Document exceptions**: Track whitelisted items and reasoning
4. **Review weekly**: Adjust based on operational experience
5. **Correlate sources**: Combine detections for higher confidence
