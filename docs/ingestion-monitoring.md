# Ingestion Monitoring Guide

How to monitor your data pipelines and detect silent failures.

---

## The Problem

Silent failures are the most dangerous failures in a SIEM. If data stops flowing:
- No errors are logged
- No alerts fire
- You're blind to attacks
- You might not notice for days

This guide covers how to implement "monitoring for the monitoring."

---

## Pipeline Health Alert

### Query

```spl
| tstats latest(_time) as last_event WHERE index=syslog OR index=netflow by index
| eval minutes_ago = round((now() - last_event) / 60, 1)
| where minutes_ago >= 30
| eval status = case(
    minutes_ago < 60, "Warning",
    1=1, "Critical"
)
| eval last_event_time = strftime(last_event, "%Y-%m-%d %H:%M:%S")
| table index, last_event_time, minutes_ago, status
```

### Interpretation

| minutes_ago | Status | Action |
|-------------|--------|--------|
| < 30 | Healthy | No action |
| 30-60 | Warning | Investigate soon |
| > 60 | Critical | Investigate immediately |

### Alert Configuration

**Schedule**: Every 15 minutes

**Trigger**: `count > 0`

**Actions**:
- Email notification
- Webhook to Slack/Teams
- PagerDuty (for critical)

---

## Common Failure Modes

### 1. WAN IP Changed

**Symptom**: Both pipelines stop simultaneously

**Cause**: ISP assigned new IP, cloud firewall blocks traffic

**Detection**:
```spl
| tstats latest(_time) as last_event WHERE index=* by index
| where last_event < relative_time(now(), "-1h")
```

**Fix**:
1. Check current WAN IP
2. Update cloud security group
3. Consider dynamic DNS

### 2. Collector Process Died

**Symptom**: NetFlow stops, syslog continues

**Cause**: nfcapd crashed or was killed

**Detection**:
```bash
ps aux | grep nfcapd
systemctl status nfcapd
```

**Fix**:
```bash
systemctl restart nfcapd
# Or: nfcapd -w -D -l /opt/netflow/capture -p 2055
```

### 3. Disk Full

**Symptom**: Gradual slowdown, then failure

**Cause**: Logs/flows filled disk

**Detection**:
```bash
df -h
du -sh /opt/splunk/var/lib/splunk/*
```

**Fix**:
1. Clear old data
2. Reduce retention in indexes.conf
3. Enable sampling for NetFlow

### 4. Processing Script Failed

**Symptom**: NetFlow collector running but no new data in Splunk

**Cause**: process_flows.sh error

**Detection**:
```bash
# Check for recent processed files
ls -lt /opt/netflow/processed/ | head
# Check script output
cat /var/log/netflow_process.log
```

**Fix**:
1. Run script manually with debug
2. Check disk space
3. Verify nfdump works

### 5. Splunk License Violation

**Symptom**: Searches fail, data not indexed

**Cause**: Exceeded daily license

**Detection**:
```spl
| rest /services/licenser/pools
| eval pct = round((used_bytes/effective_quota)*100, 1)
```

**Fix**:
1. Wait for license reset (midnight UTC)
2. Enable NetFlow sampling
3. Reduce retention
4. Upgrade license

---

## Monitoring Dashboard

Create a simple dashboard with these panels:

### Panel 1: Pipeline Status

```spl
| tstats latest(_time) as last_event WHERE index=syslog OR index=netflow by index
| eval minutes_ago = round((now() - last_event) / 60, 1)
| eval status = case(
    minutes_ago < 15, "🟢 Healthy",
    minutes_ago < 30, "🟡 Warning",
    1=1, "🔴 Critical"
)
| table index, status, minutes_ago
```

### Panel 2: Ingestion Volume (24h)

```spl
| tstats count WHERE index=syslog OR index=netflow by index, _time span=1h
| timechart span=1h sum(count) by index
```

### Panel 3: License Usage

```spl
| rest /services/licenser/pools
| eval used_GB = round(used_bytes/1024/1024/1024, 2)
| eval quota_GB = round(effective_quota/1024/1024/1024, 2)
| eval pct = round((used_bytes/effective_quota)*100, 1)
| table used_GB, quota_GB, pct
```

---

## Automated Recovery

### Systemd Service for nfcapd

```ini
# /etc/systemd/system/nfcapd.service
[Unit]
Description=NetFlow Capture Daemon
After=network.target

[Service]
Type=forking
ExecStart=/usr/bin/nfcapd -w -D -l /opt/netflow/capture -p 2055
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
systemctl enable nfcapd
systemctl start nfcapd
```

### Cron Job for Processing

```bash
# /etc/cron.d/netflow-process
*/5 * * * * root /opt/scripts/process_flows.sh >> /var/log/netflow_process.log 2>&1
```

---

## Health Check Script

```bash
#!/bin/bash
# health_check.sh - Run from cron every 15 minutes

SLACK_WEBHOOK="https://hooks.slack.com/..."
SPLUNK_HOST="localhost"
SPLUNK_PORT="8089"

# Check nfcapd
if ! pgrep -x nfcapd > /dev/null; then
    curl -X POST -H 'Content-type: application/json' \
        --data '{"text":"⚠️ nfcapd is not running!"}' \
        $SLACK_WEBHOOK
    systemctl restart nfcapd
fi

# Check Splunk
if ! curl -sk "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/server/health" | grep -q "splunkd_health"; then
    curl -X POST -H 'Content-type: application/json' \
        --data '{"text":"⚠️ Splunk API not responding!"}' \
        $SLACK_WEBHOOK
fi

# Check disk space
DISK_PCT=$(df /opt | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_PCT" -gt 85 ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"⚠️ Disk usage at ${DISK_PCT}%!\"}" \
        $SLACK_WEBHOOK
fi
```

---

## Key Takeaways

1. **Never trust silence** - No alerts doesn't mean everything is working
2. **Monitor the monitor** - Pipeline health alerts are non-negotiable
3. **Automate recovery** - Use systemd for service management
4. **Test your alerts** - Periodically stop a service to verify alerting
5. **Document failures** - Track root causes to prevent recurrence

---

## Checklist

- [ ] Pipeline health alert configured and tested
- [ ] Scheduled to run every 15 minutes
- [ ] Alert actions configured (email/Slack)
- [ ] nfcapd running as systemd service
- [ ] Processing script in cron
- [ ] Disk space monitoring enabled
- [ ] License usage alert configured
- [ ] Recovery procedures documented
