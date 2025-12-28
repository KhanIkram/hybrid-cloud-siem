#!/bin/bash
# setup.sh
# Helper script for initial SIEM setup
# Run with: sudo ./setup.sh

set -e

echo "======================================"
echo "Hybrid Cloud SIEM Setup Script"
echo "======================================"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./setup.sh)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS. This script requires Ubuntu/Debian."
    exit 1
fi

echo "[1/6] Installing dependencies..."
apt update
apt install -y nfdump jq

echo "[2/6] Creating directory structure..."
mkdir -p /opt/netflow/{scripts,processed,logs}
mkdir -p /var/cache/nfdump

echo "[3/6] Installing processing script..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/process_flows.sh" /opt/netflow/scripts/
chmod +x /opt/netflow/scripts/process_flows.sh

echo "[4/6] Setting up nfcapd service..."
# Check if nfcapd is already running
if pgrep -x "nfcapd" > /dev/null; then
    echo "  nfcapd already running"
else
    nfcapd -w -D -l /var/cache/nfdump -p 2055
    echo "  nfcapd started on UDP/2055"
fi

echo "[5/6] Setting up cron job..."
# Add cron job if not exists
CRON_CMD="*/5 * * * * /opt/netflow/scripts/process_flows.sh"
if ! crontab -l 2>/dev/null | grep -q "process_flows.sh"; then
    (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -
    echo "  Cron job added (runs every 5 minutes)"
else
    echo "  Cron job already exists"
fi

echo "[6/6] Verifying setup..."
echo

# Verify nfcapd
if pgrep -x "nfcapd" > /dev/null; then
    echo "✅ nfcapd is running"
else
    echo "❌ nfcapd is NOT running"
fi

# Verify directories
if [ -d /opt/netflow/processed ]; then
    echo "✅ Output directory exists"
else
    echo "❌ Output directory missing"
fi

# Verify script
if [ -x /opt/netflow/scripts/process_flows.sh ]; then
    echo "✅ Processing script installed"
else
    echo "❌ Processing script missing or not executable"
fi

echo
echo "======================================"
echo "Setup Complete!"
echo "======================================"
echo
echo "Next steps:"
echo "1. Install Splunk Technology Add-ons:"
echo "   sudo cp -r ../splunk/apps/TA-syslog /opt/splunk/etc/apps/"
echo "   sudo cp -r ../splunk/apps/TA-netflow /opt/splunk/etc/apps/"
echo
echo "2. Create Splunk indexes (copy indexes.conf.example)"
echo
echo "3. Configure your network device to send:"
echo "   - Syslog to <this-server>:5514"
echo "   - IPFIX/NetFlow to <this-server>:2055"
echo
echo "4. Restart Splunk:"
echo "   sudo /opt/splunk/bin/splunk restart"
echo