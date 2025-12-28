#!/bin/bash
# process_flows.sh
# Convert completed nfcapd files to NDJSON format for Splunk ingestion
#
# This script:
# 1. Finds completed nfcapd capture files
# 2. Converts them to JSON using nfdump
# 3. Transforms to NDJSON (one JSON object per line) for Splunk
# 4. Optionally samples data to reduce volume
#
# Dependencies: nfdump, jq
# Cron: */5 * * * * /opt/netflow/scripts/process_flows.sh

CAPTURE_DIR="/var/cache/nfdump"
OUTPUT_DIR="/opt/netflow/processed"
LOG_FILE="/opt/netflow/logs/process.log"

# Sampling rate configuration
# ----------------------------
# Controls how many flow records to keep. Higher = fewer records = less storage/license.
#
# | Rate | Keeps | Reduction | Use Case                                    |
# |------|-------|-----------|---------------------------------------------|
# |  1   | 100%  |    0%     | Full fidelity - best detection accuracy     |
# |  2   |  50%  |   50%     | Balanced - good accuracy, manageable volume |
# |  3   |  33%  |   67%     | Moderate reduction                          |
# |  4   |  25%  |   75%     | Aggressive reduction                        |
# |  5   |  20%  |   80%     | Maximum reduction - use if license-limited  |
#
# Trade-off: Higher sampling rates may miss low-volume patterns (early-stage C2).
# Recommendation: Start with 2, reduce to 1 if license/storage allows.
SAMPLE_RATE=2

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# Find completed capture files (not .current) and process them
for f in "$CAPTURE_DIR"/nfcapd.2*; do
    [ -e "$f" ] || continue
    
    # Skip .current files (still being written)
    [[ "$f" == *".current"* ]] && continue
    
    BASENAME=$(basename "$f")
    OUTPUT_FILE="$OUTPUT_DIR/${BASENAME}.json"
    
    # Skip if already processed
    if [ -f "$OUTPUT_FILE" ]; then
        continue
    fi
    
    # Convert to JSON, capture output for processing
    RAW_JSON=$(nfdump -r "$f" -o json 2>> "$LOG_FILE")
    
    # Skip if empty or "No matching flows"
    if echo "$RAW_JSON" | grep -q "No matching flows"; then
        echo "$(date): Skipped $BASENAME (no flows)" >> "$LOG_FILE"
        continue
    fi
    
    # Convert to NDJSON with optional sampling
    if [ "$SAMPLE_RATE" -eq 1 ]; then
        # No sampling - keep all records
        echo "$RAW_JSON" | jq -c '.[]' > "$OUTPUT_FILE" 2>> "$LOG_FILE"
    else
        # Sample: keep 1 in every SAMPLE_RATE records
        echo "$RAW_JSON" | jq -c '.[]' | awk "NR % $SAMPLE_RATE == 0" > "$OUTPUT_FILE" 2>> "$LOG_FILE"
    fi
    
    if [ $? -eq 0 ] && [ -s "$OUTPUT_FILE" ]; then
        echo "$(date): Processed $BASENAME (sampled 1:$SAMPLE_RATE)" >> "$LOG_FILE"
    else
        echo "$(date): FAILED $BASENAME" >> "$LOG_FILE"
        rm -f "$OUTPUT_FILE"
    fi
done

# Optional: Clean up old processed files (keep 7 days)
# Uncomment the line below to enable automatic cleanup
# find "$OUTPUT_DIR" -name "*.json" -mtime +7 -delete