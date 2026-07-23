#!/bin/bash
# WAF Prevent Event Watcher
# Monitors the Check Point open-appsec WAF log for Prevent (blocked) events
# and outputs formatted Telegram alerts.
#
# Designed for Hermes Agent cron jobs (no_agent=true), where the script's
# stdout is delivered verbatim as a Telegram message. Empty stdout = no message
# sent, so the job stays completely silent when there are no new blocks.
#
# How it works:
#   1. Tracks the last byte offset processed (stored in a state file)
#   2. SSHes to the proxy host and reads only the new bytes since last check
#   3. Filters JSON log lines for securityAction == "Prevent"
#   4. Formats each event as a human-readable Telegram message
#   5. Handles log rotation (resets offset if file shrinks)
#
# Cron schedule: every 1 minute
# Requirements: passwordless SSH to the proxy host, Python 3 on the proxy

set -euo pipefail

# --- Configuration ---------------------------------------------------------
LOG_FILE="/docker/appsec-agent/appsec-logs/cp-nano-http-transaction-handler.log1"
STATE_FILE="$HOME/.hermes/cron/state/waf-prevent-last-byte"
PROXY_HOST="proxy"
# ---------------------------------------------------------------------------

mkdir -p "$(dirname "$STATE_FILE")"

# Load last byte offset
LAST_BYTE=0
if [[ -f "$STATE_FILE" ]]; then
    LAST_BYTE=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
fi

# Get current log file size
CURRENT_SIZE=$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$PROXY_HOST" \
    "stat -c %s $LOG_FILE" 2>/dev/null || echo 0)

# Handle log rotation (file shrank → start from beginning)
if [[ "$CURRENT_SIZE" -lt "$LAST_BYTE" ]]; then
    LAST_BYTE=0
fi

# Nothing new → exit silently (no Telegram message)
if [[ "$CURRENT_SIZE" -le "$LAST_BYTE" ]]; then
    exit 0
fi

# Read only the new bytes since last check
NEW_DATA=$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$PROXY_HOST" \
    "tail -c +$((LAST_BYTE + 1)) $LOG_FILE" 2>/dev/null || true)

# Save current size as new offset
echo "$CURRENT_SIZE" > "$STATE_FILE"

if [[ -z "$NEW_DATA" ]]; then
    exit 0
fi

# Parse JSON log lines and format Prevent events as a Telegram message
echo "$NEW_DATA" | python3 -c "
import sys, json, html

prevents = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        continue
    ed = d.get('eventData', {})
    if ed.get('securityAction', '') != 'Prevent':
        continue

    # Truncate matched sample for readability
    sample = ed.get('matchedSample', '')[:150]
    if len(ed.get('matchedSample', '')) > 150:
        sample += '...'

    prevents.append({
        'time': d.get('eventTime', 'unknown'),
        'asset': ed.get('assetName', 'unknown'),
        'host': ed.get('httpHostName', 'unknown'),
        'method': ed.get('httpMethod', 'unknown'),
        'path': ed.get('httpUriPath', 'unknown'),
        'source_ip': ed.get('sourceIP', 'unknown'),
        'http_source_id': ed.get('httpSourceId', 'unknown'),
        'incident_type': ed.get('waapIncidentType', 'unknown'),
        'matched_sample': sample,
        'matched_param': ed.get('matchedParameter', 'unknown'),
        'matched_location': ed.get('matchedLocation', 'unknown'),
        'indicators': ed.get('waapFoundIndicators', ''),
        'response_code': ed.get('httpResponseCode', ''),
        'confidence': ed.get('eventConfidence', 'unknown'),
    })

if not prevents:
    sys.exit(0)

# Format as Telegram message
lines = []
lines.append('🚨 *WAF Prevent Alert*')
lines.append(f'{len(prevents)} blocked request(s) detected:')
lines.append('')
for i, p in enumerate(prevents, 1):
    lines.append(f'*{i}. {p[\"asset\"]}* — {p[\"incident_type\"]}')
    lines.append(f'  Time: {p[\"time\"]}')
    lines.append(f'  Host: \`{p[\"host\"]}\`')
    lines.append(f'  {p[\"method\"]} \`{p[\"path\"]}\`')
    lines.append(f'  Source IP: \`{p[\"source_ip\"]}\`')
    if p['http_source_id'] and p['http_source_id'] != p['source_ip']:
        lines.append(f'  HTTP Source ID: \`{p[\"http_source_id\"]}\`')
    if p['response_code']:
        lines.append(f'  Response: {p[\"response_code\"]}')
    lines.append(f'  Confidence: {p[\"confidence\"]}')
    lines.append(f'  Matched: {p[\"matched_location\"]} \`{p[\"matched_param\"]}\`')
    sample = html.escape(p['matched_sample'])
    lines.append(f'  Sample: \`{sample}\`')
    if p['indicators']:
        lines.append(f'  Indicators: {p[\"indicators\"]}')
    lines.append('')

print('\\n'.join(lines))
" 2>/dev/null || true