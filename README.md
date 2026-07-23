# Check Point WAF Resources

A collection of scripts and AI prompts for automating Check Point / open-appsec Web Application Firewall (WAF) operations, monitoring, and management.

## Overview

This repository contains utility scripts designed to streamline WAF management tasks in Check Point and open-appsec environments, including real-time block alerting, retrieval of tuning suggestions, policy optimization, and AI-assisted exception generation.

## Contents

- **scripts/** - Automation scripts for WAF monitoring and management
  - `waf-prevent-alert.sh` - Real-time WAF Prevent (block) event watcher that delivers formatted Telegram alerts via byte-offset log tailing
  - `waf_get_tuning_suggestions.py` - Retrieve and list WAF tuning suggestions for all assets

- **prompts/** - AI-powered prompt templates for WAF operations
  - `waf-exception-generator.prompt.md` - Generate WAF exception proposals from classified CSV events (AI assistant workflow)

## Quick Start

### Requirements
- Python 3.x
- `requests` library: `pip install requests`
- For `waf-prevent-alert.sh`: passwordless SSH to the WAF proxy host, Python 3 on the local host

### Usage

1. Clone the repository
2. Update credentials/paths in the scripts (CLIENT_ID and ACCESS_KEY for API scripts; LOG_FILE, PROXY_HOST, STATE_FILE for the alert script)
3. Run desired script:
   - `bash scripts/waf-prevent-alert.sh` — check for new WAF blocks (outputs Telegram-formatted message)
   - `python scripts/waf_get_tuning_suggestions.py` — get tuning suggestions
4. For continuous monitoring, schedule `waf-prevent-alert.sh` as a 1-minute cron job or Hermes Agent cron task

## Features

✅ Real-time WAF block notifications via Telegram  
✅ Byte-offset log tailing (only processes new data each run)  
✅ Log rotation aware (auto-resets offset on file truncation)  
✅ Silent when idle (empty output = no message sent)  
✅ Automated WAF tuning suggestion retrieval  
✅ Asset-based filtering and reporting  
✅ Detailed event analysis (severity, attack types, policies)  
✅ AI-assisted false positive exception generation  
✅ Easy-to-read output format

## Documentation

See individual script directories for detailed documentation and configuration options.

## Security Note

⚠️ Handle API credentials securely. Never commit credentials to version control.
