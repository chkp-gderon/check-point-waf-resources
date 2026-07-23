# WAF Prevent Alert — Real-time WAF Block Notifications via Telegram

A lightweight shell script that monitors the [open-appsec](https://open-appsec.io/) WAF (Check Point) transaction log for **Prevent** (blocked) events and delivers formatted alerts to Telegram. Designed to run as a 1-minute cron job via [Hermes Agent](https://hermes-agent.nousresearch.com/) but works with any scheduler that can deliver script stdout to a messaging platform.

## How It Works

The script uses a **byte-offset tracking** approach — not line counting or polling — to efficiently detect new log entries:

1. **State file** stores the last byte position processed
2. **SSH** to the proxy host and `stat` the log file size
3. **`tail -c +N`** reads only the bytes appended since the last check
4. **Python** (inline) parses JSON log lines and filters for `securityAction == "Prevent"`
5. **Formatted Telegram message** is printed to stdout — the scheduler delivers it as a chat message
6. **Silent when idle** — empty stdout means no message is sent at all

### Log Rotation Aware

If the log file shrinks (rotation/truncation), the offset resets to 0 and processing starts fresh from the beginning of the new file.

## Requirements

- **Passwordless SSH** to the WAF proxy host (key-based auth)
- **Python 3** available on the host running the script (for JSON parsing)
- **open-appsec** WAF producing JSON transaction logs at the configured path
- A scheduler or agent that can run the script on a recurring schedule and deliver stdout (Hermes Agent, cron + Telegram bot, n8n, etc.)

## Configuration

Edit the variables at the top of the script:

| Variable | Description | Default |
|---|---|---|
| `LOG_FILE` | Path to the open-appsec transaction log on the proxy host | `/docker/appsec-agent/appsec-logs/cp-nano-http-transaction-handler.log1` |
| `STATE_FILE` | Local file to persist the byte offset between runs | `$HOME/.hermes/cron/state/waf-prevent-last-byte` |
| `PROXY_HOST` | SSH host alias for the WAF proxy | `proxy` |

## Usage

### Standalone (manual run)

```bash
chmod +x scripts/waf-prevent-alert.sh
./scripts/waf-prevent-alert.sh
```

If there are new Prevent events, the script prints a formatted Telegram-style message. If there are none, it prints nothing and exits 0.

### Hermes Agent cron job

The script is designed for Hermes Agent's `no_agent=true` cron mode, where the script **is** the job — no LLM tokens are spent, and stdout is delivered verbatim to the configured Telegram chat:

```yaml
schedule: "*/1 * * * *"    # every minute
no_agent: true             # no LLM — script output delivered as-is
deliver: origin            # back to the Telegram chat where the job was created
script: waf-prevent-alert.sh
```

### Traditional cron + Telegram bot

```bash
# crontab -e
* * * * * /path/to/waf-prevent-alert.sh | /path/to/telegram-send.sh
```

Where `telegram-send.sh` pipes stdin to your Telegram Bot API endpoint.

## Example Output

When a Prevent event is detected, the script outputs a message like this:

```
🚨 WAF Prevent Alert
1 blocked request(s) detected:

1. Nginx Proxy Manager — Remote Code Execution
  Time: 2026-07-23T16:25:06.761
  Host: example.com
  GET /.env
  Source IP: 10.0.0.1
  HTTP Source ID: 203.0.113.50
  Confidence: Very High
  Matched: url `.env`
  Sample: /.env
  Indicators: [.env, /., probing]
```

This is delivered as a native Telegram message by the scheduler:

> 🚨 **WAF Prevent Alert**
> 1 blocked request(s) detected:
>
> **1. Nginx Proxy Manager** — Remote Code Execution
>   Time: 2026-07-23T16:25:06.761
>   Host: \`example.com\`
>   `GET /.env`
>   Source IP: \`10.0.0.1\`
>   HTTP Source ID: \`203.0.113.50\`
>   Confidence: Very High
>   Matched: url \`.env\`
>   Sample: \`/.env\`
>   Indicators: [.env, /., probing]

### Fields Explained

| Field | Description |
|---|---|
| **Asset** | The protected asset name as configured in open-appsec |
| **Incident Type** | Attack classification (e.g. Remote Code Execution, SQL Injection, XSS) |
| **Host** | The HTTP hostname that was targeted |
| **Method + Path** | The HTTP method and URI path of the blocked request |
| **Source IP** | The immediate source IP (may be a reverse proxy/container IP) |
| **HTTP Source ID** | The real client IP (from headers like X-Forwarded-For), shown when different from Source IP |
| **Confidence** | open-appsec confidence rating (Very High, High, Medium, etc.) |
| **Matched** | Where the malicious payload was found (url, body, header) and the parameter name |
| **Sample** | Truncated excerpt of the matched payload (max 150 chars) |
| **Indicators** | List of detection indicators that triggered the block |

## Design Notes

- **No LLM needed**: The script runs without any AI/LLM — it's pure bash + Python. In Hermes, `no_agent=true` means zero token cost per run.
- **Stateful**: The byte offset persists between runs in a file, so only new data is processed each tick.
- **Two SSH calls**: One `stat` (file size) and one `tail -c` (new bytes) per run. Minimal overhead on the proxy host.
- **Inline Python**: The JSON parsing and message formatting is done with an inline Python script to avoid managing a separate file. It uses only stdlib (`json`, `html`, `sys`).
- **Log rotation safe**: Detects file truncation and resets the offset.
- **Telegram Markdown**: Output uses Telegram-flavored Markdown (`*bold*`, `` `code` ``) for readability in chat. HTML escaping is applied to payload samples to prevent formatting issues.