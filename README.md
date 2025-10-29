# lone_wxlf

Bug bounty reconnaissance and continuous monitoring framework.

## what it does

Automates the boring parts of bug bounty hunting. Monitors your programs 24/7, finds new subdomains, scans for services, detects vulnerable tech stacks, and alerts you when something interesting shows up.

## features

- HackerOne and Bugcrowd platform integration
- Continuous subdomain monitoring
- Port scanning with version detection
- Technology stack fingerprinting
- CVE correlation with exploit tracking
- Automated report generation
- Discord and Telegram alerts
- Historical asset tracking
- Zero-downtime configuration

## installation

```bash
git clone https://github.com/ibdtech/lone_wxlf
cd lone_wxlf
pip install -r requirements.txt
```

Optional but recommended:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## usage

### first run

```bash
python3 lone_wxlf_platform.py
```

You'll be prompted to:
1. Configure safe mode (rate limiting)
2. Set up alerts
3. Enable continuous monitoring
4. Add programs

### adding programs

Three options:

**Manual entry**
- Just enter domain and program name
- Tool creates the scope automatically

**HackerOne sync**
- Provide API credentials from https://hackerone.com/settings/api_token/edit
- Syncs all your enrolled programs with full scope

**Bugcrowd sync**
- Public programs work without login
- Private programs need credentials

### daemon mode

Run continuous monitoring in background:

```bash
# start monitoring
python3 lone_wxlf_platform.py --daemon start

# check status
python3 lone_wxlf_platform.py --daemon status

# reload config without restart
python3 lone_wxlf_platform.py --daemon reload

# stop monitoring
python3 lone_wxlf_platform.py --daemon stop
```

Default scan interval is 6 hours. Change in `lone_wxlf_config.json`.

### managing programs

When you restart the tool with existing programs:

```
Options:
  1. Continue with loaded programs
  2. Add more programs
  3. Remove programs
  4. Clear all and start over
```

Press 1 or just hit Enter to continue.

## output

### reports

Generated in `reports/` directory:

```
dark_wxlf_report_ProgramName_20250128_143022.txt
```

Format includes:
- Executive summary with CVE counts
- Full asset inventory with open ports
- Technology stack breakdown
- CVE analysis with exploit availability
- High-value targets with risk scores
- Actionable recommendations

### database

Everything stored in `lone_wxlf_elite.db`:

```sql
-- view programs
SELECT * FROM programs;

-- view discovered assets
SELECT * FROM assets;

-- view scan history
SELECT * FROM scan_history ORDER BY scan_date DESC;
```

### logs

Real-time logging to `lone_wxlf_elite.log`:

```bash
tail -f lone_wxlf_elite.log
```

## configuration

Edit `lone_wxlf_config.json`:

```json
{
  "daemon_interval": 21600,
  "rate_limit_enabled": true,
  "max_requests_per_second": 10,
  "discord_webhook": "https://discord.com/api/webhooks/...",
  "telegram_bot_token": null,
  "telegram_chat_id": null
}
```

Reload without restarting daemon:
```bash
python3 lone_wxlf_platform.py --daemon reload
```

## what gets scanned

**Passive reconnaissance**
- Subdomain enumeration (crt.sh + subfinder)
- DNS records
- Certificate transparency logs

**Active reconnaissance**
- HTTP/HTTPS probing
- Port scanning (24 common ports by default)
- Service version detection
- Banner grabbing
- Technology fingerprinting

**Intelligence**
- CVE correlation
- Exploit availability checking
- Historical change tracking
- Attack surface analysis

## alerts

Get notified when:
- New subdomains discovered
- New services detected
- Critical CVEs found
- High-value targets identified

Supports Discord and Telegram. Configure during first run or edit config file.

## safe mode

Designed for bug bounty programs:
- Rate limiting (default 10 req/sec)
- Scope enforcement
- Request delays
- Respectful scanning

Always enabled by default.

## metrics

Export Prometheus-compatible metrics:

```bash
python3 lone_wxlf_platform.py --metrics
```

Track uptime, scans performed, assets found, CVEs discovered, alerts sent.

## typical workflow

1. Sync your bug bounty programs
2. Let initial scan complete (5-15 minutes)
3. Review generated reports
4. Start daemon for continuous monitoring
5. Get alerted when new assets appear
6. Run focused testing on new discoveries

## requirements

- Python 3.8+
- Internet connection
- 100MB disk space minimum

Optional:
- subfinder for better subdomain discovery
- nmap for faster port scanning (requires root)

## file structure

```
lone_wxlf_elite.db          # main database
lone_wxlf_elite.log         # application logs
lone_wxlf_config.json       # configuration
reports/                    # generated reports
  dark_wxlf_report_*.txt
daemon_state.pkl            # daemon state
tested_urls.pkl             # URL cache
metrics.json                # health metrics
```

## troubleshooting

**No subdomains found**
- Install subfinder
- Check internet connection
- Verify domain is correct

**Port scanning slow**
- Run as root for faster SYN scanning
- Install nmap
- Reduce port range in code

**Daemon won't start**
- Check if already running with `--daemon status`
- Remove stale PID: `rm lone_wxlf_elite.pid`
- Check logs: `tail -f lone_wxlf_elite.log`

**Database errors**
- Check file permissions
- Backup: `cp lone_wxlf_elite.db backup.db`
- Reset: `rm lone_wxlf_elite.db` (will recreate on next run)

## notes

This tool performs active reconnaissance. Always:
- Get written permission before testing
- Stay within program scope
- Respect rate limits
- Follow responsible disclosure
- Read program rules

Designed for authorized bug bounty hunting only.

## license

Use responsibly for authorized security testing only.

## author

[@ibdtech](https://github.com/ibdtech)
