# Masscan Monitor

Automated network reconnaissance solution based on Masscan with banner analysis, CVE checking, exploit-db validation, notifications, and web dashboard.

## Features

- **High-speed scanning**: Uses Masscan for asynchronous multi-threaded port scanning
- **Banner grabbing**: Identifies services via banner analysis + optional Nmap validation
- **ASN support**: Resolves Autonomous System Numbers to IP ranges via BGPView API
- **Deduplication**: SQLite database tracks findings; only new ports trigger alerts
- **Notifications**: Telegram Bot + Email (SMTP) alerts with CVE/exploit counts
- **CVE checking**: Vulners API integration for vulnerability assessment
- **Exploit-DB validation**: Checks discovered services against exploit-db.com database via searchsploit CLI
- **Web dashboard**: FastAPI-based real-time monitoring interface
- **Scheduled scans**: APScheduler for periodic execution
- **Graceful shutdown**: Signal handlers for clean exit
- **Dependency validation**: Automatic checks for masscan/nmap/searchsploit availability

## Architecture

```
config.yaml → main.py → scanner → banner_analyzer → nmap_validator → cve_checker → exploit_checker → database → notifier
                                    ↓
                              dashboard (FastAPI)
```

## Installation

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install masscan nmap exploitdb

# 2. Set capabilities for masscan (run without sudo)
sudo setcap cap_net_raw+ep $(which masscan)

# 3. Install Python dependencies
pip install -r requirements.txt
```

## Configuration

Edit `config.yaml`:

```yaml
scan:
  targets: ["10.0.0.0/24"]
  asns: [15169]  # Google ASN example
  ports: "22,80,443,3306,5432,8080-8090"
  rate: 5000
  banners: true
  adapter_ip: "192.168.1.100"  # Required for banner grabbing on Linux

notifications:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    user: "your_email@gmail.com"
    password: "your_app_password"
    to: "admin@example.com"

cve:
  enabled: true
  vulners_api_key: "YOUR_VULNERS_KEY"

exploit_db:
  enabled: true

scheduler:
  enabled: true
  interval_minutes: 60

dashboard:
  enabled: true
  host: "0.0.0.0"
  port: 8080
```

## Usage

```bash
# Single scan
python main.py

# With custom config
python main.py --config production.yaml
```

## Banner Grabbing Notes

On Linux, Masscan requires special setup for banner grabbing to avoid local TCP stack RST packets:

**Option 1 (recommended)**: Use `--adapter-ip` with an unused IP in your subnet:
```bash
sudo masscan 10.0.0.0/8 -p80 --banners --adapter-ip 192.168.1.100
```

**Option 2**: Block Masscan source port via iptables:
```bash
sudo iptables -A INPUT -p tcp --dport 61000 -j DROP
sudo masscan 10.0.0.0/8 -p80 --banners --adapter-port 61000
```

## Project Structure

```
masscan-monitor/
├── config.yaml              # Main configuration
├── requirements.txt         # Python dependencies
├── main.py                  # Entry point with logging & signal handling
├── core/
│   ├── models.py            # Pydantic data models (OOP)
│   ├── database.py          # Async SQLite persistence
│   ├── scanner.py           # Masscan subprocess wrapper + JSON parser
│   ├── banner_analyzer.py   # Service fingerprinting by banner
│   ├── nmap_validator.py    # Nmap -sV validation layer
│   ├── cve_checker.py       # Vulners API integration
│   ├── exploit_checker.py   # Exploit-DB validation via searchsploit
│   ├── notifier.py          # Telegram + Email notifications
│   ├── scheduler.py         # APScheduler wrapper
│   └── asn_resolver.py      # BGPView ASN lookup
├── web/
│   └── dashboard.py         # FastAPI application
└── templates/
    └── index.html           # Responsive dashboard
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML dashboard |
| `GET /api/findings?limit=100` | JSON findings |
| `GET /api/stats` | Statistics |

## Algorithm

1. **Resolve targets**: Convert ASN numbers to IP ranges via BGPView API
2. **Masscan scan**: Multi-threaded port scan with banner grabbing (`-oJ --banners`)
3. **Parse results**: Extract IP, port, protocol, banner from JSON output
4. **Service detection**: Regex-based banner analysis + port mapping
5. **Nmap validation**: Optional `-sV` scan for accurate version detection
6. **CVE check**: Query Vulners API for known vulnerabilities
7. **Exploit check**: Search exploit-db.com via searchsploit CLI
8. **Deduplication**: Compare against SQLite history; flag only new findings
9. **Notify**: Send Telegram + Email alerts for new discoveries
10. **Dashboard**: Serve real-time results via FastAPI

## License

MIT
