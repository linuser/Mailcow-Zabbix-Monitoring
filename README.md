# Mailcow Monitoring v1.0 for Zabbix

Complete monitoring solution for Mailcow-Dockerized with Zabbix Agent 2. 246 metrics, 71 triggers, 19 dashboards — secure by design, installed in 5 minutes.

🇩🇪 [Deutsche Version](README.de.md) | 🇩🇪 [Ausführliche Dokumentation](MAILCOW-MONITORING-DOKU.md)

## Architecture

```
systemd timer (60s) → mailcow-collector.py (root)
  → /var/tmp/mailcow-monitor.json (chmod 644)
    → Zabbix Agent 2 (zabbix user) → mailcow-reader.sh → reads JSON
```

The collector runs as root (needs Docker/MySQL access) and writes metrics to a world-readable JSON file. The Zabbix Agent only reads that file — no Docker access, no sudo, no UnsafeUserParameters required.

## What's Monitored

| Module | Metrics | Description |
|--------|---------|-------------|
| Postfix | 16 | Queue, connections, deferred/bounced, SASL failures |
| Postfix Logs | 11 | Relay denied, RBL rejects, TLS errors, quota warnings |
| Postscreen | 9 | Pass/reject/DNSBL/pregreet (auto-detected) |
| Dovecot | 10 | Connections, login failures, IMAP disconnects |
| Rspamd | 14 | Spam/ham ratio, reject rate, greylist, actions |
| Rspamd Bayes | 5 | Training status: untrained → low → good → excellent |
| Security | 13 | Fail2ban, RBL blacklist, DNS records, open relay |
| Security Audit | 6 | DANE/TLSA, MTA-STS, TLS-RPT, BIMI — score 0-7 |
| Disk | 15 | Root, Docker, vmail, log partitions |
| Mailboxes & Domains | 10 | Quota usage, top 5 mailboxes |
| Mailflow | 28 | Received/delivered/bounced + anomaly detection |
| ClamAV | 8 | Signature age, DB version, scan status |
| Watchdog | 18 | Health status for all 15 Mailcow services |
| Docker | 7+LLD | CPU, RAM, restarts per container |
| TLS/Certificates | 10 | HTTPS, IMAPS, Submission — days until expiry |
| Backup | 9 | Age, size, count, missing backups |
| + 6 more | ... | SOGo, Quarantine, Queue Age, Sync Jobs, Updates, Aliases |

**Total: 246 UserParameters · 303 template items · 71 triggers · 19 dashboards**

## Key Features

### Anomaly Detection
Instead of fixed thresholds, 5 baseline triggers use `trendavg()` to learn what's normal over a week and alert on deviations:

| Metric | Spike | Drop |
|--------|-------|------|
| Received | >5× weekly avg | <20% weekly avg |
| Rejected | >10× weekly avg | — |
| Bounced | >5× weekly avg | — |
| Deferred | >5× weekly avg | — |

### Security Audit Score (0-7)
Checks SPF, DKIM, DMARC plus DANE/TLSA, MTA-STS, TLS-RPT and BIMI. Trigger alerts when score drops below 3.

### Low-Level Discovery
4 LLD rules automatically discover and monitor all domains, mailboxes, sync jobs and Docker containers individually.

## Requirements

- Mailcow-Dockerized (running)
- Zabbix Server + Zabbix Agent 2
- Zabbix 7.0
- Python 3, git, dig (dnsutils), openssl, netcat
- pflogsumm (`apt install pflogsumm`)

## Installation

```bash
git clone https://github.com/linuser/Mailcow-Zabbix-Monitoring.git
cd Mailcow-Zabbix-Monitoring
sudo ./install.sh
```

Then in Zabbix:
1. **Data collection → Templates → Import** → select `templates/mailcow-complete-monitoring.yaml`
2. **Link template** to your Mailcow host: "Mailcow Complete Monitoring v1.0"
3. Wait 5–10 minutes for dashboards to populate

### Verify

```bash
sudo ./test-complete.sh
```

### Force Immediate Data

```bash
systemctl start mailcow-monitor.service    # fresh JSON
systemctl restart zabbix-agent2             # force re-check
```

## File Structure

```
mailcow-monitoring/
├── install.sh                        # Installer
├── uninstall.sh                      # Uninstaller
├── mailcow-zabbix.conf               # 246 UserParameters
├── test-complete.sh                  # Validation script (246 keys)
├── templates/
│   └── mailcow-complete-monitoring.yaml  # Zabbix 7.0 template
├── scripts/
│   ├── mailcow-collector.py          # Main collector (22 modules)
│   ├── mailcow-reader.sh             # JSON reader
│   ├── check_dns.sh                  # DNS (SPF/DKIM/DMARC)
│   ├── check_tls.sh                  # TLS/certificate checks
│   ├── check_rbl.sh                  # RBL blacklist check
│   ├── check_ptr.sh                  # PTR record check
│   ├── check_open_relay.sh           # Open relay check
│   ├── check_security_audit.sh       # DANE/MTA-STS/TLS-RPT/BIMI
│   ├── dovecot_check.sh              # Dovecot stats
│   ├── sync_jobs_check.sh            # IMAP sync jobs
│   ├── postfix_stats_docker.sh       # Postfix queue stats
│   └── postfix_log_analysis.sh       # Postfix logs + Postscreen
├── mailcow-monitor.service           # systemd oneshot
├── mailcow-monitor.timer             # systemd timer (60s)
├── LICENSE                           # GPLv3
├── CHANGELOG.md
├── MAILCOW-MONITORING-DOKU.md        # Detailed docs (German)
├── README.md                         # This file
└── README.de.md                      # German README
```

## Uninstall

```bash
sudo ./uninstall.sh
```

## License

GPLv3 — code must remain open source and the original author must be credited.
See [LICENSE](LICENSE) for details.

**© 2026 Alexander Fox | PlaNet Fox** — Created with Open Source and ❤
