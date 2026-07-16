# Mailcow Monitoring v1.2 for Zabbix

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
- zabbix-get (`apt install zabbix-get` — needed for test script validation)
- Python 3, git, dig (dnsutils), openssl, netcat
- pflogsumm (`apt install pflogsumm`)

### Zabbix Agent Configuration

**All 246 items are active agent checks.** The agent fetches them itself from the
address in `ServerActive` — `Server=` only governs passive queries and is **not**
sufficient. If `ServerActive` is missing, or points at `127.0.0.1` while your
Zabbix server runs elsewhere, **not a single item will collect data** — silently.
Items and triggers show up in the frontend, graphs stay empty.

In `/etc/zabbix/zabbix_agent2.conf`:

```
Server=<your-zabbix-server-ip>,127.0.0.1   # passive: who may query this agent
ServerActive=<your-zabbix-server-ip>       # ACTIVE: without this, no data at all
Hostname=<host name as configured in Zabbix>
```

- `127.0.0.1` in `Server=` is only needed so that `test-complete.sh` and
  `zabbix_get -s 127.0.0.1` work.
- `Hostname` must match the host's technical name in Zabbix exactly, otherwise
  the server rejects the active checks.
- Each parameter may appear **once** uncommented — duplicates prevent the agent
  from starting.

Validate the config before restarting:

```bash
zabbix_agent2 -T -c /etc/zabbix/zabbix_agent2.conf
systemctl restart zabbix-agent2
```

> Note: `test-complete.sh` queries the UserParameters passively via `zabbix_get`.
> It therefore reports success even when `ServerActive` is wrong and nothing is
> actually being collected. Always verify in *Monitoring → Latest data*.

## Installation

### 1. Get the code

```bash
git clone https://github.com/linuser/Mailcow-Zabbix-Monitoring.git
cd Mailcow-Zabbix-Monitoring
```

Without git:

```bash
curl -sL https://github.com/linuser/Mailcow-Zabbix-Monitoring/archive/refs/heads/main.tar.gz | tar xz
cd Mailcow-Zabbix-Monitoring-main
```

### 2. Adjust paths if needed

The installer uses two variables at the top of `install.sh`:

```bash
MAILCOW_DIR="/opt/mailcow-dockerized"   # Path to your Mailcow installation
BACKUP_PATH="/opt/backup"                # Path to your Mailcow backup directory
```

If your Mailcow is installed elsewhere or your backups are in a different location, edit these before running the installer.

### 3. Run the installer

```bash
sudo ./install.sh
```

It installs the collector and check scripts, sets up the systemd timer, writes the
UserParameter config — and checks your agent's `ServerActive`/`Hostname`. Take that
check seriously: without a correct `ServerActive`, none of the 246 items will ever
collect data (see [Zabbix Agent Configuration](#zabbix-agent-configuration)).

### 4. Import the template

1. **Data collection → Templates → Import**
2. Select `templates/mailcow-complete-monitoring.yaml`
3. Tick **☑ Create new** *and* **☑ Update existing** for all object types.
   Leave **Delete missing** off.
4. The template row must then show: **Items 246 | Triggers 63 | Dashboards 19**

   No number next to *Triggers* means "Create new" was not ticked.

5. **Link the template** to your Mailcow host: "Mailcow Complete Monitoring v1.0"

Data appears within about a minute. If it does not, `ServerActive` is the first
thing to check — not patience.

### 5. Where to find the dashboards

The 19 dashboards are **template dashboards**: they belong to the host, not to the
global dashboard list.

*Monitoring → Hosts* → your host's row → **Dashboards** → "01 - Postfix"

They will **not** appear under *Monitoring → Dashboards*, and they render empty
under *Data collection → Templates → Dashboards* — there is no host context there.

### Verify

```bash
sudo ./test-complete.sh
```

> This queries the UserParameters passively via `zabbix_get`. It reports success
> even when `ServerActive` is wrong and Zabbix is collecting nothing. Always
> confirm in *Monitoring → Latest data* as well.

### Force Immediate Data

```bash
systemctl start mailcow-monitor.service    # fresh JSON
systemctl restart zabbix-agent2             # force re-check
```

## Update

```bash
cd ~/Mailcow-Zabbix-Monitoring
git pull
sudo ./update.sh --check     # shows what would change, changes nothing
sudo ./update.sh
```

`update.sh` backs up the current scripts to `/var/backups/mailcow-zabbix/<date>/`,
replaces only what actually differs, clears the RBL cache, restarts the timer and
then verifies the collected values:

```
OK    246 metrics in the JSON
OK    Postfix running: 1
OK    Rspamd scanned: 73890
```

Roll back with `sudo ./update.sh --rollback`.

Then re-import the template in Zabbix:

1. **Data collection → Templates → Import**
2. Select `templates/mailcow-complete-monitoring.yaml`
3. Tick **☑ Create new** *and* **☑ Update existing** for all object types.
   Leave **Delete missing** off.
4. Verify the template row shows: **Items 246 | Triggers 63 | Dashboards 19**

> **Do not tick "Update existing" alone.** Zabbix then skips objects that do not
> exist yet — and still reports "Imported successfully". That is how installations
> ended up with 0 of 71 triggers while items worked fine.

Existing history is preserved: the template UUID and technical name are stable, so
Zabbix updates in place.

If items show "Not supported" after the update:
1. **Data collection → Hosts → your host → Items**
2. Filter by "Not supported"
3. Select all → **Enable**

Alternatively, install from a release archive instead of git — see
[UPDATE.md](UPDATE.md).

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
│   ├── sync_jobs_check.sh            # IMAP sync jobs
│   ├── postfix_stats_docker.sh       # Postfix queue stats
│   └── postfix_log_analysis.sh       # Postfix logs + Postscreen
├── mailcow-monitor.service           # systemd oneshot
├── mailcow-monitor.timer             # systemd timer (60s)
├── LICENSE                           # AGPLv3
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

AGPLv3 — code must remain open source and the original author must be credited.
See [LICENSE](LICENSE) for details.

**© 2026 Alexander Fox | PlaNet Fox** — Created with Open Source and ❤
