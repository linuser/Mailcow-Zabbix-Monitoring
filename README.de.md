# Mailcow Monitoring v1.0 für Zabbix

Vollständiges Monitoring für Mailcow-Dockerized mit Zabbix Agent 2.

## Architektur

```
systemd timer (60s) → mailcow-collector.py (root)
  → /var/tmp/mailcow-monitor.json (chmod 644)
    → Zabbix Agent 2 (zabbix user) → mailcow-reader.sh → liest JSON
```

- **Collector** läuft als root (braucht Docker-Zugriff)
- **Zabbix Agent** liest nur JSON — kein Docker, kein sudo, kein UnsafeUserParameters
- **246 UserParameters**, 303 Template Items, 71 Trigger, 19 Dashboards, 22 Module

## Voraussetzungen

- Mailcow-Dockerized (laufend)
- Zabbix Agent 2
- Python 3, git, dig (dnsutils), openssl, netcat

## Installation

```bash
unzip mailcow-monitoring-v1.0.zip
cd mailcow-monitoring-v1.0
sudo ./install.sh
```

Nach der Installation:
1. Template importieren: `templates/mailcow-complete-monitoring.yaml`
2. In Zabbix: Data collection → Templates → Import (☑ Update existing)
3. Host zuweisen: "Mailcow Complete Monitoring v1.0"
4. 5–10 Min warten, dann Dashboard prüfen

## Test

```bash
sudo ./test-complete.sh
```

## Paketstruktur

```
mailcow-monitoring-v1.0/
├── install.sh                        # Installer
├── uninstall.sh                      # Deinstallation
├── mailcow-zabbix.conf               # 246 UserParameters
├── test-complete.sh                  # Komplett-Test (246 Keys)
├── templates/
│   └── mailcow-complete-monitoring.yaml  # Zabbix 7.0 Template
├── scripts/
│   ├── mailcow-collector.py          # Haupt-Collector (22 Module)
│   ├── mailcow-reader.sh             # JSON Reader
│   ├── check_dns.sh                  # DNS (SPF/DKIM/DMARC)
│   ├── check_tls.sh                  # TLS/Zertifikate
│   ├── check_rbl.sh                  # Blacklist-Check
│   ├── check_ptr.sh                  # PTR-Record
│   ├── check_open_relay.sh           # Open-Relay-Check
│   ├── check_security_audit.sh       # DANE/MTA-STS/TLS-RPT/BIMI
│   ├── dovecot_check.sh              # Dovecot Stats
│   ├── sync_jobs_check.sh            # Sync Jobs
│   ├── postfix_stats_docker.sh       # Postfix Stats
│   └── postfix_log_analysis.sh       # Postfix Logs + Postscreen
├── mailcow-monitor.service           # systemd oneshot
├── mailcow-monitor.timer             # systemd timer (60s)
├── LICENSE                           # GPLv3
├── MAILCOW-MONITORING-DOKU.md        # Ausführliche Dokumentation
├── CHANGELOG.md
└── README.md
```

## 22 Collector-Module

Postfix, Dovecot, Rspamd, Fail2ban/Security, Disk, Sync Jobs, Mailbox & Domain,
Alias, Mailflow (pflogsumm), ClamAV, Watchdog, ACME/Cert, Docker Health,
SOGo/Memcached, Quarantine, Queue Age, LLD Master, TLS/SSL, Updates/Version,
Backup, Agent/Meta, Collector

## 4 LLD Discovery Rules

- Domain Discovery (Quota, Mailbox-Count pro Domain)
- Mailbox Discovery (Quota, Größe pro Mailbox)
- Syncjob Discovery (Status, Letzte Ausführung pro Job)
- Docker Discovery (CPU, RAM, Status pro Container)

## Deinstallation

```bash
sudo ./uninstall.sh
```

## Lizenz

GPLv3 — der Code muss Open Source bleiben und der Autor muss genannt werden.
Siehe [LICENSE](LICENSE) für Details.

**© 2026 Alexander Fox | PlaNet Fox** — Created with Open Source and ❤

https://github.com/linuser/Mailcow-Zabbix-Monitoring
