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
- Zabbix Server + Zabbix Agent 2
- Zabbix 7.0
- zabbix-get (`apt install zabbix-get` — für Test-Script)
- Python 3, git, dig (dnsutils), openssl, netcat
- pflogsumm (`apt install pflogsumm`)

### Zabbix Agent Konfiguration

In der Zabbix Agent 2 Konfiguration (`/etc/zabbix/zabbix_agent2.conf`) muss `127.0.0.1` als Server eingetragen sein:

```
Server=127.0.0.1,<dein-zabbix-server-ip>
```

Ohne `127.0.0.1` funktioniert das Test-Script (`test-complete.sh`) und `zabbix_get -s 127.0.0.1` nicht.

## Installation

Der Installer nutzt zwei Variablen die ggf. angepasst werden müssen (am Anfang von `install.sh`):

```bash
MAILCOW_DIR="/opt/mailcow-dockerized"   # Pfad zur Mailcow-Installation
BACKUP_PATH="/opt/backup"                # Pfad zum Backup-Verzeichnis
```

```bash
unzip mailcow-monitoring-v1.0.zip
cd mailcow-monitoring-v1.0
# Optional: MAILCOW_DIR und BACKUP_PATH in install.sh anpassen
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

## Update

Bestehende Installation auf eine neuere Version aktualisieren:

```bash
cd ~/Mailcow-Zabbix-Monitoring
git pull
sudo ./install.sh
```

Danach das Template in Zabbix neu importieren:
1. **Data collection → Templates → Import**
2. `templates/mailcow-complete-monitoring.yaml` auswählen
3. **☑ Update existing** aktivieren — bestehende Items, Trigger und Dashboards werden aktualisiert, History bleibt erhalten
4. Agent neu starten:

```bash
systemctl start mailcow-monitor.service
systemctl restart zabbix-agent2
```

Falls nach dem Update Items als "Not supported" erscheinen:
1. **Configuration → Hosts → Dein Host → Items**
2. Filter auf "Not supported"
3. Alle markieren → **Enable**

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
├── LICENSE                           # AGPLv3
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

AGPLv3 — der Code muss Open Source bleiben und der Autor muss genannt werden.
Siehe [LICENSE](LICENSE) für Details.

**© 2026 Alexander Fox | PlaNet Fox** — Created with Open Source and ❤

https://github.com/linuser/Mailcow-Zabbix-Monitoring
