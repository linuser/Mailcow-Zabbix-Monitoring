# Mailcow Monitoring v1.2 für Zabbix

Vollständiges Monitoring für Mailcow-Dockerized mit Zabbix Agent 2.

## Architektur

```
systemd timer (60s) → mailcow-collector.py (root)
  → /run/mailcow-monitor/monitor.json (chmod 644)
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

**Alle 246 Items sind aktive Agent-Checks.** Der Agent holt sie selbst von der
Adresse in `ServerActive` — `Server=` regelt nur passive Abfragen und genügt
**nicht**. Fehlt `ServerActive` oder zeigt es auf `127.0.0.1`, während der
Zabbix-Server woanders läuft, sammelt **kein einziges Item** Daten — ohne
Fehlermeldung. Items und Trigger sind im Frontend sichtbar, die Graphen bleiben
leer.

In `/etc/zabbix/zabbix_agent2.conf`:

```
Server=<zabbix-server-ip>,127.0.0.1   # passiv: wer diesen Agent abfragen darf
ServerActive=<zabbix-server-ip>       # AKTIV: ohne das kommen keine Daten
Hostname=<hostname wie in Zabbix konfiguriert>
```

- `127.0.0.1` in `Server=` wird nur gebraucht, damit `test-complete.sh` und
  `zabbix_get -s 127.0.0.1` funktionieren.
- `Hostname` muss exakt dem technischen Host-Namen in Zabbix entsprechen, sonst
  weist der Server die aktiven Checks ab.
- Jeder Parameter darf nur **einmal** unkommentiert vorkommen — Duplikate
  verhindern den Agent-Start.

Vor dem Neustart prüfen:

```bash
zabbix_agent2 -T -c /etc/zabbix/zabbix_agent2.conf
systemctl restart zabbix-agent2
```

> Hinweis: `test-complete.sh` fragt die UserParameter passiv per `zabbix_get` ab.
> Es meldet deshalb Erfolg, selbst wenn `ServerActive` falsch ist und in
> Wirklichkeit nichts gesammelt wird. Immer zusätzlich in
> *Monitoring → Latest data* gegenprüfen.

### Sicherheit

- Der Collector läuft als root über einen systemd-Timer; der Zabbix-Agent liest
  nur eine JSON-Datei und braucht keinerlei Rechte — keine Sudo-Regeln,
  `UnsafeUserParameters=0`.
- Der Zustand liegt in `/run/mailcow-monitor` (`root:root`, `0755`), angelegt von
  systemd. Bis v1.2 lag er im weltschreibbaren `/var/tmp`.
- Das Mailcow-DB-Passwort wird `docker exec` über eine `0600`-Env-Datei übergeben,
  nie auf der Kommandozeile — `/proc/<pid>/cmdline` ist weltlesbar.
- Die systemd-Unit ist gehärtet (`NoNewPrivileges`, `ProtectSystem=full`,
  `PrivateTmp`, `ProtectHome` u. a.).
- Werte aus der Datenbank landen nie in einer Shell: kein `shell=True` für
  irgendetwas Parametrisiertes.

## Installation

### 1. Code holen

```bash
git clone https://github.com/linuser/Mailcow-Zabbix-Monitoring.git
cd Mailcow-Zabbix-Monitoring
```

Ohne git:

```bash
curl -sL https://github.com/linuser/Mailcow-Zabbix-Monitoring/archive/refs/heads/main.tar.gz | tar xz
cd Mailcow-Zabbix-Monitoring-main
```

### 2. Pfade anpassen (falls nötig)

Der Installer nutzt zwei Variablen am Anfang von `install.sh`:

```bash
MAILCOW_DIR="/opt/mailcow-dockerized"   # Pfad zur Mailcow-Installation
BACKUP_PATH="/opt/backup"                # Pfad zum Backup-Verzeichnis
```

### 3. Installer starten

```bash
sudo ./install.sh
```

Er installiert Collector und Check-Scripts, richtet den systemd-Timer ein, legt die
UserParameter-Config an — und prüft `ServerActive`/`Hostname` des Agents. Diese
Prüfung ernst nehmen: ohne korrektes `ServerActive` sammelt **keines** der 246
Items jemals Daten (siehe [Zabbix Agent Konfiguration](#zabbix-agent-konfiguration)).

### 4. Template importieren

1. **Data collection → Templates → Import**
2. `templates/mailcow-complete-monitoring.yaml` auswählen
3. **☑ Create new** *und* **☑ Update existing** bei allen Objekttypen anhaken.
   **Delete missing** bleibt aus.
4. In der Template-Zeile muss danach stehen: **Items 246 | Triggers 63 | Dashboards 19**

   Steht bei *Triggers* keine Zahl, war „Create new" nicht gesetzt.

5. **Template dem Host zuweisen**: „Mailcow Complete Monitoring v1.0"

Daten erscheinen binnen etwa einer Minute. Falls nicht, ist `ServerActive` das
Erste, was man prüft — nicht Geduld.

### 5. Wo sind die Dashboards?

Die 19 Dashboards sind **Template-Dashboards**: sie gehören zum Host, nicht in die
globale Dashboard-Liste.

*Monitoring → Hosts* → Zeile des Hosts → **Dashboards** → „01 - Postfix"

Unter *Monitoring → Dashboards* tauchen sie **nicht** auf, und unter
*Data collection → Templates → Dashboards* sind sie leer — dort fehlt der
Host-Bezug.

## Test

```bash
sudo ./test-complete.sh
```

## Update

```bash
cd ~/Mailcow-Zabbix-Monitoring
git pull
sudo ./update.sh --check     # zeigt an, was sich aendern wuerde
sudo ./update.sh
```

`update.sh` sichert die aktuellen Scripts nach `/var/backups/mailcow-zabbix/<datum>/`,
ersetzt nur, was sich tatsächlich unterscheidet, leert den RBL-Cache, startet den
Timer neu und verifiziert anschließend die gesammelten Werte:

```
OK    246 metrics in the JSON
OK    Postfix running: 1
OK    Rspamd scanned: 73890
```

Zurück geht es mit `sudo ./update.sh --rollback`.

Danach das Template in Zabbix neu importieren:

1. **Data collection → Templates → Import**
2. `templates/mailcow-complete-monitoring.yaml` auswählen
3. **☑ Create new** *und* **☑ Update existing** bei allen Objekttypen anhaken.
   **Delete missing** bleibt aus.
4. Kontrolle in der Template-Zeile: **Items 246 | Triggers 63 | Dashboards 19**

> **Nicht nur „Update existing" anhaken.** Zabbix überspringt dann Objekte, die
> noch nicht existieren — und meldet trotzdem „Imported successfully". Genau so
> entstanden Installationen mit 0 von 71 Triggern, während die Items liefen.

Die History bleibt erhalten: Template-UUID und technischer Name sind stabil,
Zabbix aktualisiert in-place.

Falls nach dem Update Items als „Not supported" erscheinen:
1. **Data collection → Hosts → Dein Host → Items**
2. Filter auf „Not supported"
3. Alle markieren → **Enable**

Alternativ per Release-Archiv statt git — siehe [UPDATE.de.md](UPDATE.de.md).

## Paketstruktur

```
Mailcow-Zabbix-Monitoring/
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
│   ├── sync_jobs_check.sh            # Sync Jobs
│   ├── postfix_stats_docker.sh       # Postfix Stats
│   └── postfix_log_analysis.sh       # Postfix Logs + Postscreen
├── mailcow-monitor.service           # systemd oneshot
├── mailcow-monitor.timer             # systemd timer (60s)
├── LICENSE                           # MIT
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

MIT — frei nutzbar, änderbar und weitergebbar; der Copyright-Hinweis muss erhalten bleiben.
Siehe [LICENSE](LICENSE) für Details.

**© 2026 Alexander Fox | PlaNet Fox** — Created with Open Source and ❤

https://github.com/linuser/Mailcow-Zabbix-Monitoring
