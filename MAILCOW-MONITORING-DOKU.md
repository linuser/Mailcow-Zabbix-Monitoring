# Mailcow Zabbix Monitoring - Projektdokumentation

## Version: v1.2 (Stand: 16.07.2026)

---

## Architektur (Secure Service Architecture)

```
┌──────────────────────────────┐
│  mailcow-monitor.timer       │  systemd timer, alle 60s
│  → mailcow-collector.py      │  läuft als ROOT (Python)
│  Sammelt 246 Metriken        │
│  Docker, DB, TLS, DNS, ...   │
│  Schreibt → JSON-Dateien     │
└──────────┬───────────────────┘
           │
     /var/tmp/mailcow-monitor.json          (Haupt-Cache, 60s)
     /var/tmp/mailcow-monitor-slow.json     (Slow-Cache, 1h)
     /var/tmp/mailcow-monitor-mailflow.json (Mailflow-Cache, 5m)
           │
┌──────────┴───────────────────┐
│  Zabbix Agent 2              │  läuft als ZABBIX
│  246 UserParameters          │
│  → mailcow-reader.sh <key>   │  liest nur JSON (Python3)
│  KEIN Docker, KEIN sudo      │
└──────────────────────────────┘
```

### Sicherheitsmodell
- Zabbix hat **keinen** Docker-Zugriff
- **Kein** UnsafeUserParameters nötig
- Collector schreibt world-readable JSON, Reader liest nur
- MySQL-Passwort via `MYSQL_PWD` Environment-Variable (nicht auf Kommandozeile sichtbar)

### Performance-Optimierungen
- **Zentralisierte Container-Erkennung:** 1× `find_all_containers()` statt ~10 einzelne `find_container()` pro Lauf
- **ClamAV:** 1 docker exec mit Shell-Compound statt 3-5 einzelne
- **Docker Health:** gezielter `docker stats` + 1 gebatchter `docker inspect` statt N einzelne
- **Slow-Cache parallelisiert:** ThreadPoolExecutor (6 Threads) für TLS/DNS/RBL-Checks
- **Mailflow eigener 5-Min-Cache:** frische Daten statt 1h-Slow-Cache
- **shell=False:** `run_cmd()` für einfache Befehle (sicherer, schneller)

---

## Übersicht: 246 UserParameters / 246 Template Items + 21 LLD-Prototypen / 71 Trigger

| # | Modul | Items | Trigger | Beschreibung |
|---|-------|-------|---------|-------------|
| 1 | Postfix | 16 | 2 | Queue, Connections, Log-Events |
| 2 | Postfix Logs | 11 | 1 | SASL, Relay, RBL, TLS, Quota, Virus |
| 3 | Postscreen | 9 | 1 | Connect, Pass, Reject, DNSBL, Pregreet |
| 4 | Dovecot | 10 | 1 | Connections, Login-Fehler, Version |
| 5 | Rspamd | 14 | 1 | Scanned, Spam, Ham, Actions, Detail |
| 6 | Rspamd Bayes | 5 | 1 | Ham/Spam Learned, Ratio, Status |
| 7 | Security | 13 | 3 | Fail2ban, RBL, DNS Records, Open Relay |
| 8 | Security Audit | 6 | 1 | DANE/TLSA, MTA-STS, TLS-RPT, BIMI, Score |
| 9 | Disk | 15 | 2 | Root, Docker, vmail, Log Partitionen |
| 10 | Sync Jobs | 6 | 0 | Active, Running, Failed, Stuck |
| 11 | Mailbox & Domain | 10 | 0 | Quota, Top 5, Domains |
| 12 | Alias | 5 | 0 | Total, Active, Forwarding |
| 13 | Mailflow (pflogsumm) | 28 | 5 | Received/Delivered/Bounced + Baseline-Anomalie |
| 14 | ClamAV | 8 | 3 | Version, Signatures, DB Age |
| 15 | Watchdog | 18 | 2 | 15 Service Health Levels |
| 16 | ACME/Certificate | 7 | 2 | Subject, Issuer, Days Left |
| 17 | Docker Health | 7+LLD | 1 | CPU, RAM, Restarts pro Container |
| 18 | SOGo/Memcached | 8 | 1 | Cache Hits, Evictions, Items |
| 19 | Quarantine | 6 | 2 | Total, Spam, Virus, Age, Top Domains |
| 20 | Queue Age | 4 | 2 | Deferred, Active, Hold, Oldest |
| 21 | TLS/SSL | 10 | 4 | Cert Days, HTTPS/IMAPS/Submission Check |
| 22 | Updates/Version | 12 | 2 | Current, Latest, Commits Behind |
| 23 | Backup | 9 | 3 | Count, Age, Size, Zero Files, Script |
| 24 | Collector | 7 | 2 | Running, Age, Duration, Errors, Module-Timing |
| 25 | Agent/Meta | 8 | 2 | Agent Running, Log Errors |
| 26 | LLD Master | 6 | 0 | Discovery JSON für Domains/Mailboxen/Syncjobs |
| | **Gesamt** | **~303** | **71** | + 4 LLD Rules, 21 Prototypen, 8 LLD-Trigger |

---

## Anomalie-Erkennung (Baseline-Trigger)

Statt fester Schwellwerte lernen diese Trigger automatisch den Normalzustand:

| Metrik | Spike-Trigger | Drop-Trigger |
|--------|---------------|--------------|
| `mail.received` | >5× Wochendurchschnitt → WARNING | <20% Wochendurchschnitt → HIGH |
| `mail.rejected` | >10× Wochendurchschnitt → WARNING | — |
| `mail.bounced` | >5× Wochendurchschnitt → WARNING | — |
| `mail.deferred` | >5× Wochendurchschnitt → WARNING | — |

Alle mit Mindest-Baseline (z.B. `trendavg > 5`) damit frische Installationen nicht sofort alarmieren. Braucht ~1 Woche History.

---

## Security Audit Score (0-7)

| Check | Punkte | Record |
|-------|--------|--------|
| SPF | 1 | `TXT` auf Domain |
| DKIM | 1 | `TXT` auf `dkim._domainkey.domain` |
| DMARC | 1 | `TXT` auf `_dmarc.domain` |
| DANE/TLSA | 1 | `TLSA` auf `_25._tcp.hostname` |
| MTA-STS | 1 | `TXT` auf `_mta-sts.domain` |
| TLS-RPT | 1 | `TXT` auf `_smtp._tls.domain` |
| BIMI | 1 | `TXT` auf `default._bimi.domain` |

Trigger bei Score <3 (WARNING).

---

## Rspamd Bayes-Training Status

| Status | Bedeutung |
|--------|-----------|
| `untrained` | 0 Nachrichten gelernt |
| `low` | <200 gesamt gelernt |
| `unbalanced` | Ham oder Spam <50 |
| `good` | 200-999 gesamt, beide >50 |
| `excellent` | 1000+ gesamt |

Trigger: INFO bei <200 gelernten Nachrichten (wenn Rspamd >24h läuft).

---

## Postscreen Monitoring

Automatische Erkennung — wenn Postscreen nicht aktiviert ist, bleiben alle Werte auf 0:

| Metrik | Beschreibung |
|--------|-------------|
| `postscreen.active` | 1=aktiv, 0=nicht aktiv |
| `postscreen.connect` | Eingehende Verbindungen |
| `postscreen.pass.new` | Neue Clients, alle Tests bestanden |
| `postscreen.pass.old` | Wiederkehrende (bekannte) Clients |
| `postscreen.reject` | Abgelehnte Verbindungen |
| `postscreen.dnsbl` | DNSBL-Treffer |
| `postscreen.pregreet` | Bot-Erkennung (Pregreet-Failure) |
| `postscreen.hangup` | Abbrüche während Tests |
| `postscreen.whitelisted` | Whitelisted Clients |

Trigger: WARNING bei >100 Rejects.

---

## LLD (Low-Level Discovery) - 4 Discovery Rules

### Domain Discovery (5 Prototypen, 2 Trigger, 1 Graph)
Pro Domain automatisch: Active, Mailbox-Anzahl, Used MB, Quota MB, Usage %
Trigger: >80% WARNING, >95% HIGH

### Mailbox Discovery (4 Prototypen, 2 Trigger, 1 Graph)
Pro Mailbox automatisch: Active, Used MB, Quota MB, Usage %
Trigger: >80% WARNING, >95% HIGH

### Sync Job Discovery (5 Prototypen, 2 Trigger)
Pro Sync Job: Active, Running, Success, Age Hours, Exit Status
Trigger: Failed → HIGH, >48h nicht gelaufen → WARNING

### Docker Container Discovery (7 Prototypen, 2 Trigger, 2 Graphen)
Pro Container: CPU%, Memory MB/%, Restarts, Uptime, PIDs, Health
Trigger: Restarted → WARNING, Memory >25% → WARNING

---

## 19 Dashboard-Pages

| # | Dashboard | Inhalt |
|---|-----------|--------|
| 01 | Postfix | Queue & Connections, Security Events, Mail Problems |
| 02 | TLS Certificates | Cert Days Left pro Port |
| 03 | Security | Fail2ban Bans, RBL Status |
| 04 | Rspamd | Spam vs Ham, Spam Rate, Scanned & Learned, Bayes Training |
| 05 | Dovecot | Connections, Login Failures |
| 06 | Disk | Root, Docker, vmail, Log Usage |
| 07 | Backup | Count, Age, Size |
| 08 | Sync Jobs | Active, Running, Failed |
| 09 | Mailboxes | Total, Quota, Top 5 |
| 10 | Mailflow | Volume, Reject Breakdown, Bytes, Warnings |
| 11 | ClamAV | DB Age, Signatures |
| 12 | Watchdog | Overall + Service Health Levels |
| 13 | ACME Certificate | Days Left |
| 14 | Docker Health | CPU Total, Memory Total, Restarts |
| 15 | SOGo/Memcached | Hit Rate, Items, Bytes |
| 16 | Quarantine & Queue | Quarantine, Queue Deferred/Active |
| 17 | Updates | Commits Behind |
| 18 | Agent & Collector | Errors, Data Age |
| 19 | Postscreen | Connections (Connect/Pass), Blocks (Reject/DNSBL/Pregreet) |

---

## Dateien im Paket

```
mailcow-monitoring-v1.0/
├── scripts/
│   ├── mailcow-collector.py      # Haupt-Collector (22 Module, 1819 Zeilen)
│   ├── mailcow-reader.sh         # JSON-Reader (Python3-basiert)
│   ├── check_rbl.sh              # RBL-Check (Slow-Cache)
│   ├── check_dns.sh              # DNS SPF/DKIM/DMARC (Slow-Cache)
│   ├── check_tls.sh              # TLS/Cert-Check (Slow-Cache)
│   ├── check_open_relay.sh       # Open-Relay-Check (Slow-Cache)
│   ├── check_ptr.sh              # PTR-Check (Slow-Cache)
│   ├── check_security_audit.sh   # DANE/MTA-STS/TLS-RPT/BIMI (Slow-Cache)
│   ├── postfix_stats_docker.sh   # Postfix Queue Stats
│   ├── postfix_log_analysis.sh   # Postfix Log + Postscreen Analyse
│   └── sync_jobs_check.sh        # Sync-Job-Status
├── templates/
│   └── mailcow-complete-monitoring.yaml  # Zabbix 7.0 Template
├── mailcow-zabbix.conf           # 246 UserParameters
├── mailcow-monitor.service       # systemd Service
├── mailcow-monitor.timer         # systemd Timer (60s)
├── install.sh                    # Installer
├── uninstall.sh                  # Deinstallation
├── test-complete.sh              # Test-Script (246 Keys)
├── README.md                     # Kurzanleitung
├── CHANGELOG.md                  # Versionshistorie
└── MAILCOW-MONITORING-DOKU.md    # Diese Dokumentation
```

---

## Installation

```bash
# 1. Code holen
git clone https://github.com/linuser/Mailcow-Zabbix-Monitoring.git
cd Mailcow-Zabbix-Monitoring

#    ohne git:
#    curl -sL https://github.com/linuser/Mailcow-Zabbix-Monitoring/archive/refs/heads/main.tar.gz | tar xz
#    cd Mailcow-Zabbix-Monitoring-main

# 2. Installer ausführen
sudo ./install.sh

# 3. Template in Zabbix importieren
#    Data collection → Templates → Import
#    Datei: templates/mailcow-complete-monitoring.yaml
#    WICHTIG: "Create new" UND "Update existing" anhaken, "Delete missing" NICHT.
#    Kontrolle danach: Items 246 | Triggers 63 | Dashboards 19

# 4. Template dem Host zuweisen
#    Data collection → Hosts → <host> → Templates → Link
#    "Mailcow Complete Monitoring v1.0"

# 5. Test
./test-complete.sh
```

### Voraussetzung: ServerActive

Alle 246 Items sind **aktive** Agent-Checks. Der Agent holt sie selbst von der
Adresse in `ServerActive`; `Server=` regelt nur passive Abfragen und genügt
nicht. Fehlt `ServerActive`, sammelt kein einziges Item Daten — ohne
Fehlermeldung, Items und Trigger sind trotzdem sichtbar.

```ini
# /etc/zabbix/zabbix_agent2.conf
Server=<zabbix-server>,127.0.0.1
ServerActive=<zabbix-server>
Hostname=<host name wie in Zabbix>
```

`install.sh` und `update.sh` prüfen das und warnen. Details: README / UPDATE.md.

## Update

```bash
cd ~/Mailcow-Zabbix-Monitoring
git pull
sudo ./update.sh --check     # zeigt an, was sich aendern wuerde
sudo ./update.sh
```

`update.sh` sichert die bestehenden Scripts nach
`/var/backups/mailcow-zabbix/<datum>/`, ersetzt nur, was sich unterscheidet,
leert den RBL-Cache, startet den Timer neu und verifiziert anschließend die
erzeugten Werte. Zurück geht es mit `sudo ./update.sh --rollback`.

Danach das Template neu importieren — ebenfalls mit **"Create new" UND
"Update existing"**. Mit "Update existing" allein legt Zabbix fehlende Objekte
nicht an und meldet trotzdem Erfolg; so entstanden Installationen mit 0 von 71
Triggern. Die History bleibt erhalten, da Template-UUID und technischer Name
stabil sind.

### Nach Template-Reimport sofort alle Daten abrufen

```bash
# Collector sofort ausführen (frische JSON-Daten)
systemctl start mailcow-monitor.service

# Zabbix Agent neu starten (erzwingt sofortigen Re-Check aller Items)
systemctl restart zabbix-agent2
```

### Wo sind die Dashboards?

Die 19 Dashboards sind Template-Dashboards und hängen am Host:
*Monitoring → Hosts* → Zeile des Hosts → **Dashboards**.
Unter *Monitoring → Dashboards* erscheinen sie nicht.

---

## Mailflow (pflogsumm) — 28 Items

Das einzige Modul, das nicht den Ist-Zustand misst, sondern **Durchsatz über ein
Zeitfenster**. Grundlage ist `pflogsumm`, gefüttert aus den Postfix-Logs der
letzten Stunde:

```
docker logs --since 1h <postfix-container> | pflogsumm
```

Alle Werte sind damit **Stundensummen**, keine Momentaufnahmen. Ein Item wie
`mailcow.mail.received` heißt „empfangen in der letzten Stunde", nicht „aktuell
in Bearbeitung".

### Eigener Cache (5 Minuten)

`pflogsumm` über eine Stunde Logs ist teuer (Timeout: 60 s). Das Modul hält
deshalb einen eigenen Cache, getrennt vom 1h-Slow-Cache der übrigen Module:

```
/var/tmp/mailcow-monitor-mailflow.json   (max. 5 Minuten alt)
```

Ist der Cache frisch, liefert der Collector ihn direkt aus, ohne pflogsumm
erneut zu starten. Die 5 Minuten sind der Kompromiss: frisch genug für
Anomalie-Trigger, selten genug, um den Host nicht zu belasten.

### Voraussetzung

`pflogsumm` muss auf dem **Host** installiert sein (`apt install pflogsumm`) —
nicht im Container. `install.sh` installiert es automatisch nach; schlägt das
fehl, liefert das Modul stillschweigend Nullen. Fehlt der Postfix-Container oder
ist das Log leer, ebenso.

### Die 28 Items

| Gruppe | Items | Inhalt |
|---|---|---|
| Grand Totals | 13 | received, delivered, forwarded, deferred, bounced, rejected, reject.rate, bytes.received, bytes.delivered, senders, recipients, sending.domains, recipient.domains |
| Top-Listen | 4 | top.senders, top.recipients, top.sending.domains, top.recipient.domains (je Top 5, als Text) |
| Reject-Aufschlüsselung | 6 | reject.rbl, reject.unknown.user, reject.relay.denied, reject.domain.notfound, reject.cleanup (Milter/Rspamd), reject.detail |
| Bounce-Details | 1 | bounce.detail |
| Warnungen | 4 | warnings.sasl, warnings.tls, warnings.dns, warnings.postscreen |

### Trigger (9)

Fünf davon vergleichen gegen die eigene Historie statt gegen feste Schwellen —
siehe Abschnitt „Anomalie-Erkennung":

| Trigger | Bedingung | Stufe |
|---|---|---|
| Mail volume spike | `> 5 ×` Wochen-Baseline | Warning |
| Mail volume drop | `< 0.2 ×` Wochen-Baseline | High |
| Deferred spike | `> 5 ×` Baseline | Warning |
| Bounce spike | `> 5 ×` Baseline | Warning |
| Reject spike | `> 10 ×` Baseline | Warning |
| Deferred absolut | `> 10` | Warning |
| Bounce absolut | `> 50` | High |
| Reject rate | `> 80 %` | Warning |
| SASL warnings | `> 100` | Warning |

**Volume drop ist High, spike nur Warning** — ein Einbruch bedeutet meist, dass
der Mailempfang steht (DNS, Firewall, Postfix), während ein Ausschlag oft nur
eine Newsletter-Welle ist. Beide schließen sich gegenseitig aus und haben
deshalb bewusst *keine* Dependency.

Die Baseline braucht **~1 Woche History**, bis sie trägt. Frische
Installationen alarmieren dank Mindest-Baseline (`trendavg > 5`) nicht sofort.

### Einschränkungen

- **Nur auf Servern mit direktem Mail-Empfang sinnvoll.** Hinter einem
  Smarthost oder auf reinen Relay-Setups sind die Zahlen wenig aussagekräftig.
- Die Baseline ist ein reiner Wochenschnitt (`trendavg`, 1w) — sie kennt keine
  Wochentag- oder Tageszeit-Saisonalität. Dienstag 10 Uhr wird also gegen den
  Schnitt inklusive Sonntagnacht gemessen. Für saisonale Erkennung wäre
  `baselinewma()` der passende Ersatz (offen für v1.3).
- Schlägt pflogsumm fehl, sind alle 28 Werte 0 — nicht unterscheidbar von einem
  echten Nullstunde-Ergebnis. Siehe „Bekannte Einschränkungen".

---

## Collector-Module (22)

| Modul | Datenquelle | Cache |
|-------|-------------|-------|
| collect_postfix | docker exec, queue | 60s |
| collect_postfix_logs | docker logs → postfix_log_analysis.sh | 60s |
| collect_rspamd | Rspamd API :11334 + `rspamc stat` (Bayes) | 60s |
| collect_fail2ban | docker exec, iptables | 60s |
| collect_disk | df, du | 60s |
| collect_sync | MySQL (imapsync) | 60s |
| collect_mailbox | MySQL (mailbox, quota2) | 60s |
| collect_alias | MySQL (alias) | 60s |
| collect_lld | MySQL (domain, mailbox, imapsync) | 60s |
| collect_docker_health | docker stats + docker inspect (batched) | 60s |
| collect_sogo | docker exec memcached | 60s |
| collect_clamav | docker exec (single compound command) | 60s |
| collect_watchdog | docker logs watchdog | 60s |
| collect_quarantine | MySQL (quarantine) | 60s |
| collect_queue_age | docker exec postfix | 60s |
| collect_acme | openssl x509 | 60s |
| collect_version | git, docker inspect | 60s |
| collect_meta | Zabbix Agent Config | 60s |
| collect_backup | Filesystem | 60s |
| collect_mailflow | pflogsumm via docker logs | **5m** |
| collect_slow | check_*.sh (parallelisiert, 6 Threads) | **1h** |

### Collector Self-Monitoring
- `mailcow.collector.errors` — Anzahl fehlgeschlagener Module
- `mailcow.collector.error.detail` — `modul:ExceptionType` pro Fehler
- `mailcow.collector.module.times` — JSON mit Laufzeit pro Modul
- `mailcow.collector.duration` — Gesamtlaufzeit in Sekunden

---

## Bekannte Einschränkungen

- **pflogsumm:** Muss auf dem Host installiert sein (`apt install pflogsumm`)
- **Mailflow:** Nur auf Servern mit direktem Mail-Empfang sinnvoll
- **LLD Sync Jobs:** Keine Items wenn keine Sync-Jobs konfiguriert
- **Baseline-Trigger:** Brauchen ~1 Woche History bevor sie sinnvoll greifen
- **Bayes-Training:** `rspamc stat` braucht einen laufenden Rspamd-Container
- **Postscreen:** Werte = 0 wenn Postscreen in Postfix nicht aktiviert ist (kein Fehler)
- **Security Audit:** DANE/TLSA nur am MX-Hostname, nicht pro Domain

---

## Lizenz

**AGPL-3.0-or-later** — Dieser Code muss Open Source bleiben. Bei Nutzung, Änderung oder Weitergabe muss der ursprüngliche Autor genannt werden.

© 2026 Alexander Fox | PlaNet Fox — https://github.com/linuser/Mailcow-Zabbix-Monitoring

Created with Open Source and ❤
