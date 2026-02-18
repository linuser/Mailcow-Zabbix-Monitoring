# Changelog

## v1.0 (2026-02-18) — First Public Release

### Architektur
- **Secure Service Architecture:** systemd timer → Collector (root) → JSON → Zabbix Reader
- **Kein UnsafeUserParameters** — Zabbix Agent braucht kein Docker, kein sudo
- **246 UserParameters** in einer einzigen Conf-Datei
- **22 Collector-Module** in einem Python-Script
- **4 LLD Discovery Rules:** Domains, Mailboxes, Syncjobs, Docker Containers

### Neue Module (seit v4.4)
- Mailflow-Analyse (pflogsumm: sent/received/bounced/deferred/reject)
- ClamAV (Signatur-Alter, DB-Version, Scan-Status)
- Watchdog (Overall Health Score, Service-Status)
- ACME/Cert (Let's Encrypt Zertifikat-Überwachung)
- Docker Health (CPU/RAM/Status per Container via LLD)
- SOGo/Memcached (Hit Rate, Memory, Connections)
- Quarantine (Anzahl, Alter, Auto-Cleanup Status)
- Queue Age (Postfix Spool: active/deferred/hold/corrupt)
- Collector Self-Monitoring (Laufzeit, Fehler-Tracking, Module-Timing)

### Optimierungen (v5.0)
- **Baseline-Anomalie-Trigger (#8):** 5 trendavg-basierte Trigger erkennen automatisch Spikes/Drops bei received (5×/20%), rejected (10×), bounced (5×), deferred (5×) — keine festen Schwellwerte, lernt den Normalzustand
- **Security Audit Checks (#9):** DANE/TLSA, MTA-STS, TLS-RPT, BIMI prüfung pro Domain + Gesamt-Score (0-7), Trigger bei Score <3
- **Postscreen Monitoring (#6):** 9 Metriken (connect/pass_new/pass_old/reject/dnsbl/pregreet/hangup/whitelisted/active), Dashboard-Page, Trigger bei >100 Rejects
- **Rspamd Bayes-Training (#5):** Ham/Spam-Lernrate, Total learned, Ham-Ratio%, Training-Status (untrained/low/unbalanced/good/excellent), Trigger bei <200 gelernten Nachrichten, Dashboard-Widget
- **Zentralisierte Container-Erkennung:** 1x find_all_containers() statt ~10 find_container() pro Lauf
- **ClamAV:** 1 docker exec statt 3-5 (Version+Daily+Main+DBSize kombiniert)
- **Docker Health:** gezielter docker stats + 1 gebatchter docker inspect statt N einzelne
- **Slow-Cache parallelisiert:** ThreadPoolExecutor (6 Threads) für TLS/DNS/RBL-Checks
- **Mailflow:** eigener 5-Min-Cache statt im 1h-Slow-Cache (frischere Daten)
- **MySQL:** Passwort via MYSQL_PWD statt auf Kommandozeile (-p"...")
- **shell=False:** run_cmd() für einfache Befehle (sicherer, schneller)
- **Collector Error-Tracking:** Fehler pro Modul + Module-Timing im JSON
- **Rspamd:** 1 Docker-Call statt 2 (stat + detail merged)
- Dashboard Widgets: ds.hosts Referenz für Zabbix 7.0

### Paket-Bereinigung
- Alte Installer/Updater (v4.4) entfernt
- rspamd_stats.sh entfernt (merged in collector.py)
- Einheitliche Versionierung (v5.0 überall)
- Saubere Dateinamen ohne Versionssuffixe
- Template-ID `mailcow_complete_monitoring_v45` beibehalten (Zabbix Update-in-Place Kompatibilität)

### Bugfixes
- **Watchdog:** Default-Wert von -1 auf 0 geändert (UNSIGNED Items können keine negativen Werte speichern → "Not supported")
- **Watchdog:** Log-Fenster von 5m auf 10m erweitert (Watchdog-Zyklus ist ~5min, knappes Fenster verpasst manchmal den letzten Check)
- **YAML:** 100 unquotierte Hex-Farbwerte in Dashboard-Widgets gefixt (YAML interpretierte sie als Integer/Oktal)
- **Lizenz:** GPLv3 LICENSE-Datei hinzugefügt + Lizenz-Referenz in allen Script-Headern

## v4.4 (2026-02-13)

### Bugfixes
- **RBL-Check:** `curl` durch `dig` ersetzt (NAT-kompatibel)
- **PTR-Check:** `curl` durch `dig` ersetzt
- **Version:** `git describe --tags` statt fehlender Config-Variable
- **Duplikate:** Installer entfernt automatisch alte Configs
- **Fail2ban:** Container-Name wird dynamisch erkannt

### Verbesserungen
- Alle UserParameter in einer Datei
- Automatisches Backup der alten Installation
- `--all` Flag für non-interactive Installation
- Bessere Container-Erkennung (mehrere Naming-Patterns)
- Uninstall-Script hinzugefügt

## v4.3

- Meta-Monitoring (Agent überwacht sich selbst)
- Sync Jobs Monitoring (IMAP Migration)
- Dovecot Monitoring (IMAP/POP3)
- Disk Space Monitoring
- Smart Config Reading
- Timezone Fix

## v4.2.3

- Disk Space Monitoring
- History-Optimierung
- Smart Log-Monitoring

## v4.1/v4.2

- Postfix, TLS, Updates, Backup
- Security (RBL, Fail2Ban, DNS)
- Rspamd (Spam-Filter)
