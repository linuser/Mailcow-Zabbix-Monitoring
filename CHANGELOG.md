# Changelog

> Entries from v1.2 onwards are written in English. Earlier entries are in German.

## v1.2 (2026-07-16)

### Fixed — triggers were never imported (critical)
- **63 of the 71 triggers could not be created in any installation.** Their
  expressions referenced the template's *visible* name
  (`/Mailcow Complete Monitoring v1.0/...`) instead of its *technical* name
  (`/mailcow_complete_monitoring_v45/...`). No template exists under the visible
  name, so the triggers were never created. The 8 LLD trigger prototypes already
  used the technical name correctly — which is why discovery was the only part
  that worked.
- **56 trigger names** used doubled braces `{{HOST.NAME}}`. In Zabbix `{{...}}`
  is macro-function syntax and invalid without a function → `{HOST.NAME}`.
- The **RBL trigger** displayed `*UNKNOWN*` instead of the blacklist name: the
  expression macro `{?last(/<template>/mailcow.security.rbl.detail)}` inside the
  trigger name referenced the visible name as well.

### Fixed — template could not be imported at all
- All 7 hysteresis triggers carried a `recovery_expression` but no
  `recovery_mode: RECOVERY_EXPRESSION`. Zabbix defaults to `EXPRESSION`, where
  `recovery_expression` must be empty, so the import aborted with
  `Incorrect value for field "recovery_expression": should be empty.`

### Fixed — dashboards stayed empty (#3)
- **All 46 widgets across 19 dashboards** used the Zabbix 6.x data set field
  syntax (`ds.items.0.0`, `ds.color.0`). Zabbix 7.0 expects
  `ds.<dataset>.<field>.<item>` plus a `reference` field per widget. Zabbix
  silently ignores unknown fields: axes and trigger markers were rendered, the
  data set stayed empty. Items and triggers were never affected.
  - Converted to item list mode: `ds.0.dataset_type`, `ds.0.itemids.N`
    (ITEM: host+key), `ds.0.color.N`, `ds.0.missingdatafunc`, `ds.0.width`
  - Added the `reference` field (mandatory in 7.0, missing entirely)
  - The `ds.hosts` fix noted in v1.0 had no effect — that field was not present
    in the template.
- **YAML:** widget `y` coordinates are now quoted (`'y':`). YAML 1.1 reads a bare
  `y` as a boolean; official Zabbix exports quote it throughout.

### Fixed — permanent RBL false alarm on cloud hosts
- `check_rbl.sh` treated **every** non-empty DNS answer as a listing. Spamhaus,
  however, answers queries from datacenter and public resolvers (Hetzner,
  DigitalOcean, OVH, Google DNS …) with error codes `127.255.255.252/254/255`.
  The result was a permanent **Disaster** alarm on perfectly clean servers.
  Only `127.0.0.x` counts as a listing now; error codes surface as
  `error_resolver_blocked:<rbl>` in the detail item, without raising an alarm.
- IP detection now forces `dig -4`. On dual-stack hosts with IPv6 resolvers the
  OpenDNS query returned nothing and the script silently fell back to curl.
- Calling it with `detail` emitted two lines on a cache miss (count + text)
  because `echo ... | tee` also wrote to stdout.

### Fixed — batching optimisation produced silent zeros
- **Postfix PID:** Postfix writes `master.pid` right-aligned with padding
  (`"                             394"`). The batched shell variant read it
  without stripping, so `[ -d "/proc/$PID" ]` tested
  `/proc/                             394` → always 0. The "Postfix not running"
  trigger (DISASTER) fired permanently while Postfix was healthy.
  Fixed with `| tr -dc '0-9'`.
- **A failing command discarded the whole batch:** `run()` returns its default
  (`""`) on a non-zero exit code, and for a command list that is the exit code of
  the *last* command. The rspamd batch ends with `rspamc stat` — if that fails,
  the `/stat` JSON already fetched successfully was thrown away and all 18 rspamd
  metrics fell back to 0, including `scanned`, a cumulative counter that is never
  legitimately 0 on a running server. The postfix (`postconf`), vmail (`du`),
  ClamAV and agent (`tail`) batches had the same flaw. Fixed by appending
  `; exit 0` to every batched `sh -c`; missing sections simply stay empty.
  Partial data beats no data.

### Changed — duplicate alerts
- **Added 5 trigger dependencies.** Threshold ladders fired twice for the same
  condition (e.g. ClamAV ">7 days" Warning *and* ">30 days" High). The lower
  trigger now depends on the higher one: ClamAV age, watchdog, ACME expiry,
  bounce, deferred. `mailcow.mail.received` deliberately has no dependency —
  spike and drop are mutually exclusive.
- **Resolved 2 duplicate trigger names:**
  - both ACME triggers had identical names → the High one is now "... - CRITICAL"
  - `mailcow.mail.deferred` and `mailcow.queue.deferred` shared a name → the
    queue variant is now "... deferred mails in queue"

### Changed — documentation
- **`ServerActive` and `Hostname` are now documented.** All 246 items are active
  agent checks and require `ServerActive`; the previous docs only mentioned
  `Server=`, which governs passive queries alone. Without `ServerActive`, **not a
  single item** collects data — silently. `install.sh` and `update.sh` both check
  this and warn.
- Import options: **"Create new" AND "Update existing"** are required. With only
  "Update existing" Zabbix skips missing objects and still reports success — the
  cause of installations with 0 of 71 triggers. Both READMEs previously
  instructed exactly that.
- The update path pointed at `install.sh`; the correct one is `update.sh`.
- Installation via GitHub documented (git clone and tar.gz); the German README
  still referenced a non-existent `mailcow-monitoring-v1.0.zip`.
- Documented where template dashboards actually live
  (*Monitoring → Hosts → host → Dashboards*, not *Monitoring → Dashboards*).
- Removed "wait 5–10 minutes, then check the dashboard". Data appears within a
  minute; if it stays empty the cause was never patience, but `ServerActive`.
- Noted that `test-complete.sh` only probes passively via `zabbix_get` and can
  therefore verify neither active checks nor triggers nor dashboards.
- Documented the limits of the RBL check on cloud hosts (own resolver or a
  Spamhaus DQS key required).
- **Added a Mailflow chapter** to the project documentation. The largest module
  (28 items, 9 triggers) previously existed only as table rows: pflogsumm runs
  over `docker logs --since 1h`, so every value is an hourly total; it keeps its
  own 5-minute cache separate from the 1h slow cache; pflogsumm is a host
  prerequisite; documents all 9 triggers and why "volume drop" is High while
  "spike" is only Warning.
- Project documentation: header still said v1.0 (18.02.2026), the install section
  referenced a non-existent zip, an update section was missing entirely, and menu
  paths said "Configuration → Templates" (renamed to "Data collection" in Zabbix
  6.0). Item count corrected: 303 claimed, actually 246 items + 21 LLD prototypes.
- `UPDATE.md` is now English, the German version moved to `UPDATE.de.md` —
  matching the existing README pattern.
- Script output is now English; code comments stay German.

### Changed — licence
- Switched from **GPLv3 to AGPL-3.0-or-later**, matching Zabbix since 7.0.
- Unified licence headers: 10 of 15 files still said `License: GPLv3` while the
  LICENSE file was already AGPL-3.0.

### Added — tools
- `update.sh`: updates the host side, with backup, `--check`, `--rollback`,
  `ServerActive` validation and verification of the collected values. It waits
  for a genuinely fresh JSON instead of sleeping a fixed interval.
- `tools/fix_dashboards.py`, `tools/fix_triggers.py`, `tools/fix_collector.py`:
  idempotent converters that make the template and collector fixes above
  reproducible.

### Removed
- **`scripts/dovecot_check.sh`.** Since the inline optimisation (#opt10)
  `collect_dovecot()` does everything itself via docker exec; the script was
  never called again, yet was still installed to `/usr/local/bin`, backed up on
  every update and documented as an active module in both READMEs and the project
  documentation. `install.sh` now removes it from existing installations.
  (The only orphan — every other script has verified callers.)
- Dead code flagged by shellcheck: unused `MAILCOW_DIR` in `check_open_relay.sh`
  (SC2034), a loop over a single element in `install.sh` (SC2043), and
  `local x=$(...)` masking return values in `postfix_stats_docker.sh` (SC2155).
  The repository is now clean at `--severity=warning`, not just at the CI level
  `--severity=error`.

### Known issues
- The collector writes **0** when a measurement fails instead of omitting the
  key. "Measurement failed" and "the value really is 0" are indistinguishable —
  even to `mailcow.collector.errors`, which stays at 0. With triggers active this
  can produce false alarms. Planned for v1.3.
- Quota/used items display "KMB" (unit `MB` plus Zabbix's automatic SI prefix).
  The fix would be `!MB`, or switching to bytes with unit `B`.
- `docker ps --filter name=postfix` also matches `postfix-tlspol-mailcow-1` in
  newer Mailcow versions. The selection currently picks the right one by chance;
  exact matching would be more robust.
- The anomaly baseline uses `trendavg` over one week — a flat mean without
  weekday or time-of-day seasonality. `baselinewma()` would be the appropriate
  replacement (planned for v1.3).

## v1.1 (2026-03-28)

### Bugfix
- **Netfilter/Fail2ban:** Mailcow ab Version 2025-03 hat fail2ban durch eine eigene Python-Lösung ersetzt. `fail2ban-client` existiert nicht mehr im netfilter-Container und erzeugte alle 5 Minuten Fehlermeldungen im Docker-Log. Der Collector erkennt jetzt automatisch welche Version läuft:
  - **Neue Methode:** Gesamt-Bans über iptables/nftables MAILCOW-Chain
  - **Alte Methode:** fail2ban-client für Pro-Service-Bans (nur wenn vorhanden)
  - Kompatibel mit alten und neuen Mailcow-Versionen
- **SOGo Cache Trigger:** `change()>0` feuerte bei jeder einzelnen Eviction. Jetzt: `min(1h)>0 AND change()>50` — alarmiert nur bei echtem Cache-Druck

### Optimierungen
- **Postfix Batch:** 6 docker_exec Aufrufe → 1 (ein sh -c Block mit Sektions-Markern)
- **Quarantine Batch:** 3 MySQL-Queries → 2 (COUNT/Alter/Spam/Virus in einer Query)
- **ACME Batch:** 6 openssl-Aufrufe → 1 (`openssl x509 -subject -issuer -dates -serial`)
- **Rspamd Batch:** 2 docker_exec → 1 (wget stat + rspamc stat kombiniert)
- **Disk/vmail Batch:** 3 docker_exec → 1 (test + df + du in einem Aufruf)
- **Meta Batch:** 3 run() → 1 (systemctl is-active/show + tail log)
- **Dovecot Inline:** 9 externe Script-Aufrufe → 1 docker_exec (version + connections + awk log-Analyse)
- **Version Batch:** 8 separate git-Aufrufe → 1 Batch-Call + offizielles `update.sh --check-tags` für Update-Erkennung
- **Trigger-Hysterese:** 7 Recovery-Expressions hinzugefügt (Disk, Queue, Banned IPs, Backup) — verhindert Trigger-Flapping bei Grenzwerten
- **History-Optimierung:** 24 TEXT/CHAR Items von 30-90d auf 7d reduziert (Versionsstrings, Zertifikat-Details, Config-Werte brauchen keine Langzeit-History)
- **Version Batch:** 8 separate git-Aufrufe → 1 Batch-Call + offizielles `update.sh --check-tags` für Update-Erkennung
- **Fail2ban Cache:** `which fail2ban-client` wird nur einmal pro Collector-Lauf geprüft statt bei jedem Zyklus

### Dokumentation
- zabbix-get als Voraussetzung dokumentiert
- Zabbix Agent `Server=127.0.0.1` Konfiguration dokumentiert
- `MAILCOW_DIR` und `BACKUP_PATH` Variablen in install.sh dokumentiert

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
