# Changelog

## v1.2 (2026-07-15)

### Bugfix: Trigger wurden nie importiert (schwerwiegend)
- **63 der 71 Trigger konnten in keiner Installation angelegt werden.** Ihre
  Expressions referenzierten den *sichtbaren* Template-Namen
  (`/Mailcow Complete Monitoring v1.0/...`) statt des *technischen*
  (`/mailcow_complete_monitoring_v45/...`). Unter dem sichtbaren Namen
  existiert kein Template -> Trigger wurden nicht erstellt.
  Die 8 LLD-Trigger-Prototypen nutzten den technischen Namen bereits korrekt,
  daher funktionierte ausschliesslich die Discovery.
- **56 Trigger-Namen** nutzten doppelte Klammern `{{HOST.NAME}}`. In Zabbix ist
  `{{...}}` Makro-Funktions-Syntax und ohne Funktion ungueltig -> `{HOST.NAME}`.
- **RBL-Trigger** zeigte `*UNKNOWN*` statt der Blacklist: das Expression-Makro
  `{?last(/<template>/mailcow.security.rbl.detail)}` im Trigger-Namen
  referenzierte ebenfalls den sichtbaren Namen.

### Bugfix: Dashboards leer (#3)
- **Alle 46 Widgets in 19 Dashboards** nutzten die Zabbix-6.x-Syntax fuer Data
  Sets (`ds.items.0.0`, `ds.color.0`). Zabbix 7.0 erwartet
  `ds.<dataset>.<feld>.<item>` und ein `reference`-Feld je Widget. Unbekannte
  Felder ignoriert Zabbix stillschweigend: Achsen und Trigger-Marker wurden
  gezeichnet, das Data Set blieb leer. Items und Trigger waren nie betroffen.
  - Umstellung auf Item-List-Modus: `ds.0.dataset_type`, `ds.0.itemids.N`
    (ITEM: host+key), `ds.0.color.N`, `ds.0.missingdatafunc`, `ds.0.width`
  - `reference`-Feld ergaenzt (in 7.0 Pflicht, fehlte komplett)
  - Der in v1.0 vermerkte `ds.hosts`-Fix war nicht wirksam - das Feld war im
    Template nicht vorhanden.
- **YAML:** `y`-Koordinate der Widgets quotiert (`'y':`). YAML 1.1 liest bloszes
  `y` als Boolean; offizielle Zabbix-Exports quoten es durchgehend.

### Bugfix: RBL-Dauerfehlalarm auf Cloud-Hosts
- `check_rbl.sh` wertete **jede** nicht-leere DNS-Antwort als Listung. Spamhaus
  antwortet Rechenzentrums- und Public-Resolvern (Hetzner, DigitalOcean, OVH,
  Google DNS ...) aber mit Fehlercodes `127.255.255.252/254/255`. Ergebnis:
  permanenter **Disaster**-Alarm auf voellig sauberen Servern.
  Jetzt zaehlen nur `127.0.0.x` als Listung; Fehlercodes erscheinen als
  `error_resolver_blocked:<rbl>` im Detail-Item, ohne Alarm.
- IP-Ermittlung: `dig -4` erzwungen. Auf Dual-Stack-Hosts mit IPv6-Resolvern
  lieferte die OpenDNS-Abfrage nichts, das Script fiel stumm auf curl zurueck.
- Aufruf mit `detail` gab bei Cache-Miss zwei Zeilen aus (Zahl + Text), weil
  `echo ... | tee` zusaetzlich nach stdout schrieb.

### Verbesserung: doppelte Alarme
- **5 Trigger-Dependencies** ergaenzt. Schwellen-Leitern feuerten doppelt fuer
  denselben Sachverhalt (z.B. ClamAV ">7 Tage" Warning *und* ">30 Tage" High).
  Der jeweils niedrigere Trigger haengt jetzt am hoeheren:
  ClamAV-Alter, Watchdog, ACME-Restlaufzeit, Bounce, Deferred.
  `mailcow.mail.received` bleibt bewusst ohne Dependency - Spike und Drop
  schliessen sich gegenseitig aus.
- **2 doppelte Trigger-Namen** aufgeloest:
  - beide ACME-Trigger hiessen identisch -> High heisst jetzt "... - CRITICAL"
  - `mailcow.mail.deferred` und `mailcow.queue.deferred` teilten sich einen
    Namen -> Queue-Variante heisst jetzt "... deferred mails in queue"

### Dokumentation
- **`ServerActive` und `Hostname`** dokumentiert. Alle 246 Items sind aktive
  Agent-Checks und brauchen `ServerActive`; die bisherige Doku nannte nur
  `Server=`, das ausschliesslich passive Abfragen regelt. Fehlt `ServerActive`,
  liefert **kein einziges Item** Daten - ohne Fehlermeldung.
  `update.sh` prueft das jetzt und warnt.
- Import-Optionen: "Create new" **und** "Update existing" noetig. Mit nur
  "Update existing" ueberspringt Zabbix fehlende Objekte und meldet trotzdem
  Erfolg.
- Klargestellt, dass Template-Dashboards nur ueber
  *Monitoring -> Hosts -> <host> -> Dashboards* sichtbar sind.
- Hinweis, dass `test-complete.sh` nur passiv per `zabbix_get` prueft und damit
  weder aktive Checks noch Trigger oder Dashboards verifiziert.
- Grenzen der RBL-Pruefung auf Cloud-Hosts dokumentiert (eigener Resolver oder
  Spamhaus-DQS noetig).

### Lizenz
- Wechsel von **GPLv3 auf AGPL-3.0-or-later**, passend zu Zabbix seit 7.0.

### Werkzeuge
- `update.sh`: aktualisiert die Host-Seite, mit Backup, `--check`, `--rollback`,
  ServerActive-Pruefung und Verifikation der erzeugten Werte.
- `tools/fix_dashboards.py`, `tools/fix_triggers.py`: idempotente Konverter, mit
  denen die obigen Template-Fixes reproduzierbar sind.

### Bekannt / offen
- Der Collector schreibt bei fehlgeschlagener Messung **0** statt den Wert
  wegzulassen. "Messung fehlgeschlagen" und "echter Wert ist 0" sind dadurch
  nicht unterscheidbar, auch nicht fuer `mailcow.collector.errors`. Mit aktiven
  Triggern kann das Fehlalarme erzeugen. Geplant fuer v1.3.
- Quota-/Used-Items zeigen "KMB" (Einheit `MB` + automatischer SI-Praefix von
  Zabbix). Fix waere `!MB` oder Umstellung auf Bytes mit Einheit `B`.
- `docker ps --filter name=postfix` matcht seit neueren Mailcow-Versionen auch
  `postfix-tlspol-mailcow-1`. Aktuell greift die Auswahl zufaellig richtig;
  ein exaktes Matching waere robuster.
### Bugfix: Batching-Optimierung erzeugte stille Nullen
- **Postfix-PID:** `master.pid` wird von Postfix rechtsbuendig mit Leerzeichen
  aufgefuellt ("                             394"). Die gebuendelte Shell-Variante
  las sie ohne Strip, `[ -d "/proc/$PID" ]` pruefte also
  `/proc/                             394` -> immer 0. Ergebnis: Trigger
  "Postfix not running" (DISASTER) feuerte dauerhaft bei laufendem Postfix.
  Fix: `| tr -dc '0-9'`.
- **Batch verwarf alles bei einem Fehler:** `run()` liefert bei Exit != 0 den
  Default ""; bei einer Befehlskette ist das der Exit des LETZTEN Befehls.
  Der Rspamd-Batch endet auf `rspamc stat` - scheitert das, wurde das bereits
  erfolgreich geholte `/stat`-JSON verworfen und alle 18 Rspamd-Metriken fielen
  auf 0 (u.a. `scanned`, ein kumulativer Zaehler, der auf einem laufenden Server
  nie 0 ist). Betraf ebenso Postfix (`postconf`), vmail (`du`), ClamAV und
  Agent-Meta (`tail`). Fix: `; exit 0` am Ende jedes gebuendelten `sh -c`,
  fehlende Sektionen bleiben einfach leer. Teildaten sind besser als keine.

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
