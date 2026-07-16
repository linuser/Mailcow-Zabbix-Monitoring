# Update auf v1.2

English version: [UPDATE.md](UPDATE.md)

Dieses Paket aktualisiert eine bestehende Installation. Es besteht aus **zwei
Teilen**, die man leicht verwechselt:

| Teil | Wohin | Womit |
|---|---|---|
| Collector + Check-Scripts | Mailcow-Server (`/usr/local/bin/`) | `sudo ./update.sh` |
| Zabbix-Template | Zabbix-Frontend | Import im Browser |

Beide sind nötig. Nur das Template zu importieren behebt nichts, wenn der
Collector alt ist — und umgekehrt.

---

## 1. Mailcow-Server

```bash
unzip mailcow-zabbix-v1.2.zip
cd mailcow-zabbix-v1.2
sudo ./update.sh --check     # zeigt an, was passieren wuerde
sudo ./update.sh             # fuehrt es aus
```

`update.sh` legt vorher ein Backup unter `/var/backups/mailcow-zabbix/<datum>/`
an. Zurück geht es mit `sudo ./update.sh --rollback`.

Der Updater prüft am Ende selbst nach, ob die Werte plausibel sind, u. a.:

```
OK    246 Metriken in der JSON
OK    Postfix laeuft: 1
OK    Rspamd scanned: 73890
OK    RBL detail: clean
```

Steht dort `Postfix laeuft: 0` **und** `Rspamd scanned: 0`, lief noch der alte
Collector — dann prüfen:

```bash
md5sum /usr/local/bin/mailcow-collector.py    # muss 96548338af442ecdd755a9b19c098129 sein
```

## 2. Zabbix-Frontend

*Data collection → Templates → Import*, Datei
`templates/mailcow-complete-monitoring.yaml`.

**Wichtig — Import-Optionen:** bei **allen** Objekttypen sowohl **Create new**
als auch **Update existing** anhaken. `Delete missing` bleibt aus.

Mit nur „Update existing" legt Zabbix fehlende Objekte **nicht** an und meldet
trotzdem „Imported successfully". Genau so entstand der Zustand, in dem 0 von 71
Triggern existierten.

Kontrolle danach in der Template-Zeile:

```
Items 246 | Triggers 63 | Dashboards 19 | Discovery 4
```

Steht bei *Triggers* keine Zahl, war „Create new" nicht gesetzt.

### Wo sind die Dashboards?

Template-Dashboards erscheinen **nicht** unter *Monitoring → Dashboards* — dort
stehen nur globale Dashboards. Sie hängen am Host:

*Monitoring → Hosts* → Zeile des Hosts → Link **Dashboards** → „01 - Postfix"

Öffnet man sie stattdessen unter *Data collection → Templates → Dashboards*,
sind sie leer: dort fehlt der Host-Bezug, es gibt nichts zu zeichnen.

---

## Voraussetzung: ServerActive (häufigste Fehlerursache)

**Alle 246 Items sind aktive Agent-Checks.** Aktive Checks holt sich der Agent
selbst — von der Adresse in `ServerActive`. `Server=` regelt nur passive
Abfragen und reicht **nicht**.

In `/etc/zabbix/zabbix_agent2.conf`:

```ini
Server=zabbix.example.com,127.0.0.1     # passiv (u.a. fuer test-complete.sh)
ServerActive=zabbix.example.com         # AKTIV - ohne das: keine Daten
Hostname=mail.example.com               # exakt der Host-Name in Zabbix
```

Danach `systemctl restart zabbix-agent2`.

Fehlt `ServerActive` oder zeigt es auf `127.0.0.1`, während der Zabbix-Server
woanders läuft, liefert **kein einziges Item** Daten — Items und Trigger sind im
Frontend sichtbar, Graphen bleiben leer. `update.sh` prüft das und warnt.

Jeder Parameter darf nur **einmal** unkommentiert vorkommen; sonst startet der
Agent nicht. Vor dem Neustart testen:

```bash
zabbix_agent2 -T -c /etc/zabbix/zabbix_agent2.conf
```

---

## RBL-Prüfung auf Cloud-Hosts

Spamhaus beantwortet Anfragen von Rechenzentrums- und Public-Resolvern
(Hetzner, DigitalOcean, OVH, Google DNS, Cloudflare) nicht mit einem Ergebnis,
sondern mit einem Fehlercode aus `127.255.255.0/24`:

| Antwort | Bedeutung |
|---|---|
| `127.0.0.2` / `.3` | SBL — echte Listung |
| `127.0.0.4`–`.7` | XBL — echte Listung |
| `127.0.0.10` / `.11` | PBL — echte Listung |
| `127.255.255.252` | Fehler: ungültige Abfrage |
| `127.255.255.254` | Fehler: Abfrage über Public Resolver |
| `127.255.255.255` | Fehler: Rate Limit |

Bis v1.1 zählte jede nicht-leere Antwort als Listung — auf einem Hetzner-Host
also ein dauerhafter **Disaster-Fehlalarm**. Seit v1.2 zählen nur `127.0.0.x`;
Fehlercodes erscheinen als `error_resolver_blocked:<rbl>` im Detail-Item, ohne
Alarm.

Damit ist der Fehlalarm weg — aber die Prüfung liefert auf solchen Hosts auch
kein echtes Ergebnis. Wer eines will, betreibt einen eigenen rekursiven Resolver
(z. B. unbound) und setzt in `check_rbl.sh`:

```bash
RBL_RESOLVER=127.0.0.1
```

oder verwendet einen Spamhaus-DQS-Key.

---

## Was `test-complete.sh` nicht prüft

`test-complete.sh` fragt die UserParameter mit `zabbix_get -s 127.0.0.1` ab —
das sind **passive** Abfragen. Es meldet also 246/246 OK, obwohl das Template
über aktive Checks nichts bekommt. Es prüft ebenfalls nicht, ob Trigger
existieren oder Dashboards Daten zeigen. Ein bestandener Test ist deshalb kein
Beleg dafür, dass das Monitoring arbeitet — die Kontrolle im Frontend
(*Latest data*, Trigger-Zahl) bleibt nötig.

---

## Enthaltene Fixes

Siehe `CHANGELOG.md`.

## Lizenz

AGPL-3.0-or-later, passend zu Zabbix seit 7.0 (vorher GPLv2). Siehe `LICENSE`.
