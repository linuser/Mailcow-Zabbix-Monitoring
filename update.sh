#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Update auf v1.2
#  Vendor:   Alexander Fox | PlaNet Fox
#  Project:  https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  License:  AGPL-3.0-or-later (siehe LICENSE)
# ====================================================================
#
#  Aktualisiert die Host-Seite (Collector + Check-Scripts + Agent-Config).
#  Die Zabbix-Seite (Template-Import) muss im Frontend erfolgen, siehe UPDATE.md.
#
#  Aufruf:
#      sudo ./update.sh              # aktualisieren
#      sudo ./update.sh --check      # nur pruefen, nichts aendern
#      sudo ./update.sh --rollback   # letztes Backup zurueckspielen
# ====================================================================

set -u

BIN_DIR="/usr/local/bin"
AGENT_CONF="/etc/zabbix/zabbix_agent2.conf"
JSON="/var/tmp/mailcow-monitor.json"
BACKUP_ROOT="/var/backups/mailcow-zabbix"
SRC="$(cd "$(dirname "$0")" && pwd)"

CHECK_ONLY=0
ROLLBACK=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1
[ "${1:-}" = "--rollback" ] && ROLLBACK=1

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; NC=$'\033[0m'
ok()   { echo "  ${GRN}OK${NC}    $*"; }
warn() { echo "  ${YEL}WARN${NC}  $*"; }
err()  { echo "  ${RED}FEHLER${NC} $*"; }

FAIL=0

if [ "$(id -u)" -ne 0 ]; then
    err "Bitte als root ausfuehren (sudo ./update.sh)"
    exit 1
fi

# ---------------------------------------------------------------- rollback
if [ $ROLLBACK -eq 1 ]; then
    LAST=$(ls -1d "$BACKUP_ROOT"/* 2>/dev/null | sort | tail -1)
    if [ -z "$LAST" ]; then
        err "Kein Backup unter $BACKUP_ROOT gefunden"
        exit 1
    fi
    echo "Rollback aus: $LAST"
    cp -a "$LAST"/*.sh "$LAST"/*.py "$BIN_DIR"/ 2>/dev/null
    systemctl restart mailcow-monitor.timer 2>/dev/null
    ok "Scripts zurueckgespielt. Template im Frontend ggf. separat zuruecksetzen."
    exit 0
fi

echo "=============================================="
echo " Mailcow-Zabbix-Monitoring  Update v1.2"
[ $CHECK_ONLY -eq 1 ] && echo " MODUS: --check (es wird nichts geaendert)"
echo "=============================================="
echo

# ------------------------------------------------- 1. Voraussetzungen
echo "[1/6] Voraussetzungen"
command -v docker >/dev/null 2>&1 && ok "docker gefunden" || { err "docker fehlt"; FAIL=1; }
command -v python3 >/dev/null 2>&1 && ok "python3 gefunden" || { err "python3 fehlt"; FAIL=1; }
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'postfix-mailcow'; then
    ok "Mailcow-Container laufen"
else
    err "Kein postfix-mailcow-Container gefunden - laeuft Mailcow?"
    FAIL=1
fi
[ $FAIL -eq 1 ] && { echo; err "Abbruch."; exit 1; }
echo

# ------------------------------------------------- 2. Agent-Konfiguration
# Das ist der Bug, der in v1.0/v1.1 jede Installation still lahmgelegt hat:
# ALLE Items sind aktive Checks und brauchen ServerActive. Server= allein
# genuegt NICHT. Wir aendern hier nichts automatisch (eine kaputte Config
# verhindert den Agent-Start), sondern melden nur.
echo "[2/6] Zabbix-Agent-Konfiguration"
if [ -f "$AGENT_CONF" ]; then
    SA=$(grep -E '^ServerActive=' "$AGENT_CONF" | head -1 | cut -d= -f2-)
    HN=$(grep -E '^Hostname=' "$AGENT_CONF" | head -1 | cut -d= -f2-)
    SA_COUNT=$(grep -cE '^ServerActive=' "$AGENT_CONF")
    if [ -z "$SA" ]; then
        err "ServerActive fehlt -> KEIN einziges Item wird Daten liefern!"
        echo "        Eintragen: ServerActive=<ip-oder-name-des-zabbix-servers>"
        FAIL=1
    elif echo "$SA" | grep -qE '^(127\.0\.0\.1|localhost)$'; then
        warn "ServerActive=$SA zeigt auf localhost."
        echo "        Nur korrekt, wenn der Zabbix-Server auf DIESEM Host laeuft."
    else
        ok "ServerActive=$SA"
    fi
    [ "$SA_COUNT" -gt 1 ] && err "ServerActive $SA_COUNT-mal definiert - Agent startet damit nicht"
    if [ -z "$HN" ]; then
        warn "Hostname nicht gesetzt (muss exakt dem Host-Namen in Zabbix entsprechen)"
    else
        ok "Hostname=$HN"
    fi
else
    warn "$AGENT_CONF nicht gefunden - Agent 2 installiert?"
fi
echo

# ------------------------------------------------- 3. Backup
echo "[3/6] Backup"
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="$BACKUP_ROOT/$STAMP"
if [ $CHECK_ONLY -eq 0 ]; then
    mkdir -p "$BACKUP"
    N=0
    for f in "$BIN_DIR"/mailcow-collector.py "$BIN_DIR"/mailcow-reader.sh "$BIN_DIR"/check_*.sh \
             "$BIN_DIR"/dovecot_check.sh "$BIN_DIR"/postfix_*.sh "$BIN_DIR"/sync_jobs_check.sh; do
        [ -f "$f" ] && { cp -a "$f" "$BACKUP/"; N=$((N+1)); }
    done
    ok "$N Dateien gesichert -> $BACKUP"
else
    ok "(check) Backup wuerde nach $BACKUP gehen"
fi
echo

# ------------------------------------------------- 4. Scripts aktualisieren
echo "[4/6] Scripts"
UPD=0
for f in "$SRC"/scripts/*; do
    NAME=$(basename "$f")
    TARGET="$BIN_DIR/$NAME"
    if [ -f "$TARGET" ] && cmp -s "$f" "$TARGET"; then
        echo "        unveraendert: $NAME"
        continue
    fi
    if [ $CHECK_ONLY -eq 1 ]; then
        warn "(check) wuerde ersetzen: $NAME"
    else
        install -o root -g root -m 0755 "$f" "$TARGET" && ok "aktualisiert: $NAME"
    fi
    UPD=$((UPD+1))
done
[ $UPD -eq 0 ] && ok "Alle Scripts bereits aktuell"
echo

# ------------------------------------------------- 5. Caches + Dienst
echo "[5/6] Caches und Dienst"
if [ $CHECK_ONLY -eq 0 ]; then
    # RBL-Cache muss weg, sonst liefert der alte Fehlalarm noch bis zu 30 Min.
    rm -f /var/tmp/rbl_check.cache /var/tmp/rbl_check_detail.cache
    ok "RBL-Cache geleert"
    systemctl daemon-reload 2>/dev/null
    if systemctl list-unit-files 2>/dev/null | grep -q mailcow-monitor.timer; then
        systemctl restart mailcow-monitor.timer && ok "Timer neu gestartet"
        systemctl start mailcow-monitor.service 2>/dev/null
        ok "Collector-Lauf angestossen"
    else
        warn "mailcow-monitor.timer nicht installiert (install.sh noetig?)"
    fi
    sleep 3
else
    ok "(check) Cache/Dienst unveraendert"
fi
echo

# ------------------------------------------------- 6. Verifikation
echo "[6/6] Verifikation"
if [ -f "$JSON" ]; then
    AGE=$(( $(date +%s) - $(stat -c %Y "$JSON") ))
    [ $AGE -lt 180 ] && ok "JSON ist ${AGE}s alt" || warn "JSON ist ${AGE}s alt - laeuft der Timer?"
    python3 - "$JSON" <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("  \033[0;31mFEHLER\033[0m JSON nicht lesbar:", e); sys.exit(0)

def show(label, key, bad=None):
    v = d.get(key, "<fehlt>")
    flag = "\033[0;33mWARN\033[0m  " if (bad is not None and v == bad) else "\033[0;32mOK\033[0m    "
    print(f"  {flag}{label}: {v}")

print(f"  \033[0;32mOK\033[0m    {len(d)} Metriken in der JSON")
show("Postfix laeuft", "postfix.process.running", bad=0)
show("Rspamd scanned", "mailcow.rspamd.scanned", bad=0)
show("RBL gelistet", "mailcow.security.rbl.listed")
show("RBL detail", "mailcow.security.rbl.detail")
show("Collector-Fehler", "mailcow.collector.errors")
EOF
else
    err "$JSON existiert nicht - Collector lief nie erfolgreich"
fi
echo
echo "=============================================="
echo " Host-Seite fertig."
echo
echo " NAECHSTER SCHRITT (Zabbix-Frontend, nicht automatisierbar):"
echo "   Data collection -> Templates -> Import"
echo "   Datei: templates/mailcow-complete-monitoring.yaml"
echo "   WICHTIG: 'Create new' UND 'Update existing' anhaken,"
echo "            'Delete missing' NICHT."
echo "   Danach muss beim Template stehen: Items 246 | Triggers 63 | Dashboards 19"
echo
echo " Details und Fehlersuche: UPDATE.md"
echo "=============================================="
