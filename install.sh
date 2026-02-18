#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Installer
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/mailcow-monitoring
#  Description: Installiert Collector, Reader, Configs und systemd Units
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Mailcow Monitoring v1.0 - Install       ║${NC}"
echo -e "${BLUE}║  Secure Service Architecture             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Root check ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Bitte als root ausführen${NC}"
    exit 1
fi

# --- Mailcow finden ---
MAILCOW_DIR="/opt/mailcow-dockerized"
if [ ! -f "$MAILCOW_DIR/mailcow.conf" ]; then
    echo -e "${RED}mailcow.conf nicht gefunden in $MAILCOW_DIR${NC}"
    exit 1
fi

DOMAIN=$(grep -oP "^MAILCOW_HOSTNAME=\K[a-zA-Z0-9._-]+" "$MAILCOW_DIR/mailcow.conf" 2>/dev/null)
echo -e "${GREEN}✓ Domain: $DOMAIN${NC}"

# --- Backup-Pfad ---
BACKUP_PATH="/opt/backup"
OLD_BACKUP=$(grep -rh "BACKUP_PATH_PLACEHOLDER\|find -L " /usr/local/bin/check_backup_*.sh 2>/dev/null | grep -oP '(?<=-L )[^ ]+' | head -1)
[ -n "$OLD_BACKUP" ] && BACKUP_PATH="$OLD_BACKUP"
if [ -d "/opt/backup" ]; then BACKUP_PATH="/opt/backup"
elif [ -d "/backup" ]; then BACKUP_PATH="/backup"
fi
echo -e "${GREEN}✓ Backup-Pfad: $BACKUP_PATH${NC}"

# ====================================================================
echo ""
echo -e "${BLUE}=== [1/5] Scripts installieren ===${NC}"
# ====================================================================

# Collector + Reader
for SCRIPT in mailcow-reader.sh; do
    cp "$SCRIPT_DIR/scripts/$SCRIPT" /usr/local/bin/
    chmod +x /usr/local/bin/$SCRIPT
    echo -e "  ${GREEN}✓ $SCRIPT${NC}"
done

# Python Collector
cp "$SCRIPT_DIR/scripts/mailcow-collector.py" /usr/local/bin/
chmod +x /usr/local/bin/mailcow-collector.py
echo -e "  ${GREEN}✓ mailcow-collector.py (Python)${NC}"

# Alten Bash-Collector entfernen
rm -f /usr/local/bin/mailcow-collector.sh
echo -e "  ${GREEN}✓ mailcow-collector.sh (Bash) entfernt${NC}"

# Alte Scripts aus v4.0-v4.3 aufräumen
for OLD_SCRIPT in check_postfix_running.sh check_backup_age.sh check_backup_size.sh \
                  check_backup_count.sh check_backup_exists.sh check_backup_zero.sh \
                  check_dovecot_running.sh check_rspamd_running.sh check_fail2ban.sh \
                  check_disk_usage.sh check_vmail.sh mailcow_version.sh; do
    if [ -f "/usr/local/bin/$OLD_SCRIPT" ]; then
        rm -f "/usr/local/bin/$OLD_SCRIPT"
        echo -e "  ${YELLOW}✓ $OLD_SCRIPT (veraltet) entfernt${NC}"
    fi
done

# Alten Slow-Cache löschen (Format hat sich geändert)
rm -f /var/tmp/mailcow-monitor-slow.json
echo -e "  ${GREEN}✓ Slow-Cache zurückgesetzt${NC}"

# Bestehende Scripts aktualisieren
for SCRIPT in check_rbl.sh check_dns.sh check_tls.sh check_ptr.sh check_open_relay.sh \
              check_security_audit.sh \
              dovecot_check.sh sync_jobs_check.sh \
              postfix_stats_docker.sh postfix_log_analysis.sh; do
    if [ -f "$SCRIPT_DIR/scripts/$SCRIPT" ]; then
        cp "$SCRIPT_DIR/scripts/$SCRIPT" /usr/local/bin/
        chmod +x /usr/local/bin/$SCRIPT
        echo -e "  ${GREEN}✓ $SCRIPT${NC}"
    fi
done

# Python Collector erkennt Backup-Pfad automatisch

# Git safe.directory
git config --system --add safe.directory "$MAILCOW_DIR" 2>/dev/null

# pflogsumm für Mailflow-Statistiken
if ! which pflogsumm >/dev/null 2>&1; then
    echo -e "  ${YELLOW}pflogsumm nicht gefunden, installiere...${NC}"
    apt-get install -y pflogsumm >/dev/null 2>&1 && \
        echo -e "  ${GREEN}✓ pflogsumm installiert${NC}" || \
        echo -e "  ${YELLOW}⚠ pflogsumm konnte nicht installiert werden (Mailflow-Stats nicht verfügbar)${NC}"
else
    echo -e "  ${GREEN}✓ pflogsumm vorhanden${NC}"
fi

# ====================================================================
echo ""
echo -e "${BLUE}=== [2/5] Systemd Service installieren ===${NC}"
# ====================================================================

cp "$SCRIPT_DIR/mailcow-monitor.service" /etc/systemd/system/
cp "$SCRIPT_DIR/mailcow-monitor.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable mailcow-monitor.timer
systemctl start mailcow-monitor.timer
echo -e "${GREEN}✓ mailcow-monitor.timer aktiviert${NC}"

# Ersten Lauf manuell starten
echo -e "${YELLOW}  Erster Collector-Lauf (kann bis zu 60s dauern)...${NC}"
systemctl start mailcow-monitor.service
echo -e "${GREEN}✓ Erster Lauf abgeschlossen${NC}"

# ====================================================================
echo ""
echo -e "${BLUE}=== [3/5] Zabbix Agent konfigurieren ===${NC}"
# ====================================================================

# Alte Einzel-Configs entfernen
rm -f /etc/zabbix/zabbix_agent2.d/mailcow-*.conf
rm -f /etc/zabbix/zabbix_agent2.d/mailcow.conf.bak

# Neue Single-Config
cp "$SCRIPT_DIR/mailcow-zabbix.conf" /etc/zabbix/zabbix_agent2.d/mailcow.conf
echo -e "${GREEN}✓ 246 UserParameters in einer Config${NC}"

# UnsafeUserParameters NICHT mehr nötig
if grep -q "^UnsafeUserParameters=1" /etc/zabbix/zabbix_agent2.conf 2>/dev/null; then
    sed -i 's/^UnsafeUserParameters=1/UnsafeUserParameters=0/' /etc/zabbix/zabbix_agent2.conf
    echo -e "${GREEN}✓ UnsafeUserParameters=0 gesetzt${NC}"
fi

# ====================================================================
echo ""
echo -e "${BLUE}=== [4/5] Sicherheit härten ===${NC}"
# ====================================================================

# Docker-Gruppe: nicht anfassen (wird ggf. von anderen Templates benötigt)

# Alte sudoers entfernen
if [ -f /etc/sudoers.d/zabbix-mailcow ]; then
    rm -f /etc/sudoers.d/zabbix-mailcow
    echo -e "${GREEN}✓ Sudo-Regeln entfernt${NC}"
else
    echo -e "${GREEN}✓ Keine Sudo-Regeln vorhanden${NC}"
fi

# JSON-File für zabbix lesbar
chmod 644 /var/tmp/mailcow-monitor.json 2>/dev/null

# ====================================================================
echo ""
echo -e "${BLUE}=== [5/5] Agent neustarten + Test ===${NC}"
# ====================================================================

systemctl restart zabbix-agent2
sleep 3

# Quick test
ERRORS=0
PASS=0
for key in postfix.process.running mailcow.rspamd.scanned mailcow.disk.root.used \
           mailcow.dovecot.running mailcow.version.current \
           mailcow.mailbox.total mailcow.collector.running; do
    RESULT=$(zabbix_get -s 127.0.0.1 -k "$key" 2>/dev/null)
    if [ -n "$RESULT" ] && ! echo "$RESULT" | grep -q "NOTSUPPORTED\|error"; then
        echo -e "  ${GREEN}✓ $key = $RESULT${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗ $key = $RESULT${NC}"
        ERRORS=$((ERRORS + 1))
    fi
done

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        INSTALLATION ABGESCHLOSSEN         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}✓ Collector: systemd timer (alle 60s als root)${NC}"
echo -e "  ${GREEN}✓ Reader: /var/tmp/mailcow-monitor.json${NC}"
echo -e "  ${GREEN}✓ Zabbix: liest nur JSON (keine Rechte nötig)${NC}"
echo ""
echo -e "  Sicherheit:"
echo -e "  ${GREEN}✓ Kein UnsafeUserParameters${NC}"

echo -e "  ${GREEN}✓ Kein sudo für Zabbix${NC}"
echo ""
echo -e "  Test: $PASS bestanden, $ERRORS fehlgeschlagen"
echo ""
echo -e "  Befehle:"
echo -e "    systemctl status mailcow-monitor.timer"
echo -e "    cat /var/tmp/mailcow-monitor.json | python3 -m json.tool | head -20"
echo -e "    zabbix_get -s 127.0.0.1 -k mailcow.rspamd.scanned"
echo ""
echo -e "  ${YELLOW}⚠ Zabbix Template:${NC}"
echo -e "    Falls noch alte Einzel-Templates (Postfix, Dovecot, Security...)"
echo -e "    verlinkt sind: Unlink + 'Mailcow Complete Monitoring v1.0' importieren"
echo -e "    Template: templates/mailcow-complete-monitoring.yaml"
