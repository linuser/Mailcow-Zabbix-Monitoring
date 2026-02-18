#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Uninstaller
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/mailcow-monitoring
#  Description: Entfernt Collector, Reader, Configs und systemd Units
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo ""
echo "============================================="
echo " Mailcow Monitoring v1.0 - Deinstallation"
echo "============================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ Bitte als root ausführen!${NC}"
    exit 1
fi

read -p "Mailcow Monitoring komplett entfernen? (j/n): " -n 1 -r
echo ""
[[ ! $REPLY =~ ^[JjYy]$ ]] && { echo "Abgebrochen."; exit 0; }

# 1. systemd Timer/Service stoppen
echo -e "${YELLOW}[1/6] systemd Units stoppen...${NC}"
systemctl stop mailcow-monitor.timer 2>/dev/null || true
systemctl disable mailcow-monitor.timer 2>/dev/null || true
systemctl stop mailcow-monitor.service 2>/dev/null || true
rm -f /etc/systemd/system/mailcow-monitor.timer
rm -f /etc/systemd/system/mailcow-monitor.service
systemctl daemon-reload
echo -e "${GREEN}✓ systemd Units entfernt${NC}"

# 2. Collector & Reader & Helper
echo -e "${YELLOW}[2/6] Scripts entfernen...${NC}"
rm -f /usr/local/bin/mailcow-collector.py
rm -f /usr/local/bin/mailcow-reader.sh
for S in check_rbl.sh check_dns.sh check_tls.sh check_ptr.sh check_open_relay.sh \
         check_security_audit.sh \
         dovecot_check.sh sync_jobs_check.sh postfix_stats_docker.sh \
         postfix_log_analysis.sh check_postfix_running.sh check_mailcow_ui.sh \
         check_agent_uptime.sh check_backup_age.sh check_backup_size.sh \
         check_backup_zero.sh rspamd_stats.sh; do
    rm -f "/usr/local/bin/$S"
done
echo -e "${GREEN}✓ Scripts entfernt${NC}"

# 3. Zabbix Agent Config
echo -e "${YELLOW}[3/6] Zabbix Config entfernen...${NC}"
rm -f /etc/zabbix/zabbix_agent2.d/mailcow*.conf
echo -e "${GREEN}✓ UserParameter Configs entfernt${NC}"

# 4. Sudoers
echo -e "${YELLOW}[4/6] Sudoers entfernen...${NC}"
rm -f /etc/sudoers.d/zabbix-mailcow
echo -e "${GREEN}✓ Sudoers entfernt${NC}"

# 5. Cache/JSON
echo -e "${YELLOW}[5/6] Cache entfernen...${NC}"
rm -f /var/tmp/mailcow-monitor.json
rm -f /var/tmp/mailcow-monitor.json.tmp
rm -f /var/tmp/mailcow-monitor-slow.json
rm -f /var/tmp/mailcow-monitor-mailflow.json
rm -f /var/tmp/postfix_log_analysis.cache /var/tmp/dovecot_check.cache
rm -f /var/tmp/rbl_check.cache /var/tmp/rspamd_stats.cache /var/tmp/rbl_check_detail.cache
echo -e "${GREEN}✓ Cache entfernt${NC}"

# 6. Zabbix Agent neustarten
echo -e "${YELLOW}[6/6] Zabbix Agent neustarten...${NC}"
systemctl restart zabbix-agent2 2>/dev/null && \
    echo -e "${GREEN}✓ Zabbix Agent 2 neugestartet${NC}" || \
    echo -e "${YELLOW}! Zabbix Agent 2 konnte nicht neugestartet werden${NC}"

echo ""
echo "============================================="
echo -e "${GREEN} Deinstallation abgeschlossen.${NC}"
echo "============================================="
echo ""
echo "  Backups: /root/mailcow-monitoring-backup-*"
echo "  Zabbix Template manuell entfernen:"
echo "    Data collection → Templates → Mailcow Complete Monitoring v1.0 → Unlink/Delete"
echo ""
