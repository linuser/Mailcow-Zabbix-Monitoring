#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Sync Jobs Check
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Überwacht Mailcow IMAP Sync Jobs (eingebaute Migration)
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
MAILCOW_DIR=""
if [ -d "/opt/mailcow-dockerized" ]; then
    MAILCOW_DIR="/opt/mailcow-dockerized"
elif [ -d "/opt/containers/mailcow" ]; then
    MAILCOW_DIR="/opt/containers/mailcow"
else
    echo "0"
    exit 0
fi

# DB Password auslesen
DBPASS=$(grep "^DBPASS=" "$MAILCOW_DIR/mailcow.conf" 2>/dev/null | cut -d= -f2)

if [ -z "$DBPASS" ]; then
    echo "0"
    exit 0
fi

# MySQL Container
MYSQL_CONTAINER=$(docker ps --filter "name=mysql" --format "{{.Names}}" 2>/dev/null | head -1)

if [ -z "$MYSQL_CONTAINER" ]; then
    echo "0"
    exit 0
fi

case "$1" in
    active)
        # Anzahl aktiver Sync Jobs
        docker exec "$MYSQL_CONTAINER" mysql -u mailcow -p"$DBPASS" mailcow -Nse "SELECT COUNT(*) FROM imapsync WHERE active=1;" 2>/dev/null || echo 0
        ;;
    running)
        # Aktuell laufende Sync Jobs
        docker exec "$MYSQL_CONTAINER" mysql -u mailcow -p"$DBPASS" mailcow -Nse "SELECT COUNT(*) FROM imapsync WHERE is_running=1;" 2>/dev/null || echo 0
        ;;
    failed)
        # Failed Syncs (letzte 24h)
        docker exec "$MYSQL_CONTAINER" mysql -u mailcow -p"$DBPASS" mailcow -Nse "SELECT COUNT(*) FROM imapsync WHERE (returned_text LIKE '%error%' OR returned_text LIKE '%fail%' OR returned_text LIKE '%died%') AND last_run > DATE_SUB(NOW(), INTERVAL 24 HOUR);" 2>/dev/null || echo 0
        ;;
    never_run)
        # Jobs die noch nie liefen aber aktiv sind
        docker exec "$MYSQL_CONTAINER" mysql -u mailcow -p"$DBPASS" mailcow -Nse "SELECT COUNT(*) FROM imapsync WHERE active=1 AND last_run IS NULL;" 2>/dev/null || echo 0
        ;;
    oldest_run)
        # Ältester Last-Run in Stunden (von aktiven Jobs)
        docker exec "$MYSQL_CONTAINER" mysql -u mailcow -p"$DBPASS" mailcow -Nse "SELECT COALESCE(TIMESTAMPDIFF(HOUR, MAX(last_run), NOW()), 0) FROM imapsync WHERE active=1 AND last_run IS NOT NULL;" 2>/dev/null || echo 0
        ;;
    stuck)
        # Jobs die >24h am Laufen sind (stuck)
        docker exec "$MYSQL_CONTAINER" mysql -u mailcow -p"$DBPASS" mailcow -Nse "SELECT COUNT(*) FROM imapsync WHERE is_running=1 AND last_run < DATE_SUB(NOW(), INTERVAL 24 HOUR);" 2>/dev/null || echo 0
        ;;
    *)
        echo 0
        ;;
esac
