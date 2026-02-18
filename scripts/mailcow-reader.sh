#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - JSON Reader
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Liest Metriken aus /var/tmp/mailcow-monitor.json
#               Wird von Zabbix UserParameters aufgerufen - keine Rechte nötig
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
#  v1.0: Python3 für alle Value-Typen (LLD JSON-Arrays etc.)
# ====================================================================

JSON_FILE="/var/tmp/mailcow-monitor.json"
KEY="$1"

if [ -z "$KEY" ]; then
    echo "Usage: $0 <key>"
    exit 1
fi

if [ ! -f "$JSON_FILE" ]; then
    echo "ZBX_NOTSUPPORTED: No data file"
    exit 1
fi

# Prüfe ob Datei älter als 5 Minuten (Collector läuft nicht)
FILE_AGE=$(( $(date +%s) - $(stat -c %Y "$JSON_FILE" 2>/dev/null || echo 0) ))
if [ "$FILE_AGE" -gt 300 ]; then
    echo "ZBX_NOTSUPPORTED: Data stale (${FILE_AGE}s)"
    exit 1
fi

# Python3 zum Lesen - sicher für alle Value-Typen (Strings, Zahlen, JSON-Arrays)
RESULT=$(python3 -c "
import json,sys
with open('${JSON_FILE}') as f:
    d = json.load(f)
v = d.get('${KEY}')
if v is None:
    print('ZBX_NOTSUPPORTED: Key not found')
    sys.exit(1)
if isinstance(v, (dict, list)):
    print(json.dumps(v, separators=(',',':')))
else:
    print(v)
" 2>/dev/null)

if [ $? -ne 0 ] || [ -z "$RESULT" ]; then
    echo "ZBX_NOTSUPPORTED: Read error"
    exit 1
fi

echo "$RESULT"
