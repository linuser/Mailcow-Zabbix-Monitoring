#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - RBL Blacklist Check
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/mailcow-monitoring
#  Description: Prüft ob die Server-IP auf gängigen Blacklists gelistet ist
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
CACHE_FILE="/var/tmp/rbl_check.cache"
CACHE_DETAIL_FILE="/var/tmp/rbl_check_detail.cache"
CACHE_MAX_AGE=1800  # 30 Minuten

# Cache prüfen
if [ -f "$CACHE_FILE" ]; then
    CACHE_AGE=$(($(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0)))
    if [ $CACHE_AGE -lt $CACHE_MAX_AGE ]; then
        if [ "$1" = "detail" ] && [ -f "$CACHE_DETAIL_FILE" ]; then
            cat "$CACHE_DETAIL_FILE"
        else
            cat "$CACHE_FILE"
        fi
        exit 0
    fi
fi

# FIX: Öffentliche IP via DNS ermitteln (kein curl nötig!)
MAIL_IP=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null | grep -oP "^[0-9.]+" | head -1)
[ -z "$MAIL_IP" ] && MAIL_IP=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null)
[ -z "$MAIL_IP" ] && MAIL_IP=$(curl -4 -s --max-time 5 icanhazip.com 2>/dev/null)

# Fallback: Google DNS
if [ -z "$MAIL_IP" ]; then
    MAIL_IP=$(dig +short txt o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '"' | head -1)
fi

# Prüfe ob IP gültig und öffentlich
if [ -z "$MAIL_IP" ] || echo "$MAIL_IP" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
    echo "0" | tee "$CACHE_FILE"
    echo "error_no_public_ip" > "$CACHE_DETAIL_FILE"
    exit 0
fi

# Nur die wichtigsten RBLs
RBLS=(
    "zen.spamhaus.org"
    "bl.spamcop.net"
    "b.barracudacentral.org"
)

LISTED=0
DETAILS=""
REVERSED=$(echo $MAIL_IP | awk -F. '{print $4"."$3"."$2"."$1}')

# Prüfe RBLs
for RBL in "${RBLS[@]}"; do
    RESULT=$(dig +short +time=5 "$REVERSED.$RBL" 2>/dev/null)
    if [ -n "$RESULT" ]; then
        LISTED=$((LISTED + 1))
        DETAILS="${DETAILS}${RBL} "
    fi
done

# Cache schreiben
echo $LISTED | tee "$CACHE_FILE"

if [ $LISTED -eq 0 ]; then
    echo "clean" > "$CACHE_DETAIL_FILE"
else
    echo "${DETAILS% }" > "$CACHE_DETAIL_FILE"
fi

# Detail-Modus
if [ "$1" = "detail" ]; then
    cat "$CACHE_DETAIL_FILE"
fi
