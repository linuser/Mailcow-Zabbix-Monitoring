#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - DNS Record Check
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Prüft SPF/DKIM/DMARC für alle aktiven Mail-Domains
#  Usage:      check_dns.sh [spf|dkim|dmarc|detail|domains]
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================

MAILCOW_DIR="/opt/mailcow-dockerized"
CHECK_TYPE="${1:-detail}"

# --- Get all active mail domains from MySQL ---
get_domains() {
    DBPASS=$(grep -oP "DBPASS=\K[a-zA-Z0-9._-]+" "$MAILCOW_DIR/mailcow.conf" 2>/dev/null)
    MYSQL_CONTAINER=$(docker ps --filter "name=mysql" --format "{{.Names}}" 2>/dev/null | grep -i mailcow | head -1)
    
    if [ -z "$MYSQL_CONTAINER" ] || [ -z "$DBPASS" ]; then
        # Fallback: try MariaDB container name
        MYSQL_CONTAINER=$(docker ps --filter "name=maria" --format "{{.Names}}" 2>/dev/null | grep -i mailcow | head -1)
    fi
    
    if [ -z "$MYSQL_CONTAINER" ]; then
        echo ""
        return 1
    fi
    
    docker exec "$MYSQL_CONTAINER" mysql -u mailcow -p"$DBPASS" mailcow -Nse \
        "SELECT domain FROM domain WHERE active=1 AND domain NOT LIKE '%_sogo%'" 2>/dev/null
}

# --- Check SPF for a domain ---
check_spf() {
    local domain="$1"
    timeout 5 dig +short +time=2 +tries=1 TXT "$domain" 2>/dev/null | grep -q "v=spf1"
    echo $?
}

# --- Check DKIM for a domain ---
check_dkim() {
    local domain="$1"
    # Try common selectors
    for selector in dkim mail default s1; do
        if timeout 5 dig +short +time=2 +tries=1 TXT "${selector}._domainkey.${domain}" 2>/dev/null | grep -q "v=DKIM1"; then
            echo 0
            return
        fi
    done
    echo 1
}

# --- Check DMARC for a domain ---
check_dmarc() {
    local domain="$1"
    timeout 5 dig +short +time=2 +tries=1 TXT "_dmarc.${domain}" 2>/dev/null | grep -q "v=DMARC1"
    echo $?
}

# --- Main ---
DOMAINS=$(get_domains)

if [ -z "$DOMAINS" ]; then
    # Fallback: try hostname domain
    HOSTNAME_DOMAIN=$(grep -oP "^MAILCOW_HOSTNAME=\K[a-zA-Z0-9._-]+" "$MAILCOW_DIR/mailcow.conf" 2>/dev/null)
    # Extract base domain (cow.fox1.de -> fox1.de)
    DOMAINS=$(echo "$HOSTNAME_DOMAIN" | sed 's/^[^.]*\.//')
fi

case "$CHECK_TYPE" in
    domains)
        echo "$DOMAINS" | tr '\n' ' '
        ;;
    spf)
        FAIL=0
        for domain in $DOMAINS; do
            result=$(check_spf "$domain")
            [ "$result" != "0" ] && FAIL=$((FAIL + 1))
        done
        # Return 1 (OK) if no failures, 0 if any failures
        [ "$FAIL" -eq 0 ] && echo 1 || echo 0
        ;;
    dkim)
        FAIL=0
        for domain in $DOMAINS; do
            result=$(check_dkim "$domain")
            [ "$result" != "0" ] && FAIL=$((FAIL + 1))
        done
        [ "$FAIL" -eq 0 ] && echo 1 || echo 0
        ;;
    dmarc)
        FAIL=0
        for domain in $DOMAINS; do
            result=$(check_dmarc "$domain")
            [ "$result" != "0" ] && FAIL=$((FAIL + 1))
        done
        [ "$FAIL" -eq 0 ] && echo 1 || echo 0
        ;;
    detail)
        ISSUES=""
        for domain in $DOMAINS; do
            spf=$(check_spf "$domain")
            dkim=$(check_dkim "$domain")
            dmarc=$(check_dmarc "$domain")
            
            MISSING=""
            [ "$spf" != "0" ] && MISSING="${MISSING}SPF "
            [ "$dkim" != "0" ] && MISSING="${MISSING}DKIM "
            [ "$dmarc" != "0" ] && MISSING="${MISSING}DMARC "
            
            if [ -n "$MISSING" ]; then
                ISSUES="${ISSUES}${domain}:${MISSING% },"
            fi
        done
        
        if [ -n "$ISSUES" ]; then
            echo "${ISSUES%,}"
        else
            echo "OK"
        fi
        ;;
    *)
        echo "Usage: $0 [spf|dkim|dmarc|detail|domains]"
        exit 1
        ;;
esac
