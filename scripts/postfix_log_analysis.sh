#!/bin/bash
# ====================================================================
#  Mailcow Zabbix Monitoring - Postfix Log Analysis
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Analysiert Postfix Logs nach SASL, Relay, TLS, Spam, Virus und Postscreen Events
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
CONTAINER=$(docker ps --filter "name=postfix" --format "{{.Names}}" 2>/dev/null | grep -i mailcow | head -1)
if [ -z "$CONTAINER" ]; then
    echo 0
    exit 0
fi
CACHE_FILE="/var/tmp/postfix_log_analysis.cache"
CACHE_MAX_AGE=60  # 60 Sekunden Cache

# Cache aktualisieren wenn nötig
update_cache() {
    LOGS=$(docker exec "$CONTAINER" tail -1000 /var/log/mail.log 2>/dev/null)

    if [ -z "$LOGS" ]; then
        echo '{"sasl_auth_failed":0}' > "$CACHE_FILE"
        return
    fi

    # Alle Counts in einem Durchgang
    SASL_AUTH_FAILED=$(echo "$LOGS" | grep -c "SASL.*authentication failed" || echo 0)
    RELAY_DENIED=$(echo "$LOGS" | grep -c "Relay access denied" || echo 0)
    USER_UNKNOWN=$(echo "$LOGS" | grep -c "User unknown in" || echo 0)
    RBL_REJECT=$(echo "$LOGS" | grep -c "blocked using" || echo 0)
    CONNECTION_TIMEOUT=$(echo "$LOGS" | grep -c "Connection timed out" || echo 0)
    TLS_FAILED=$(echo "$LOGS" | grep -cE "TLS.*handshake failed|SSL.*error" || echo 0)
    QUOTA_EXCEEDED=$(echo "$LOGS" | grep -cE "mailbox.*full|quota.*exceeded|Disk quota" || echo 0)
    SPAM_REJECTED=$(echo "$LOGS" | grep -c "milter-reject.*Spam message rejected" || echo 0)
    VIRUS_FOUND=$(echo "$LOGS" | grep -c "Infected.*FOUND" || echo 0)
    WARNINGS=$(echo "$LOGS" | grep -c "warning:" || echo 0)
    ERRORS=$(echo "$LOGS" | grep -cE "error:|fatal:" || echo 0)

    # Postscreen Stats (nur wenn aktiv)
    POSTSCREEN_PASS_NEW=$(echo "$LOGS" | grep -c "postscreen.*PASS NEW" || echo 0)
    POSTSCREEN_PASS_OLD=$(echo "$LOGS" | grep -c "postscreen.*PASS OLD" || echo 0)
    POSTSCREEN_REJECT=$(echo "$LOGS" | grep -c "postscreen.*NOQUEUE.*reject" || echo 0)
    POSTSCREEN_DNSBL=$(echo "$LOGS" | grep -c "postscreen.*DNSBL" || echo 0)
    POSTSCREEN_PREGREET=$(echo "$LOGS" | grep -c "postscreen.*PREGREET" || echo 0)
    POSTSCREEN_HANGUP=$(echo "$LOGS" | grep -c "postscreen.*HANGUP" || echo 0)
    POSTSCREEN_WHITELISTED=$(echo "$LOGS" | grep -c "postscreen.*WHITELISTED" || echo 0)
    POSTSCREEN_CONNECT=$(echo "$LOGS" | grep -c "postscreen.*CONNECT" || echo 0)
    # Aktiv = mindestens 1 postscreen-Logeintrag
    if [ "$POSTSCREEN_CONNECT" -gt 0 ] || [ "$POSTSCREEN_PASS_NEW" -gt 0 ]; then
        POSTSCREEN_ACTIVE=1
    else
        POSTSCREEN_ACTIVE=0
    fi

    # JSON schreiben
    cat > "$CACHE_FILE" << EOFJSON
{
  "sasl_auth_failed": $SASL_AUTH_FAILED,
  "relay_denied": $RELAY_DENIED,
  "user_unknown": $USER_UNKNOWN,
  "rbl_reject": $RBL_REJECT,
  "connection_timeout": $CONNECTION_TIMEOUT,
  "tls_failed": $TLS_FAILED,
  "quota_exceeded": $QUOTA_EXCEEDED,
  "spam_rejected": $SPAM_REJECTED,
  "virus_found": $VIRUS_FOUND,
  "warnings": $WARNINGS,
  "errors": $ERRORS,
  "postscreen_active": $POSTSCREEN_ACTIVE,
  "postscreen_pass_new": $POSTSCREEN_PASS_NEW,
  "postscreen_pass_old": $POSTSCREEN_PASS_OLD,
  "postscreen_reject": $POSTSCREEN_REJECT,
  "postscreen_dnsbl": $POSTSCREEN_DNSBL,
  "postscreen_pregreet": $POSTSCREEN_PREGREET,
  "postscreen_hangup": $POSTSCREEN_HANGUP,
  "postscreen_whitelisted": $POSTSCREEN_WHITELISTED,
  "postscreen_connect": $POSTSCREEN_CONNECT
}
EOFJSON
}

# Cache prüfen
if [ ! -f "$CACHE_FILE" ] || [ $(($(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0))) -gt $CACHE_MAX_AGE ]; then
    update_cache
fi

# Aus Cache lesen
if command -v jq &>/dev/null; then
    cat "$CACHE_FILE" 2>/dev/null | jq -r ".${1} // 0" 2>/dev/null || echo 0
else
    grep -oP "\"$1\":\s*\K\d+" "$CACHE_FILE" 2>/dev/null || echo 0
fi
