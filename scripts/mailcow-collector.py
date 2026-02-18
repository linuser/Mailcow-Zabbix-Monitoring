#!/usr/bin/env python3
# ====================================================================
#  Mailcow Zabbix Monitoring - Collector
#  Version:    1.0
#  Vendor:     Alexander Fox | PlaNet Fox
#  Project:    https://github.com/linuser/Mailcow-Zabbix-Monitoring
#  Description: Sammelt 246 Metriken aus 22 Modulen (Docker, MySQL, DNS,
#               TLS, Rspamd, ClamAV, Postscreen, Bayes u.v.m.) in JSON
#  License:    GPLv3 (see LICENSE)
#  Created with Open Source and ♥
# ====================================================================
"""
Mailcow Monitoring Collector v1.0
Sammelt alle Metriken in eine JSON-Datei.
Läuft als systemd service (root) — kein Docker/Sudo für Zabbix nötig.
"""

import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ====================================================================
# KONFIGURATION
# ====================================================================

MAILCOW_DIR = "/opt/mailcow-dockerized"
OUTPUT = "/var/tmp/mailcow-monitor.json"
OUTPUT_TMP = OUTPUT + ".tmp"
SLOW_CACHE = "/var/tmp/mailcow-monitor-slow.json"
SLOW_MAX_AGE = 3600  # Sekunden
MAILFLOW_CACHE = "/var/tmp/mailcow-monitor-mailflow.json"
MAILFLOW_MAX_AGE = 300  # 5 Minuten

# ====================================================================
# HILFSFUNKTIONEN
# ====================================================================

def now():
    return int(time.time())


def run(cmd, timeout=30, default=""):
    """Shell-Befehl ausführen, bei Fehler default zurückgeben."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else default
    except (subprocess.TimeoutExpired, Exception):
        return default


def run_cmd(args, timeout=30, default=""):
    """Befehl als Liste ausführen (kein shell=True, sicherer & schneller)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else default
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return default


def run_int(cmd, timeout=30, default=0):
    """Shell-Befehl ausführen, Ergebnis als int."""
    val = run(cmd, timeout, str(default))
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def docker_exec(container, cmd, timeout=15, default=""):
    """Befehl in Docker-Container ausführen."""
    if not container:
        return default
    return run(f'docker exec "{container}" {cmd}', timeout, default)


def docker_exec_int(container, cmd, timeout=15, default=0):
    """Befehl in Docker-Container ausführen, Ergebnis als int."""
    val = docker_exec(container, cmd, timeout, str(default))
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def mysql_exec(container, dbpass, sql, timeout=15, default=""):
    """MySQL-Query via docker exec mit MYSQL_PWD (Passwort nicht auf Kommandozeile)."""
    if not container or not dbpass:
        return default
    return run_cmd(
        ["docker", "exec", "-e", f"MYSQL_PWD={dbpass}", container,
         "mysql", "-u", "mailcow", "mailcow", "-Nse", sql],
        timeout=timeout, default=default)


def read_config():
    """Mailcow-Konfiguration lesen."""
    conf_path = os.path.join(MAILCOW_DIR, "mailcow.conf")
    config = {"hostname": "", "dbpass": "", "timezone": "unknown"}
    try:
        with open(conf_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("MAILCOW_HOSTNAME="):
                    config["hostname"] = line.split("=", 1)[1].strip()
                elif line.startswith("DBPASS="):
                    config["dbpass"] = line.split("=", 1)[1].strip()
                elif line.startswith("TZ="):
                    config["timezone"] = line.split("=", 1)[1].strip()
    except FileNotFoundError:
        pass
    return config


def find_container(name_filter):
    """Docker-Container finden (nach Name-Fragment)."""
    out = run_cmd(
        ["docker", "ps", "--filter", f"name={name_filter}", "--format", "{{.Names}}"],
        timeout=10)
    for line in out.splitlines():
        if "mailcow" in line.lower():
            return line.strip()
    return ""


def find_all_containers():
    """Alle Mailcow-Container einmal suchen (#2: zentral statt pro Modul)."""
    containers = {}
    for name in ["postfix", "dovecot", "rspamd", "netfilter", "clamd", "watchdog", "memcached"]:
        containers[name] = find_container(name)
    containers["mysql"] = find_container("mysql") or find_container("maria")
    return containers


# ====================================================================
# COLLECTOR-MODULE
# ====================================================================

def collect_postfix(container):
    """Postfix-Metriken sammeln."""
    data = {
        "postfix.process.running": 0,
        "postfix.pfmailq": 0,
        "postfix.connections": 0,
        "mailcow.queue.disk": 0,
        "mailcow.container.version.postfix": "unknown",
    }
    if not container:
        return data

    # Prozess-Check
    pid = docker_exec(container, "cat /var/spool/postfix/pid/master.pid 2>/dev/null").strip()
    if pid:
        check = docker_exec(container, f"test -d /proc/{pid} && echo 1 || echo 0")
        data["postfix.process.running"] = 1 if check == "1" else 0

    # Queue
    mq = docker_exec(container, 'mailq 2>/dev/null')
    data["postfix.pfmailq"] = len([l for l in mq.splitlines() if l and l[0].isalnum() and l[0].isupper()])

    # Connections
    conn_count = docker_exec_int(container,
        "sh -c \"ss -tn state established '( dport = :25 or sport = :25 )' 2>/dev/null | tail -n +2 | wc -l\"")
    data["postfix.connections"] = max(0, conn_count)

    # Queue disk
    df_out = docker_exec(container, "df /var/spool/postfix 2>/dev/null")
    for line in df_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            data["mailcow.queue.disk"] = int(parts[4].replace("%", ""))
            break

    # Version
    ver = docker_exec(container, "postconf mail_version 2>/dev/null")
    if ver and "=" in ver:
        data["mailcow.container.version.postfix"] = ver.split()[-1]

    return data


def collect_postfix_logs():
    """Postfix Log-Statistiken sammeln."""
    data = {
        "postfix.fetch_log_data": run("/usr/local/bin/postfix_stats_docker.sh 2>/dev/null"),
    }
    log_keys = [
        ("postfix.log.sasl.auth.failed", "sasl_auth_failed"),
        ("postfix.log.relay.denied", "relay_denied"),
        ("postfix.log.spam.rejected", "spam_rejected"),
        ("postfix.log.rbl.reject", "rbl_reject"),
        ("postfix.log.user.unknown", "user_unknown"),
        ("postfix.log.connection.timeout", "connection_timeout"),
        ("postfix.log.tls.failed", "tls_failed"),
        ("postfix.log.quota.exceeded", "quota_exceeded"),
        ("postfix.log.virus.found", "virus_found"),
        ("postfix.log.warnings", "warnings"),
        ("postfix.log.errors", "errors"),
        # Postscreen (#6 Roadmap)
        ("postfix.postscreen.active", "postscreen_active"),
        ("postfix.postscreen.pass.new", "postscreen_pass_new"),
        ("postfix.postscreen.pass.old", "postscreen_pass_old"),
        ("postfix.postscreen.reject", "postscreen_reject"),
        ("postfix.postscreen.dnsbl", "postscreen_dnsbl"),
        ("postfix.postscreen.pregreet", "postscreen_pregreet"),
        ("postfix.postscreen.hangup", "postscreen_hangup"),
        ("postfix.postscreen.whitelisted", "postscreen_whitelisted"),
        ("postfix.postscreen.connect", "postscreen_connect"),
    ]
    for json_key, arg in log_keys:
        data[json_key] = run_int(f"/usr/local/bin/postfix_log_analysis.sh {arg} 2>/dev/null")
    return data


def collect_dovecot(container):
    """Dovecot-Metriken sammeln."""
    data = {
        "mailcow.dovecot.running": 0,
        "mailcow.dovecot.connections": 0,
        "mailcow.dovecot.version": "unknown",
        "mailcow.dovecot.imap.errors": 0,
        "mailcow.dovecot.imap.login.failed": 0,
        "mailcow.dovecot.pop3.login.failed": 0,
        "mailcow.dovecot.imap.disconnected": 0,
        "mailcow.dovecot.quota.warnings": 0,
        "mailcow.dovecot.sync.errors": 0,
        "mailcow.container.version.dovecot": "unknown",
    }
    if not container:
        return data

    checks = [
        ("mailcow.dovecot.running", "process"),
        ("mailcow.dovecot.connections", "connections"),
        ("mailcow.dovecot.imap.errors", "imap_errors"),
        ("mailcow.dovecot.imap.login.failed", "imap_login_failed"),
        ("mailcow.dovecot.pop3.login.failed", "pop3_login_failed"),
        ("mailcow.dovecot.imap.disconnected", "imap_disconnected"),
        ("mailcow.dovecot.quota.warnings", "quota_warnings"),
        ("mailcow.dovecot.sync.errors", "sync_errors"),
    ]
    for json_key, arg in checks:
        data[json_key] = run_int(f"/usr/local/bin/dovecot_check.sh {arg} 2>/dev/null")

    version = run(f"/usr/local/bin/dovecot_check.sh version 2>/dev/null", default="unknown")
    data["mailcow.dovecot.version"] = version
    data["mailcow.container.version.dovecot"] = version
    return data


def collect_rspamd(container):
    """Rspamd-Metriken sammeln (inkl. Detail-Actions + Bayes-Training)."""
    data = {
        "mailcow.rspamd.running": 0,
        "mailcow.rspamd.scanned": 0,
        "mailcow.rspamd.spam": 0,
        "mailcow.rspamd.ham": 0,
        "mailcow.rspamd.greylist": 0,
        "mailcow.rspamd.soft_reject": 0,
        "mailcow.rspamd.rewrite": 0,
        "mailcow.rspamd.learned": 0,
        "mailcow.rspamd.spam.rate": 0,
        "mailcow.rspamd.uptime": 0,
        "mailcow.rspamd.version": "unknown",
        "mailcow.rspamd.add.header": 0,
        "mailcow.rspamd.reject.total": 0,
        "mailcow.rspamd.action.detail": "-",
        # Bayes Training (#5 Roadmap)
        "mailcow.rspamd.bayes.ham.learned": 0,
        "mailcow.rspamd.bayes.spam.learned": 0,
        "mailcow.rspamd.bayes.total.learned": 0,
        "mailcow.rspamd.bayes.ratio": 0,
        "mailcow.rspamd.bayes.status": "unknown",
    }
    if not container:
        return data

    data["mailcow.rspamd.running"] = 1

    raw = docker_exec(container, "wget -q -O - --timeout=5 http://localhost:11334/stat 2>/dev/null")
    if not raw:
        return data

    try:
        stat = json.loads(raw)
    except json.JSONDecodeError:
        return data

    actions = stat.get("actions", {})
    scanned = stat.get("scanned", 0)

    data["mailcow.rspamd.scanned"] = scanned
    data["mailcow.rspamd.spam"] = actions.get("reject", 0)
    data["mailcow.rspamd.ham"] = actions.get("no action", 0)
    data["mailcow.rspamd.greylist"] = actions.get("greylist", 0)
    data["mailcow.rspamd.soft_reject"] = actions.get("soft reject", 0)
    data["mailcow.rspamd.rewrite"] = actions.get("rewrite subject", 0)
    data["mailcow.rspamd.learned"] = stat.get("learned", 0)
    data["mailcow.rspamd.uptime"] = stat.get("uptime", 0)
    data["mailcow.rspamd.version"] = stat.get("version", "unknown")

    if scanned > 0:
        spam_total = actions.get("reject", 0) + actions.get("add header", 0)
        data["mailcow.rspamd.spam.rate"] = round(spam_total * 100 / scanned, 1)

    # Detail actions
    data["mailcow.rspamd.add.header"] = actions.get("add header", 0)
    data["mailcow.rspamd.reject.total"] = actions.get("reject", 0)

    parts = []
    for act_name, act_count in actions.items():
        if act_count > 0:
            parts.append(f'{act_name.replace(" ", "_")}:{act_count}')
    data["mailcow.rspamd.action.detail"] = ",".join(parts) if parts else "-"

    # --- Bayes Training Stats via rspamc stat ---
    bayes_raw = docker_exec(container, "rspamc stat 2>/dev/null", timeout=10)
    if bayes_raw:
        ham_learned = 0
        spam_learned = 0
        current_statfile = ""
        for line in bayes_raw.splitlines():
            line_s = line.strip()
            if "BAYES_HAM" in line_s:
                current_statfile = "ham"
            elif "BAYES_SPAM" in line_s:
                current_statfile = "spam"
            elif line_s.startswith("learned:") or line_s.startswith("Learned:"):
                try:
                    val = int(line_s.split(":")[1].strip())
                    if current_statfile == "ham":
                        ham_learned = val
                    elif current_statfile == "spam":
                        spam_learned = val
                except (ValueError, IndexError):
                    pass

        total = ham_learned + spam_learned
        data["mailcow.rspamd.bayes.ham.learned"] = ham_learned
        data["mailcow.rspamd.bayes.spam.learned"] = spam_learned
        data["mailcow.rspamd.bayes.total.learned"] = total

        if total > 0:
            data["mailcow.rspamd.bayes.ratio"] = round(ham_learned * 100 / total, 1)

        # Status: untrained / low / good / excellent
        if total == 0:
            data["mailcow.rspamd.bayes.status"] = "untrained"
        elif total < 200:
            data["mailcow.rspamd.bayes.status"] = "low"
        elif ham_learned < 50 or spam_learned < 50:
            data["mailcow.rspamd.bayes.status"] = "unbalanced"
        elif total < 1000:
            data["mailcow.rspamd.bayes.status"] = "good"
        else:
            data["mailcow.rspamd.bayes.status"] = "excellent"

    return data


def collect_fail2ban(container):
    """Fail2ban/Netfilter-Metriken sammeln."""
    data = {
        "mailcow.security.fail2ban.banned": 0,
        "mailcow.security.fail2ban.postfix": 0,
        "mailcow.security.fail2ban.dovecot": 0,
        "mailcow.security.fail2ban.sogo": 0,
    }
    if not container:
        return data

    # Gesamt-Bans aus iptables
    ipt = docker_exec(container, "iptables -L MAILCOW -n 2>/dev/null")
    data["mailcow.security.fail2ban.banned"] = len([l for l in ipt.splitlines() if "DROP" in l])

    # Pro-Service Bans
    for service, key in [("postfix-sasl", "postfix"), ("dovecot", "dovecot"), ("sogo-auth", "sogo")]:
        out = docker_exec(container, f"fail2ban-client status {service} 2>/dev/null")
        for line in out.splitlines():
            if "Currently banned" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    data[f"mailcow.security.fail2ban.{key}"] = int(match.group(1))
                break

    return data


def collect_disk(dovecot_container):
    """Disk-Metriken sammeln."""
    data = {}

    # Lokale Partitionen
    for mount, prefix in [("/", "root"), ("/var/lib/docker", "docker"), ("/var/log", "log")]:
        data[f"mailcow.disk.{prefix}.total"] = 0
        data[f"mailcow.disk.{prefix}.free"] = 0
        data[f"mailcow.disk.{prefix}.used"] = 0
        df_out = run(f"df {mount} 2>/dev/null")
        lines = df_out.splitlines()
        if len(lines) >= 2:
            parts = lines[-1].split()
            if len(parts) >= 5:
                data[f"mailcow.disk.{prefix}.total"] = int(parts[1])
                data[f"mailcow.disk.{prefix}.free"] = int(parts[3])
                data[f"mailcow.disk.{prefix}.used"] = int(parts[4].replace("%", ""))

    # Docker top containers
    top = run("docker ps --format 'table {{.Names}}\t{{.Size}}' 2>/dev/null")
    lines = top.splitlines()[1:6]  # Erste 5 Container
    data["mailcow.disk.docker.top.containers"] = ",".join(lines) if lines else "N/A"

    # vmail
    data["mailcow.disk.vmail.exists"] = 0
    data["mailcow.disk.vmail.total"] = 0
    data["mailcow.disk.vmail.free"] = 0
    data["mailcow.disk.vmail.used"] = 0
    data["mailcow.disk.vmail.maildir.size"] = 0

    if dovecot_container:
        exists = docker_exec(dovecot_container, "test -d /var/vmail && echo 1 || echo 0")
        if exists == "1":
            data["mailcow.disk.vmail.exists"] = 1
            df_out = docker_exec(dovecot_container, "df /var/vmail 2>/dev/null")
            lines = df_out.splitlines()
            if len(lines) >= 2:
                parts = lines[-1].split()
                if len(parts) >= 5:
                    data["mailcow.disk.vmail.total"] = int(parts[1])
                    data["mailcow.disk.vmail.free"] = int(parts[3])
                    data["mailcow.disk.vmail.used"] = int(parts[4].replace("%", ""))
            data["mailcow.disk.vmail.maildir.size"] = docker_exec_int(
                dovecot_container, "du -sm /var/vmail 2>/dev/null | cut -f1")

    return data


def collect_sync():
    """Sync-Jobs-Metriken sammeln."""
    data = {}
    for arg in ["active", "running", "failed", "stuck", "never_run", "oldest_run"]:
        key = f"mailcow.sync.jobs.{arg}"
        data[key] = run_int(f"/usr/local/bin/sync_jobs_check.sh {arg} 2>/dev/null")
    return data


def collect_mailbox(mysql_container, dbpass):
    """Mailbox-Metriken sammeln."""
    data = {
        "mailcow.mailbox.total": 0,
        "mailcow.mailbox.active": 0,
        "mailcow.mailbox.quota.used.total": 0,
        "mailcow.mailbox.over.quota": 0,
        "mailcow.mailbox.unlimited": 0,
        "mailcow.mailbox.top5": "-",
        "mailcow.mailbox.over.detail": "-",
        "mailcow.domain.total": 0,
        "mailcow.domain.active": 0,
        "mailcow.domain.list": "-",
    }
    if not mysql_container or not dbpass:
        return data

    # Domains abfragen
    dom_raw = mysql_exec(mysql_container, dbpass,
        "SELECT domain, active FROM domain", timeout=10)
    if dom_raw:
        domains = []
        for line in dom_raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                domains.append({"domain": parts[0], "active": int(parts[1])})
        data["mailcow.domain.total"] = len(domains)
        data["mailcow.domain.active"] = sum(1 for d in domains if d["active"] == 1)
        active_list = [d["domain"] for d in domains if d["active"] == 1]
        data["mailcow.domain.list"] = ",".join(active_list) if active_list else "-"

    # Mailboxen abfragen

    sql = ("SELECT m.username, m.quota, m.active, COALESCE(q.bytes,0) "
           "FROM mailbox m LEFT JOIN quota2 q ON m.username=q.username "
           "WHERE m.kind='' OR m.kind IS NULL")
    raw = mysql_exec(mysql_container, dbpass, sql, timeout=20)
    if not raw:
        return data

    mailboxes = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            try:
                mailboxes.append({
                    "user": parts[0],
                    "quota": int(parts[1]),
                    "active": int(parts[2]),
                    "used": int(parts[3]),
                })
            except ValueError:
                continue

    if not mailboxes:
        return data

    data["mailcow.mailbox.total"] = len(mailboxes)
    data["mailcow.mailbox.active"] = sum(1 for m in mailboxes if m["active"] == 1)
    data["mailcow.mailbox.quota.used.total"] = sum(m["used"] for m in mailboxes) // 1048576
    data["mailcow.mailbox.unlimited"] = sum(1 for m in mailboxes if m["active"] == 1 and m["quota"] == 0)

    # Über 80% Quota
    over = []
    for m in mailboxes:
        if m["active"] == 1 and m["quota"] > 0:
            pct = m["used"] * 100 // m["quota"]
            if pct >= 80:
                over.append(f'{m["user"]}:{pct}%')
    data["mailcow.mailbox.over.quota"] = len(over)
    data["mailcow.mailbox.over.detail"] = ",".join(over) if over else "-"

    # Top 5 größte
    by_size = sorted(mailboxes, key=lambda m: m["used"], reverse=True)[:5]
    data["mailcow.mailbox.top5"] = ",".join(
        f'{m["user"]}:{m["used"] // 1048576}MB' for m in by_size)

    return data


def collect_clamav(container):
    """ClamAV/Antivirus-Metriken — 1 docker exec statt 3-5 (#5)."""
    data = {
        "mailcow.clamav.running": 0,
        "mailcow.clamav.version": "unknown",
        "mailcow.clamav.signatures": 0,
        "mailcow.clamav.daily.version": 0,
        "mailcow.clamav.daily.age": 999,
        "mailcow.clamav.daily.build": "unknown",
        "mailcow.clamav.main.version": 0,
        "mailcow.clamav.db.size": 0,
    }

    if not container:
        return data

    data["mailcow.clamav.running"] = 1

    # Ein einziger docker exec für alle ClamAV-Infos
    combined = docker_exec(container, 'sh -c "'
        'echo ===VERSION===; clamscan --version 2>/dev/null; '
        'echo ===DAILY===; '
        'sigtool --info /var/lib/clamav/daily.cvd 2>/dev/null || '
        'sigtool --info /var/lib/clamav/daily.cld 2>/dev/null; '
        'echo ===MAIN===; '
        'sigtool --info /var/lib/clamav/main.cvd 2>/dev/null || '
        'sigtool --info /var/lib/clamav/main.cld 2>/dev/null; '
        'echo ===DBSIZE===; du -sm /var/lib/clamav 2>/dev/null'
        '"', timeout=20)

    if not combined:
        return data

    section = ""
    for line in combined.splitlines():
        if line.startswith("===") and line.endswith("==="):
            section = line.strip("=")
            continue

        if section == "VERSION" and line.strip():
            parts = line.split("/")
            if parts:
                data["mailcow.clamav.version"] = parts[0].replace("ClamAV ", "").strip()

        elif section in ("DAILY", "MAIN"):
            if line.startswith("Version:"):
                try:
                    ver = int(line.split(":")[1].strip())
                    if section == "DAILY":
                        data["mailcow.clamav.daily.version"] = ver
                    else:
                        data["mailcow.clamav.main.version"] = ver
                except ValueError:
                    pass
            elif line.startswith("Signatures:"):
                try:
                    data["mailcow.clamav.signatures"] += int(line.split(":")[1].strip())
                except ValueError:
                    pass
            elif section == "DAILY" and line.startswith("Build time:"):
                build_str = line.split(":", 1)[1].strip()
                data["mailcow.clamav.daily.build"] = build_str
                for fmt in ["%d %b %Y %H:%M %z", "%d %b %Y %H:%M:%S %z"]:
                    try:
                        build_dt = datetime.strptime(build_str, fmt)
                        data["mailcow.clamav.daily.age"] = (datetime.now(timezone.utc) - build_dt).days
                        break
                    except ValueError:
                        continue

        elif section == "DBSIZE" and line.strip():
            try:
                data["mailcow.clamav.db.size"] = int(line.split()[0])
            except (ValueError, IndexError):
                pass

    return data


def collect_watchdog(container):
    """Mailcow Watchdog Health-Daten aus Container-Logs."""
    # Services die der Watchdog prüft
    services = {
        "Postfix": "mailcow.watchdog.postfix",
        "Dovecot": "mailcow.watchdog.dovecot",
        "Rspamd": "mailcow.watchdog.rspamd",
        "MySQL/MariaDB": "mailcow.watchdog.mysql",
        "Nginx": "mailcow.watchdog.nginx",
        "SOGo": "mailcow.watchdog.sogo",
        "Redis": "mailcow.watchdog.redis",
        "Unbound": "mailcow.watchdog.unbound",
        "PHP-FPM": "mailcow.watchdog.phpfpm",
        "Fail2ban": "mailcow.watchdog.fail2ban",
        "ACME": "mailcow.watchdog.acme",
        "Mail queue": "mailcow.watchdog.queue",
        "Olefy": "mailcow.watchdog.olefy",
        "Dovecot replication": "mailcow.watchdog.replication",
        "Ratelimit": "mailcow.watchdog.ratelimit",
    }

    data = {}
    for svc, key in services.items():
        data[key] = 0  # 0 = keine Daten / nicht geprüft

    data["mailcow.watchdog.overall"] = 0
    data["mailcow.watchdog.unhealthy"] = 0
    data["mailcow.watchdog.detail"] = "-"

    if not container:
        return data

    # Letzte 10 Minuten Watchdog-Logs parsen (Watchdog prüft alle ~5min)
    raw = run(f'docker logs --since 10m "{container}" 2>&1', timeout=15)
    if not raw:
        return data

    # Letzten Health-Level pro Service extrahieren
    # Format: "Postfix health level: 100% (8/8), health trend: 0"
    seen = set()
    for line in raw.splitlines():
        for svc, key in services.items():
            if svc + " health level:" in line:
                m = re.search(r'health level: (\d+)%', line)
                if m:
                    data[key] = int(m.group(1))
                    seen.add(key)

    # Overall berechnen + unhealthy zählen
    levels = []
    unhealthy = []
    for svc, key in services.items():
        if key in seen:
            levels.append(data[key])
            if data[key] < 100:
                unhealthy.append(f"{svc}:{data[key]}%")
    if levels:
        data["mailcow.watchdog.overall"] = min(levels)
    data["mailcow.watchdog.unhealthy"] = len(unhealthy)
    data["mailcow.watchdog.detail"] = ",".join(unhealthy) if unhealthy else "-"

    return data




def collect_acme():
    """ACME/Let's Encrypt Zertifikat-Metriken."""
    data = {
        "mailcow.acme.cert.exists": 0,
        "mailcow.acme.cert.subject": "unknown",
        "mailcow.acme.cert.issuer": "unknown",
        "mailcow.acme.cert.valid.from": "unknown",
        "mailcow.acme.cert.valid.until": "unknown",
        "mailcow.acme.cert.days.left": 0,
        "mailcow.acme.cert.serial": "unknown",
    }

    cert_path = os.path.join(MAILCOW_DIR, "data/assets/ssl/cert.pem")
    if not os.path.isfile(cert_path):
        return data

    data["mailcow.acme.cert.exists"] = 1

    # Subject
    subj = run(f'openssl x509 -in "{cert_path}" -noout -subject 2>/dev/null')
    if subj:
        # "subject=CN = cow.fox1.de" → "cow.fox1.de"
        m = re.search(r'CN\s*=\s*(.+)', subj)
        if m:
            data["mailcow.acme.cert.subject"] = m.group(1).strip()

    # Issuer
    iss = run(f'openssl x509 -in "{cert_path}" -noout -issuer 2>/dev/null')
    if iss:
        m = re.search(r'CN\s*=\s*(.+)', iss)
        if m:
            data["mailcow.acme.cert.issuer"] = m.group(1).strip()

    # Dates
    dates = run(f'openssl x509 -in "{cert_path}" -noout -dates 2>/dev/null')
    if dates:
        for line in dates.splitlines():
            if line.startswith("notBefore="):
                data["mailcow.acme.cert.valid.from"] = line.split("=", 1)[1].strip()
            elif line.startswith("notAfter="):
                data["mailcow.acme.cert.valid.until"] = line.split("=", 1)[1].strip()

    # Days left
    days_raw = run(f'openssl x509 -in "{cert_path}" -noout -checkend 0 2>/dev/null; '
                   f'echo "---"; '
                   f'openssl x509 -in "{cert_path}" -noout -enddate 2>/dev/null')
    enddate = run(f'openssl x509 -in "{cert_path}" -noout -enddate 2>/dev/null')
    if enddate:
        # "notAfter=May 16 21:39:00 2026 GMT"
        m = re.search(r'notAfter=(.+)', enddate)
        if m:
            try:
                end_str = m.group(1).strip()
                # Parse "Feb 15 21:39:00 2026 GMT"
                end_dt = datetime.strptime(end_str, "%b %d %H:%M:%S %Y %Z")
                end_dt = end_dt.replace(tzinfo=timezone.utc)
                days_left = (end_dt - datetime.now(timezone.utc)).days
                data["mailcow.acme.cert.days.left"] = max(0, days_left)
            except (ValueError, Exception):
                pass

    # Serial
    serial = run(f'openssl x509 -in "{cert_path}" -noout -serial 2>/dev/null')
    if serial:
        data["mailcow.acme.cert.serial"] = serial.split("=", 1)[-1].strip()

    return data


def collect_alias(mysql_container, dbpass):
    """Alias-Monitoring: Anzahl, aktive, Weiterleitungen."""
    data = {
        "mailcow.alias.total": 0,
        "mailcow.alias.active": 0,
        "mailcow.alias.inactive": 0,
        "mailcow.alias.forwarding": 0,
        "mailcow.alias.internal": 0,
    }
    if not mysql_container or not dbpass:
        return data

    raw = mysql_exec(mysql_container, dbpass,
        "SELECT address, goto, active, internal FROM alias", timeout=10)
    if not raw:
        return data

    aliases = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            aliases.append({
                "address": parts[0],
                "goto": parts[1],
                "active": int(parts[2]),
                "internal": int(parts[3]),
            })

    data["mailcow.alias.total"] = len(aliases)
    data["mailcow.alias.active"] = sum(1 for a in aliases if a["active"] == 1)
    data["mailcow.alias.inactive"] = sum(1 for a in aliases if a["active"] == 0)
    data["mailcow.alias.internal"] = sum(1 for a in aliases if a["internal"] == 1)

    # Echte Weiterleitungen: address != goto (nicht nur sich selbst)
    data["mailcow.alias.forwarding"] = sum(
        1 for a in aliases
        if a["active"] == 1 and a["address"] != a["goto"]
        and not a["goto"].endswith("@localhost"))

    return data


def collect_lld(mysql_container, dbpass):
    """Low-Level Discovery Daten für Zabbix LLD."""
    data = {
        "mailcow.lld.domains": "[]",
        "mailcow.lld.domain.data": "{}",
        "mailcow.lld.mailboxes": "[]",
        "mailcow.lld.mailbox.data": "{}",
        "mailcow.lld.syncjobs": "[]",
        "mailcow.lld.syncjob.data": "{}",
    }
    if not mysql_container or not dbpass:
        return data

    # === Domain Discovery ===
    dom_sql = ("SELECT d.domain, d.aliases, d.mailboxes, d.maxquota, d.quota, d.active, "
               "COUNT(m.username) as mb_count, COALESCE(SUM(q.bytes),0) as used_bytes "
               "FROM domain d "
               "LEFT JOIN mailbox m ON d.domain=m.domain AND (m.kind='' OR m.kind IS NULL) "
               "LEFT JOIN quota2 q ON m.username=q.username "
               "GROUP BY d.domain")
    dom_raw = mysql_exec(mysql_container, dbpass, dom_sql, timeout=15)
    if dom_raw:
        discovery = []
        domain_data = {}
        for line in dom_raw.splitlines():
            p = line.split("\t")
            if len(p) >= 8:
                dom = p[0]
                active = int(p[5])
                mb_count = int(p[6])
                used_bytes = int(p[7])
                max_aliases = int(p[1])
                max_mailboxes = int(p[2])
                maxquota_mb = int(p[3])
                quota_mb = int(p[4])

                discovery.append({
                    "{#DOMAIN}": dom,
                    "{#ACTIVE}": str(active),
                })
                domain_data[dom] = {
                    "active": active,
                    "mailbox_count": mb_count,
                    "max_aliases": max_aliases,
                    "max_mailboxes": max_mailboxes,
                    "maxquota_mb": maxquota_mb,
                    "quota_mb": quota_mb,
                    "used_mb": used_bytes // 1048576,
                    "usage_pct": round(used_bytes * 100 / (quota_mb * 1048576), 1) if quota_mb > 0 else 0,
                }
        data["mailcow.lld.domains"] = json.dumps(discovery)
        data["mailcow.lld.domain.data"] = json.dumps(domain_data)

    # === Mailbox Discovery ===
    mb_sql = ("SELECT m.username, m.domain, m.quota, m.active, COALESCE(q.bytes,0) "
              "FROM mailbox m LEFT JOIN quota2 q ON m.username=q.username "
              "WHERE m.kind='' OR m.kind IS NULL")
    mb_raw = mysql_exec(mysql_container, dbpass, mb_sql, timeout=15)
    if mb_raw:
        discovery = []
        mailbox_data = {}
        for line in mb_raw.splitlines():
            p = line.split("\t")
            if len(p) >= 5:
                user = p[0]
                domain = p[1]
                quota = int(p[2])
                active = int(p[3])
                used = int(p[4])
                quota_mb = quota // 1048576
                used_mb = used // 1048576
                pct = round(used * 100 / quota, 1) if quota > 0 else 0

                discovery.append({
                    "{#MAILBOX}": user,
                    "{#DOMAIN}": domain,
                    "{#ACTIVE}": str(active),
                })
                mailbox_data[user] = {
                    "domain": domain,
                    "active": active,
                    "quota_mb": quota_mb,
                    "used_mb": used_mb,
                    "usage_pct": pct,
                }
        data["mailcow.lld.mailboxes"] = json.dumps(discovery)
        data["mailcow.lld.mailbox.data"] = json.dumps(mailbox_data)

    # === Sync Job Discovery ===
    sync_sql = ("SELECT id, user2, host1, active, is_running, "
                "COALESCE(success,-1), COALESCE(exit_status,'unknown'), "
                "COALESCE(UNIX_TIMESTAMP(last_run),0) "
                "FROM imapsync")
    sync_raw = mysql_exec(mysql_container, dbpass, sync_sql, timeout=15)
    if sync_raw:
        discovery = []
        syncjob_data = {}
        for line in sync_raw.splitlines():
            p = line.split("\t")
            if len(p) >= 8:
                job_id = p[0]
                user = p[1]
                host = p[2]
                active = int(p[3])
                running = int(p[4])
                success = int(p[5])
                exit_status = p[6]
                last_run = int(p[7])

                discovery.append({
                    "{#SYNCJOB_ID}": job_id,
                    "{#SYNCJOB_USER}": user,
                    "{#SYNCJOB_HOST}": host,
                    "{#ACTIVE}": str(active),
                })
                syncjob_data[job_id] = {
                    "user": user,
                    "host": host,
                    "active": active,
                    "running": running,
                    "success": success,
                    "exit_status": exit_status,
                    "last_run": last_run,
                    "age_hours": (now() - last_run) // 3600 if last_run > 0 else -1,
                }
        data["mailcow.lld.syncjobs"] = json.dumps(discovery)
        data["mailcow.lld.syncjob.data"] = json.dumps(syncjob_data)

    return data


def collect_docker_health():
    """Docker Container Health — optimiert: gezielter stats + gebatchter inspect (#4)."""
    data = {
        "mailcow.docker.containers": "[]",
        "mailcow.docker.container.data": "{}",
        "mailcow.docker.total": 0,
        "mailcow.docker.running": 0,
        "mailcow.docker.restarts.total": 0,
        "mailcow.docker.mem.total.mb": 0,
        "mailcow.docker.cpu.total": 0,
    }

    # Schritt 1: Nur Mailcow-Container-Namen holen (schnell, kein stats)
    names_raw = run_cmd(
        ["docker", "ps", "--filter", "name=mailcow", "--format", "{{.Names}}"],
        timeout=10)
    if not names_raw:
        return data

    container_names = [n.strip() for n in names_raw.splitlines() if n.strip()]
    if not container_names:
        return data

    # Schritt 2: docker stats NUR für bekannte Container (schneller als alle + grep)
    names_args = " ".join(f'"{n}"' for n in container_names)
    stats_raw = run(
        f'docker stats --no-stream --format '
        f'"{{{{.Name}}}}|{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.MemPerc}}}}|{{{{.PIDs}}}}" '
        f'{names_args} 2>/dev/null',
        timeout=30)

    # Schritt 3: EIN docker inspect für ALLE Container (statt N einzelne)
    inspect_fmt = '{{.Name}}|{{.RestartCount}}|{{.State.StartedAt}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'
    inspect_raw = run_cmd(
        ["docker", "inspect", "--format", inspect_fmt] + container_names,
        timeout=15)

    # Parse inspect info
    restart_map = {}
    if inspect_raw:
        for line in inspect_raw.splitlines():
            parts = line.split("|")
            if len(parts) >= 4:
                name = parts[0].strip().lstrip("/")
                short = name.replace("mailcowdockerized-", "").replace("-mailcow-1", "").replace("-mailcow-", "-")
                try:
                    restarts = int(parts[1].strip())
                except ValueError:
                    restarts = 0
                started = parts[2].strip()
                health = parts[3].strip()
                uptime_h = -1
                try:
                    st = datetime.fromisoformat(started.replace("Z", "+00:00"))
                    uptime_h = int((datetime.now(timezone.utc) - st).total_seconds() // 3600)
                except (ValueError, Exception):
                    pass
                restart_map[name] = {
                    "short": short,
                    "restarts": restarts,
                    "uptime_h": uptime_h,
                    "health": health if health and health != "<no value>" else "none",
                }

    # Parse stats
    discovery = []
    container_data = {}
    total_mem_mb = 0
    total_cpu = 0.0
    total_restarts = 0

    if stats_raw:
        for line in stats_raw.splitlines():
            parts = line.split("|")
            if len(parts) < 5:
                continue

            name = parts[0].strip()
            cpu_str = parts[1].strip().replace("%", "")
            mem_usage_str = parts[2].strip()
            mem_pct_str = parts[3].strip().replace("%", "")
            pids_str = parts[4].strip()

            short = name.replace("mailcowdockerized-", "").replace("-mailcow-1", "").replace("-mailcow-", "-")

            try:
                cpu = float(cpu_str)
            except ValueError:
                cpu = 0.0

            try:
                mem_pct = float(mem_pct_str)
            except ValueError:
                mem_pct = 0.0

            # Parse mem usage "24.05MiB / 7.575GiB"
            mem_mb = 0
            try:
                used_part = mem_usage_str.split("/")[0].strip()
                if "GiB" in used_part:
                    mem_mb = int(float(used_part.replace("GiB", "").strip()) * 1024)
                elif "MiB" in used_part:
                    mem_mb = int(float(used_part.replace("MiB", "").strip()))
                elif "KiB" in used_part:
                    mem_mb = max(1, int(float(used_part.replace("KiB", "").strip()) / 1024))
            except (ValueError, IndexError):
                pass

            try:
                pids = int(pids_str)
            except ValueError:
                pids = 0

            rinfo = restart_map.get(name, {})
            restarts = rinfo.get("restarts", 0)
            uptime_h = rinfo.get("uptime_h", -1)
            health = rinfo.get("health", "none")

            total_mem_mb += mem_mb
            total_cpu += cpu
            total_restarts += restarts

            discovery.append({
                "{#CONTAINER}": short,
                "{#CONTAINER_FULL}": name,
            })
            container_data[short] = {
                "cpu": round(cpu, 2),
                "mem_mb": mem_mb,
                "mem_pct": round(mem_pct, 2),
                "pids": pids,
                "restarts": restarts,
                "uptime_h": uptime_h,
                "health": health,
            }

    data["mailcow.docker.containers"] = json.dumps(discovery)
    data["mailcow.docker.container.data"] = json.dumps(container_data)
    data["mailcow.docker.total"] = len(discovery)
    data["mailcow.docker.running"] = len(discovery)
    data["mailcow.docker.restarts.total"] = total_restarts
    data["mailcow.docker.mem.total.mb"] = total_mem_mb
    data["mailcow.docker.cpu.total"] = round(total_cpu, 2)

    return data


def collect_sogo(container):
    """SOGo Sessions und Memcached Stats."""
    data = {
        "mailcow.sogo.memcached.items": 0,
        "mailcow.sogo.memcached.bytes": 0,
        "mailcow.sogo.memcached.limit.mb": 0,
        "mailcow.sogo.memcached.hits": 0,
        "mailcow.sogo.memcached.misses": 0,
        "mailcow.sogo.memcached.hit.rate": 0,
        "mailcow.sogo.memcached.evictions": 0,
        "mailcow.sogo.memcached.uptime": 0,
    }

    if not container:
        return data

    stats_raw = run(
        f'docker exec {container} sh -c "echo stats | nc 127.0.0.1 11211" 2>/dev/null',
        timeout=10)

    if not stats_raw:
        return data

    stats = {}
    for line in stats_raw.splitlines():
        if line.startswith("STAT "):
            parts = line.split()
            if len(parts) >= 3:
                stats[parts[1]] = parts[2]

    curr_items = int(stats.get("curr_items", 0))
    bytes_used = int(stats.get("bytes", 0))
    limit_bytes = int(stats.get("limit_maxbytes", 0))
    hits = int(stats.get("get_hits", 0))
    misses = int(stats.get("get_misses", 0))
    evictions = int(stats.get("evictions", 0))
    uptime = int(stats.get("uptime", 0))

    total_gets = hits + misses
    hit_rate = round(hits * 100 / total_gets, 1) if total_gets > 0 else 0

    data["mailcow.sogo.memcached.items"] = curr_items
    data["mailcow.sogo.memcached.bytes"] = bytes_used
    data["mailcow.sogo.memcached.limit.mb"] = limit_bytes // (1024 * 1024)
    data["mailcow.sogo.memcached.hits"] = hits
    data["mailcow.sogo.memcached.misses"] = misses
    data["mailcow.sogo.memcached.hit.rate"] = hit_rate
    data["mailcow.sogo.memcached.evictions"] = evictions
    data["mailcow.sogo.memcached.uptime"] = uptime

    return data


def collect_quarantine(mysql_container, dbpass):
    """Quarantine Stats aus MySQL."""
    data = {
        "mailcow.quarantine.total": 0,
        "mailcow.quarantine.spam": 0,
        "mailcow.quarantine.virus": 0,
        "mailcow.quarantine.age.oldest.hours": 0,
        "mailcow.quarantine.age.newest.hours": 0,
        "mailcow.quarantine.top.domains": "none",
    }

    if not mysql_container or not dbpass:
        return data

    # Gesamtzahl + Alter
    result = mysql_exec(mysql_container, dbpass,
        "SELECT COUNT(*), "
        "COALESCE(TIMESTAMPDIFF(HOUR, MIN(created), NOW()), 0), "
        "COALESCE(TIMESTAMPDIFF(HOUR, MAX(created), NOW()), 0) "
        "FROM quarantine", timeout=10)

    if result:
        for line in result.splitlines():
            parts = line.split('\t')
            if len(parts) >= 3 and parts[0].isdigit():
                data["mailcow.quarantine.total"] = int(parts[0])
                data["mailcow.quarantine.age.oldest.hours"] = int(parts[1])
                data["mailcow.quarantine.age.newest.hours"] = int(parts[2])

    # Spam vs Virus (nur wenn Quarantine nicht leer)
    if data["mailcow.quarantine.total"] > 0:
        result = mysql_exec(mysql_container, dbpass,
            "SELECT "
            "COALESCE(SUM(CASE WHEN action='reject' THEN 1 ELSE 0 END),0), "
            "COALESCE(SUM(CASE WHEN action='virus' THEN 1 ELSE 0 END),0) "
            "FROM quarantine", timeout=10)

        if result:
            for line in result.splitlines():
                parts = line.split('\t')
                if len(parts) >= 2:
                    try:
                        data["mailcow.quarantine.spam"] = int(parts[0])
                        data["mailcow.quarantine.virus"] = int(parts[1])
                    except ValueError:
                        pass

        # Top Domains
        result = mysql_exec(mysql_container, dbpass,
            "SELECT SUBSTRING_INDEX(rcpt,'@',-1) as domain, COUNT(*) as cnt "
            "FROM quarantine GROUP BY domain ORDER BY cnt DESC LIMIT 5",
            timeout=10)

        if result:
            domains = []
            for line in result.splitlines():
                parts = line.split('\t')
                if len(parts) >= 2:
                    domains.append(f"{parts[0]}:{parts[1]}")
            if domains:
                data["mailcow.quarantine.top.domains"] = ",".join(domains)

    return data


def collect_queue_age(postfix_container):
    """Mail Queue Age - älteste und Anzahl deferred Mails."""
    data = {
        "mailcow.queue.deferred": 0,
        "mailcow.queue.active": 0,
        "mailcow.queue.age.oldest.hours": 0,
        "mailcow.queue.hold": 0,
    }

    if not postfix_container:
        return data

    # Deferred count
    result = docker_exec(postfix_container,
        'sh -c "find /var/spool/postfix/deferred -type f 2>/dev/null | wc -l"',
        timeout=10)
    if result:
        try:
            data["mailcow.queue.deferred"] = int(result.strip())
        except ValueError:
            pass

    # Active count
    result = docker_exec(postfix_container,
        'sh -c "find /var/spool/postfix/active -type f 2>/dev/null | wc -l"',
        timeout=10)
    if result:
        try:
            data["mailcow.queue.active"] = int(result.strip())
        except ValueError:
            pass

    # Hold count
    result = docker_exec(postfix_container,
        'sh -c "find /var/spool/postfix/hold -type f 2>/dev/null | wc -l"',
        timeout=10)
    if result:
        try:
            data["mailcow.queue.hold"] = int(result.strip())
        except ValueError:
            pass

    # Älteste deferred Mail (Stunden)
    if data["mailcow.queue.deferred"] > 0:
        result = docker_exec(postfix_container,
            "sh -c \"find /var/spool/postfix/deferred -type f -printf '%T@\\n' 2>/dev/null | sort -n | head -1\"",
            timeout=10)
        if result and result.strip():
            try:
                oldest_ts = float(result.strip())
                age_hours = int((time.time() - oldest_ts) / 3600)
                data["mailcow.queue.age.oldest.hours"] = max(0, age_hours)
            except (ValueError, Exception):
                pass

    return data


def collect_version():
    """Version/Update-Metriken sammeln."""
    data = {
        "mailcow.version.current": "unknown",
        "mailcow.version.branch": "unknown",
        "mailcow.version.commit": "unknown",
        "mailcow.version.date": "unknown",
        "mailcow.version.latest": "unknown",
        "mailcow.updates.available": 0,
        "mailcow.updates.commits.behind": 0,
        "mailcow.update.script.exists": 0,
    }

    git = f"cd {MAILCOW_DIR} &&"

    data["mailcow.version.current"] = run(
        f"{git} git describe --tags 2>/dev/null || git log -1 --format='%H' 2>/dev/null | cut -c1-8",
        default="unknown")
    data["mailcow.version.branch"] = run(f"{git} git rev-parse --abbrev-ref HEAD 2>/dev/null", default="unknown")
    data["mailcow.version.commit"] = run(f"{git} git rev-parse --short HEAD 2>/dev/null", default="unknown")
    data["mailcow.version.date"] = run(f"{git} git log -1 --format=%cd --date=short 2>/dev/null", default="unknown")

    # Fetch + latest
    run(f"{git} git fetch --tags origin 2>/dev/null", timeout=15)
    data["mailcow.version.latest"] = run(
        f"{git} git describe --tags $(git rev-list --tags --max-count=1) 2>/dev/null",
        default="unknown")

    # Update check
    head = run(f"{git} git rev-parse HEAD 2>/dev/null")
    upstream = run(f"{git} git rev-parse @{{u}} 2>/dev/null")
    if head and upstream and head != upstream:
        data["mailcow.updates.available"] = 1

    data["mailcow.updates.commits.behind"] = run_int(
        f"{git} git rev-list --count HEAD..@{{u}} 2>/dev/null")

    if os.path.isfile(os.path.join(MAILCOW_DIR, "update.sh")):
        data["mailcow.update.script.exists"] = 1

    return data


def collect_meta():
    """Agent/Meta-Metriken sammeln."""
    data = {
        "zabbix.agent.running": 0,
        "zabbix.agent.uptime": 0,
        "zabbix.agent.restarts": 0,
        "zabbix.agent.configs": 0,
        "zabbix.agent.log.errors": 0,
        "zabbix.agent.log.warnings": 0,
        "zabbix.agent.timeout": 3,
        "zabbix.agent.unsafe": 0,
    }

    # Agent running
    data["zabbix.agent.running"] = 1 if run("systemctl is-active zabbix-agent2 2>/dev/null") == "active" else 0

    # Uptime
    ts = run("systemctl show zabbix-agent2 --property=ActiveEnterTimestamp --value 2>/dev/null")
    if ts and ts != "0":
        start = run_int(f'date -d "{ts}" +%s 2>/dev/null')
        if start > 0:
            data["zabbix.agent.uptime"] = now() - start

    # Restarts
    data["zabbix.agent.restarts"] = run_int(
        "systemctl show zabbix-agent2 --property=NRestarts --value 2>/dev/null")

    # Config count
    configs = list(Path("/etc/zabbix/zabbix_agent2.d/").glob("mailcow*.conf"))
    data["zabbix.agent.configs"] = len(configs)

    # Log analysis
    log_content = run("tail -100 /var/log/zabbix/zabbix_agent2.log 2>/dev/null")
    if log_content:
        data["zabbix.agent.log.errors"] = sum(
            1 for l in log_content.splitlines() if "error" in l.lower())
        data["zabbix.agent.log.warnings"] = sum(
            1 for l in log_content.splitlines() if "warning" in l.lower())

    # Config values
    agent_conf = ""
    try:
        with open("/etc/zabbix/zabbix_agent2.conf") as f:
            agent_conf = f.read()
    except FileNotFoundError:
        pass

    for line in agent_conf.splitlines():
        if line.startswith("Timeout="):
            data["zabbix.agent.timeout"] = int(line.split("=")[1].strip())
        elif line.startswith("UnsafeUserParameters="):
            data["zabbix.agent.unsafe"] = int(line.split("=")[1].strip())

    return data


def collect_backup(backup_path):
    """Backup-Metriken sammeln."""
    data = {
        "mailcow.backup.age": 999999,
        "mailcow.backup.size": 0,
        "mailcow.backup.zero.files": 0,
        "mailcow.backup.last.timestamp": 0,
        "mailcow.backup.dir.exists": 0,
        "mailcow.backup.count": 0,
        "mailcow.backup.disk.free": 0,
        "mailcow.backup.script.exists": 0,
    }

    if os.path.isfile(os.path.join(MAILCOW_DIR, "helper-scripts/backup_and_restore.sh")):
        data["mailcow.backup.script.exists"] = 1

    if not os.path.isdir(backup_path):
        return data

    data["mailcow.backup.dir.exists"] = 1

    # Disk free
    df_out = run(f"df '{backup_path}' 2>/dev/null")
    for line in df_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            data["mailcow.backup.disk.free"] = 100 - int(parts[4].replace("%", ""))
            break

    # Backup dirs finden
    backup_dirs = []
    try:
        for entry in os.scandir(backup_path):
            if entry.is_dir(follow_symlinks=True) and entry.name.startswith("mailcow-"):
                backup_dirs.append(entry)
    except OSError:
        pass

    data["mailcow.backup.count"] = len(backup_dirs)

    if not backup_dirs:
        return data

    # Neuestes Backup
    newest = max(backup_dirs, key=lambda e: e.stat(follow_symlinks=True).st_mtime)
    newest_mtime = int(newest.stat(follow_symlinks=True).st_mtime)
    data["mailcow.backup.last.timestamp"] = newest_mtime
    data["mailcow.backup.age"] = (now() - newest_mtime) // 3600

    # Größe des neuesten Backups
    data["mailcow.backup.size"] = run_int(f"du -sm '{newest.path}' 2>/dev/null | cut -f1")

    # Zero-size files
    data["mailcow.backup.zero.files"] = run_int(
        f"find '{newest.path}' -type f -size 0 ! -path '*/.*' 2>/dev/null | wc -l")

    return data


def collect_slow():
    """Langsame Checks: TLS, DNS, RBL, Open Relay. Cache: 1h. Parallelisiert (#6)."""
    # Cache prüfen
    try:
        cache_age = now() - int(os.path.getmtime(SLOW_CACHE))
        if cache_age <= SLOW_MAX_AGE:
            with open(SLOW_CACHE) as f:
                return json.load(f)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        pass

    # Alle Checks als (key, command, is_int) Tripel
    checks = [
        # TLS
        ("mailcow.tls.cert.days.443", "/usr/local/bin/check_tls.sh cert_days 443 2>/dev/null", True),
        ("mailcow.tls.cert.days.587", "/usr/local/bin/check_tls.sh cert_days 587 2>/dev/null", True),
        ("mailcow.tls.cert.days.993", "/usr/local/bin/check_tls.sh cert_days 993 2>/dev/null", True),
        ("mailcow.tls.cert.raw.443", "/usr/local/bin/check_tls.sh cert_raw 443 2>/dev/null", False),
        ("mailcow.tls.cert.raw.587", "/usr/local/bin/check_tls.sh cert_raw 587 2>/dev/null", False),
        ("mailcow.tls.cert.raw.993", "/usr/local/bin/check_tls.sh cert_raw 993 2>/dev/null", False),
        ("mailcow.tls.https.check", "/usr/local/bin/check_tls.sh port_check 443 2>/dev/null", True),
        ("mailcow.tls.submission.check", "/usr/local/bin/check_tls.sh port_check 587 2>/dev/null", True),
        ("mailcow.tls.imaps.check", "/usr/local/bin/check_tls.sh port_check 993 2>/dev/null", True),
        ("mailcow.ui.check", "/usr/local/bin/check_tls.sh ui_check 2>/dev/null", True),
        # DNS
        ("mailcow.dns.spf.exists", "/usr/local/bin/check_dns.sh spf 2>/dev/null", True),
        ("mailcow.dns.dkim.exists", "/usr/local/bin/check_dns.sh dkim 2>/dev/null", True),
        ("mailcow.dns.dmarc.exists", "/usr/local/bin/check_dns.sh dmarc 2>/dev/null", True),
        ("mailcow.dns.ptr.valid", "/usr/local/bin/check_ptr.sh 2>/dev/null", True),
        ("mailcow.dns.detail", "/usr/local/bin/check_dns.sh detail 2>/dev/null", False),
        ("mailcow.dns.domains", "/usr/local/bin/check_dns.sh domains 2>/dev/null", False),
        # RBL
        ("mailcow.security.rbl.listed", "/usr/local/bin/check_rbl.sh 2>/dev/null", True),
        ("mailcow.security.rbl.detail", "/usr/local/bin/check_rbl.sh detail 2>/dev/null", False),
        # Open Relay
        ("mailcow.security.open.relay", "/usr/local/bin/check_open_relay.sh 2>/dev/null", True),
        # Security Audit (#9): DANE, MTA-STS, TLS-RPT, BIMI
        ("mailcow.security.dane.exists", "/usr/local/bin/check_security_audit.sh dane 2>/dev/null", True),
        ("mailcow.security.mta_sts.exists", "/usr/local/bin/check_security_audit.sh mta_sts 2>/dev/null", True),
        ("mailcow.security.tls_rpt.exists", "/usr/local/bin/check_security_audit.sh tls_rpt 2>/dev/null", True),
        ("mailcow.security.bimi.exists", "/usr/local/bin/check_security_audit.sh bimi 2>/dev/null", True),
        ("mailcow.security.audit.score", "/usr/local/bin/check_security_audit.sh score 2>/dev/null", True),
        ("mailcow.security.audit.detail", "/usr/local/bin/check_security_audit.sh detail 2>/dev/null", False),
    ]

    data = {}

    def _run_check(item):
        key, cmd, is_int = item
        return key, run_int(cmd) if is_int else run(cmd)

    # Parallel ausführen (max 6 Threads — I/O-bound)
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_run_check, c): c[0] for c in checks}
        for f in as_completed(futures):
            try:
                key, val = f.result(timeout=60)
                data[key] = val
            except Exception:
                pass

    # Cache schreiben
    try:
        with open(SLOW_CACHE + ".tmp", "w") as f:
            json.dump(data, f, indent=2)
        os.rename(SLOW_CACHE + ".tmp", SLOW_CACHE)
    except OSError:
        pass

    return data


def collect_mailflow(postfix_container):
    """Mailflow-Metriken via pflogsumm. Eigener 5-Min-Cache (#1)."""
    defaults = {
        # Grand Totals
        "mailcow.mail.received": 0,
        "mailcow.mail.delivered": 0,
        "mailcow.mail.forwarded": 0,
        "mailcow.mail.deferred": 0,
        "mailcow.mail.bounced": 0,
        "mailcow.mail.rejected": 0,
        "mailcow.mail.reject.rate": 0,
        "mailcow.mail.bytes.received": 0,
        "mailcow.mail.bytes.delivered": 0,
        "mailcow.mail.senders": 0,
        "mailcow.mail.recipients": 0,
        "mailcow.mail.sending.domains": 0,
        "mailcow.mail.recipient.domains": 0,
        # Top-Listen
        "mailcow.mail.top.senders": "-",
        "mailcow.mail.top.recipients": "-",
        "mailcow.mail.top.sending.domains": "-",
        "mailcow.mail.top.recipient.domains": "-",
        # Reject-Details
        "mailcow.mail.reject.rbl": 0,
        "mailcow.mail.reject.unknown.user": 0,
        "mailcow.mail.reject.relay.denied": 0,
        "mailcow.mail.reject.domain.notfound": 0,
        "mailcow.mail.reject.cleanup": 0,
        "mailcow.mail.reject.detail": "-",
        # Bounce-Details
        "mailcow.mail.bounce.detail": "-",
        # Warnings
        "mailcow.mail.warnings.sasl": 0,
        "mailcow.mail.warnings.tls": 0,
        "mailcow.mail.warnings.dns": 0,
        "mailcow.mail.warnings.postscreen": 0,
    }

    # 5-Min-Cache prüfen
    try:
        cache_age = now() - int(os.path.getmtime(MAILFLOW_CACHE))
        if cache_age <= MAILFLOW_MAX_AGE:
            with open(MAILFLOW_CACHE) as f:
                return json.load(f)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        pass

    if not postfix_container:
        return defaults

    # pflogsumm prüfen
    has_pflogsumm = run_cmd(["which", "pflogsumm"])
    if not has_pflogsumm:
        return defaults

    # Logs der letzten Stunde durch pflogsumm jagen
    raw = run(
        f'docker logs --since 1h "{postfix_container}" 2>&1 | pflogsumm 2>/dev/null',
        timeout=60)
    if not raw:
        return defaults

    data = dict(defaults)
    lines = raw.splitlines()

    # === Grand Totals parsen ===
    # Format: "   138   received" (nur Zahl + Keyword, NICHT "bytes received")
    grand_total_map = {
        "received": "mailcow.mail.received",
        "delivered": "mailcow.mail.delivered",
        "forwarded": "mailcow.mail.forwarded",
        "deferred": "mailcow.mail.deferred",
        "bounced": "mailcow.mail.bounced",
        "senders": "mailcow.mail.senders",
        "recipients": "mailcow.mail.recipients",
        "sending hosts/domains": "mailcow.mail.sending.domains",
        "recipient hosts/domains": "mailcow.mail.recipient.domains",
    }
    for line in lines:
        line_stripped = line.strip()

        # Exakter Match: "138   received" — NICHT "4977k  bytes received"
        for keyword, key in grand_total_map.items():
            m = re.match(r'^(\d+)\s+' + re.escape(keyword) + r'$', line_stripped)
            if m:
                data[key] = int(m.group(1))

        # Rejected mit Prozentzahl
        if "rejected" in line_stripped and "%" in line_stripped:
            match = re.match(r'\s*(\d+)\s+rejected\s+\((\d+)%\)', line_stripped)
            if match:
                data["mailcow.mail.rejected"] = int(match.group(1))
                data["mailcow.mail.reject.rate"] = int(match.group(2))

        # Bytes: "   4977k  bytes received"
        if "bytes received" in line_stripped:
            data["mailcow.mail.bytes.received"] = _parse_bytes(line_stripped)
        elif "bytes delivered" in line_stripped:
            data["mailcow.mail.bytes.delivered"] = _parse_bytes(line_stripped)

    # === Sektionen parsen ===
    sections = _split_sections(lines)

    # Top Sender (nach Anzahl)
    if "Senders by message count" in sections:
        top = _parse_top_list(sections["Senders by message count"], 5)
        data["mailcow.mail.top.senders"] = top if top else "-"

    # Top Empfänger (nach Anzahl)
    if "Recipients by message count" in sections:
        top = _parse_top_list(sections["Recipients by message count"], 5)
        data["mailcow.mail.top.recipients"] = top if top else "-"

    # Top Sender-Domains
    if "Host/Domain Summary: Messages Received" in sections:
        top = _parse_domain_list(sections["Host/Domain Summary: Messages Received"], 5)
        data["mailcow.mail.top.sending.domains"] = top if top else "-"

    # Top Empfänger-Domains
    if "Host/Domain Summary: Message Delivery" in sections:
        top = _parse_domain_list(sections["Host/Domain Summary: Message Delivery"], 5)
        data["mailcow.mail.top.recipient.domains"] = top if top else "-"

    # === Reject-Details ===
    if "message reject detail" in sections:
        reject_lines = sections["message reject detail"]
        reject_text = "\n".join(reject_lines)

        # RBL rejects (spamhaus, barracuda, etc.)
        rbl_count = 0
        for rl in reject_lines:
            if "blocked using" in rl:
                m = re.match(r'\s+blocked using .+ \(total: (\d+)\)', rl)
                if m:
                    rbl_count += int(m.group(1))
        data["mailcow.mail.reject.rbl"] = rbl_count

        # Unknown user
        m = re.search(r'User unknown in virtual mailbox table \(total: (\d+)\)', reject_text)
        if m:
            data["mailcow.mail.reject.unknown.user"] = int(m.group(1))

        # Relay access denied
        m = re.search(r'Relay access denied \(total: (\d+)\)', reject_text)
        if m:
            data["mailcow.mail.reject.relay.denied"] = int(m.group(1))

        # Domain not found
        m = re.search(r'Domain not found \(total: (\d+)\)', reject_text)
        if m:
            data["mailcow.mail.reject.domain.notfound"] = int(m.group(1))

        # Cleanup (rspamd/milter rejects)
        m = re.search(r'END-OF-MESSAGE \(total: (\d+)\)', reject_text)
        if m:
            data["mailcow.mail.reject.cleanup"] = int(m.group(1))

        # Kompakte Zusammenfassung der Reject-Gründe
        reject_parts = []
        if data["mailcow.mail.reject.rbl"] > 0:
            reject_parts.append(f'RBL:{data["mailcow.mail.reject.rbl"]}')
        if data["mailcow.mail.reject.unknown.user"] > 0:
            reject_parts.append(f'UnknownUser:{data["mailcow.mail.reject.unknown.user"]}')
        if data["mailcow.mail.reject.domain.notfound"] > 0:
            reject_parts.append(f'DomainNotFound:{data["mailcow.mail.reject.domain.notfound"]}')
        if data["mailcow.mail.reject.relay.denied"] > 0:
            reject_parts.append(f'RelayDenied:{data["mailcow.mail.reject.relay.denied"]}')
        if data["mailcow.mail.reject.cleanup"] > 0:
            reject_parts.append(f'Milter:{data["mailcow.mail.reject.cleanup"]}')
        data["mailcow.mail.reject.detail"] = ",".join(reject_parts) if reject_parts else "-"

    # === Bounce-Details ===
    if "message bounce detail (by relay)" in sections:
        bounce_lines = sections["message bounce detail (by relay)"]
        bounce_parts = []
        for bl in bounce_lines:
            m = re.match(r'\s+(\d+)\s+(.+)', bl.strip())
            if m and int(m.group(1)) > 0:
                bounce_parts.append(f'{m.group(2).strip()[:60]}:{m.group(1)}')
        data["mailcow.mail.bounce.detail"] = ",".join(bounce_parts[:5]) if bounce_parts else "-"

    # === Warnings zählen ===
    if "Warnings" in sections:
        warn_lines = sections["Warnings"]
        warn_text = "\n".join(warn_lines)
        data["mailcow.mail.warnings.sasl"] = _count_total(warn_text, "SASL")
        data["mailcow.mail.warnings.tls"] = _count_total(warn_text, "TLS")
        data["mailcow.mail.warnings.dns"] = _count_total(warn_text, "dnsblog")
        data["mailcow.mail.warnings.postscreen"] = _count_total(warn_text, "postscreen")

    # 5-Min-Cache schreiben
    try:
        with open(MAILFLOW_CACHE + ".tmp", "w") as f:
            json.dump(data, f, indent=2)
        os.rename(MAILFLOW_CACHE + ".tmp", MAILFLOW_CACHE)
    except OSError:
        pass

    return data


def _parse_bytes(line):
    """Parse pflogsumm byte Angaben: '4977k', '12m', '2g'."""
    m = re.match(r'\s*([\d.]+)([kmgKMG]?)\s+bytes', line.strip())
    if not m:
        return 0
    val = float(m.group(1))
    unit = m.group(2).lower()
    if unit == 'k':
        return int(val * 1024)
    elif unit == 'm':
        return int(val * 1024 * 1024)
    elif unit == 'g':
        return int(val * 1024 * 1024 * 1024)
    return int(val)


def _split_sections(lines):
    """Pflogsumm-Output in Sektionen aufteilen (Header → Zeilen)."""
    sections = {}
    current = None
    for line in lines:
        # Sektion erkannt wenn nächste Zeile nur --- enthält
        if line.strip() and all(c == '-' for c in line.strip()):
            continue
        # Neue Sektion: Zeile ohne führende Leerzeichen, gefolgt von ---
        if line and not line.startswith(" ") and not line.startswith("\t") and line.strip():
            current = line.strip()
            if current not in sections:
                sections[current] = []
        elif current and line.strip():
            sections[current].append(line)
    return sections


def _parse_top_list(lines, count=5):
    """Parse 'count  address' Listen aus pflogsumm."""
    entries = []
    for line in lines:
        # "     72   smmsp@cow.fox1.de"
        m = re.match(r'\s*(\d+)\s+(\S+)', line)
        if m:
            entries.append(f'{m.group(2)}:{m.group(1)}')
    return ",".join(entries[:count]) if entries else ""


def _parse_domain_list(lines, count=5):
    """Parse Domain-Listen (sent cnt / msg cnt Format)."""
    entries = []
    for line in lines:
        # " 19     1452k       0     1.6 s    3.6 s  linuser.de"
        # oder " 74   161382   cow.fox1.de"
        parts = line.split()
        if len(parts) >= 2:
            # Domain ist letztes Feld
            domain = parts[-1]
            cnt = parts[0]
            if cnt.isdigit() and "." in domain:
                entries.append(f'{domain}:{cnt}')
    return ",".join(entries[:count]) if entries else ""


def _count_total(text, keyword):
    """Zähle Vorkommnisse eines Keywords in Warning-Sektionen."""
    count = 0
    for line in text.splitlines():
        if keyword.lower() in line.lower():
            m = re.match(r'\s*(\d+)\s+', line)
            if m:
                count += int(m.group(1))
    return count


# ====================================================================
# HAUPTPROGRAMM
# ====================================================================

def main():
    start_time = time.time()
    errors = []  # #10: Fehler-Tracking pro Modul

    # Config lesen
    config = read_config()

    # Container einmal zentral erkennen (#2)
    ct = find_all_containers()

    # Backup-Pfad ermitteln
    backup_path = "/opt/backup"
    if not os.path.isdir(backup_path):
        backup_path = "/backup"

    # Alle Metriken sammeln — mit Error-Tracking (#10)
    metrics = {"timestamp": now()}
    module_times = {}

    modules = [
        ("postfix",      lambda: collect_postfix(ct["postfix"])),
        ("postfix_logs", lambda: collect_postfix_logs()),
        ("dovecot",      lambda: collect_dovecot(ct["dovecot"])),
        ("rspamd",       lambda: collect_rspamd(ct["rspamd"])),
        ("fail2ban",     lambda: collect_fail2ban(ct["netfilter"])),
        ("disk",         lambda: collect_disk(ct["dovecot"])),
        ("sync",         lambda: collect_sync()),
        ("mailbox",      lambda: collect_mailbox(ct["mysql"], config["dbpass"])),
        ("alias",        lambda: collect_alias(ct["mysql"], config["dbpass"])),
        ("lld",          lambda: collect_lld(ct["mysql"], config["dbpass"])),
        ("docker",       lambda: collect_docker_health()),
        ("sogo",         lambda: collect_sogo(ct["memcached"])),
        ("quarantine",   lambda: collect_quarantine(ct["mysql"], config["dbpass"])),
        ("queue_age",    lambda: collect_queue_age(ct["postfix"])),
        ("clamav",       lambda: collect_clamav(ct["clamd"])),
        ("watchdog",     lambda: collect_watchdog(ct["watchdog"])),
        ("acme",         lambda: collect_acme()),
        ("version",      lambda: collect_version()),
        ("meta",         lambda: collect_meta()),
        ("backup",       lambda: collect_backup(backup_path)),
        ("mailflow",     lambda: collect_mailflow(ct["postfix"])),  # #1: eigener 5-Min-Cache
        ("slow",         lambda: collect_slow()),                    # #6: parallelisiert
    ]

    for name, func in modules:
        t0 = time.time()
        try:
            metrics.update(func())
        except Exception as e:
            errors.append(f"{name}:{type(e).__name__}")
        module_times[name] = round(time.time() - t0, 2)

    # Config-Werte
    metrics["mailcow.config.hostname"] = config["hostname"]
    metrics["mailcow.config.timezone"] = config["timezone"]

    # Collector Self-Monitoring (#10)
    duration = round(time.time() - start_time, 2)
    metrics["mailcow.collector.running"] = 1
    metrics["mailcow.collector.age"] = 0
    metrics["mailcow.collector.keys"] = len(metrics) + 5  # +5 für diese Keys selbst
    metrics["mailcow.collector.duration"] = duration
    metrics["mailcow.collector.errors"] = len(errors)
    metrics["mailcow.collector.error.detail"] = ",".join(errors) if errors else "-"
    metrics["mailcow.collector.module.times"] = json.dumps(module_times)

    # JSON atomar schreiben
    try:
        with open(OUTPUT_TMP, "w") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        os.rename(OUTPUT_TMP, OUTPUT)
        os.chmod(OUTPUT, 0o644)
    except OSError as e:
        print(f"FEHLER: JSON schreiben fehlgeschlagen: {e}", file=sys.stderr)
        sys.exit(1)

    if errors:
        print(f"WARN: {len(metrics)} Metriken in {duration}s, {len(errors)} Fehler: {','.join(errors)} -> {OUTPUT}")
    else:
        print(f"OK: {len(metrics)} Metriken in {duration}s geschrieben -> {OUTPUT}")


if __name__ == "__main__":
    main()
