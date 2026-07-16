#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Alexander Fox (PlaNet Fox)
"""
Fix two bugs introduced by the docker-exec batching optimisation.

Bug 1 - Postfix PID not stripped
--------------------------------
Postfix writes master.pid right-aligned with padding:

    "                             394"

The unbatched version read it in Python and called .strip(). The batched version
does it in the shell:

    PID=$(cat /var/spool/postfix/pid/master.pid 2>/dev/null)
    [ -n "$PID" ] && [ -d "/proc/$PID" ] && echo 1 || echo 0

Command substitution strips trailing newlines but NOT leading spaces, so the
test becomes [ -d "/proc/                             394" ] -> false -> 0.
Result: "Postfix not running" fires permanently at DISASTER severity while
Postfix is perfectly healthy.

Bug 2 - a failing command discards the whole batch
-------------------------------------------------
run() returns its `default` ("") whenever the return code is non-zero. For a
command list the return code is that of the LAST command, so any batch whose
final command can fail throws away everything the earlier commands produced.

Observed: the rspamd batch ends with `rspamc stat`. When that fails, wget's
JSON (already fetched successfully) is discarded and all 18 rspamd metrics fall
back to 0 - including scanned, which is a cumulative counter that is never
legitimately 0 on a running server.

The fix appends `; exit 0` to every batched sh -c, so the shell always succeeds
and the section parser simply sees empty sections for the parts that failed.
Partial data beats no data.

Usage:
    ./fix_collector.py <mailcow-collector.py> [-o <out.py>]
"""

import argparse
import re
import sys

# The batched sh -c calls. Each entry: a marker that identifies the batch and
# the last command in it (where `; exit 0` has to go).
BATCH_TAILS = [
    # postfix
    ("postconf mail_version 2>/dev/null\n'", "postconf mail_version 2>/dev/null; exit 0\n'"),
    # dovecot: ends with the awk block, closing quote on its own line
    # rspamd
    ("echo ===BAYES=== && rspamc stat 2>/dev/null'",
     "echo ===BAYES===; rspamc stat 2>/dev/null; exit 0'"),
    # vmail / disk
    ("echo ===DU=== && du -sm /var/vmail 2>/dev/null | cut -f1'",
     "echo ===DU===; du -sm /var/vmail 2>/dev/null | cut -f1; exit 0'"),
]

PID_OLD = "PID=$(cat /var/spool/postfix/pid/master.pid 2>/dev/null)"
# tr -dc '0-9' keeps digits only: kills the padding spaces and any stray newline.
PID_NEW = "PID=$(cat /var/spool/postfix/pid/master.pid 2>/dev/null | tr -dc '0-9')"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("collector")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()

    src = open(args.collector).read()
    orig = src
    report = []

    # --- Bug 1 -------------------------------------------------------------
    if PID_OLD in src:
        src = src.replace(PID_OLD, PID_NEW)
        report.append("postfix PID: padding entfernt (tr -dc '0-9')")
    elif PID_NEW in src:
        report.append("postfix PID: bereits gefixt")
    else:
        report.append("WARN postfix PID: Muster nicht gefunden")

    # --- Bug 2 -------------------------------------------------------------
    for old, new in BATCH_TAILS:
        if old in src:
            src = src.replace(old, new)
            report.append(f"batch abgesichert: ...{old[-38:]}")
        elif new in src:
            report.append("batch bereits abgesichert")

    # Remaining batches that end without an explicit exit 0: the agent and
    # clamav ones are built from concatenated string literals, so patch their
    # closing fragments individually.
    extra = [
        ('"echo ===LOG=== && tail -100 /var/log/zabbix/zabbix_agent2.log 2>/dev/null"',
         '"echo ===LOG===; tail -100 /var/log/zabbix/zabbix_agent2.log 2>/dev/null; exit 0"'),
    ]
    for old, new in extra:
        if old in src:
            src = src.replace(old, new)
            report.append("batch abgesichert: zabbix-agent log")

    out = args.output or args.collector
    open(out, "w").write(src)

    for line in report:
        print("  " + line)
    print(f"  geaendert: {'ja' if src != orig else 'nein'}")
    print("  geschrieben:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
