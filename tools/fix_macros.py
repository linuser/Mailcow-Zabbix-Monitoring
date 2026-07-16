#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Etappe 1 der Zabbix-Guideline-Konformitaet: zwei echte Fehler beheben.

1) TOTE MACROS VERDRAHTEN
   Das Template definiert 4 User-Macros, die kein einziger Trigger benutzt.
   Wer {$MAILCOW.DISK.WARN} auf 95 stellt, aendert nichts - der Trigger
   vergleicht hart gegen 90. Das ist schlimmer als gar keine Macros: es sieht
   nach Konfigurierbarkeit aus, ohne welche zu sein.

   Wichtig: Schwellen haben bei den Hysterese-Triggern ein Gegenstueck in der
   recovery_expression. Wird nur die Problem-Seite zum Macro, kann der Nutzer
   die Recovery-Schwelle UEBER die Problem-Schwelle schieben (WARN=20, Recovery
   <30) - der Trigger flappt dann dauerhaft. Jede Schwelle bekommt deshalb ihr
   Paar.

2) {ITEM.VALUE} AUS DEN TRIGGER-NAMEN
   Zabbix-Guideline: "Don't use {ITEM.LASTVALUE1-9} macros right in trigger
   names. [...] Use it in the operational data field instead."
   Der Problemname wird bei der Event-Erzeugung eingefroren - der angezeigte
   Wert veraltet also sofort. opdata wird dagegen live aktualisiert.

Idempotent: mehrfach ausfuehrbar.
"""
import re
import sys

import yaml

TPL = "mailcow_complete_monitoring_v45"

# --- 1. Macros -------------------------------------------------------------
# vorhanden (aber unbenutzt): QUEUE.WARN=50, CERT.WARN=14, DISK.WARN=90,
#                             RBL.CRITICAL=1
# neu noetig: die Gegenstuecke der Hysterese + abweichende Schwellen
NEW_MACROS = [
    ("{$MAILCOW.QUEUE.RECOVER}", "30",
     "Mail queue trigger resolves below this value (must be < QUEUE.WARN)"),
    ("{$MAILCOW.DISK.RECOVER}", "85",
     "Disk trigger resolves below this percentage (must be < DISK.WARN)"),
    ("{$MAILCOW.DISK.VMAIL.WARN}", "85",
     "Mail storage warns earlier than other filesystems"),
    ("{$MAILCOW.DISK.VMAIL.RECOVER}", "80",
     "vmail trigger resolves below this percentage (must be < DISK.VMAIL.WARN)"),
    ("{$MAILCOW.CERT.CRIT}", "7",
     "Certificate expiry: critical threshold in days (must be < CERT.WARN)"),
]

MACRO_DESCRIPTIONS = {
    "{$MAILCOW.QUEUE.WARN}": "Mail queue length that triggers a problem",
    "{$MAILCOW.CERT.WARN}": "Certificate expiry: warning threshold in days",
    "{$MAILCOW.DISK.WARN}": "Disk usage percentage that triggers a problem",
    "{$MAILCOW.RBL.CRITICAL}": "Number of RBL listings that triggers a problem",
}

# (item-key, alter ausdruck) -> neuer ausdruck
EXPR = {
    ("postfix.pfmailq",
     f"min(/{TPL}/postfix.pfmailq,5m)>50"):
        f"min(/{TPL}/postfix.pfmailq,5m)>{{$MAILCOW.QUEUE.WARN}}",
    ("mailcow.tls.cert.days.443",
     f"last(/{TPL}/mailcow.tls.cert.days.443)<14"):
        f"last(/{TPL}/mailcow.tls.cert.days.443)<{{$MAILCOW.CERT.WARN}}",
    ("mailcow.security.rbl.listed",
     f"last(/{TPL}/mailcow.security.rbl.listed)>0"):
        f"last(/{TPL}/mailcow.security.rbl.listed)>={{$MAILCOW.RBL.CRITICAL}}",
    ("mailcow.disk.root.used",
     f"last(/{TPL}/mailcow.disk.root.used)>90"):
        f"last(/{TPL}/mailcow.disk.root.used)>{{$MAILCOW.DISK.WARN}}",
    ("mailcow.disk.docker.used",
     f"last(/{TPL}/mailcow.disk.docker.used)>90"):
        f"last(/{TPL}/mailcow.disk.docker.used)>{{$MAILCOW.DISK.WARN}}",
    ("mailcow.disk.log.used",
     f"last(/{TPL}/mailcow.disk.log.used)>90"):
        f"last(/{TPL}/mailcow.disk.log.used)>{{$MAILCOW.DISK.WARN}}",
    ("mailcow.disk.vmail.used",
     f"last(/{TPL}/mailcow.disk.vmail.used)>85"):
        f"last(/{TPL}/mailcow.disk.vmail.used)>{{$MAILCOW.DISK.VMAIL.WARN}}",
    ("mailcow.acme.cert.days.left",
     f"last(/{TPL}/mailcow.acme.cert.days.left)<14"):
        f"last(/{TPL}/mailcow.acme.cert.days.left)<{{$MAILCOW.CERT.WARN}}",
    ("mailcow.acme.cert.days.left",
     f"last(/{TPL}/mailcow.acme.cert.days.left)<7"):
        f"last(/{TPL}/mailcow.acme.cert.days.left)<{{$MAILCOW.CERT.CRIT}}",
}

# recovery_expressions - das Gegenstueck, sonst bricht die Hysterese
RECOV = {
    ("postfix.pfmailq",
     f"max(/{TPL}/postfix.pfmailq,5m)<30"):
        f"max(/{TPL}/postfix.pfmailq,5m)<{{$MAILCOW.QUEUE.RECOVER}}",
    ("mailcow.disk.root.used",
     f"last(/{TPL}/mailcow.disk.root.used)<85"):
        f"last(/{TPL}/mailcow.disk.root.used)<{{$MAILCOW.DISK.RECOVER}}",
    ("mailcow.disk.docker.used",
     f"last(/{TPL}/mailcow.disk.docker.used)<85"):
        f"last(/{TPL}/mailcow.disk.docker.used)<{{$MAILCOW.DISK.RECOVER}}",
    ("mailcow.disk.log.used",
     f"last(/{TPL}/mailcow.disk.log.used)<85"):
        f"last(/{TPL}/mailcow.disk.log.used)<{{$MAILCOW.DISK.RECOVER}}",
    ("mailcow.disk.vmail.used",
     f"last(/{TPL}/mailcow.disk.vmail.used)<80"):
        f"last(/{TPL}/mailcow.disk.vmail.used)<{{$MAILCOW.DISK.VMAIL.RECOVER}}",
}

# --- 2. {ITEM.VALUE} raus aus den Namen, rein in opdata --------------------
# alter name -> (neuer name, opdata)
NAMES = {
    "Mailcow: Postscreen rejecting heavily ({ITEM.VALUE}) on {HOST.NAME}":
        ("Mailcow: Postscreen rejecting heavily on {HOST.NAME}",
         "{ITEM.LASTVALUE1} rejects/h"),
    "Mailcow: TLS cert expires in {ITEM.VALUE} days (443) on {HOST.NAME}":
        ("Mailcow: TLS certificate expires soon (443) on {HOST.NAME}",
         "{ITEM.LASTVALUE1} days left"),
    "Mailcow: High number of banned IPs ({ITEM.VALUE}) on {HOST.NAME}":
        ("Mailcow: High number of banned IPs on {HOST.NAME}",
         "{ITEM.LASTVALUE1} IPs banned"),
    "Mailcow: IP on {ITEM.VALUE} RBL list(s): "
    f"{{?last(/{TPL}/mailcow.security.rbl.detail)}}"
    " on {HOST.NAME}":
        ("Mailcow: IP listed on RBL on {HOST.NAME}",
         "{ITEM.LASTVALUE1} list(s): "
         f"{{?last(/{TPL}/mailcow.security.rbl.detail)}}"),
    "Mailcow: Security audit score critically low ({ITEM.VALUE}/7) on {HOST.NAME}":
        ("Mailcow: Security audit score critically low on {HOST.NAME}",
         "score {ITEM.LASTVALUE1} of 7"),
    "Mailcow: {ITEM.VALUE} commits behind on {HOST.NAME}":
        ("Mailcow: Mailcow update available on {HOST.NAME}",
         "{ITEM.LASTVALUE1} commits behind"),
    "Mailcow: {ITEM.VALUE} mailbox(es) over 80% quota on {HOST.NAME}":
        ("Mailcow: Mailboxes over 80% quota on {HOST.NAME}",
         "{ITEM.LASTVALUE1} mailbox(es)"),
    "Mailcow: Mail volume spike - {ITEM.VALUE} received (5x baseline) on {HOST.NAME}":
        ("Mailcow: Mail volume spike on {HOST.NAME}",
         "{ITEM.LASTVALUE1} received/h (>5x weekly baseline)"),
    "Mailcow: Mail volume drop - {ITEM.VALUE} received (<20% baseline) on {HOST.NAME}":
        ("Mailcow: Mail volume drop on {HOST.NAME}",
         "{ITEM.LASTVALUE1} received/h (<20% of weekly baseline)"),
    "Mailcow: {ITEM.VALUE} deferred mails on {HOST.NAME}":
        ("Mailcow: Deferred mails on {HOST.NAME}",
         "{ITEM.LASTVALUE1} deferred/h"),
    "Mailcow: Deferred spike - {ITEM.VALUE} deferred (5x baseline) on {HOST.NAME}":
        ("Mailcow: Deferred mail spike on {HOST.NAME}",
         "{ITEM.LASTVALUE1} deferred/h (>5x weekly baseline)"),
    "Mailcow: {ITEM.VALUE} bounced mails on {HOST.NAME}":
        ("Mailcow: Bounced mails on {HOST.NAME}",
         "{ITEM.LASTVALUE1} bounced/h"),
    "Mailcow: Bounce spike - {ITEM.VALUE} bounced (5x baseline) on {HOST.NAME}":
        ("Mailcow: Bounce spike on {HOST.NAME}",
         "{ITEM.LASTVALUE1} bounced/h (>5x weekly baseline)"),
    "Mailcow: Reject spike - {ITEM.VALUE} rejected (10x baseline) on {HOST.NAME}":
        ("Mailcow: Reject spike on {HOST.NAME}",
         "{ITEM.LASTVALUE1} rejected/h (>10x weekly baseline)"),
    "Mailcow: Reject rate {ITEM.VALUE}% on {HOST.NAME}":
        ("Mailcow: Mail reject rate too high on {HOST.NAME}",
         "{ITEM.LASTVALUE1}% of incoming mail rejected"),
    "Mailcow: {ITEM.VALUE} SASL warnings on {HOST.NAME}":
        ("Mailcow: High number of SASL warnings on {HOST.NAME}",
         "{ITEM.LASTVALUE1} warnings/h"),
    "Mailcow: ClamAV definitions {ITEM.VALUE} days old on {HOST.NAME}":
        ("Mailcow: ClamAV definitions outdated on {HOST.NAME}",
         "{ITEM.LASTVALUE1} days old"),
    "Mailcow: ClamAV definitions critically outdated ({ITEM.VALUE} days) on {HOST.NAME}":
        ("Mailcow: ClamAV definitions critically outdated on {HOST.NAME}",
         "{ITEM.LASTVALUE1} days old"),
    "Mailcow: Watchdog health {ITEM.VALUE}% on {HOST.NAME}":
        ("Mailcow: Watchdog health degraded on {HOST.NAME}",
         "{ITEM.LASTVALUE1}% healthy"),
    "Mailcow: Watchdog health CRITICAL {ITEM.VALUE}% on {HOST.NAME}":
        ("Mailcow: Watchdog health critical on {HOST.NAME}",
         "{ITEM.LASTVALUE1}% healthy"),
    "Mailcow: Bayes filter poorly trained ({ITEM.VALUE} messages) on {HOST.NAME}":
        ("Mailcow: Bayes filter poorly trained on {HOST.NAME}",
         "{ITEM.LASTVALUE1} messages learned"),
    "Mailcow: ACME cert expires in {ITEM.VALUE} days on {HOST.NAME}":
        ("Mailcow: ACME certificate expires soon on {HOST.NAME}",
         "{ITEM.LASTVALUE1} days left"),
    "Mailcow: ACME cert expires in {ITEM.VALUE} days - CRITICAL on {HOST.NAME}":
        ("Mailcow: ACME certificate expiry critical on {HOST.NAME}",
         "{ITEM.LASTVALUE1} days left"),
    "Mailcow: Docker restart count high ({ITEM.VALUE}) on {HOST.NAME}":
        ("Mailcow: Docker restart count high on {HOST.NAME}",
         "{ITEM.LASTVALUE1} restarts"),
    "Mailcow: Quarantine has {ITEM.VALUE} mails on {HOST.NAME}":
        ("Mailcow: Many mails in quarantine on {HOST.NAME}",
         "{ITEM.LASTVALUE1} mails"),
    "Mailcow: Virus mails in quarantine ({ITEM.VALUE}) on {HOST.NAME}":
        ("Mailcow: Virus mails in quarantine on {HOST.NAME}",
         "{ITEM.LASTVALUE1} virus mails"),
    "Mailcow: {ITEM.VALUE} deferred mails in queue on {HOST.NAME}":
        ("Mailcow: Deferred mails in queue on {HOST.NAME}",
         "{ITEM.LASTVALUE1} mails in deferred queue"),
    "Mailcow: Deferred mail stuck for {ITEM.VALUE}h on {HOST.NAME}":
        ("Mailcow: Deferred mail stuck in queue on {HOST.NAME}",
         "oldest mail {ITEM.LASTVALUE1}h old"),
}


def dump_safely(doc, path):
    """YAML schreiben, ohne die zwei Quoting-Fallen zu reissen.

    yaml.safe_dump quotet nur, was PyYAMLs eigener Resolver fuer mehrdeutig
    haelt. Zabbix' Parser folgt aber YAML 1.1:
      - der nackte Key `y` ist dort ein Boolean (true) - die Widget-Position
        geht verloren
      - eine Hex-Farbe wie 007700 ist oktal, 888888 wird zu einem Integer
    Offizielle Zabbix-Exporte quoten beides. Ohne diese Nachbearbeitung macht
    ein safe_dump die Datei unimportierbar - genau der Fehler, den v1.2 behoben
    hat. Gleiche Logik wie in fix_dashboards.py.
    """
    text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=4096)
    text = re.sub(r"^(\s*)y:", r"\1'y':", text, flags=re.M)
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if ".color." in line and line.strip().startswith("name:"):
            j = i + 1
            if j < len(lines):
                m = re.match(r"^(\s*value: )(?!['\"])(.+)$", lines[j])
                if m:
                    lines[j] = f"{m.group(1)}'{m.group(2)}'"
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def verify(path, before):
    """Nachrechnen, dass das Schreiben nichts kaputtgemacht hat."""
    text = open(path).read()
    checks = {
        "'y': gequotet": (len(re.findall(r"^\s*'y':", text, re.M)), before["y"]),
        "farben gequotet": (len(re.findall(r"value: '[0-9A-Fa-f]{6}'", text)),
                            before["colors"]),
    }
    ok = True
    for name, (now, was) in checks.items():
        state = "OK" if now == was else "!! REGRESSION"
        print(f"  {state}  {name}: {was} -> {now}")
        if now != was:
            ok = False
    return ok


def main(path):
    with open(path) as f:
        raw = f.read()
    before = {
        "y": len(re.findall(r"^\s*'y':", raw, re.M)),
        "colors": len(re.findall(r"value: '[0-9A-Fa-f]{6}'", raw)),
    }
    doc = yaml.safe_load(raw)
    tpl = doc["zabbix_export"]["templates"][0]

    # --- macros ergaenzen + beschreiben ---
    macros = tpl.setdefault("macros", [])
    have = {m["macro"] for m in macros}
    added = 0
    for name, val, desc in NEW_MACROS:
        if name not in have:
            macros.append({"macro": name, "value": val, "description": desc})
            added += 1
    for m in macros:
        if m["macro"] in MACRO_DESCRIPTIONS and not m.get("description"):
            m["description"] = MACRO_DESCRIPTIONS[m["macro"]]
    macros.sort(key=lambda m: m["macro"])

    expr_fixed = recov_fixed = name_fixed = 0
    for item in tpl.get("items", []):
        key = item["key"]
        for tr in item.get("triggers", []):
            new = EXPR.get((key, tr.get("expression")))
            if new:
                tr["expression"] = new
                expr_fixed += 1
            new = RECOV.get((key, tr.get("recovery_expression")))
            if new:
                tr["recovery_expression"] = new
                recov_fixed += 1
            hit = NAMES.get(tr["name"])
            if hit:
                tr["name"], tr["opdata"] = hit
                name_fixed += 1

    dump_safely(doc, path)

    print(f"macros added:                {added}")
    print(f"expressions -> macro:        {expr_fixed}")
    print(f"recovery_expr -> macro:      {recov_fixed}")
    print(f"names cleaned -> opdata:     {name_fixed}")
    print("quoting-gegenprobe:")
    return 0 if verify(path, before) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1
                  else "templates/mailcow-complete-monitoring.yaml"))
