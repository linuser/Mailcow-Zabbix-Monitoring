#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Etappe 2: Zabbix-Guideline-Konformitaet der Trigger und des Templates.

1) {HOST.NAME} AUS DEN TRIGGER-NAMEN
   Guideline: "Trigger names should not use the {HOST.NAME} macro to keep names
   shorter. Consider getting this data from the host column."
   Zabbix zeigt den Host in jeder Problem-Ansicht ohnehin in einer eigenen
   Spalte an - im Namen ist er redundant und macht ihn nur laenger.

2) event_name FUER DIE SCHWELLE
   Guideline: "Consider explaining why trigger fired (threshold) in parenthesis.
   Use the event name field for it, to keep the trigger name short."
   Wichtiger Nebeneffekt: Nach Etappe 1 sind die Schwellen Macros, die Namen
   nannten aber weiter feste Zahlen ("Root disk >90%"). Wer {$MAILCOW.DISK.WARN}
   auf 95 stellt, bekaeme einen Namen, der 90 behauptet. event_name loest das
   Macro auf - der Name bleibt generisch, die Meldung nennt die echte Schwelle.

3) scope-TAGS
   Guideline: "Use at least one scope tag with these values: performance,
   availability, capacity, notice, security."
   Die Items tragen bereits component+application. Problem-Events erben die Tags
   der ganzen Kette (Template -> Host -> Item -> Trigger), component kommt also
   schon vom Item; die Trigger brauchen nur scope. Die 5 vorhandenen
   scope: anomaly werden ersetzt - 'anomaly' gehoert nicht zum Modell.

4) TEMPLATE-TAGS
   Guideline: mindestens ein class- und ein target-Tag je Template.

Idempotent.
"""
import re
import sys

import yaml

TPL = "mailcow_complete_monitoring_v45"

# --- scope je trigger ------------------------------------------------------
# availability: Dienst/Port/UI weg, Datenfluss steht
# security:     Angriff, Fehlkonfiguration mit Sicherheitsfolge, Zertifikate
# capacity:     Ressource laeuft voll
# performance:  Durchsatz/Latenz auffaellig
# notice:       Hinweis, nichts ist kaputt
SCOPE = {
    "Mailcow: Postfix not running": ["availability"],
    "Mailcow: Mail queue too large": ["capacity", "performance"],
    "Mailcow: Postfix errors detected": ["notice"],
    "Mailcow: Postscreen rejecting heavily": ["security"],
    "Mailcow: HTTPS not reachable": ["availability"],
    "Mailcow: SMTP submission not reachable": ["availability"],
    "Mailcow: IMAPS not reachable": ["availability"],
    "Mailcow: Web UI not accessible": ["availability"],
    "Mailcow: TLS certificate expires soon (443)": ["security"],
    "Mailcow: High number of banned IPs": ["security"],
    "Mailcow: IP listed on RBL": ["security"],
    "Mailcow: OPEN RELAY DETECTED": ["security"],
    "Mailcow: Security audit score critically low": ["security"],
    "Mailcow: SPF record missing for one or more domains": ["security"],
    "Mailcow: DKIM record missing for one or more domains": ["security"],
    "Mailcow: DMARC record missing for one or more domains": ["security"],
    "Mailcow: PTR record invalid": ["security"],
    "Mailcow: Root disk >90%": ["capacity"],
    "Mailcow: Docker disk >90%": ["capacity"],
    "Mailcow: Log disk >90%": ["capacity"],
    "Mailcow: vmail disk >85%": ["capacity"],
    "Mailcow: Update available": ["notice"],
    "Mailcow: Mailcow update available": ["notice"],
    "Mailcow: Rspamd not running": ["availability"],
    "Mailcow: Dovecot not running": ["availability"],
    "Mailcow: Dovecot IMAP errors": ["notice"],
    "Mailcow: Backup older than 48h": ["notice"],
    "Mailcow: Backup disk low (<10% free)": ["capacity"],
    "Mailcow: Backup directory missing": ["notice"],
    "Mailcow: Backup contains empty files": ["notice"],
    "Mailcow: Sync jobs failed": ["notice"],
    "Mailcow: Sync jobs never executed": ["notice"],
    "Mailcow: Sync job not run for >48h": ["notice"],
    "Mailcow: Sync job stuck": ["notice"],
    "Mailcow: Mailboxes over 80% quota": ["capacity"],
    "Mailcow: Mail volume spike": ["performance"],
    "Mailcow: Mail volume drop": ["availability"],
    "Mailcow: Deferred mails": ["performance"],
    "Mailcow: Deferred mail spike": ["performance"],
    "Mailcow: Bounced mails": ["performance"],
    "Mailcow: Bounce spike": ["performance"],
    "Mailcow: Reject spike": ["performance"],
    "Mailcow: Mail reject rate too high": ["performance"],
    "Mailcow: High number of SASL warnings": ["security"],
    "Mailcow: ClamAV not running": ["availability", "security"],
    "Mailcow: ClamAV definitions outdated": ["security"],
    "Mailcow: ClamAV definitions critically outdated": ["security"],
    "Mailcow: Watchdog health degraded": ["availability"],
    "Mailcow: Watchdog health critical": ["availability"],
    "Mailcow: Bayes filter poorly trained": ["notice"],
    "Mailcow: ACME certificate expires soon": ["security"],
    "Mailcow: ACME certificate expiry critical": ["security"],
    "Mailcow: Zabbix agent not running": ["availability"],
    "Mailcow: Zabbix agent errors": ["notice"],
    "Mailcow: Collector service down": ["availability"],
    "Mailcow: Collector data stale (>5min)": ["availability"],
    "Mailcow: Collector module errors detected": ["notice"],
    "Mailcow: Docker restart count high": ["availability"],
    "Mailcow: SOGo Memcached cache pressure (>50 evictions/5m)": ["performance"],
    "Mailcow: Many mails in quarantine": ["capacity"],
    "Mailcow: Virus mails in quarantine": ["security"],
    "Mailcow: Deferred mails in queue": ["performance"],
    "Mailcow: Deferred mail stuck in queue": ["performance"],
}

# --- umbenennungen: schwelle raus aus dem namen, rein ins event_name -------
# alter name -> (neuer name, event_name)
RENAME = {
    "Mailcow: Root disk >90%": (
        "Mailcow: Root disk usage is too high",
        "Mailcow: Root disk usage is too high (over {$MAILCOW.DISK.WARN}%)"),
    "Mailcow: Docker disk >90%": (
        "Mailcow: Docker disk usage is too high",
        "Mailcow: Docker disk usage is too high (over {$MAILCOW.DISK.WARN}%)"),
    "Mailcow: Log disk >90%": (
        "Mailcow: Log disk usage is too high",
        "Mailcow: Log disk usage is too high (over {$MAILCOW.DISK.WARN}%)"),
    "Mailcow: vmail disk >85%": (
        "Mailcow: Mail storage usage is too high",
        "Mailcow: Mail storage usage is too high "
        "(over {$MAILCOW.DISK.VMAIL.WARN}%)"),
    "Mailcow: Mail queue too large": (
        "Mailcow: Mail queue is too large",
        "Mailcow: Mail queue is too large "
        "(over {$MAILCOW.QUEUE.WARN} mails for 5m)"),
    "Mailcow: TLS certificate expires soon (443)": (
        "Mailcow: TLS certificate expires soon (443)",
        "Mailcow: TLS certificate expires soon "
        "(less than {$MAILCOW.CERT.WARN} days left, port 443)"),
    "Mailcow: ACME certificate expires soon": (
        "Mailcow: ACME certificate expires soon",
        "Mailcow: ACME certificate expires soon "
        "(less than {$MAILCOW.CERT.WARN} days left)"),
    "Mailcow: ACME certificate expiry critical": (
        "Mailcow: ACME certificate expiry critical",
        "Mailcow: ACME certificate expiry critical "
        "(less than {$MAILCOW.CERT.CRIT} days left)"),
    "Mailcow: IP listed on RBL": (
        "Mailcow: IP listed on RBL",
        "Mailcow: IP listed on {$MAILCOW.RBL.CRITICAL} or more RBLs"),
}

TEMPLATE_TAGS = [
    {"tag": "class", "value": "software"},
    {"tag": "target", "value": "mailcow"},
]


# --- LLD-trigger-prototypen -----------------------------------------------
# Wurden beim ersten Anlauf uebersehen: das Script lief nur ueber items, nicht
# ueber discovery_rules[*].trigger_prototypes. Ergebnis waeren 63 konforme
# Trigger und 8 nicht-konforme Prototypen im selben Template gewesen.
# Die Namen folgen der Prototyp-Regel bereits ("Prefix names with the entity
# [...] use square brackets"), es fehlen {HOST.NAME}-Entfernung, scope, opdata
# und die Schwellen-Macros.
PROTO = {
    "Mailcow: Domain [{#DOMAIN}] quota usage >80%": {
        "name": "Mailcow: Domain [{#DOMAIN}] quota usage is high",
        "event_name": "Mailcow: Domain [{#DOMAIN}] quota usage is high "
                      "(over {$MAILCOW.QUOTA.WARN}%)",
        "expression": "last(/{T}/mailcow.domain.usage_pct[{{#DOMAIN}}])"
                      ">{$MAILCOW.QUOTA.WARN}",
        "opdata": "{ITEM.LASTVALUE1}% used",
        "scope": ["capacity"],
    },
    "Mailcow: Domain [{#DOMAIN}] quota usage >95%": {
        "name": "Mailcow: Domain [{#DOMAIN}] quota usage is critical",
        "event_name": "Mailcow: Domain [{#DOMAIN}] quota usage is critical "
                      "(over {$MAILCOW.QUOTA.CRIT}%)",
        "expression": "last(/{T}/mailcow.domain.usage_pct[{{#DOMAIN}}])"
                      ">{$MAILCOW.QUOTA.CRIT}",
        "opdata": "{ITEM.LASTVALUE1}% used",
        "scope": ["capacity"],
    },
    "Mailcow: Mailbox [{#MAILBOX}] quota >80%": {
        "name": "Mailcow: Mailbox [{#MAILBOX}] quota usage is high",
        "event_name": "Mailcow: Mailbox [{#MAILBOX}] quota usage is high "
                      "(over {$MAILCOW.QUOTA.WARN}%)",
        "expression": "last(/{T}/mailcow.mailbox.lld.usage_pct[{{#MAILBOX}}])"
                      ">{$MAILCOW.QUOTA.WARN}",
        "opdata": "{ITEM.LASTVALUE1}% used",
        "scope": ["capacity"],
    },
    "Mailcow: Mailbox [{#MAILBOX}] quota >95%": {
        "name": "Mailcow: Mailbox [{#MAILBOX}] quota usage is critical",
        "event_name": "Mailcow: Mailbox [{#MAILBOX}] quota usage is critical "
                      "(over {$MAILCOW.QUOTA.CRIT}%)",
        "expression": "last(/{T}/mailcow.mailbox.lld.usage_pct[{{#MAILBOX}}])"
                      ">{$MAILCOW.QUOTA.CRIT}",
        "opdata": "{ITEM.LASTVALUE1}% used",
        "scope": ["capacity"],
    },
    "Mailcow: Syncjob [{#SYNCJOB_USER}] failed": {
        "name": "Mailcow: Syncjob [{#SYNCJOB_USER}] failed",
        "scope": ["notice"],
    },
    "Mailcow: Syncjob [{#SYNCJOB_USER}] not run for >48h": {
        "name": "Mailcow: Syncjob [{#SYNCJOB_USER}] has not run recently",
        "event_name": "Mailcow: Syncjob [{#SYNCJOB_USER}] has not run for "
                      "{$MAILCOW.SYNCJOB.AGE.MAX}h",
        "expression": "last(/{T}/mailcow.syncjob.age_hours[{{#SYNCJOB_ID}}])"
                      ">{$MAILCOW.SYNCJOB.AGE.MAX}",
        "opdata": "last run {ITEM.LASTVALUE1}h ago",
        "scope": ["notice"],
    },
    "Mailcow: Container [{#CONTAINER}] restarted": {
        "name": "Mailcow: Container [{#CONTAINER}] has been restarted",
        "scope": ["notice"],
    },
    "Mailcow: Container [{#CONTAINER}] memory >25%": {
        "name": "Mailcow: Container [{#CONTAINER}] memory usage is high",
        "event_name": "Mailcow: Container [{#CONTAINER}] memory usage is high "
                      "(over {$MAILCOW.CONTAINER.MEM.MAX}%)",
        "expression": "last(/{T}/mailcow.docker.mem_pct[{{#CONTAINER}}])"
                      ">{$MAILCOW.CONTAINER.MEM.MAX}",
        "opdata": "{ITEM.LASTVALUE1}% of host memory",
        "scope": ["capacity"],
    },
}

PROTO_MACROS = [
    ("{$MAILCOW.QUOTA.WARN}", "80",
     "Domain/mailbox quota: warning threshold in percent"),
    ("{$MAILCOW.QUOTA.CRIT}", "95",
     "Domain/mailbox quota: critical threshold in percent"),
    ("{$MAILCOW.SYNCJOB.AGE.MAX}", "48",
     "Sync job is considered stale after this many hours"),
    ("{$MAILCOW.CONTAINER.MEM.MAX}", "25",
     "Container memory usage that triggers a problem, in percent of host memory"),
]


def fix_prototypes(tpl):
    changed = 0
    for rule in tpl.get("discovery_rules", []):
        for tp in rule.get("trigger_prototypes", []):
            base = tp["name"].replace(" on {HOST.NAME}", "")
            spec = PROTO.get(base)
            if not spec:
                continue
            tp["name"] = spec["name"]
            if "event_name" in spec:
                tp["event_name"] = spec["event_name"]
            if "expression" in spec:
                tp["expression"] = spec["expression"].replace("{T}", TPL)
            if "opdata" in spec:
                tp["opdata"] = spec["opdata"]
            keep = [t for t in tp.get("tags", []) if t["tag"] != "scope"]
            tp["tags"] = keep + [{"tag": "scope", "value": s}
                                 for s in spec["scope"]]
            changed += 1
    return changed


NO_DEPENDENCY = {"mailcow.mail.received"}
SAME_PRIORITY_RULES = [
    ("mailcow.mail.deferred", "spike", "deferred mails"),
]


def rebuild_dependencies(tpl):
    """Dependencies nach dem Umbenennen neu aufbauen.

    Zabbix identifiziert das Ziel einer Dependency ueber name UND expression.
    Etappe 1 und 2 haben beides geaendert - die vorhandenen Referenzen zeigten
    danach auf Trigger, die es nicht mehr gibt, und der Import waere gescheitert.
    Statt alte auf neue Namen zu mappen, werden sie aus dem aktuellen Stand neu
    erzeugt: identische Logik wie in fix_triggers.py (niedrigere Schwelle haengt
    an der hoeheren), nur eben mit den jetzt gueltigen Namen.
    """
    order = {"NOT_CLASSIFIED": 0, "INFO": 1, "WARNING": 2, "AVERAGE": 3,
             "HIGH": 4, "DISASTER": 5}
    for item in tpl.get("items", []):
        for tr in item.get("triggers", []):
            tr.pop("dependencies", None)

    added = 0
    for item in tpl.get("items", []):
        trs = item.get("triggers", [])
        if len(trs) < 2 or item["key"] in NO_DEPENDENCY:
            continue
        prios = [order.get(tr.get("priority"), 0) for tr in trs]
        if len(set(prios)) > 1:
            master = trs[prios.index(max(prios))]
            for tr in trs:
                if tr is master:
                    continue
                tr["dependencies"] = [{"name": master["name"],
                                       "expression": master["expression"]}]
                added += 1
        else:
            for ikey, dep_sub, master_sub in SAME_PRIORITY_RULES:
                if item["key"] != ikey:
                    continue
                dep = next((t for t in trs if dep_sub in t["name"].lower()), None)
                master = next((t for t in trs
                               if master_sub in t["name"].lower()), None)
                if dep and master and dep is not master:
                    dep["dependencies"] = [{"name": master["name"],
                                            "expression": master["expression"]}]
                    added += 1
    return added


def check_dependencies(tpl):
    """Zeigt jede Dependency auf einen existierenden Trigger?

    Diese Pruefung fehlte - deshalb blieben die kaputten Referenzen unbemerkt,
    bis jemand importiert haette.
    """
    trs = [tr for i in tpl.get("items", []) for tr in i.get("triggers", [])]
    known = {(tr["name"], tr["expression"]) for tr in trs}
    broken = []
    for tr in trs:
        for d in tr.get("dependencies", []):
            if (d["name"], d.get("expression")) not in known:
                broken.append(f"{tr['name']} -> {d['name']}")
    return broken


# Nach dem Umbenennen heissen 5 Trigger und 6 Prototypen anders als der
# Schluessel, unter dem sie hier stehen. Ohne diese Ergaenzung findet ein
# zweiter Lauf sie nicht wieder, meldet "kein scope hinterlegt" fuer Trigger,
# die laengst einen haben, und endet mit Exit 1 - ein Fehlalarm des eigenen
# Werkzeugs.
for _old, (_new, _ev) in RENAME.items():
    if _old in SCOPE and _new not in SCOPE:
        SCOPE[_new] = SCOPE[_old]
for _old, _spec in list(PROTO.items()):
    if _spec["name"] not in PROTO:
        PROTO[_spec["name"]] = _spec


def dump_safely(doc, path):
    """Siehe fix_macros.py: safe_dump entfernt das Quoting von 'y' und der
    Hex-Farben. Zabbix' Parser folgt YAML 1.1, wo der nackte Key y ein Boolean
    und 007700 oktal ist - ohne diese Nachbearbeitung ist die Datei nicht mehr
    importierbar."""
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


def main(path):
    raw = open(path).read()
    before = {
        "y": len(re.findall(r"^\s*'y':", raw, re.M)),
        "colors": len(re.findall(r"value: '[0-9A-Fa-f]{6}'", raw)),
    }
    doc = yaml.safe_load(raw)
    tpl = doc["zabbix_export"]["templates"][0]

    # template-tags
    have = {(t["tag"], t["value"]) for t in tpl.get("tags", [])}
    tags = tpl.setdefault("tags", [])
    for t in TEMPLATE_TAGS:
        if (t["tag"], t["value"]) not in have:
            tags.append(dict(t))

    hostname = renamed = evented = scoped = 0
    unknown = []
    for item in tpl.get("items", []):
        for tr in item.get("triggers", []):
            # 1. {HOST.NAME} raus
            base = tr["name"].replace(" on {HOST.NAME}", "")
            if base != tr["name"]:
                tr["name"] = base
                hostname += 1

            # 2. schwelle -> event_name
            hit = RENAME.get(tr["name"])
            if hit:
                new_name, ev = hit
                if tr["name"] != new_name:
                    renamed += 1
                tr["name"] = new_name
                tr["event_name"] = ev
                evented += 1

            # 3. scope-tags
            scopes = SCOPE.get(base)
            if scopes is None:
                unknown.append(base)
                continue
            keep = [t for t in tr.get("tags", []) if t["tag"] != "scope"]
            tr["tags"] = keep + [{"tag": "scope", "value": s} for s in scopes]
            scoped += 1

    # LLD-prototypen + ihre macros
    macros = tpl.setdefault("macros", [])
    have_m = {m["macro"] for m in macros}
    for name, val, desc in PROTO_MACROS:
        if name not in have_m:
            macros.append({"macro": name, "value": val, "description": desc})
    macros.sort(key=lambda m: m["macro"])
    protos = fix_prototypes(tpl)

    deps = rebuild_dependencies(tpl)
    broken = check_dependencies(tpl)

    dump_safely(doc, path)

    print(f"'{{HOST.NAME}}' aus namen entfernt:  {hostname}")
    print(f"namen ohne feste schwelle:        {renamed}")
    print(f"event_name gesetzt:               {evented}")
    print(f"scope-tags gesetzt:               {scoped}")
    print(f"template-tags:                    {len(tpl['tags'])}")
    print(f"LLD-prototypen angepasst:         {protos}")
    print(f"dependencies neu aufgebaut:       {deps}")
    for u in unknown:
        print(f"  !! kein scope hinterlegt: {u}")
    print("dependency-gegenprobe:")
    if broken:
        for b in broken:
            print(f"  !! zeigt ins leere: {b}")
    else:
        print("  OK  alle dependencies zeigen auf existierende trigger")

    text = open(path).read()
    now_y = len(re.findall(r"^\s*'y':", text, re.M))
    now_c = len(re.findall(r"value: '[0-9A-Fa-f]{6}'", text))
    ok = now_y == before["y"] and now_c == before["colors"]
    print("quoting-gegenprobe:")
    print(f"  {'OK' if now_y == before['y'] else '!! REGRESSION'}  "
          f"'y': {before['y']} -> {now_y}")
    print(f"  {'OK' if now_c == before['colors'] else '!! REGRESSION'}  "
          f"farben: {before['colors']} -> {now_c}")
    return 0 if ok and not unknown and not broken else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1
                  else "templates/mailcow-complete-monitoring.yaml"))
