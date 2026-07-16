#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Alexander Fox (PlaNet Fox)
"""
Fix trigger definitions so they actually import.

Two bugs, both silent:

1. Expressions referenced the template's *visible* name:

       last(/Mailcow Complete Monitoring v1.0/postfix.process.running)=0

   Trigger expressions address a host/template by its *technical* name
   (`template:` in the export), here `mailcow_complete_monitoring_v45`. No
   template exists under the visible name, so none of the 63 triggers could be
   created. The 8 LLD trigger prototypes in the same template already used the
   technical name correctly - which is why discovery imported and the plain
   triggers did not.

2. Trigger names used doubled braces:

       Mailcow: Postfix not running on {{HOST.NAME}}

   In Zabbix `{{...}}` is macro-function syntax ({{MACRO}.func()}); without a
   function it is invalid. The correct macro is {HOST.NAME}.

Usage:
    ./fix_triggers.py <template.yaml> [-o <output.yaml>]
"""

import argparse
import re
import sys

import yaml


def fix_text(value, visible, technical):
    """Rewrite expression host references from visible -> technical name."""
    return value.replace(f"/{visible}/", f"/{technical}/")


def fix_braces(value):
    """{{HOST.NAME}} -> {HOST.NAME} (only for plain doubled macros)."""
    return re.sub(r"\{\{([A-Z][A-Z0-9._]*)\}\}", r"{\1}", value)


# Items whose two triggers describe mutually exclusive conditions (a spike and
# a drop can never be true at once), so they must NOT depend on each other.
NO_DEPENDENCY = {"mailcow.mail.received"}

# Same-severity pairs need an explicit ruling: (item key, dependent substring,
# master substring). The absolute threshold is the more actionable signal, so
# the baseline-spike trigger yields to it.
SAME_PRIORITY_RULES = [
    ("mailcow.mail.deferred", "spike", "deferred mails"),
]

# Trigger names that shipped duplicated, making them indistinguishable in the
# problem list. Keys are (item key, priority).
RENAME = {
    ("mailcow.acme.cert.days.left", "HIGH"):
        "Mailcow: ACME cert expires in {ITEM.VALUE} days - CRITICAL on {HOST.NAME}",
    # Two different metrics shared one name: deferred counted from the logs vs
    # deferred sitting in the queue.
    ("mailcow.queue.deferred", "WARNING"):
        "Mailcow: {ITEM.VALUE} deferred mails in queue on {HOST.NAME}",
}


def fix_recovery_mode(tpl):
    """recovery_expression ist nur mit recovery_mode: RECOVERY_EXPRESSION gueltig.

    Zabbix' Default ist recovery_mode: EXPRESSION - dort MUSS recovery_expression
    leer sein, sonst bricht der Import ab:

        Incorrect value for field "recovery_expression": should be empty.

    Trigger, die eine recovery_expression tragen, brauchen also zwingend das
    passende recovery_mode. Fehlt es, wird es hier ergaenzt.
    """
    fixed = 0
    items = list(tpl.get("items", []))
    for item in items:
        for tr in item.get("triggers", []):
            if tr.get("recovery_expression") and \
                    tr.get("recovery_mode") != "RECOVERY_EXPRESSION":
                tr["recovery_mode"] = "RECOVERY_EXPRESSION"
                fixed += 1
    for tr in tpl.get("triggers", []):
        if tr.get("recovery_expression") and \
                tr.get("recovery_mode") != "RECOVERY_EXPRESSION":
            tr["recovery_mode"] = "RECOVERY_EXPRESSION"
            fixed += 1
    return fixed


def apply_renames(tpl):
    renamed = 0
    for item in tpl.get("items", []):
        for tr in item.get("triggers", []):
            key = (item["key"], tr.get("priority"))
            if key in RENAME:
                tr["name"] = RENAME[key]
                renamed += 1
    return renamed


def add_dependencies(tpl):
    """Stop threshold ladders from firing twice for the same condition."""
    added = 0
    order = {"NOT_CLASSIFIED": 0, "INFO": 1, "WARNING": 2, "AVERAGE": 3,
             "HIGH": 4, "DISASTER": 5}
    for item in tpl.get("items", []):
        trs = item.get("triggers", [])
        if len(trs) < 2 or item["key"] in NO_DEPENDENCY:
            continue

        prios = [order.get(tr.get("priority"), 0) for tr in trs]
        if len(set(prios)) > 1:
            # Threshold ladder: everything below the top severity depends on it.
            master = trs[prios.index(max(prios))]
            for tr in trs:
                if tr is master or "dependencies" in tr:
                    continue
                tr["dependencies"] = [{"name": master["name"],
                                       "expression": master["expression"]}]
                added += 1
        else:
            for ikey, dep_sub, master_sub in SAME_PRIORITY_RULES:
                if item["key"] != ikey:
                    continue
                dep = next((t for t in trs if dep_sub in t["name"].lower()), None)
                master = next((t for t in trs if master_sub in t["name"].lower()), None)
                if dep and master and dep is not master and "dependencies" not in dep:
                    dep["dependencies"] = [{"name": master["name"],
                                            "expression": master["expression"]}]
                    added += 1
    return added


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("template")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()

    with open(args.template) as fh:
        doc = yaml.safe_load(fh)

    tpl = doc["zabbix_export"]["templates"][0]
    technical = tpl["template"]
    visible = tpl.get("name", technical)

    expr_fixed = brace_fixed = macro_fixed = 0
    triggers = [tr for i in tpl.get("items", []) for tr in i.get("triggers", [])]
    triggers += tpl.get("triggers", [])

    for tr in triggers:
        for field in ("expression", "recovery_expression"):
            if field in tr and f"/{visible}/" in tr[field]:
                tr[field] = fix_text(tr[field], visible, technical)
                expr_fixed += 1
        # Expression macros {?last(/template/key)} can also sit inside the
        # trigger name / event name / opdata. They resolve against the same
        # technical name, so they break the same way - and render as *UNKNOWN*.
        for field in ("name", "event_name", "opdata", "description", "url"):
            if field not in tr or not isinstance(tr[field], str):
                continue
            if f"/{visible}/" in tr[field]:
                tr[field] = fix_text(tr[field], visible, technical)
                macro_fixed += 1
            if "{{" in tr[field]:
                new = fix_braces(tr[field])
                if new != tr[field]:
                    tr[field] = new
                    brace_fixed += 1

    out = args.output or args.template
    renamed = apply_renames(tpl)
    dep_added = add_dependencies(tpl)
    rec_fixed = fix_recovery_mode(tpl)
    text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=4096)
    text = re.sub(r"^(\s*)y:", r"\1'y':", text, flags=re.M)
    # keep hex colours quoted (YAML 1.1 would read e.g. 888888 as an int)
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if ".color." in line and line.strip().startswith("name:"):
            j = i + 1
            if j < len(lines):
                m = re.match(r"^(\s*value: )(?!['\"])(.+)$", lines[j])
                if m:
                    lines[j] = f"{m.group(1)}'{m.group(2)}'"
    text = "\n".join(lines)
    with open(out, "w") as fh:
        fh.write(text)

    print(f"expressions rewritten to technical name: {expr_fixed}")
    print(f"expression macros in names fixed:        {macro_fixed}")
    print(f"doubled-brace macros fixed:              {brace_fixed}")
    print(f"trigger dependencies added:              {dep_added}")
    print(f"recovery_mode ergaenzt:                  {rec_fixed}")
    print(f"duplicate trigger names renamed:         {renamed}")
    print("written:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
