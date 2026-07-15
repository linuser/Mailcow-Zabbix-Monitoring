#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Alexander Fox (PlaNet Fox)
"""
Rebuild svggraph dashboard widgets for Zabbix 7.0.

Problem
-------
The dashboards were written with the Zabbix 6.x data set field naming:

    ds.items.0.0 = postfix.pfmailq      # 6.x: ds.<field>.<dataset>.<item>
    ds.color.0   = DD0000

Zabbix 7.0 restructured these fields to ds.<dataset>.<field>.<item> and
requires a per-widget "reference" field:

    ds.0.dataset_type = 0               # 0 = item list
    ds.0.itemids.0    = {host, key}     # type ITEM
    ds.0.color.0      = DD0000
    reference         = ABCDE

Zabbix silently ignores the unknown 6.x fields, so the widget renders its axes
and trigger markers but the data set stays empty -> "dashboard is empty" while
items and triggers work fine.

This script converts every svggraph widget to the 7.0 item-list syntax. The old
values are item *keys*, which map directly onto 7.0's ITEM references
(host + key), so no name guessing is involved.

Usage:
    ./fix_dashboards.py <template.yaml> [-o <output.yaml>]
"""

import argparse
import re
import sys

import yaml

# Zabbix 7.0 defaults, mirrored from the official templates
MISSINGDATAFUNC = "1"   # connected
LINE_WIDTH = "2"


def ref_code(n):
    """Deterministic 5-char uppercase reference, unique within a dashboard."""
    letters = []
    for _ in range(5):
        letters.append(chr(ord("A") + (n % 26)))
        n //= 26
    return "".join(reversed(letters))


def convert_widget(widget, host):
    """Return (converted, changed). Non-svggraph widgets pass through."""
    if widget.get("type") != "svggraph":
        return widget, False

    fields = widget.get("fields", [])
    # Collect legacy 6.x fields: ds.items.<dataset>.<item> and ds.color.<dataset>
    legacy_items = {}   # dataset index -> key
    legacy_colors = {}  # dataset index -> color
    other = []
    for f in fields:
        name = f.get("name", "")
        if name.startswith("ds.items."):
            parts = name.split(".")          # ds items <ds> <item>
            legacy_items[int(parts[2])] = f["value"]
        elif name.startswith("ds.color."):
            parts = name.split(".")          # ds color <ds>
            legacy_colors[int(parts[2])] = f["value"]
        elif name.startswith("ds."):
            # already-7.0 or unknown ds field -> leave the widget alone
            return widget, False
        else:
            other.append(f)

    if not legacy_items:
        return widget, False

    # Each legacy data set held exactly one item; collapse them into a single
    # 7.0 data set where every item carries its own colour.
    new_fields = [
        {"type": "INTEGER", "name": "ds.0.dataset_type", "value": "0"},
    ]
    for pos, ds_idx in enumerate(sorted(legacy_items)):
        new_fields.append({
            "type": "ITEM",
            "name": f"ds.0.itemids.{pos}",
            "value": {"host": host, "key": legacy_items[ds_idx]},
        })
        color = legacy_colors.get(ds_idx)
        if color:
            new_fields.append({
                "type": "STRING",
                "name": f"ds.0.color.{pos}",
                "value": color,
            })
    new_fields.append(
        {"type": "INTEGER", "name": "ds.0.missingdatafunc", "value": MISSINGDATAFUNC})
    new_fields.append(
        {"type": "INTEGER", "name": "ds.0.width", "value": LINE_WIDTH})
    new_fields.extend(other)

    widget["fields"] = new_fields
    return widget, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("template")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()

    with open(args.template) as fh:
        doc = yaml.safe_load(fh)

    tpl = doc["zabbix_export"]["templates"][0]
    host = tpl["template"]
    valid_keys = {i["key"] for i in tpl.get("items", [])}

    changed = 0
    warnings = []
    for dash in tpl.get("dashboards", []):
        ref_n = 0
        for page in dash.get("pages", []):
            for widget in page.get("widgets", []):
                widget, did = convert_widget(widget, host)
                if not did:
                    continue
                changed += 1
                # unique reference per dashboard (required by 7.0)
                widget["fields"].append(
                    {"type": "STRING", "name": "reference", "value": ref_code(ref_n)})
                ref_n += 1
                for f in widget["fields"]:
                    if f["name"].startswith("ds.0.itemids."):
                        k = f["value"]["key"]
                        if k not in valid_keys:
                            warnings.append(f"{dash['name']} / {widget['name']}: "
                                            f"unbekannter key {k}")

    out = args.output or args.template
    text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=4096)
    # PyYAML does not quote the bare key "y", but YAML 1.1 (which Zabbix's
    # parser follows) resolves y/n/on/off as booleans. Official Zabbix exports
    # always write 'y'. Quote it so the widget position survives any parser.
    text = re.sub(r"^(\s*)y:", r"\1'y':", text, flags=re.M)
    # Force-quote every colour value. PyYAML only quotes what *its* resolver
    # considers ambiguous (e.g. 888888 -> int), but hex colours like 007700 are
    # octal under YAML 1.1 and DD0000 is fine either way. Quoting all of them
    # unconditionally keeps the file parser-independent and matches both the
    # official exports and this project's existing convention.
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

    print(f"converted widgets: {changed}")
    for w in warnings:
        print("WARN:", w)
    print("written:", out)
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
