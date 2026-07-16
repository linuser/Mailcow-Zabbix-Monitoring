# Update to v1.2

This updates an existing installation. It has **two parts** that are easy to
confuse:

| Part | Where | How |
|---|---|---|
| Collector + check scripts | Mailcow server (`/usr/local/bin/`) | `sudo ./update.sh` |
| Zabbix template | Zabbix frontend | import in the browser |

Both are required. Importing only the template fixes nothing if the collector is
outdated — and vice versa.

Deutsche Fassung: [UPDATE.de.md](UPDATE.de.md)

---

## 1. Mailcow server

```bash
unzip mailcow-zabbix-v1.2.zip
cd mailcow-zabbix-v1.2
sudo ./update.sh --check     # shows what would happen
sudo ./update.sh             # does it
```

`update.sh` backs up to `/var/backups/mailcow-zabbix/<date>/` first. Roll back
with `sudo ./update.sh --rollback`.

It waits for a genuinely fresh JSON and then verifies the values itself:

```
OK    246 metrics in the JSON
OK    Postfix running: 1
OK    Rspamd scanned: 73890
OK    RBL detail: clean
```

If you see `Postfix running: 0` **and** `Rspamd scanned: 0`, the old collector is
still in place — check:

```bash
md5sum /usr/local/bin/mailcow-collector.py
```

## 2. Zabbix frontend

*Data collection → Templates → Import*, file
`templates/mailcow-complete-monitoring.yaml`.

**Import options matter:** tick both **Create new** and **Update existing** for
**all** object types. Leave `Delete missing` off.

With only "Update existing" Zabbix does **not** create missing objects and still
reports "Imported successfully". That is how installations ended up with 0 of 71
triggers.

Check the template row afterwards:

```
Items 246 | Triggers 63 | Dashboards 19 | Discovery 4
```

No number next to *Triggers* means "Create new" was not ticked.

### Where are the dashboards?

Template dashboards do **not** appear under *Monitoring → Dashboards* — that page
only lists global dashboards. They belong to the host:

*Monitoring → Hosts* → the host's row → **Dashboards** link → "01 - Postfix"

Opening them under *Data collection → Templates → Dashboards* shows them empty:
there is no host context there, so there is nothing to plot.

---

## Prerequisite: ServerActive (most common cause of "no data")

**All 246 items are active agent checks.** The agent fetches them itself from the
address in `ServerActive`. `Server=` only governs passive queries and is **not**
sufficient.

In `/etc/zabbix/zabbix_agent2.conf`:

```ini
Server=zabbix.example.com,127.0.0.1     # passive (used by test-complete.sh)
ServerActive=zabbix.example.com         # ACTIVE — without this: no data at all
Hostname=mail.example.com               # exactly the host name in Zabbix
```

Then `systemctl restart zabbix-agent2`.

If `ServerActive` is missing, or points at `127.0.0.1` while your Zabbix server
runs elsewhere, **not a single item** collects data — items and triggers are
visible in the frontend, graphs stay empty. `install.sh` and `update.sh` both
check this and warn.

Each parameter may appear **once** uncommented, otherwise the agent refuses to
start. Validate before restarting:

```bash
zabbix_agent2 -T -c /etc/zabbix/zabbix_agent2.conf
```

---

## RBL checks on cloud hosts

Spamhaus does not answer queries coming from datacenter or public resolvers
(Hetzner, DigitalOcean, OVH, Google DNS, Cloudflare) with a result, but with an
error code from `127.255.255.0/24`:

| Response | Meaning |
|---|---|
| `127.0.0.2` / `.3` | SBL — real listing |
| `127.0.0.4`–`.7` | XBL — real listing |
| `127.0.0.10` / `.11` | PBL — real listing |
| `127.255.255.252` | error: invalid query |
| `127.255.255.254` | error: query via public resolver |
| `127.255.255.255` | error: rate limited |

Up to v1.1 every non-empty answer counted as a listing — on a Hetzner host that
meant a permanent **Disaster** false alarm. Since v1.2 only `127.0.0.x` counts;
error codes surface as `error_resolver_blocked:<rbl>` in the detail item, without
raising an alarm.

That removes the false alarm, but the check still yields no real answer on such
hosts. For a usable result, run your own recursive resolver (e.g. unbound) and
set in `check_rbl.sh`:

```bash
RBL_RESOLVER=127.0.0.1
```

or use a Spamhaus DQS key.

---

## What `test-complete.sh` does not check

`test-complete.sh` queries the UserParameters with `zabbix_get -s 127.0.0.1` —
those are **passive** queries. It therefore reports 246/246 OK even when the
template receives nothing over active checks. It also does not verify that
triggers exist or that dashboards show data. A passing test is not proof that
monitoring works — always confirm in the frontend (*Latest data*, trigger count).

---

## Included fixes

See `CHANGELOG.md`.

## License

MIT. See `LICENSE`.
