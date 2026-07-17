# Changelog

> Entries from v1.2 onwards are written in English. Earlier entries are in German.

## v1.3.4 (2026-07-16)

### Changed — Zabbix template guideline conformance
- **Macro `{$MAILCOW.RBL.CRITICAL}` renamed to `{$MAILCOW.RBL.CRIT}`.** The
  guidelines define `CRIT` as the standard abbreviation for the critical
  threshold suffix. Updated in all three places — the macro definition, the RBL
  trigger expression and its `event_name` — so the trigger keeps resolving the
  macro. (If you overrode `{$MAILCOW.RBL.CRITICAL}` at host level, re-create the
  override under the new name; the template default is unchanged.)

_With this, the guideline pass A–D is complete: DISASTER→HIGH (v1.3.1), template
name (v1.3.2), template group (v1.3.3) and the RBL macro abbreviation (v1.3.4)._

## v1.3.3 (2026-07-16)

### Changed — Zabbix template guideline conformance
- **Template group moved from `Templates/Mailcow` to `Templates/Applications`.**
  The guidelines require `Templates/<category>`, and Mailcow is an application —
  `Mailcow` was never a Zabbix category. The `template_groups` entry now carries
  the **canonical UUID** of the standard "Templates/Applications" group
  (`a571c0d144b14fd4a87a9d9b2aa9fcd6`, verified against Zabbix's official Docker
  and Proxmox templates), so on import the template links to the existing standard
  group by UUID instead of creating a duplicate or colliding on the name.

## v1.3.2 (2026-07-16)

### Changed — Zabbix template guideline conformance
- **Template renamed, separate visible name dropped.** The technical name
  `mailcow_complete_monitoring_v45` (the version-like `_v45` suffix isn't allowed
  by the guidelines) is now **`Mailcow by Zabbix agent 2`** — product plus
  data-collection method, in the official Zabbix style. The separate visible name
  ("Mailcow Complete Monitoring v1.0") was dropped — the guidelines suggest leaving
  it empty, which in the export means the `name` field is set equal to the
  technical name (Zabbix import rejects an absent/empty `name` with
  *"/1/name cannot be empty"*, so it can't literally be blank).
- **All 208 references updated in the same pass** so the import stays consistent:
  the template header, 77 trigger expressions + 7 recovery expressions + 1 opdata,
  and 107 dashboard `host:` fields. Verified: no occurrence of the old name
  remains, every trigger expression still resolves to an existing item, YAML
  parses.
- Zabbix matches the template by its **UUID** on import, so the rename applies
  **in place** to already-linked hosts — links and history are preserved. README,
  README.de and DOKU were updated to the new name (and the "technical name is
  stable" note corrected to reference the UUID, since the name now changes).

## v1.3.1 (2026-07-16)

### Changed — Zabbix template guideline conformance
- **All 6 DISASTER-severity triggers downgraded to HIGH.** The guidelines state
  that "there should be no triggers with disaster level severity in resource
  templates" — disaster is reserved for top-level business-service triggers, to
  avoid alert fatigue in component templates. Affected: Postfix / Dovecot / Rspamd
  / Zabbix agent not running, IP listed on RBL, and open relay detected. This
  reverses the deliberate deviation noted in v1.3.0. Severity only — trigger
  expressions, dependencies, event names and tags are unchanged, so alerting
  logic and history are unaffected (HIGH triggers went 27 → 33).

## v1.3.0 (2026-07-16)

### Changed — Zabbix template guideline conformance
- **Units added to 41 metric items.** The Zabbix template guidelines ask to
  "provide units wherever possible". Following the template's existing label
  convention: 26× `%` (rates, disk-used, all 15 watchdog health levels, Bayes
  ratio), 5× `d` (certificate days remaining, ClamAV DB age), 4× `MB`, 2× `s`
  (uptime), 2× `B` (mail bytes) and 2× `h` (backup / sync age). Items carrying a
  unit went from 11 to 52. This is pure display metadata — item keys, history and
  the collector are untouched, and plain counters (messages, bans, connections)
  correctly stay unitless. Template vendor version bumped 1.2 → 1.3.
- **Value maps completed for the remaining boolean items.**
  `mailcow.security.open.relay`, `mailcow.backup.script.exists` and
  `mailcow.db.reachable` now map their 0/1 through the existing "Mailcow Boolean"
  value map (items with a value map: 23 → 26).

_Audited against the official guidelines. Already-compliant areas confirmed: LLD
rules/keys end in `discovery`, all item names use the `Location: Metric` form, all
items carry a `component` tag, all triggers a `scope` tag, no `{HOST.NAME}` /
`{ITEM.VALUE}` in names, `{$MAILCOW.*}` macro namespace. Open guideline items left
to a deliberate decision: DISASTER-severity triggers (kept — for a mail server,
service-down / RBL listing / open relay are genuinely disaster-level), and the
template visible/technical name, group and `{$MAILCOW.RBL.CRITICAL}` abbreviation
(identity / re-linking impact)._

## v1.2.2 (2026-07-16)

### Security
- **The check scripts still passed the DB password on the command line.** The
  collector already used a `0600` env file (v1.2.1), but `check_dns.sh`,
  `check_security_audit.sh` and `sync_jobs_check.sh` still ran
  `docker exec ... mysql -p"$DBPASS"` (and one `-e "MYSQL_PWD=$DBPASS"`), exposing
  the secret in the host process list and in the `docker exec` argv. All three now
  `export MYSQL_PWD` and pass it via `docker exec -e MYSQL_PWD` — the value lives
  only in the environment, never in argv.
- **`monitor.json` was world-readable (`0644`) and leaked PII.** The JSON holds
  mailbox lists, domain lists, top senders/recipients and the LLD mailbox/domain
  data — i.e. email addresses. Any local account could read it. The collector now
  runs with `umask 0027`, writes the JSON `0640` and the runtime dir `0750`, and
  the systemd unit sets `Group=zabbix`, `RuntimeDirectoryMode=0750` and
  `UMask=0027`, so only root and the zabbix service can read it. The DB password
  was never in the JSON. **This requires the `zabbix` group to exist** — standard
  when zabbix-agent2 is installed; adjust `Group=` if yours differs.
- **Command injection via the port argument in `check_tls.sh`.** `$2` was
  interpolated unvalidated into `bash -c "</dev/tcp/$DOMAIN/$PORT"`. The shipped
  UserParameters only pass fixed ports, but the script is executable in
  `/usr/local/bin`; the port is now validated as numeric before use.
- **DB-password parsing truncated secrets with special characters.** The
  charset-limited `grep -oP "DBPASS=\K[a-zA-Z0-9._-]+"` and `cut -d= -f2` cut the
  password at the first `!`, `@`, `+`, `=` … — silently breaking DB auth and
  falling back to hostname-only mode. Now `grep -m1 "^DBPASS=" | cut -d= -f2-`
  reads it verbatim.
- **systemd unit hardened further, and the hardening comment corrected.** Added
  `PrivateDevices=yes` and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
  AF_NETLINK`; `SystemCallFilter=@system-service` ships commented-out with a
  test note (the collector spawns many subprocesses). The comment now states
  honestly that Docker-socket access as root is the dominant residual risk and the
  namespace directives are defense-in-depth, not a barrier against a collector
  compromise.

### Performance
- **`collect_version()` now has its own 1 h cache.** It ran `git fetch --tags
  origin` and Mailcow's `./update.sh --check-tags` — two network operations — on
  every 60 s cycle. Version info changes on the scale of hours/days; the cache
  removes that per-minute git/network load and the git-lock / rate-limit exposure.
- **One `docker ps` instead of eight.** `find_all_containers()` now fetches every
  container name in a single `docker ps` and matches in Python, instead of calling
  `find_container()` (a separate `docker ps`) eight times per run.
- **Modules run in parallel.** The 22 collector modules are almost entirely
  I/O-bound (waiting on `docker exec` / MySQL / DNS). They now run in a bounded
  `ThreadPoolExecutor` (4 workers) instead of sequentially, cutting wall-clock
  time. Capped at 4 to keep concurrent Docker/MySQL load on the mail server in
  check; `db.env` is created once (via the preceding `db_reachable()` call) before
  the pool, so there is no race on the lazy env-file init.

### Fixed
- **`postfix_log_analysis.sh` produced invalid JSON whenever a counter was zero.**
  `grep -c "..." || echo 0` prints `0` *and* exits 1 on zero matches, so the
  `|| echo 0` appended a second `0` → `0\n0` → malformed JSON. On a healthy server
  several of these counters are legitimately zero, so this was the *common* case:
  `jq` then failed to parse the cache and **every** key from this script read 0.
  Replaced with a validated `safe_count` helper that always emits a single number.
- **Empty Postfix queue reported `pfmailq = 1`.** The old heuristic counted the
  first uppercase-alphanumeric character per line, so `Mail queue is empty` (the
  `M`) counted as one message — and it also missed long queue IDs that start with
  a digit. Now the authoritative `-- N Requests` trailer is used, with an
  empty-queue guard and a queue-ID fallback that handles short and long IDs.
- **`test-complete.sh` gave false PASS/FAIL and skipped a key.** The pass/fail gate
  fuzzy-matched `error|not supported|cannot` in the returned *value*, so string
  metrics whose content contains "error" (e.g. `mailcow.watchdog.detail`) failed
  falsely, while the reader's real sentinels (`ZBX_NOTSUPPORTED: …`) could slip
  through. It now matches the exact sentinel prefix and additionally tests
  `mailcow.db.reachable` (247 keys instead of 246).
- **Template import failed: LLD trigger prototypes used double discovery braces.**
  Six trigger prototypes referenced their item key with double `{{ }}` —
  `mailcow.domain.usage_pct[{{#DOMAIN}}]` and likewise for `{{#MAILBOX}}`,
  `{{#SYNCJOB_ID}}` and `{{#CONTAINER}}` — while the item prototypes correctly use
  single `{#…}`. Zabbix rejected the import with *"Incorrect item key … provided
  for trigger expression"*. All six now use single braces; every trigger reference
  in the template was re-validated to resolve to an existing item key. (Carried
  over from the v1.2.1 template.)

### Changed — robustness
- Timeouts added to the `dig` calls in `check_ptr.sh` and to the `docker exec` log
  fetch in both Postfix scripts, so an unresponsive resolver or a hung container
  can't stall the 60 s root collector.
- The `int()` conversions in `collect_disk` are guarded, so an unexpected `df`
  line degrades to defaults instead of aborting the whole disk module.

## v1.2.1 (2026-07-16)

### Fixed — user macros were defined but never used
- The template shipped 4 user macros (`{$MAILCOW.QUEUE.WARN}`,
  `{$MAILCOW.CERT.WARN}`, `{$MAILCOW.DISK.WARN}`, `{$MAILCOW.RBL.CRITICAL}`) that
  **not a single trigger referenced**. All thresholds were hardcoded, and the
  macro values matched the literals exactly — so they were meant to be wired up
  and never were. Setting `{$MAILCOW.DISK.WARN}` to 95 changed nothing, without
  any error: the template looked configurable without being so.
  All 9 affected triggers now use their macro.
- Wiring only the problem side would have broken the hysteresis triggers: with
  `{$MAILCOW.QUEUE.WARN}` set to 20, the hardcoded recovery threshold (`<30`)
  would sit *above* the problem threshold and the trigger would flap. Every
  threshold therefore got its counterpart: `{$MAILCOW.QUEUE.RECOVER}` (30),
  `{$MAILCOW.DISK.RECOVER}` (85), `{$MAILCOW.CERT.CRIT}` (7).
- `vmail` warns earlier than the other filesystems (85/80 instead of 90/85) and
  got its own pair: `{$MAILCOW.DISK.VMAIL.WARN}` / `{$MAILCOW.DISK.VMAIL.RECOVER}`.
- All macros now carry a description.

### Fixed — {ITEM.VALUE} in trigger names
- 28 trigger names embedded `{ITEM.VALUE}`. Zabbix guidelines are explicit that
  these macros belong in the operational data field: a problem name is generated
  once at event creation, so the value shown there freezes and goes stale, while
  `opdata` keeps updating. Names are now static and describe the condition; the
  live value moved to `opdata` (e.g. "TLS certificate expires soon (443)" with
  opdata `{ITEM.LASTVALUE1} days left`).

### Changed — Zabbix template guidelines (triggers)
- **`{HOST.NAME}` removed from 60 trigger names.** The guidelines are explicit:
  "Trigger names should not use the {HOST.NAME} macro to keep names shorter."
  Zabbix already shows the host in its own column on every problem view.
- **`event_name` added to the 9 macro-driven triggers.** After wiring the macros,
  the names still claimed fixed thresholds ("Root disk >90%") while the
  expression compared against `{$MAILCOW.DISK.WARN}` — setting the macro to 95
  would have produced a problem name insisting on 90. The name is now generic and
  `event_name` resolves the macro, so the alert always states the real threshold.
- **`scope` tags on all 63 triggers.** The guidelines require at least one scope
  tag per trigger from a fixed set. Distribution: security 17, availability 15,
  notice 14, performance 11, capacity 8. The 5 existing `scope: anomaly` tags
  were replaced — `anomaly` is not part of the model. `component` is not
  duplicated on triggers: problem events inherit tags from the whole chain
  (template → host → item → trigger), and the items already carry it.
- **Template tags** `class: software` and `target: mailcow` added (at least one
  of each is mandatory).

- **LLD trigger prototypes pulled along.** The first pass only walked
  `items` and missed `discovery_rules[*].trigger_prototypes`, which would have
  left 63 conformant triggers next to 8 non-conformant prototypes in the same
  template. All 8 now drop `{HOST.NAME}`, carry a scope tag and use macros for
  their thresholds (`{$MAILCOW.QUOTA.WARN}` / `.CRIT`,
  `{$MAILCOW.SYNCJOB.AGE.MAX}`, `{$MAILCOW.CONTAINER.MEM.MAX}`).
- **Trigger dependencies rebuilt.** Zabbix identifies a dependency target by
  name *and* expression — renaming the triggers left all 5 dependencies pointing
  at triggers that no longer existed, which would have failed the import. They
  are now regenerated from the current state instead of remapped, and
  `fix_guidelines.py` verifies that every dependency resolves.

### Added
- `tools/fix_guidelines.py` — same idempotent, self-verifying pattern as
  `fix_macros.py`: it re-quotes `'y'` and the hex colours after dumping, checks
  that every dependency resolves, and fails if any trigger has no scope.

### Security
- **The Mailcow database password was readable by any local user.** The collector
  ran `docker exec -e MYSQL_PWD=<secret> ...` — the docstring claimed "password
  not on the command line", which only held for the `mysql` call *inside* the
  container. The `docker` invocation is a host process, and `/proc/<pid>/cmdline`
  is mode 0444: world-readable regardless of owner. With the collector running
  every 60 seconds across up to 6 database modules per run, a `while :; do cat
  /proc/*/cmdline; done` loop from an unprivileged account captured the password
  within minutes. The password now goes into a 0600 file under
  `/run/mailcow-monitor/` and is passed via `docker exec --env-file`; only the
  path appears in argv.
- **Python code injection in `mailcow-reader.sh`.** The key was interpolated
  straight into the Python source: `d.get('${KEY}')` inside a double-quoted
  here-string. Any caller could execute arbitrary Python —
  `mailcow-reader.sh "x') or open('/tmp/pwn','w').write('x') or d.get('y"`
  created the file, verified against both the old and the fixed version. The
  template's own UserParameters only ever pass fixed keys from the config, and
  none of them are parameterised with `[*]`, so this was not reachable from the
  Zabbix server — but the script sits executable in `/usr/local/bin` and runs
  with the caller's privileges. Path and key now go through `argv`; the Python
  program is single-quoted, so the shell substitutes nothing into it.
- **All state moved from `/var/tmp` to `/run/mailcow-monitor`.** `/var/tmp` is
  world-writable (`drwxrwxrwt`); root wrote its JSON and caches there and read
  them back. Only the kernel sysctls `fs.protected_symlinks` and
  `protected_regular` stood between that and an arbitrary-file-write as root —
  that is luck, not a defence. systemd now creates the directory via
  `RuntimeDirectory=` as `drwxr-xr-x root:root`.
  - `RuntimeDirectoryPreserve=yes` is mandatory here, not a detail: systemd
    deletes a RuntimeDirectory when the unit stops, which for `Type=oneshot` is
    after *every* run — the JSON would vanish before the agent reads it, silently.
  - The collector creates the directory itself as a fallback, so a manual
    `sudo python3 mailcow-collector.py` still works.
  - `install.sh` and `update.sh` remove the old `/var/tmp` files from existing
    installations.
- **`update.sh` never installed the systemd units.** It only replaced the scripts
  under `/usr/local/bin`, so anyone updating would have received the new collector
  next to the old, unhardened unit — no `RuntimeDirectory`, no hardening. Thanks
  to the collector's fallback it would even have worked, just without any of the
  protection: an update reporting success while delivering half of it. It now
  installs both units, reports what changed and reloads systemd.
- **systemd unit hardened.** It previously had no restrictions whatsoever while
  running as root, driving Docker and executing Mailcow's `update.sh`. Added
  `NoNewPrivileges`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`,
  `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `RestrictSUIDSGID`,
  `RestrictRealtime`, `RestrictNamespaces`, `LockPersonality`, `PrivateTmp` and
  `ProtectSystem=full`.
  - `PrivateTmp` only became safe *because* the state moved to `/run` — it
    isolates `/tmp` and `/var/tmp` and would have hidden the old location.
  - `ProtectSystem=full` rather than `strict`: Mailcow's `update.sh --check-tags`
    performs git operations in `/opt`, which `strict` would block — and the
    collector would have written 0 for it without a word.

### Fixed — diagnostics and dead code
- **The reader threw away its own diagnosis.** The shell wrapper replaced
  Python's precise `Key not found` with a generic `Read error`, and reported a
  legitimately empty value as an error. Python's message and exit code are now
  passed through: missing key → `Key not found` (rc 1), empty value → empty
  string (rc 0), broken JSON → `Read error`.
- **`tools/fix_guidelines.py` raised a false alarm on a second run.** Its lookup
  tables are keyed by the original trigger names, so after the rename it no
  longer recognised its own output: it reported "no scope" for 5 triggers that
  have one, processed 1 of 8 LLD prototypes, and exited 1 — a red CI run with no
  cause. It is now idempotent: two runs produce identical output and exit 0.
- **Removed `docker_exec_int()`** from the collector — 0 callers.

### Reviewed and found sound
- No SQL injection and no command injection: `mysql_exec` passes an argument list
  (no `shell=True`), and values from the database (domains, mailboxes, sync job
  names) never reach a shell. A domain named `foo.de; rm -rf /` does nothing.
- The password is not written to the JSON.
- `UnsafeUserParameters=0`, no sudo rules for Zabbix.
- The JSON is written atomically (`.tmp` + `os.rename`).

### Changed — licence
- Relicensed from AGPL-3.0-or-later to **MIT**. The Zabbix community template
  repository publishes exclusively under MIT and does not accept GPL-style
  licences, so this is the prerequisite for submitting the template there.
  Sole copyright holder: Alexander Fox (PlaNet Fox) — no third-party code.

### Added
- `tools/fix_macros.py` — wires the macros and moves `{ITEM.VALUE}` to `opdata`,
  idempotent. It re-quotes the `'y'` widget keys and hex colours after dumping
  and verifies the counts: `yaml.safe_dump` silently strips both, which would
  reintroduce the v1.2 import blocker.

### Added — the collector now admits when it cannot measure
- **`mailcow.db.reachable` (new item + trigger, HIGH).** Running the collector on
  a machine with no Docker, no Mailcow and no mail server at all produced:
  `OK: 246 metrics written` and `mailcow.collector.errors = 0`. Full success
  reported, nothing measured — the exact failure this project exists to catch,
  still present in its own collector.
  The mechanism: `errors` only counts module *exceptions*. `mysql_exec` returns an
  empty string on any failure, `collect_mailbox()` then returns its zero defaults
  without raising, and the module counts as successful. So a database outage was
  invisible: `mailbox.total=0`, `domain.total=0`, `quarantine=0`,
  `collector.errors=0`, no alert.
  The new item probes with `SELECT 1` and reports whether an answer actually came
  back. This is also the signal that catches `docker exec --env-file` not being
  supported — the one deployment risk that could not be tested off-host.

### Known issues
- `collector.errors` still counts only crashes, not "could not measure". Modules
  that return their zero defaults on failure still count as successful. Beyond the
  database, this affects every module whose container is missing. A per-module
  "measured" signal is planned for v1.3; `mailcow.db.reachable` covers the case
  with the most metrics behind it.
- Not yet conformant to the Zabbix template guidelines: data is collected via 246
  individual UserParameters instead of one master item with dependent items and
  preprocessing; the visible template name carries a version; the template group
  is `Templates/Mailcow` instead of one of the recommended categories; macro names
  do not follow the `{$[<NAMESPACE>.]<METRIC_NAME>[.MAX|.MIN][.WARN|.CRIT]}`
  pattern; 50 triggers and 207 items have no description.
- Two hysteresis triggers still use hardcoded thresholds on both sides
  (`fail2ban.banned` 20/10, `backup.age` 48/24). Both sides are hardcoded, so
  they are consistent — but they are not tunable.

## v1.2 (2026-07-16)

### Fixed — triggers were never imported (critical)
- **63 of the 71 triggers could not be created in any installation.** Their
  expressions referenced the template's *visible* name
  (`/Mailcow Complete Monitoring v1.0/...`) instead of its *technical* name
  (`/mailcow_complete_monitoring_v45/...`). No template exists under the visible
  name, so the triggers were never created. The 8 LLD trigger prototypes already
  used the technical name correctly — which is why discovery was the only part
  that worked.
- **56 trigger names** used doubled braces `{{HOST.NAME}}`. In Zabbix `{{...}}`
  is macro-function syntax and invalid without a function → `{HOST.NAME}`.
- The **RBL trigger** displayed `*UNKNOWN*` instead of the blacklist name: the
  expression macro `{?last(/<template>/mailcow.security.rbl.detail)}` inside the
  trigger name referenced the visible name as well.

### Fixed — template could not be imported at all
- All 7 hysteresis triggers carried a `recovery_expression` but no
  `recovery_mode: RECOVERY_EXPRESSION`. Zabbix defaults to `EXPRESSION`, where
  `recovery_expression` must be empty, so the import aborted with
  `Incorrect value for field "recovery_expression": should be empty.`

### Fixed — dashboards stayed empty (#3)
- **All 46 widgets across 19 dashboards** used the Zabbix 6.x data set field
  syntax (`ds.items.0.0`, `ds.color.0`). Zabbix 7.0 expects
  `ds.<dataset>.<field>.<item>` plus a `reference` field per widget. Zabbix
  silently ignores unknown fields: axes and trigger markers were rendered, the
  data set stayed empty. Items and triggers were never affected.
  - Converted to item list mode: `ds.0.dataset_type`, `ds.0.itemids.N`
    (ITEM: host+key), `ds.0.color.N`, `ds.0.missingdatafunc`, `ds.0.width`
  - Added the `reference` field (mandatory in 7.0, missing entirely)
  - The `ds.hosts` fix noted in v1.0 had no effect — that field was not present
    in the template.
- **YAML:** widget `y` coordinates are now quoted (`'y':`). YAML 1.1 reads a bare
  `y` as a boolean; official Zabbix exports quote it throughout.

### Fixed — permanent RBL false alarm on cloud hosts
- `check_rbl.sh` treated **every** non-empty DNS answer as a listing. Spamhaus,
  however, answers queries from datacenter and public resolvers (Hetzner,
  DigitalOcean, OVH, Google DNS …) with error codes `127.255.255.252/254/255`.
  The result was a permanent **Disaster** alarm on perfectly clean servers.
  Only `127.0.0.x` counts as a listing now; error codes surface as
  `error_resolver_blocked:<rbl>` in the detail item, without raising an alarm.
- IP detection now forces `dig -4`. On dual-stack hosts with IPv6 resolvers the
  OpenDNS query returned nothing and the script silently fell back to curl.
- Calling it with `detail` emitted two lines on a cache miss (count + text)
  because `echo ... | tee` also wrote to stdout.

### Fixed — batching optimisation produced silent zeros
- **Postfix PID:** Postfix writes `master.pid` right-aligned with padding
  (`"                             394"`). The batched shell variant read it
  without stripping, so `[ -d "/proc/$PID" ]` tested
  `/proc/                             394` → always 0. The "Postfix not running"
  trigger (DISASTER) fired permanently while Postfix was healthy.
  Fixed with `| tr -dc '0-9'`.
- **A failing command discarded the whole batch:** `run()` returns its default
  (`""`) on a non-zero exit code, and for a command list that is the exit code of
  the *last* command. The rspamd batch ends with `rspamc stat` — if that fails,
  the `/stat` JSON already fetched successfully was thrown away and all 18 rspamd
  metrics fell back to 0, including `scanned`, a cumulative counter that is never
  legitimately 0 on a running server. The postfix (`postconf`), vmail (`du`),
  ClamAV and agent (`tail`) batches had the same flaw. Fixed by appending
  `; exit 0` to every batched `sh -c`; missing sections simply stay empty.
  Partial data beats no data.

### Changed — duplicate alerts
- **Added 5 trigger dependencies.** Threshold ladders fired twice for the same
  condition (e.g. ClamAV ">7 days" Warning *and* ">30 days" High). The lower
  trigger now depends on the higher one: ClamAV age, watchdog, ACME expiry,
  bounce, deferred. `mailcow.mail.received` deliberately has no dependency —
  spike and drop are mutually exclusive.
- **Resolved 2 duplicate trigger names:**
  - both ACME triggers had identical names → the High one is now "... - CRITICAL"
  - `mailcow.mail.deferred` and `mailcow.queue.deferred` shared a name → the
    queue variant is now "... deferred mails in queue"

### Changed — documentation
- **`ServerActive` and `Hostname` are now documented.** All 246 items are active
  agent checks and require `ServerActive`; the previous docs only mentioned
  `Server=`, which governs passive queries alone. Without `ServerActive`, **not a
  single item** collects data — silently. `install.sh` and `update.sh` both check
  this and warn.
- Import options: **"Create new" AND "Update existing"** are required. With only
  "Update existing" Zabbix skips missing objects and still reports success — the
  cause of installations with 0 of 71 triggers. Both READMEs previously
  instructed exactly that.
- The update path pointed at `install.sh`; the correct one is `update.sh`.
- Installation via GitHub documented (git clone and tar.gz); the German README
  still referenced a non-existent `mailcow-monitoring-v1.0.zip`.
- Documented where template dashboards actually live
  (*Monitoring → Hosts → host → Dashboards*, not *Monitoring → Dashboards*).
- Removed "wait 5–10 minutes, then check the dashboard". Data appears within a
  minute; if it stays empty the cause was never patience, but `ServerActive`.
- Noted that `test-complete.sh` only probes passively via `zabbix_get` and can
  therefore verify neither active checks nor triggers nor dashboards.
- Documented the limits of the RBL check on cloud hosts (own resolver or a
  Spamhaus DQS key required).
- **Added a Mailflow chapter** to the project documentation. The largest module
  (28 items, 9 triggers) previously existed only as table rows: pflogsumm runs
  over `docker logs --since 1h`, so every value is an hourly total; it keeps its
  own 5-minute cache separate from the 1h slow cache; pflogsumm is a host
  prerequisite; documents all 9 triggers and why "volume drop" is High while
  "spike" is only Warning.
- Project documentation: header still said v1.0 (18.02.2026), the install section
  referenced a non-existent zip, an update section was missing entirely, and menu
  paths said "Configuration → Templates" (renamed to "Data collection" in Zabbix
  6.0). Item count corrected: 303 claimed, actually 246 items + 21 LLD prototypes.
- `UPDATE.md` is now English, the German version moved to `UPDATE.de.md` —
  matching the existing README pattern.
- Script output is now English; code comments stay German.

### Changed — licence
- Switched from **GPLv3 to AGPL-3.0-or-later**, matching Zabbix since 7.0.
- Unified licence headers: 10 of 15 files still said `License: GPLv3` while the
  LICENSE file had already changed.

### Added — tools
- `update.sh`: updates the host side, with backup, `--check`, `--rollback`,
  `ServerActive` validation and verification of the collected values. It waits
  for a genuinely fresh JSON instead of sleeping a fixed interval.
- `tools/fix_dashboards.py`, `tools/fix_triggers.py`, `tools/fix_collector.py`:
  idempotent converters that make the template and collector fixes above
  reproducible.

### Removed
- **`scripts/dovecot_check.sh`.** Since the inline optimisation (#opt10)
  `collect_dovecot()` does everything itself via docker exec; the script was
  never called again, yet was still installed to `/usr/local/bin`, backed up on
  every update and documented as an active module in both READMEs and the project
  documentation. `install.sh` now removes it from existing installations.
  (The only orphan — every other script has verified callers.)
- Dead code flagged by shellcheck: unused `MAILCOW_DIR` in `check_open_relay.sh`
  (SC2034), a loop over a single element in `install.sh` (SC2043), and
  `local x=$(...)` masking return values in `postfix_stats_docker.sh` (SC2155).
  The repository is now clean at `--severity=warning`, not just at the CI level
  `--severity=error`.

### Known issues
- The collector writes **0** when a measurement fails instead of omitting the
  key. "Measurement failed" and "the value really is 0" are indistinguishable —
  even to `mailcow.collector.errors`, which stays at 0. With triggers active this
  can produce false alarms. Planned for v1.3.
- Quota/used items display "KMB" (unit `MB` plus Zabbix's automatic SI prefix).
  The fix would be `!MB`, or switching to bytes with unit `B`.
- `docker ps --filter name=postfix` also matches `postfix-tlspol-mailcow-1` in
  newer Mailcow versions. The selection currently picks the right one by chance;
  exact matching would be more robust.
- The anomaly baseline uses `trendavg` over one week — a flat mean without
  weekday or time-of-day seasonality. `baselinewma()` would be the appropriate
  replacement (planned for v1.3).

## v1.1 (2026-03-28)

### Bugfix
- **Netfilter/Fail2ban:** Mailcow ab Version 2025-03 hat fail2ban durch eine eigene Python-Lösung ersetzt. `fail2ban-client` existiert nicht mehr im netfilter-Container und erzeugte alle 5 Minuten Fehlermeldungen im Docker-Log. Der Collector erkennt jetzt automatisch welche Version läuft:
  - **Neue Methode:** Gesamt-Bans über iptables/nftables MAILCOW-Chain
  - **Alte Methode:** fail2ban-client für Pro-Service-Bans (nur wenn vorhanden)
  - Kompatibel mit alten und neuen Mailcow-Versionen
- **SOGo Cache Trigger:** `change()>0` feuerte bei jeder einzelnen Eviction. Jetzt: `min(1h)>0 AND change()>50` — alarmiert nur bei echtem Cache-Druck

### Optimierungen
- **Postfix Batch:** 6 docker_exec Aufrufe → 1 (ein sh -c Block mit Sektions-Markern)
- **Quarantine Batch:** 3 MySQL-Queries → 2 (COUNT/Alter/Spam/Virus in einer Query)
- **ACME Batch:** 6 openssl-Aufrufe → 1 (`openssl x509 -subject -issuer -dates -serial`)
- **Rspamd Batch:** 2 docker_exec → 1 (wget stat + rspamc stat kombiniert)
- **Disk/vmail Batch:** 3 docker_exec → 1 (test + df + du in einem Aufruf)
- **Meta Batch:** 3 run() → 1 (systemctl is-active/show + tail log)
- **Dovecot Inline:** 9 externe Script-Aufrufe → 1 docker_exec (version + connections + awk log-Analyse)
- **Version Batch:** 8 separate git-Aufrufe → 1 Batch-Call + offizielles `update.sh --check-tags` für Update-Erkennung
- **Trigger-Hysterese:** 7 Recovery-Expressions hinzugefügt (Disk, Queue, Banned IPs, Backup) — verhindert Trigger-Flapping bei Grenzwerten
- **History-Optimierung:** 24 TEXT/CHAR Items von 30-90d auf 7d reduziert (Versionsstrings, Zertifikat-Details, Config-Werte brauchen keine Langzeit-History)
- **Version Batch:** 8 separate git-Aufrufe → 1 Batch-Call + offizielles `update.sh --check-tags` für Update-Erkennung
- **Fail2ban Cache:** `which fail2ban-client` wird nur einmal pro Collector-Lauf geprüft statt bei jedem Zyklus

### Dokumentation
- zabbix-get als Voraussetzung dokumentiert
- Zabbix Agent `Server=127.0.0.1` Konfiguration dokumentiert
- `MAILCOW_DIR` und `BACKUP_PATH` Variablen in install.sh dokumentiert

## v1.0 (2026-02-18) — First Public Release

### Architektur
- **Secure Service Architecture:** systemd timer → Collector (root) → JSON → Zabbix Reader
- **Kein UnsafeUserParameters** — Zabbix Agent braucht kein Docker, kein sudo
- **246 UserParameters** in einer einzigen Conf-Datei
- **22 Collector-Module** in einem Python-Script
- **4 LLD Discovery Rules:** Domains, Mailboxes, Syncjobs, Docker Containers

### Neue Module (seit v4.4)
- Mailflow-Analyse (pflogsumm: sent/received/bounced/deferred/reject)
- ClamAV (Signatur-Alter, DB-Version, Scan-Status)
- Watchdog (Overall Health Score, Service-Status)
- ACME/Cert (Let's Encrypt Zertifikat-Überwachung)
- Docker Health (CPU/RAM/Status per Container via LLD)
- SOGo/Memcached (Hit Rate, Memory, Connections)
- Quarantine (Anzahl, Alter, Auto-Cleanup Status)
- Queue Age (Postfix Spool: active/deferred/hold/corrupt)
- Collector Self-Monitoring (Laufzeit, Fehler-Tracking, Module-Timing)

### Optimierungen (v5.0)
- **Baseline-Anomalie-Trigger (#8):** 5 trendavg-basierte Trigger erkennen automatisch Spikes/Drops bei received (5×/20%), rejected (10×), bounced (5×), deferred (5×) — keine festen Schwellwerte, lernt den Normalzustand
- **Security Audit Checks (#9):** DANE/TLSA, MTA-STS, TLS-RPT, BIMI prüfung pro Domain + Gesamt-Score (0-7), Trigger bei Score <3
- **Postscreen Monitoring (#6):** 9 Metriken (connect/pass_new/pass_old/reject/dnsbl/pregreet/hangup/whitelisted/active), Dashboard-Page, Trigger bei >100 Rejects
- **Rspamd Bayes-Training (#5):** Ham/Spam-Lernrate, Total learned, Ham-Ratio%, Training-Status (untrained/low/unbalanced/good/excellent), Trigger bei <200 gelernten Nachrichten, Dashboard-Widget
- **Zentralisierte Container-Erkennung:** 1x find_all_containers() statt ~10 find_container() pro Lauf
- **ClamAV:** 1 docker exec statt 3-5 (Version+Daily+Main+DBSize kombiniert)
- **Docker Health:** gezielter docker stats + 1 gebatchter docker inspect statt N einzelne
- **Slow-Cache parallelisiert:** ThreadPoolExecutor (6 Threads) für TLS/DNS/RBL-Checks
- **Mailflow:** eigener 5-Min-Cache statt im 1h-Slow-Cache (frischere Daten)
- **MySQL:** Passwort via MYSQL_PWD statt auf Kommandozeile (-p"...")
- **shell=False:** run_cmd() für einfache Befehle (sicherer, schneller)
- **Collector Error-Tracking:** Fehler pro Modul + Module-Timing im JSON
- **Rspamd:** 1 Docker-Call statt 2 (stat + detail merged)
- Dashboard Widgets: ds.hosts Referenz für Zabbix 7.0

### Paket-Bereinigung
- Alte Installer/Updater (v4.4) entfernt
- rspamd_stats.sh entfernt (merged in collector.py)
- Einheitliche Versionierung (v5.0 überall)
- Saubere Dateinamen ohne Versionssuffixe
- Template-ID `mailcow_complete_monitoring_v45` beibehalten (Zabbix Update-in-Place Kompatibilität)

### Bugfixes
- **Watchdog:** Default-Wert von -1 auf 0 geändert (UNSIGNED Items können keine negativen Werte speichern → "Not supported")
- **Watchdog:** Log-Fenster von 5m auf 10m erweitert (Watchdog-Zyklus ist ~5min, knappes Fenster verpasst manchmal den letzten Check)
- **YAML:** 100 unquotierte Hex-Farbwerte in Dashboard-Widgets gefixt (YAML interpretierte sie als Integer/Oktal)
- **Lizenz:** GPLv3 LICENSE-Datei hinzugefügt + Lizenz-Referenz in allen Script-Headern

## v4.4 (2026-02-13)

### Bugfixes
- **RBL-Check:** `curl` durch `dig` ersetzt (NAT-kompatibel)
- **PTR-Check:** `curl` durch `dig` ersetzt
- **Version:** `git describe --tags` statt fehlender Config-Variable
- **Duplikate:** Installer entfernt automatisch alte Configs
- **Fail2ban:** Container-Name wird dynamisch erkannt

### Verbesserungen
- Alle UserParameter in einer Datei
- Automatisches Backup der alten Installation
- `--all` Flag für non-interactive Installation
- Bessere Container-Erkennung (mehrere Naming-Patterns)
- Uninstall-Script hinzugefügt

## v4.3

- Meta-Monitoring (Agent überwacht sich selbst)
- Sync Jobs Monitoring (IMAP Migration)
- Dovecot Monitoring (IMAP/POP3)
- Disk Space Monitoring
- Smart Config Reading
- Timezone Fix

## v4.2.3

- Disk Space Monitoring
- History-Optimierung
- Smart Log-Monitoring

## v4.1/v4.2

- Postfix, TLS, Updates, Backup
- Security (RBL, Fail2Ban, DNS)
- Rspamd (Spam-Filter)
