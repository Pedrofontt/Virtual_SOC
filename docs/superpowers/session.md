# Session state — resume here

Last updated: 2026-11-14 (Phase 4 SOAR **execution started** — Task 0 done). Resume by reading this file; next is Phase 4 SOAR Task 1 (SOAR01 VM build, interactive).

## Where we are — PHASE 3 NDR: COMPLETE; PHASE 4 SOAR: IN PROGRESS

Phase 3 NDR (UC-06..12, 7 detections) verified end-to-end and committed (`b713802`/`edc775c`/`8ebe2ea`).

Phase 4 SOAR (UC-13): design spec + implementation plan committed (`7b220e8` + `e2b33bd`), execution started. Task 0 pre-flight done; next is Task 1 (build SOAR01 VM — interactive user install).

## Current lab state

- **SOC01**: RUNNING. Wazuh 4.14.8 healthy (indexer+manager+dashboard active, cluster yellow = normal single-node). Custom rules 100010+100020+100029–100034 + 100040–100046 live. Clock fixed (was ~12 d behind after host downtime; reset to real UTC, `timedatectl set-ntp off`).
- **WIN01**: RUNNING. Snapshot **`pre-soar`** taken (new Phase 4 rollback point, child of `pre-uc06`). Helpers at `C:\lab\`. Port 445 OPEN.
- **DC01**: OFF (poweroff — correct for S4).
- **NDR01**: OFF (saved-state — correct for S4).
- **SOAR01**: not yet created (Task 1).
- **Repo**: clean at `e2b33bd` (Phase 4 plan).

## Next session — first steps

1. Read this file.
2. **Phase 4 SOAR Task 1**: create SOAR01 VM + Ubuntu install (interactive user step). Plan: `docs/superpowers/plans/2026-11-14-phase4-soar.md`.

## Phase 4 SOAR — locked decisions (from design spec)

- **Tool**: n8n on SOAR01 — Docker Engine (not Desktop), single container, SQLite, queue off. 1 vCPU / 2 GB / 20 GB. host-only `10.10.30.20` (n8n `:5678`) + temporary NAT (attach only during VT demo).
- **n8n env**: `EXECUTIONS_DATA_PRUNE=true`, `EXECUTIONS_DATA_MAX_AGE=168`, `N8N_METRICS=false`, no workers.
- **Trigger**: Sysmon **EID 22** (DNS query) on WIN01 → Wazuh rule **100047** (level 12, MITRE T1071.004, group `dns,lab,soar,`) matching `win.eventdata.queryName` = `<MALICIOUS_DOMAIN>` (VT-verified at demo time).
- **Bridge**: Wazuh integration `forward-to-n8n` → POST rule-100047 alert JSON to n8n webhook `/webhook/soar`.
- **Workflow (7 nodes)**: Webhook → extract (Code) → VT domain lookup (HTTP) → build-incident (Code) → write incident/notification/audit under bind-mounted `/srv/soar`.
- **Safe action**: local analyst notification (`/srv/soar/notifications/latest.json`) + incident record + audit line. No destructive active response.
- **Power-on set S4**: SOC01 + WIN01 + SOAR01 (11 GB; DC01 + NDR01 OFF).
- **Secrets**: VT key in `lab/runbook/.local-credentials.md` (gitignored) + n8n credential only; never committed/exported.
- **UC-13** exit gate; MITRE T1071.004; `<MALICIOUS_DOMAIN>` chosen + VT-verified immediately before demo (`malicious > 0`).

## Notes carried over

- **Remote control**: plink from host. SOC01: `plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10` (host-only; NOT 10.10.10.5). **NDR01 has NO NAT now** — reach it ONLY via SOC01 hop: `plink ... socadmin@10.10.30.10` then `ssh ndradmin@10.10.10.40` (key auth set up). The old `-P 2223 ndradmin@127.0.0.1` is GONE (NAT detached). sudo = `echo <PW> | sudo -S`.
- **plink quoting**: NEVER use `\"` inside a PowerShell double-quoted remote command. For anything non-trivial, write a `.sh` in `C:\Users\pedro\AppData\Local\Temp\opencode\` and run `plink ... -m <file>`.
- **sudo grep self-match**: `sudo grep <phrase> alerts.json` adds a rule-5402 self-alert per run; filter `grep -v COMMAND`. Grep the description phrase (JSON `"id":"1000xx"` is not plain `id:1000xx`).
- **Custom Wazuh rules** in `/var/ossec/etc/rules/local_rules.xml` (repo `lab/soc01/local_rules.xml`). Suricata-sourced rules MUST be children of built-in 86601 (`<if_sid>86601</if_sid>`), keyed on `<field name="alert.signature_id">` (dotted, NO `data.` prefix). `signature_id` is a NUMBER in eve.json, a STRING in Wazuh alerts.
- **Test-NetConnection gotcha (UC-08)**: `Test-NetConnection -Port <closed>` retransmits SYN ~5× and trips SYN-count thresholds; use a single non-blocking `BeginConnect` for a 1-SYN benign control.
- **Clock**: no NTP anywhere; Linux VMs STALL when the host is off/sleeping (WIN01 stays synced via Guest Additions). After ANY resume, `date` on SOC01/NDR01/DC01 first, fix with `timedatectl set-ntp off` + `set-time`, then restart Suricata (stale flow/threshold state).
- **SMB (UC-11) gotchas**: 445 is firewalled by default on WIN01 (open via elevated `Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True`). `smbclient.py` hangs against a filtered 445. Windows rate-limits failed SMB logons ~2s → use CONCURRENT attempts to hit the 10/30s threshold. A real brute force LOCKS the account (recover via `pre-uc06` snapshot restore).
- **Wazuh API**: `token=$(curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token)`; api password has a TRAILING PERIOD.
- **Indexer**: admin password is NOT `admin:admin`; filebeat auths via `/etc/filebeat/filebeat.keystore` (no `show` subcommand).
- **alerts.json** rotates daily → older alerts in `alerts/YYYY/Mmm/` rotated files; `zgrep` them.
- **jq gotcha**: `.rule.id` is a STRING — compare to a quoted string.
- **User runs all attack simulations**; assistant builds/tunes/verifies. Lab is left attack-ready on purpose — do NOT run cleanup/revert without asking.
- Secrets: `lab/runbook/.local-credentials.md` (gitignored). NDR01 `ndradmin/ndradmin123`; SOC01 `socadmin/socadmin123`; WIN01 `labadmin/labadmin123`; Wazuh API `wazuh:<apiPw>`.
