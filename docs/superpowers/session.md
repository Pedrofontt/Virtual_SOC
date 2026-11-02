# Session state — resume here

Last updated: 2026-11-02 (Phase 3 NDR **COMPLETE + committed**; Phase 4 SOAR brainstorming started, trigger question pending). Resume by reading this file; next is Phase 4 SOAR.

## Where we are — PHASE 3 NDR: COMPLETE

All 7 detections verified end-to-end (Suricata eve.json → agent 003 → SOC01 manager → custom rule):

| UC | MITRE | Status | Trigger | sid → rule |
|---|---|---|---|---|
| UC-06 marker | — | **PASS** | `Invoke-WebRequest` UA `lab-ndr-test` → SOC01 | 7000001 → 100040 lvl 8 |
| UC-07 port scan | T1046 | **PASS** | `C:\lab\port-scan.ps1` (60 SYNs) | 7000002 → 100041 lvl 10 |
| UC-08 beaconing | T1571 | **PASS** | `C:\lab\beacon.ps1` (SYNs to :4444) | 7000003 → 100042 lvl 12 |
| UC-09 ICMP tunnel | T1095 | **PASS** | `ping -n 3 -l 1200 10.10.10.5` | 7000004 → 100043 lvl 12 |
| UC-10 DNS anomaly | T1071.004 | **PASS** | `C:\lab\dns-exfil.ps1` → SOC01:53 | 7000005 → 100044 lvl 12 |
| UC-11 SMB brute force | T1110 | **PASS** (+lab controls) | SOC01 impacket ×12 → WIN01:445 | 7000006 → 100045 lvl 12 |
| UC-12 cleartext FTP | T1040 | **PASS** | WIN01 `ftp` → SOC01:21 (`mini_ftpd.py`) | 7000007 → 100046 lvl 10 |

Task 14 close-out done: 7 case docs (`lab/cases/uc-06..12`), exercise log, lessons-learned,
`ndr01-walkthrough.md` + `setup.md` §4, evidence `lab/evidence/phase3-alerts.json`,
NDR01 NAT detached + RAM 1 GB + snapshot `base-phase3`.

## Current lab state

- **SOC01**: RUNNING. Wazuh 4.14.8 healthy. Custom rules 100010+100020+100029–100034 +
  **100040–100046** live (8467 rules total). Clock synced. `mini_ftpd.py` stopped (UC-12 done).
  HTTP server tmux session `http` (port 80) still up.
- **WIN01**: RUNNING. Snapshot **`pre-uc06`** (rollback point; recovered the UC-11 `labadmin`
  lockout by restoring to it). Helpers at `C:\lab\`: `beacon.ps1`, `dns-exfil.ps1`, `port-scan.ps1`.
  **Port 445 is OPEN** (File/Printer Sharing rule enabled) — permanent lab change for UC-11.
- **DC01**: OFF (correct — S3).
- **NDR01**: RUNNING (headless). Suricata 8.0.8 active (af-packet enp0s3, promisc allow-all,
  sids 7000001–7000007). Wazuh agent **003** active. **NAT detached, RAM 1 GB, snapshot
  `base-phase3`**. Clock synced.
- **Repo**: clean. Phase 3 fully committed: `b713802` (Phase 3 complete), `edc775c` (UC-06..12 screenshots), `8ebe2ea` (NDR01 runbook + walkthrough).

## Next session — first steps

1. Read this file.
2. **Phase 4 SOAR** (brainstorming in progress): agree on the trigger use case (UC-01 T1003.001 vs NDR vs both), then finish design → write spec → plan. See "Phase 4 SOAR context" below.

## Phase 4 SOAR — brainstorming context (carry over)

- **Purpose (agreed)**: complete the pipeline (alert → enrich → incident → safe action → audit), automate the analyst loop, demonstrate SIEM→SOAR orchestration, safe + accountable (non-destructive; human approval for anything that changes the endpoint). This is Nivel 3 in `initial_info.md`.
- **Tool (locked in architecture)**: n8n on SOAR01 — Docker Engine (not Docker Desktop), single container, SQLite backend, queue mode off. 1 vCPU / 2 GB / 20 GB. host-only `10.10.30.20` (n8n `:5678`) + temporary NAT.
- **n8n container settings**: `EXECUTIONS_DATA_PRUNE=true`, `EXECUTIONS_DATA_MAX_AGE=168`, metrics off, no extra workers.
- **Playbook must**: record alert id / rule id / agent name / timestamp; enrich locally (no mandatory internet); write an incident record (local file or n8n data store); take one safe action (tag the alert or send a local notification); append an audit line with action + result.
- **Out of scope**: destructive active response (disable account, isolate host, delete files); VirusTotal unless a documented exception (local enrichment preferred to preserve isolation).
- **Power-on set S4**: SOC01 + WIN01 + SOAR01 (11 GB; DC01 + NDR01 off).
- **OPEN — trigger question** (not yet answered): UC-01 T1003.001 (requires WIN01 lab-control rework) vs an NDR detection (fresh/easy) vs both staged. Architecture doc assumes UC-01.

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
