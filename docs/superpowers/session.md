# Session state — resume here

Last updated: 2026-11-15 (Phase 4 SOAR **COMPLETE — Tasks 0–8**; UC-13 demo PASS + close-out; snapshot `base-phase4`; all VMs powered off). Resume by reading this file; next = Phase 5 / optional.

## Where we are — PHASE 3 NDR: COMPLETE; PHASE 4 SOAR: COMPLETE (9/9)

Phase 3 NDR (UC-06..12) done + committed. Phase 4 SOAR (UC-13) done + committed:

- **Task 0** pre-flight: DONE (S4 power-on, WIN01 snapshot `pre-soar`, SOC01 clock fixed).
- **Task 1** SOAR01 VM: DONE (Ubuntu 24.04, `soaradmin`, static `10.10.30.20/24`, NAT `10.0.3.0/24`).
- **Task 2** Docker + n8n: DONE (Docker 29.1.3, n8n **v2.47.7**, owner `soaradmin@corp.lab`).
- **Task 3** Sysmon EID 22: DONE (field **`win.eventdata.queryName`**, group **`sysmon_event_22`** confirmed).
- **Task 4** rule 100047: DONE + **smoke-test PASSED** (fires on `malware.wicar.org`).
- **Task 5** Wazuh→n8n integration: DONE (`custom-forward-to-n8n`).
- **Task 6** n8n workflow: DONE + **smoke-test PASSED** (manual POST `google.com` → VT verdict + files written). Committed `3bb61eb`.
- **Task 7** UC-13 demo: DONE — rule 100047 → integration → n8n verified end-to-end **twice** (18:55 and 20:12 alerts; incidents, notification, audit written). Evidence exported to `lab/evidence/`.
- **Task 8** close-out: DONE — SOAR01 NAT detached, snapshot `base-phase4`; docs written (`uc-13`, `soar01.md`, `soar01-walkthrough.md`, `setup.md` §5, exercise-log, lessons-learned); all VMs powered off.

## Current lab state (ALL VMs OFF — Phase 4 closed, 2026-11-15)

- **SOC01**: poweroff. Wazuh 4.14.8 healthy when running (cluster `yellow` = normal single-node). Rule **100047** live; integration `custom-forward-to-n8n` wired (rule 100047 → `http://10.10.30.20:5678/webhook/soar`).
- **WIN01**: poweroff. Sysmon EID 22 (DNS) enabled. Snapshot **`pre-soar`**. Defender real-time was left OFF after demos — re-enable (`Set-MpPreference -DisableRealtimeMonitoring $false` + Tamper on) before normal use. Sysmon64.exe `C:\lab\tools\Sysmon64.exe`.
- **SOAR01**: poweroff. n8n `:5678` (container `n8n`), workflow id `uw47iA9RnDEEyCrS` published (7 nodes). **NAT detached** (`nic2 none`); snapshot **`base-phase4`** (UUID `f418912c`). `/srv/soar` holds 2 demo incidents + notification + audit.
- **DC01**: poweroff. **NDR01**: saved-state. Correct for S4.
- **Repo**: see `git log`; Phase 4 commits include `844ae2e`…`514dd4c`, workflow `3bb61eb`, ledger `0f536cf`, Task 7 evidence `fc8e965`, Task 8 final commit.

## Reproducing the UC-13 demo (for live runs)

Steps:
IMPORTANT: exact `malware.wicar.org` sticks in WIN01's DNS **negative cache**; `ipconfig /flushdns` does NOT clear it and `dnscache` is a protected service. A WIN01 **reboot** clears it (power-cycling the VM does too). Defender real-time also blocks the exact domain (tamper is OFF in the lab).

1. Power on **SOC01, WIN01, SOAR01** (S4). Re-check clocks.
2. On WIN01 (elevated PowerShell):
   `Set-MpPreference -DisableRealtimeMonitoring $true`
   `ipconfig /flushdns`
   `Resolve-DnsName -Type A malware.wicar.org`   # timeout expected; must log Sysmon EID 22
3. Verify SOC01 rule 100047 alert, and SOAR01 `/srv/soar/incidents/<id>.json` + `notifications/latest.json` + `audit.log`.
4. Benign control: `Resolve-DnsName -Type TXT example.com` → event but **no** 100047 alert.

Gotchas: unique subdomains are cache-proof but VT returns 404 (workflow stops). Typos (`==`, `.com`) either 404 or don't match the rule. After demos, re-enable Defender: `Set-MpPreference -DisableRealtimeMonitoring $false`.

### Phase 5 / optional next
Phase 4 is complete (Task 8 exit gate green). Optional next: Phase 5 design, or polish/presentation. Re-enable WIN01 Defender before any non-demo use.

### Task 6 workflow (7 nodes) — actual built names
1. **Webhook** (trigger): Method `POST`, Path `soar`, Respond `Immediately`; `webhookId` `df4927e2-a3ad-4bfe-8201-0692ce96bf10`. URL `http://10.10.30.20:5678/webhook/soar`.
2. **Code** `extract`: `const a = $input.first().json; const body = a.body ?? a; ...domain = body.data?.win?.eventdata?.queryName`
3. **HTTP Request** `vt-lookup`: `GET =https://www.virustotal.com/api/v3/domains/{{ $json.domain }}`, Header Auth `x-apikey` credential id `GoRRmQCCX6TxwaP7`.
4. **Code** `build-incident` (VT verdict → incident/notification/audit objects).
5. **Code** `write-incident` (fs write `/srv/soar/incidents/<alert_id>.json`).
6. **Code** `write-notification` (fs write `/srv/soar/notifications/latest.json`).
7. **Code** `write-audit` (fs append `/srv/soar/audit.log`).

## Phase 4 SOAR — locked decisions (design spec)

- **Tool**: n8n on SOAR01, Docker Engine, single container, SQLite, queue off. 1 vCPU / 2 GB / 20 GB. host-only `10.10.30.20` (`:5678`) + temporary NAT (detach in Task 8).
- **n8n env (container)**: `EXECUTIONS_DATA_PRUNE=true`, `EXECUTIONS_DATA_MAX_AGE=168`, `N8N_METRICS=false`, `N8N_SECURE_COOKIE=false`, **`NODE_FUNCTION_ALLOW_BUILTIN=fs`** (NOT the 1.x `N8N_CODE_ENABLE_BUILTIN_MODULES`, which is ignored in 2.x). Volume `/srv/n8n:/home/node/.n8n`.
- **Trigger**: Sysmon EID 22 → rule **100047** (level 12, T1071.004, `dns,lab,soar,`) on `win.eventdata.queryName` = `<MALICIOUS_DOMAIN>` (VT-verified at demo). **Current placeholder: `malware.wicar.org` — swap in Task 7.**
- **Bridge**: Wazuh integration **`custom-forward-to-n8n`** (custom- prefix REQUIRED) → POST alert JSON to `/webhook/soar`.
- **Safe action**: notification + incident + audit under `/srv/soar`. No destructive response.
- **S4**: SOC01 + WIN01 + SOAR01 (11 GB; DC01 + NDR01 OFF).
- **Secrets**: VT key only in `.local-credentials.md` + n8n credential; never in git.

## Notes carried over (still valid)

- **Remote control**: plink from host. SOC01 `plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw socadmin123 socadmin@10.10.30.10`. **SOAR01** `plink -batch -hostkey SHA256:L0z4KGt1aq87MtiZCTB+7+JAlCl3dFOrveJK/YsKK/E -pw soaradmin123 soaradmin@10.10.30.20` (also NAT fwd `-P 2224 soaradmin@127.0.0.1`). NDR01 = SOC01 hop only (no NAT). DC01 = SOC01 hop / natpf 2222. sudo = `echo <PW> | sudo -S`.
- **plink quoting**: NEVER use `\"` in a PowerShell double-quoted remote command. For anything non-trivial, write a `.sh` in `C:\Users\pedro\AppData\Local\Temp\opencode\` and run `plink ... -m <file>`; or pscp a file + `sudo mv`.
- **Wazuh 4.14 locations**: built-in rules in `/var/ossec/ruleset/rules/` (NOT `/var/ossec/etc/rules/`). Custom rules in `/var/ossec/etc/rules/local_rules.xml` (repo `lab/soc01/local_rules.xml`). Sysmon EID 22 group = `sysmon_event_22` (built-in rule 61650). Field names: Sysmon `win.eventdata.*`; NDR `alert.signature_id` (child of 86601).
- **Wazuh integration interface (4.14)**: script args = `$1` alert-JSON file path, `$2` api_key, `$3` hook_url. Custom scripts MUST be named `custom-*`. Ownership `root:wazuh`, `chmod 750`.
- **ossec.conf has TWO `<ossec_config>` blocks** (Phase 2 duplicate) — insert additions before the FIRST `</ossec_config>`.
- **Clock**: no NTP; Linux VMs stall on host sleep. Check `date` on SOC01/SOAR01 after ANY resume; fix `timedatectl set-ntp off` + `set-time` + restart wazuh-manager (and re-check Suricata if NDR01 were on). WIN01 stays synced via Guest Additions.
- **guestcontrol is NON-elevated** on WIN01 — can't run Sysmon reload / reg add / firewall changes. Those need the user in an elevated PowerShell (switch WIN01 to GUI if needed).
- **Host-only adapter #2 DHCP is MISCONFIGURED** (serves `192.168.56.x` on the `10.10.30.0/24` wire) — always use STATIC IPs on new host-only VMs; don't rely on DHCP.
- **sudo grep self-match** → rule-5402; filter `grep -v COMMAND`; grep the description phrase not `id:...`.
- **n8n 2.x gotchas**: activation = **Publish** (async via `workflow_publication_outbox`; DB `active=1` alone does NOT register the webhook; container restart re-registers published webhooks). Expression fields need leading `=` (`=https://.../{{ $json.domain }}`). Webhook output nests alert under `json.body`. Webhook node needs its `webhookId`. `require('fs')` needs `NODE_FUNCTION_ALLOW_BUILTIN=fs`.
- **DNS demo gotcha (Task 7)**: `Resolve-DnsName malware.wicar.org` is often answered from the Windows DNS cache (no wire query → no Sysmon EID 22 event). Force a never-queried name (`zzq7x1.malware.wicar.org`, still matches rule 100047's substring regex) or a fresh unique subdomain.
- **Wazuh API**: `token=$(curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token)`; api pw has a TRAILING PERIOD. Indexer admin = `admin:3e7Rzku4MNktFJQZ.Pxo?P0tTsAVt0jD` (single-node yellow is normal).
- **alerts.json** rotates daily; `zgrep` older rotated files. jq `.rule.id` is a STRING.
- **User runs all attack simulations** (DNS lookups); assistant builds/tunes/verifies. Lab left attack-ready — don't cleanup/revert without asking.
- Secrets in `lab/runbook/.local-credentials.md` (gitignored). SOC01 `socadmin/socadmin123`; WIN01 `labadmin/labadmin123`; SOAR01 `soaradmin/soaradmin123`; Wazuh API `wazuh:1O58pEByLzeNx27aHgsZYp2L+R5pyga.`; domain admin `Administrator/DomAdmin!lab123`; attacker `Attacker!lab123`, victim `Victim!lab123`, svc-sql `SvcSQL!lab123`.

## Demo-ready state (2026-11-16)

- **SOC01 would not boot** from its current overlay: initramfs stall, AHCI resets, RCU stall.
  SOAR01 booted fine → SOC01-specific disk-overlay corruption. Safety snapshot
  `broken-20261115` kept.
- **Recovery:** restored snapshot `base-phase1-fixed`, then re-applied from the repo:
  `lab/soc01/local_rules.xml` (16 rules incl. 100047), `lab/soc01/custom-forward-to-n8n`
  (root:wazuh 750) + the `<integration>` block in `ossec.conf`, then restarted Wazuh.
  Indexer + dashboard up; integratord running; agent 001 `Active` when WIN01 boots.
- **SOC01 boot settings left at** 2 vCPUs and `paravirtprovider=none` (boot stability; no
  demo impact). Documented deviation from setup.md (3 vCPUs).
- **Live preflight** 2026-11-16T00:27:27Z: rule 100047 fired with **Defender real-time ON**;
  VT 16 malicious; incident + notification + audit written. Same alert forwarded twice
  (dedup gap, cosmetic).
- **WIN01** left with Defender real-time **ON** (verified compatible). Clean shutdown clears
  the DNS negative cache, so the next demo run is a fresh wire query.
- **Snapshots `demo-ready`:** SOC01 `24844a31-5807-4751-b71a-38a7e13a2e16`,
  WIN01 `1b961a52-e577-48f2-9e42-ba0a755f3e8b`,
  SOAR01 `71cc7d65-2239-47ab-9696-51fa123d3cd2`.
- **All VMs powered off; SOAR01 `nic2=nat` attached** (required for the VirusTotal call).
- **Demo checklist:** `lab/runbook/demo-day.md`.
- **Host note:** Windows hypervisor/VBS is ON (`HypervisorPresent=True`), so VirtualBox uses
  NEM. This was not the cause (SOAR01 booted); do not change host settings for the demo.
