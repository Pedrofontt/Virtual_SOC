# Session state — resume here

Last updated: 2026-11-15 (Phase 4 SOAR **Tasks 0–7 complete** — UC-13 demo reproduced end-to-end; evidence exported). Resume by reading this file; next is **Task 8 close-out**.

## Where we are — PHASE 3 NDR: COMPLETE; PHASE 4 SOAR: TASK 8/9

Phase 3 NDR (UC-06..12) done + committed. Phase 4 SOAR (UC-13) execution in progress:

- **Task 0** pre-flight: DONE (S4 power-on, WIN01 snapshot `pre-soar`, SOC01 clock fixed).
- **Task 1** SOAR01 VM: DONE (Ubuntu 24.04, `soaradmin`, static `10.10.30.20/24`, NAT `10.0.3.0/24`).
- **Task 2** Docker + n8n: DONE (Docker 29.1.3, n8n **v2.47.7**, owner `soaradmin@corp.lab`).
- **Task 3** Sysmon EID 22: DONE (field **`win.eventdata.queryName`**, group **`sysmon_event_22`** confirmed).
- **Task 4** rule 100047: DONE + **smoke-test PASSED** (fires on `malware.wicar.org`).
- **Task 5** Wazuh→n8n integration: DONE (`custom-forward-to-n8n`).
- **Task 6** n8n workflow: DONE + **smoke-test PASSED** (manual POST `google.com` → VT verdict + files written). Committed `3bb61eb`.
- **Task 7** UC-13 demo: DONE — rule 100047 → integration → n8n verified end-to-end **twice** (18:55 and 20:12 alerts; incidents, notification, audit written). Evidence exported to `lab/evidence/`.
- **Task 8** close-out: not started.

## Current lab state (SOC01/WIN01/SOAR01 RUNNING — ready for next demo, 2026-11-15)

- **SOC01**: running. Wazuh 4.14.8 healthy (cluster `yellow` = normal single-node). Rule **100047** live. Integration `custom-forward-to-n8n` wired (rule 100047 → `http://10.10.30.20:5678/webhook/soar`). Clock synced.
- **WIN01**: running. Sysmon EID 22 (DNS) enabled. **Defender real-time OFF + tamper OFF** (for demos; re-enable after). Snapshot **`pre-soar`**. Sysmon64.exe `C:\lab\tools\Sysmon64.exe`, config `C:\lab\sysmon-config.xml`. **guestcontrol NON-elevated** → elevated WIN01 ops require the USER.
- **SOAR01**: running. n8n `:5678` up (container `n8n`), workflow id `uw47iA9RnDEEyCrS` published (7 nodes). NAT still attached (detach in Task 8). `/srv/soar` holds 2 demo incidents + notification + audit.
- **DC01**: poweroff. **NDR01**: saved-state. Correct for S4.
- **Repo**: see `git log`; Phase 4 commits include `844ae2e`…`514dd4c`, workflow `3bb61eb`, ledger `0f536cf`, Task 7 evidence.

## Next — Task 8 close-out (after any live demos)

### Reproducing the UC-13 demo (every live run)
IMPORTANT: exact `malware.wicar.org` sticks in WIN01's DNS **negative cache**; `ipconfig /flushdns` does NOT clear it and `dnscache` is a protected service. A WIN01 **reboot** clears it (power-cycling the VM does too). Defender real-time also blocks the exact domain (tamper is OFF in the lab).

1. Power on **SOC01, WIN01, SOAR01** (S4). Re-check clocks.
2. On WIN01 (elevated PowerShell):
   `Set-MpPreference -DisableRealtimeMonitoring $true`
   `ipconfig /flushdns`
   `Resolve-DnsName -Type A malware.wicar.org`   # timeout expected; must log Sysmon EID 22
3. Verify SOC01 rule 100047 alert, and SOAR01 `/srv/soar/incidents/<id>.json` + `notifications/latest.json` + `audit.log`.
4. Benign control: `Resolve-DnsName -Type TXT example.com` → event but **no** 100047 alert.

Gotchas: unique subdomains are cache-proof but VT returns 404 (workflow stops). Typos (`==`, `.com`) either 404 or don't match the rule. After demos, re-enable Defender: `Set-MpPreference -DisableRealtimeMonitoring $false`.

### Task 8 close-out
1. Detach SOAR01 NAT (keep host-only). 2. Refresh this file / runbook / ledger. 3. Acceptance.

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
