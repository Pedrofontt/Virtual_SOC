# Session state — resume here

Last updated: 2026-11-15 (Phase 4 SOAR **Tasks 0–5 complete; Task 6 in progress** — n8n workflow build, waiting on user VT credential). Resume by reading this file; next is **Task 6 workflow build**.

## Where we are — PHASE 3 NDR: COMPLETE; PHASE 4 SOAR: TASK 6/9

Phase 3 NDR (UC-06..12) done + committed. Phase 4 SOAR (UC-13) execution in progress:

- **Task 0** pre-flight: DONE (S4 power-on, WIN01 snapshot `pre-soar`, SOC01 clock fixed).
- **Task 1** SOAR01 VM: DONE (Ubuntu 24.04, `soaradmin`, static `10.10.30.20/24`, NAT `10.0.3.0/24`).
- **Task 2** Docker + n8n: DONE (Docker 29.1.3, n8n **v2.47.7**, owner `soaradmin@corp.lab`).
- **Task 3** Sysmon EID 22: DONE (field **`win.eventdata.queryName`**, group **`sysmon_event_22`** confirmed).
- **Task 4** rule 100047: DONE + **smoke-test PASSED** (fires on `malware.wicar.org`).
- **Task 5** Wazuh→n8n integration: DONE (`custom-forward-to-n8n`).
- **Task 6** n8n workflow: **IN PROGRESS** — VT credential + 7-node workflow build (user action).
- **Task 7** UC-13 demo, **Task 8** close-out: not started.

## Current lab state

- **SOC01**: RUNNING, Wazuh 4.14.8 healthy (cluster `yellow` = normal single-node). Custom rules through **100047** live. Integration `custom-forward-to-n8n` wired (rule 100047 → `http://10.10.30.20:5678/webhook/soar`). Clock ~synced (re-check `date` after any host sleep). `content-updater`/`vulnerability_feed_manager` errors are BENIGN (SOC01 offline, no internet — stale CVE feed only).
- **WIN01**: RUNNING. Sysmon EID 22 (DNS) enabled. Snapshot **`pre-soar`** (rollback point). Sysmon64.exe at `C:\lab\tools\Sysmon64.exe`, config `C:\lab\sysmon-config.xml`. **guestcontrol runs NON-elevated** → elevated WIN01 ops (e.g. Sysmon reload) require the USER.
- **SOAR01**: RUNNING. n8n `:5678` up (container `n8n`), owner `soaradmin@corp.lab` / `soaradmin123`. NAT still attached (detach in Task 8). `/srv/soar` (incidents/, notifications/, audit.log) world-writable; `/srv/n8n` bind-mounted for n8n data persistence.
- **DC01**: OFF (poweroff). **NDR01**: OFF (saved-state). Correct for S4.
- **Repo**: clean at `514dd4c` (Phase 4 commits `844ae2e`…`514dd4c`).

## Next — Task 6 (n8n workflow) first steps

1. User provides **VirusTotal API key**: add to `lab/runbook/.local-credentials.md` (gitignored) as `VirusTotal API key: <key>`.
2. n8n → Credentials → **Header Auth**: Name `x-apikey`, Value = VT key.
3. Build the 7-node workflow (order + names matter — see below).
4. Smoke-test with a manual POST, export `lab/soar01/workflow.json` (+ `workflow.md`), commit.

### Workflow (7 nodes) — exact order & names
1. **Webhook** (trigger): Method `POST`, Path `soar`, Respond `Immediately`. Production URL `http://10.10.30.20:5678/webhook/soar`.
2. **Code** `extract` (Run Once for All Items):
   `const a = $input.first().json; return { alert_id: a.id, rule_id: a.rule?.id, agent: a.agent?.name, timestamp: a.timestamp, domain: a.data?.win?.eventdata?.queryName || null, raw: a };`
3. **HTTP Request** `vt-lookup`: `GET https://www.virustotal.com/api/v3/domains/{{ $json.domain }}`, Auth = the `x-apikey` Header Auth credential.
4. **Code** `build-incident` (Run Once for All Items): see plan §Task 6 Step 2 (extracts VT verdict → incident/notification/audit objects).
5. **Read/Write Files** `write-incident`: Write `/srv/soar/incidents/{{ $json.alert_id }}.json`, data `{{ JSON.stringify($json.incident) }}`.
6. **Read/Write Files** `write-notification`: Write `/srv/soar/notifications/latest.json`, data `{{ JSON.stringify($json.notification) }}`.
7. **Code** `write-audit` (audit append — `N8N_CODE_ENABLE_BUILTIN_MODULES=fs` already enabled):
   `const { appendFileSync } = require('fs'); appendFileSync('/srv/soar/audit.log', JSON.stringify($input.first().json.audit) + '\n'); return $input.first().json;`

Full JS for `build-incident` + expression list: `docs/superpowers/plans/2026-11-14-phase4-soar.md` Task 6.

## Phase 4 SOAR — locked decisions (design spec)

- **Tool**: n8n on SOAR01, Docker Engine, single container, SQLite, queue off. 1 vCPU / 2 GB / 20 GB. host-only `10.10.30.20` (`:5678`) + temporary NAT (detach in Task 8).
- **n8n env (container)**: `EXECUTIONS_DATA_PRUNE=true`, `EXECUTIONS_DATA_MAX_AGE=168`, `N8N_METRICS=false`, `N8N_SECURE_COOKIE=false`, `N8N_CODE_ENABLE_BUILTIN_MODULES=fs`. Volume `/srv/n8n:/home/node/.n8n`.
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
- **Wazuh API**: `token=$(curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token)`; api pw has a TRAILING PERIOD. Indexer admin = `admin:3e7Rzku4MNktFJQZ.Pxo?P0tTsAVt0jD` (single-node yellow is normal).
- **alerts.json** rotates daily; `zgrep` older rotated files. jq `.rule.id` is a STRING.
- **User runs all attack simulations** (DNS lookups); assistant builds/tunes/verifies. Lab left attack-ready — don't cleanup/revert without asking.
- Secrets in `lab/runbook/.local-credentials.md` (gitignored). SOC01 `socadmin/socadmin123`; WIN01 `labadmin/labadmin123`; SOAR01 `soaradmin/soaradmin123`; Wazuh API `wazuh:1O58pEByLzeNx27aHgsZYp2L+R5pyga.`; domain admin `Administrator/DomAdmin!lab123`; attacker `Attacker!lab123`, victim `Victim!lab123`, svc-sql `SvcSQL!lab123`.
