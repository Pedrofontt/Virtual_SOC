# How to create a detection in this lab (the recipe)

The exact process used for rule 100010 (UC-01). Follow it for every new detection; update this file when the process evolves.

## 1. Pick the threat
- Choose the technique + MITRE ID (e.g. T1003.001 LSASS credential dumping).
- Define the success condition BEFORE touching the SIEM (e.g. "alert when rundll32 accesses lsass").

## 2. Understand the log source
- Run the technique once and look at the RAW event (WinEvent, log file, etc.).
- Note the discriminator fields: the 2-4 values that separate evil from normal
  (e.g. SourceImage, TargetImage, GrantedAccess).
- IMPORTANT: confirm the exact field names Wazuh sees. Read a real alert from
  `/var/ossec/logs/alerts/alerts.json` with jq — never guess (e.g. Wazuh JSON uses
  lowercase `win.eventdata.sourceImage`, Sysmon's display shows `SourceImage`).

## 3. Check shipped rules first
- Find the relevant ruleset file (`/var/ossec/ruleset/rules/0xxx-*.xml`).
- Does a shipped rule exist? Test it mentally against BOTH the real technique AND the
  background noise. Shipped rules can be unanchored/substring buggy (92900) — verify.
- Write a custom rule only if shipped rules miss the technique or generate noise.

## 4. Find the parent chain
- Wazuh 4.14 note: Sysmon rules chain via `if_group sysmon_event_N` (added by the built-in
  `windows_eventchannel` decoder — compiled in, NOT an XML file). There is no 61610 parent.
- Rule files: shipped = `/var/ossec/ruleset/rules/`, custom = `/var/ossec/etc/rules/local_rules.xml`
  (repo copy: `lab/soc01/local_rules.xml`).

## 5. Write the rule
- Template:
  ```xml
  <rule id="1000XX" level="LEVEL">
    <if_group>GROUP</if_group>           <!-- or <if_sid> for rule-id chains -->
    <field name="win.eventdata.X" type="pcre2">PATTERN</field>
    <description>WHAT and WHY</description>
    <mitre><id>T1234.567</id></mitre>
    <group>tactic,lab,...</group>
  </rule>
  ```
- Field rules: ANCHOR your regexes (`^...$`), use `(?i)`, escape dots (`\.exe`).
- NO raw quote chars in regex text: the dashboard save fails with API error 1113 (XML) — use PCRE2
  hex escapes `\x22` (`"`) / `\x27` (`'`) instead (UC-02 lesson).
- Constrain enough fields to kill false positives; keep enough to catch variants.
- Level 12+ for real attacks; add MITRE id.

## 6. Deploy + verify
- Repo copy is source of truth → `pscp` to SOC01 → `install -o root -g wazuh -m 640` into
  `/var/ossec/etc/rules/local_rules.xml` → `systemctl restart wazuh-manager` → check
  `ossec.log` for errors.
- UI alternative (Wazuh 4.14 dashboard): **Server Management → Rules → Manage rules files →
  edit the custom rules file (local_rules.xml)**. The UI writes the manager file directly and
  reloads the manager on save. Only ever edit CUSTOM rules files this way (never shipped
  rules files — updates overwrite them). After ANY UI edit, sync the file back to the repo
  (`pscp` SOC01 -> host -> commit) so the repo stays the source of truth.
- `wazuh-logtest` CANNOT test the windows_eventchannel chain — verify with real events.

## 7. Test with a real event + benign control
- USER runs the technique twice (reproducibility) and a benign control (open Notepad).
- Verify: alert in `alerts.json` + dashboard (Discover: `rule.id:XXXXX`), benign = silent.
- Record expected vs observed in the case doc + exercise log; screenshot evidence to
  `lab/cases/evidence/`.

## 8. Document (mandatory)
- Case doc in `lab/cases/uc-XX-*.md`: threat, log source, detection logic, tuning (FP vs TP),
  replay procedure, evidence.
- Lab controls used → `lab/runbook/win01.md` lab controls log.
- Gotchas → `lab/cases/lessons-learned.md` (problem → symptom → root cause → fix).
- Deploy commands → `lab/runbook/setup.md` new subsection.
- Commit with a conventional message.

## Phase 4 — SOAR / automation addendum (confirmed 2026-11-15, UC-13)

When a detection must **trigger automation** (not just alert), extend the recipe:

1. **Source + rule are unchanged** — still Sysmon EID 22 → custom rule (100047) in `local_rules.xml`.
   Nothing about the detection logic changes; automation is a consumer of the alert.
2. **Bridge on the rule id, not on "all alerts".** Wazuh `integratord` runs the integration only for the
   configured `rule_id`. In 4.14 the integration script receives `$1`=alert JSON file, `$2`=api_key,
   `$3`=hook_url; custom scripts MUST be named `custom-*`. The script POSTs the full alert JSON to n8n.
3. **Verify the bridge server-side:** `/var/ossec/logs/integrations.log` must show
   `custom-forward-to-n8n: {"message":"Workflow was started"}HTTP:200` for each alert.
4. **n8n 2.x gotchas (cost real debugging time):**
   - activation = **Publish** (a DB `active=1` alone does NOT register the webhook);
   - expression fields need a leading `=`;
   - the Webhook node nests the POST body under `json.body`;
   - `require('fs')` in Code nodes needs `NODE_FUNCTION_ALLOW_BUILTIN=fs`.
5. **External enrichment can fail and stop the run.** VirusTotal returns 404 for unknown domains; the
   HTTP node errors on non-2xx, so the workflow never reaches the write nodes. Use a domain VT knows, or
   make the node tolerate errors and degrade gracefully.
6. **Evidence is the output artifacts**, not just the alert: the incident JSON (alert + enrichment),
   the notification, and the audit line under `/srv/soar`. Save the alert + incident to `lab/evidence/`.
7. **Demo reproducibility gotcha:** the exact malicious domain can be suppressed by the endpoint (Windows
   DNS negative cache that `flushdns` won't clear → reboot WIN01; Defender blocking the exact known-bad
   name at the DNS layer → disable real-time for the demo). A fresh `*.malware.wicar.org` subdomain is
   cache-proof but VT-unknown; use the cached name after a WIN01 reboot.

## Phase 2 — Samba/KDC decoded field map (confirmed 2026-10-23, wazuh-logtest)

Three log sources on DC01, all shipping to manager agent `002` (`dc01`):

1. **`/var/log/samba/audit.json`** (localfile `log_format=json`) — decoder `json`.
   JSON keys are preserved VERBATIM (case + spaces) as dynamic fields — do NOT lowercase:
   - `Authentication.status`, `Authentication.eventId` (string, e.g. `"4624"`/`"4625"`),
     `Authentication.logonType`, `Authentication.clientAccount`, `Authentication.clientDomain`,
     `Authentication.remoteAddress`, `Authentication.serviceDescription` (`LDAP` | `Kerberos KDC`),
     `Authentication.authDescription`, `Authentication.passwordType`, plus `type`, `timestamp`.
   - Correlation gotcha (UC-03a): `Authentication.remoteAddress` is `ipv4:IP:<srcport>` — the port
     changes per connection, so `same_field` on it never matches. And `clientAccount` is
     `attacker@CORP` over Kerberos KDC but `attacker` over SMB2/NTLM. Use the normalized
     `Authentication.mappedAccount` for `same_field` burst correlation (rule 100030).
   - KDC Authorization events (UC-04 signal): `KDC Authorization.status`, `.account`,
     `.serviceDescription` (e.g. `MSSQLSvc/dc01.corp.lab:1433@CORP.LAB`),
     `.authType` (`TGS-REQ with Ticket-Granting Ticket`), `.domain`, `.remoteAddress`,
     `.logonServer`, `.authTime`.
   NOTE: `type` discriminates the two shapes (`Authentication` vs `KDC Authorization`).

2. **`/var/log/samba/log.samba`** (localfile `log_format=syslog`) — decoder is EMPTY (`{}`).
   Only these fields exist: `full_log` (whole RFC3164-ized line, e.g.
   `Oct 23 04:31:31 dc01 samba:    Kerberos: TGS-REQ SUCCESS ipv4:...`), `predecoder.program_name`
   (`samba`), `predecoder.hostname`, `predecoder.timestamp`, `location`. There is NO `message`
   field — rules must match on `full_log`.
   UC-04: `TGS-REQ SUCCESS ... MSSQLSvc/...` ; UC-05 (adapted): `AS-REQ ERR_PREAUTH_REQUIRED
   ... client-pa=128` + `Need\sto\suse\sPA-ENC-TIMESTAMP/PA-PK-AS-REQ`.

3. **journald** (default localfile, `log_format=journald`) — Samba syslog ALSO lands here
   (Debian 12: /dev/log belongs to journald). Same content as log.samba but RAW msg (no RFC3164
   prefix, leading spaces), decoder empty, only `full_log` + predecoder. Rules matching
   `full_log` text patterns will fire TWICE per KDC line (log.samba + journald) — plan for
   dedup (`same_field`/frequency) or filter on `location`.

4. FIM (UC-03b): the real write target is the **domain partition** `file` =
   `/var/lib/samba/private/sam.ldb.d/DC=CORP,DC=LAB.ldb` — NOT the top-level `sam.ldb`
   (a stub whose mtime never changes). `sam.ldb` is TDB: writes are mmap/msync, so mtime
   updates but **inotify/realtime FIM never fires** — only the periodic checksum scan detects
   the change. Config therefore uses `<frequency>60</frequency>` (near-realtime, ~60s latency)
   and watches the `sam.ldb.d` directory. FIM event: `syscheck.path` =
   `/var/lib/samba/private/sam.ldb.d/DC=CORP,DC=LAB.ldb`, `syscheck.event` = `modified`,
    rule 550 (level 7). **Rule 100032's regex must match the `sam.ldb.d` path, not `sam.ldb`.**

    **FIM rule-field gotcha (UC-03b, cost a full debugging loop):** the ALERT JSON shows the path
    under `syscheck.path`, but RULE matching uses the *FIM field name* `file` — NOT `syscheck.path`.
    The two are inconsistent by design (and `wazuh-logtest` disagrees with `analysisd` here, see
    wazuh#26327). A FIM custom rule must therefore use:
    ```xml
    <rule id="100032" level="12">
      <if_sid>550</if_sid>
      <field name="file" type="pcre2">sam\.ldb\.d/DC=CORP,DC=LAB\.ldb</field>
      <description>LAB: Active Directory database modified - $(file)</description>
      <group>fim,lab,identity_attack,</group>
      <mitre><id>T1565.001</id></mitre>
    </rule>
    ```
    Use `if_sid 550` (child of "Integrity checksum changed") rather than `if_group syscheck` so the
    rule only matches *modifications* of the target, not adds/deletes. Full FIM rule-field map:
    `file`(path) `size`(size_after) `perm` `mode` `md5`/`sha1`/`sha256` `mtime`/`inode`
    `changed_fields`(changed_attributes) `user_name`/`process_name` etc. In the description you may
    reference either `$(syscheck.path)` (alert name) or `$(file)` (FIM name).

Samples: `lab/evidence/phase2-capture-*.json` (archive-format records, one JSON per line).

