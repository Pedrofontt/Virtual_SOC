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
