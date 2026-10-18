# UC-02 — T1059.001 PowerShell Encoded Command

Status: PASS

## Hypothesis
PowerShell launched with a base64 `-EncodedCommand` (the classic T1059.001 obfuscation) is detectable
from Sysmon EID 1 telemetry with a custom Wazuh rule that covers the shortened flag variants shipped
rules miss — regardless of parent process.

## Detection logic
- Source: Sysmon EID 1 (ProcessCreate) on WIN01 — logged unfiltered (`ProcessCreate onmatch="exclude"`
  with an empty list in `lab/win01/sysmon-config.xml`).
- Custom rule `100020` (level 12, MITRE T1059.001) in `lab/soc01/local_rules.xml` (written by the user
  via the dashboard UI — first UI-created rule in the lab):
  - `if_group sysmon_event1` — note: EID 1's group has NO underscore (unlike EID 10's `sysmon_event_10`)
  - `image =~ (?i)(?:powershell|pwsh)\.exe$` AND
    `commandLine =~ (?i)\s-(?:encodedcommand|enco|enc|ec|en|e)\b\s+[\x22\x27]?[A-Za-z0-9+/]{12,}={0,2}`
  - PowerShell accepts unambiguous prefix abbreviations; attackers shorten `-EncodedCommand` to evade
    naive searches, so the variant list matters.
  - `\x22`/`\x27` = quote chars as PCRE2 hex escapes — raw `"` in the rule file caused dashboard save
    error 1113 (see lessons-learned).
- Field names were confirmed from a REAL EID 1 alert first (recipe step 2): `win.eventdata.image`
  (lowercase) and `win.eventdata.commandLine` (**capital L** — casing differs per event id; EID 10
  uses `sourceImage`/`targetImage`).

## Shipped-rule gap analysis (why custom)
- 92057 ("Powershell.exe spawned a powershell process which executed a base64 encoded command"):
  requires `parentImage = powershell.exe` AND its alternation `(encodedcommand|e|ea|ec|encodeda|encode|en|enco)\b`
  misses `-Enc` — the `\b` never matches mid-prefix. Proven in our capture run: only generic 92027 fired.
- 92071: WMI-parent only (`if_sid 92070`).
- **No shipped rule catches `cmd.exe → powershell -enc`** — the most common attack pattern.
  Rule 100020 covers both parent variants.

## Test procedure
1. Capture run (before the rule): `powershell.exe -NoP -NonI -Enc <b64>` from a PS console → raw EID 1
   alert pulled from `alerts.json`; field names confirmed; shipped coverage evaluated.
2. Rule 100020 written via dashboard UI (Server Management → Rules → Manage rules files →
   `local_rules.xml`), saved (manager reloads automatically), file pscp'd back to repo and committed.
3. Run 1: same command from a PowerShell console (parent `powershell.exe`).
4. Run 2: same command from `cmd.exe` (parent `cmd.exe` — the shipped gap).
5. Controls: `powershell.exe -Command "Write-Output hello"` from PS console and from cmd — must be silent.

Payload used (benign): base64/UTF-16LE of `Write-Output hello` =
`VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGUAbABsAG8A`

## Expected vs observed
Expected: one 100020 per run; silence on controls. Observed: exactly that.

| Run | Parent | Wazuh alert ts (UTC) | Result |
|---|---|---|---|
| capture (pre-rule) | powershell.exe | 2026-10-18T05:35:18 | 92027 only (lvl 4) — 92057 missed `-Enc` |
| 1 | powershell.exe | 2026-10-18T06:25:14.857 | 100020 lvl 12 ✓ |
| 2 | cmd.exe | 2026-10-18T07:00:36.177 | 100020 lvl 12 ✓ |
| control PS | powershell.exe | n/a | silent ✓ |
| control cmd | cmd.exe | n/a | silent ✓ |

Alert JSON (run 2, abbreviated):
```json
{"timestamp":"2026-10-18T07:00:36.177+0000",
 "rule":{"id":"100020","level":12,"description":"LAB: PowerShell encoded command (T1059.001)...","mitre":{"id":["T1059.001"]}},
 "agent":{"id":"001","name":"win01","ip":"10.10.10.20"},
 "data":{"win":{"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
   "commandLine":"powershell.exe -NoP -NonI -Enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGUAbABsAG8A",
   "parentImage":"C:\\Windows\\System32\\cmd.exe"}}}}
```

## False positives / tuning
- Benign plain `-Command` runs: silent. The `\b` after the variant is the FP kill switch —
  `-Encoding`-style flags fail the boundary, plain `-Command` never matches.
- Known gap (documented, not closed): colon form `-EncodedCommand:<b64>` requires `\s+` after the
  flag, so it would be missed. Rare in the wild; future enhancement, never silent.
- Cosmetic: alert `groups` show `lab` twice (file-level `<group name="lab,">` plus `lab` inside the
  rule's group). Harmless; optional cleanup.
- WIN01 background noise unaffected by this rule: shipped 92900 FPs continue (~2/min,
  `svchost.exe` 0x101000) — separate issue, see UC-01.

## Cleanup
- None needed: benign payload only, no defense controls disabled, no snapshot revert.
- Rule 100020 intentionally left deployed (detection baseline).

## Troubleshooting notes
- Dashboard save error "Could not upload rule (1113) - XML syntax error": raw `"` in the regex text.
  Fix: PCRE2 hex escapes (`\x22` for `"`, `\x27` for `'`). See lessons-learned.
- `wazuh-logtest` cannot verify this rule (windows_eventchannel chain limitation, Task 7 lesson) —
  verified with real events only.
