# Lessons learned (narrative — what surprised us, and why)

Written as problem -> symptom -> root cause -> fix. Setup commands live in `setup.md`; this file is the "why".

## UC-02 (T1059.001 PowerShell -enc, 2026-10-18)

1. **Raw quote characters in a rule's regex break the dashboard save (API error 1113).**
   Problem: first version of rule 100020 used `["']?` for optional quotes around the base64 payload.
   Symptom: saving via the UI failed — "Could not upload rule (1113) - XML syntax error" (both for a
   new file and for `local_rules.xml`; nothing written to disk).
   Root cause: the `"` inside the field text breaks Wazuh's XML validation path for the upload.
   Fix: PCRE2 hex escapes — `[\x22\x27]?` — same regex semantics, zero raw quote chars in the file.

2. **Shipped encoded-command coverage is parent-specific AND buggy.**
   Problem: evaluating shipped rules before writing ours (recipe step 3).
   Findings: 92057 only fires when `parentImage = powershell.exe`; its alternation
   `(encodedcommand|e|ea|ec|encodeda|encode|en|enco)\b` misses `-Enc` (no `enc`/`enco` alternatives and
   `\b` kills prefix matching). 92071 is WMI-parent only. Proven empirically: our capture event fired
   only generic 92027. The classic `cmd.exe -> powershell -enc` has NO shipped coverage.
   Fix: custom generic rule (no parent constraint) — and it caught both parent variants.

3. **Grepping `alerts.json` self-matches your own sudo audit lines.**
   Symptom: alert counts drifted +1 per check; `grep -c id:100020` matched a sudo alert whose
   `full_log` recorded the grep command itself.
   Root cause: every `sudo` on SOC01 generates rule-5402 alerts containing the command text; and
   `id:100020` does not match the JSON `"id":"100020"` (quote+colon), so the only match WAS the sudo line.
   Fix: grep the description phrase (`LAB: PowerShell encoded ...`) and filter `COMMAND` lines out, or
   use jq on the JSON structure. Also: the failed check still adds a sudo alert with the same phrase —
   counts need +1 compensation per previous grep.

4. **EID 1 field casing differs from EID 10.**
   Symptom: assumed `win.eventdata.commandline` (lowercase L) by analogy with EID 10's `sourceImage`.
   Reality (from a real alert): EID 1 uses `win.eventdata.commandLine` — capital L — while `image` is
   lowercase. Always confirm per-event-id field names from `alerts.json` (recipe step 2 paid off).

5. **Cosmetic: rule group duplicating the file-level group name.**
   Symptom: alert `groups` shows `lab` twice (`"groups":["lab","execution","lab","sysmon_process_create"]`).
   Root cause: `<group name="lab,">` on the file root already tags everything `lab`; the rule's own
   `<group>` also contains `lab`. Harmless — optional cleanup.

## Task 7 (UC-01 T1003.001)

1. **Defender's AMSI blocks its own disable command.**
   Problem: the lab-control `Set-MpPreference -DisableRealtimeMonitoring $true`.
   Symptom: PowerShell ParserError "This script contains malicious content and has been blocked by your antivirus software" — before the command even runs.
   Root cause: Defender's Antimalware Scan Interface flags the pattern of disabling Defender.
   Fix: disable via Windows Security GUI instead (and log it as a manual lab control).

2. **Win11 24H2+ enables LSA Protection by default (RunAsPPL=2).**
   Problem: the classic LOTL LSASS dump (`rundll32 comsvcs MiniDump`) "ran fine" but produced nothing.
   Symptom: no error output, empty `C:\lab\dumps` — a silent failure.
   Root cause: `RunAsPPL=2` — lsass runs as Protected Process Light; OpenProcess with dump rights is denied, and comsvcs fails silently.
   Fix: `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f` + reboot (worked on this VM; no UEFI lock). Snapshot revert restores the protected state.

3. **Wazuh 4.14 has no 61610 parent rule for Sysmon EID 10.**
   Problem: the plan's custom rule used `if_sid 61610`.
   Symptom: 61610 doesn't exist in 4.14's ruleset (`0945-sysmon_id_10.xml` holds 92900+ directly).
   Root cause: 4.14 restructured Sysmon rules per event id; the chain uses the group `sysmon_event_10`, added by the built-in `windows_eventchannel` decoder — which is compiled into analysisd, not an XML file (not greppable anywhere in ruleset/decoders).
   Fix: use `<if_group>sysmon_event_10</if_group>`.

4. **`wazuh-logtest` can't test the windows_eventchannel chain.**
   Problem: synthetic EID 10 JSON through logtest stops at Phase 2 with the generic `json` decoder; the built-in `windows_eventchannel` decoder never applies, so rules using `sysmon_event_10` can't match in logtest.
   Root cause: the modern decoder path runs in analysisd with agent context; logtest feeds raw lines.
   Fix: verify custom rules with real events only (and confirm the rule file loads clean via manager restart + ossec.log).

5. **Shipped rule 92900 has an unanchored regex (FP machine).**
   Problem: 92900 ("Lsass process was accessed...possible credential dump") kept firing on background noise.
   Symptom: repeated alerts for `MsMpEng.exe` (Defender) and `svchost.exe` (TokenBroker) with `grantedAccess 0x101000`.
   Root cause: its grantedAccess pcre2 is `(?i)(0x1010|0x40)` — substring match: `0x101000` contains `0x1010`.
   Fix (lab rule): anchor the masks `^0x(...)$` and constrain sourceImage. Result: 92900 missed both real dumps; 100010 caught both, zero FPs. (Design lesson: always anchor; test your regexes against real noise.)

6. **One dump = two EID 10 events = two alerts.**
   Symptom: each rundll32 dump produced two 100010 alerts, not one.
   Root cause: rundll32 opens lsass twice — a probe open (GrantedAccess 0x1410) then the dump open (0x1FFFFF, call trace via dbgcore.DLL MiniDumpWriteDump). Sysmon logs both.
   Fix: none needed — document as expected behavior; the mask list must cover both.

7. **Sysmon log needs admin to read.**
   Symptom: `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational` from a non-elevated (medium token) session throws UnauthorizedAccessException.
   Fix: source-event verification runs in the elevated session (or the Wazuh alert itself is the evidence).

8. **Guest clock drift: WIN01 runs ~12s ahead of SOC01.**
   Symptom: EID 10 UtcTime (Sysmon, guest clock) appeared ~12s later than the Wazuh alert timestamp (manager clock).
   Fix: don't treat sub-minute timestamp deltas between hosts as event loss; compare masks/PIDs instead.

## Task 6 (UC-00 FIM) — already in `uc-00-fim.md`
- 4.14.8 ships FIM rules referencing decoders that don't exist (fixed with stubs).
- Windows agents: no second `<syscheck>` block; no per-directory frequency; realtime yes.
- `scan_on_start` is silently baselined; realtime events drop while agent is disconnected.

## Task 7 FIM rule (100032, AD DB modification)

1. **FIM rule field is `file`, not `syscheck.path`.**
   Problem: custom rule 100032 would not fire even though rule 550 fired for every modification.
   Symptom: `grep`/`jq` of `alerts.json` showed rule 550 + `syscheck.path` =
   `/var/lib/samba/private/sam.ldb.d/DC=CORP,DC=LAB.ldb`, but 0 alerts for 100032 across two rule
   variants (`if_sid 550` + `<field name="syscheck.path">`; then `if_group syscheck` + the same field).
   Root cause: the ALERT JSON nests the path under `syscheck.path`, but the rule engine matches FIM
   fields by their *FIM* name, where the path is `file` (and size=`size`, mtime=`mtime`,
   changed-attributes=`changed_fields`, …). `syscheck.path` simply does not exist as a rule-match field.
   (Known Wazuh inconsistency: `wazuh-logtest` accepts `syscheck.path` but `analysisd` never matches it —
   wazuh#26327.)
   Fix: `<if_sid>550</if_sid>` + `<field name="file" type="pcre2">sam\.ldb\.d/DC=CORP,DC=LAB\.ldb</field>`.
   Verified: re-triggered `samba-tool user setexpiry victim --days=90`, alert 100032 (level 12, T1565.001)
   fired from agent `dc01`.

## Task 9 logon burst (100030, UC-03 re-verify)

1. **`same_field` on `Authentication.remoteAddress` never matches (ephemeral port).**
   Problem: rule 100030 correlated failed logons with `same_field Authentication.remoteAddress`.
   Symptom: the burst never fired, even with 3 wrong-password attempts.
   Root cause: Samba's `Authentication.remoteAddress` is `ipv4:10.10.10.20:<source-port>`, and the
   source port changes on every connection — so the three events never share an identical value.
   Fix: correlate on the normalized account instead — `same_field Authentication.mappedAccount`
   (see next).

2. **`clientAccount` differs between Kerberos and NTLM auth paths.**
   Problem: after switching `same_field` to `Authentication.clientAccount`, the burst still did not fire.
   Root cause: the same `attacker` logon is decoded as `clientAccount="attacker@CORP"` over Kerberos KDC
   but `clientAccount="attacker"` over SMB2/NTLMSSP — the string differs, so `same_field` fails.
   Fix: use `Authentication.mappedAccount`, which is normalized to plain `attacker` on both paths.
   Verified: 3 failed logons (`\\dc01` Kerberos, `\\dc01.corp.lab` Kerberos, `\\10.10.10.10` NTLM)
   -> alert 100030 (level 12, T1110) fired from agent `dc01`.

3. **Windows negative-caches a failed credential per server name.**
   Problem: from the domain-joined WIN01, `net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass`
   sent only ONE auth attempt; the 2nd/3rd returned cached "System error 1326" with no new 4625.
   Root cause: the SMB redirector caches the failed-credential result keyed by server name (not cleared
   by `net use * /delete`).
   Fix: force fresh sessions by targeting the DC under three different names (`\\dc01`, `\\dc01.corp.lab`,
   `\\10.10.10.10`). Each name = a distinct SMB session -> a fresh 4625. Documented in `lab/runbook/win01.md`.
