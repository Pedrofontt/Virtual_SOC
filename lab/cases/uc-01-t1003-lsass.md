# UC-01 — T1003.001 OS Credential Dumping: LSASS Memory

Status: PASS

## Hypothesis
A local-admin living-off-the-land LSASS dump (rundll32 + comsvcs MiniDump — no malware, no domain)
is detectable from Sysmon process-access telemetry with a custom Wazuh rule that out-performs the
shipped ruleset.

## Detection logic
- Source: Sysmon Event ID 10 (ProcessAccess) on WIN01, filtered at install time to `TargetImage = lsass.exe` only (`lab/win01/sysmon-config.xml`).
- Custom rule `100010` (level 12, MITRE T1003.001) in `lab/soc01/local_rules.xml`:
  - `if_group sysmon_event_10` (4.14 adds this group via the built-in `windows_eventchannel` decoder — there is no `61610` parent rule in 4.14; the plan's `if_sid 61610` was a placeholder to verify)
  - `targetImage =~ lsass.exe$` AND `sourceImage =~ rundll32.exe$` AND `grantedAccess =~ ^0x(1010|1410|1438|1fffff)$`
  - Anchored masks on purpose: the shipped 92900 regex (`(0x1010|0x40)`) is an unanchored substring match.

## Prerequisites
- S1 powered on; agent 001 active; Sysmon EID 10 logging lsass only.
- Lab controls for the test window only (see `lab/runbook/win01.md` lab controls log):
  - Defender real-time protection OFF (GUI toggle — `Set-MpPreference` is AMSI-blocked, see below)
  - Tamper Protection already OFF on this image
  - LSA Protection OFF: `RunAsPPL` 2 -> 0 + reboot (Win11 24H2+ ships RunAsPPL=2; with it on, comsvcs MiniDump fails silently with no dump and no alert)
- `pre-uc01` snapshot taken (UUID 9fc45cd2-86b7-4e4c-b4ad-fa405e4b35f1) and reverted after the test.

## Test procedure
1. Snapshot `pre-uc01` (powered off).
2. Defender RT off (GUI), RunAsPPL=0 + reboot.
3. Admin PowerShell:
   ```powershell
   $lsassPid = (Get-Process lsass).Id
   rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $lsassPid C:\lab\dumps\lsass_lab.dmp full
   ```
4. Run twice (reproducibility), then benign control (Notepad open/close).

## Expected vs observed
Expected: rule 100010 fires per run. Observed: **two alerts per run** — rundll32 opens lsass twice:
a probe open (`GrantedAccess 0x1410`) then the dump open (`0x1FFFFF`). Both matched 100010.

| Run | Sysmon UtcTime (WIN01) | Wazuh alert timestamp (UTC) | GrantedAccess |
|---|---|---|---|
| 1 | 04:16:45 local (~12s ahead of SOC01 clock) | 2026-10-16T22:16:33.729 | 0x1410 |
| 1 | same | 2026-10-16T22:16:33.731 | 0x1fffff |
| 2 | 04:20:08.638 / 04:20:08.647 local | 2026-10-16T22:19:56.344 | 0x1410 |
| 2 | same | 2026-10-16T22:19:56.344 | 0x1fffff |

Source event (WIN01 Sysmon, run 2):
```
UtcTime: 2026-10-17 04:20:08.647  SourceImage: C:\WINDOWS\system32\rundll32.exe
TargetImage: C:\WINDOWS\system32\lsass.exe  GrantedAccess: 0x1FFFFF
CallTrace: ...dbgcore.DLL (MiniDumpWriteDump)...comsvcs.dll...rundll32.exe
```

Alert JSON (alerts.json, one of four):
```json
{"timestamp":"2026-10-16T22:16:33.729+0000",
 "rule":{"id":"100010","level":12,"description":"LAB: LSASS access by rundll32 (T1003.001 simulation)...","mitre":{"id":["T1003.001"]}},
 "agent":{"id":"001","name":"win01","ip":"10.10.10.20"},
 "data":{"win":{"eventdata":{"sourceImage":"C:\\WINDOWS\\system32\\rundll32.exe",
        "targetImage":"C:\\WINDOWS\\system32\\lsass.exe","grantedAccess":"0x1410"}}}}
```

## Benign control
Notepad open/close between runs: zero 100010 alerts (pipeline was live — other EID 10/92900 noise continued to flow).

## False positives / tuning (the point of the exercise)
- Shipped rule 92900 kept firing on benign LSASS readers during the test window: `MsMpEng.exe`
  (Defender AV, 0x101000) and `svchost.exe`/TokenBroker (0x101000). Its unanchored grantedAccess
  regex matches 0x1010 inside 0x101000.
- Shipped 92900 missed BOTH dump runs (0x1410/0x1fffff not in its pattern). The custom rule caught
  both. Anchored masks + sourceImage constraint = zero FP from AV/background readers.
- Widening 100010 (e.g. adding procdump, more masks) is future work — never done silently.

## Cleanup
- WIN01 reverted to `pre-uc01` snapshot: dumps gone, RunAsPPL back to 2, Defender settings restored.
- Rule 100010 intentionally left deployed on SOC01 (part of the lab's detection baseline).

## Troubleshooting notes
- `Set-MpPreference -DisableRealtimeMonitoring` is blocked by AMSI before execution ("This script
  contains malicious content...") — Defender self-protection. Use the Windows Security GUI toggle.
- Win11 24H2+ enables LSA Protection by default (`RunAsPPL=2`): comsvcs MiniDump fails silently
  (no console error, no dump). Fix: `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
  /t REG_DWORD /d 0 /f` + reboot. Registry override worked on this VM (no UEFI lock).
- Sysmon/Operational log is admin-only read (Get-WinEvent throws UnauthorizedAccessException on
  medium token) — source-event verification must run in the elevated session.
- WIN01 clock runs ~12s ahead of SOC01: EID 10 UtcTime appears later than the Wazuh alert ts.
