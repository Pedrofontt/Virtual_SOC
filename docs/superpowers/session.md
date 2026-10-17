# Session state — resume here

Last updated: 2026-10-16 (session 6). Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — Task 7 of 8, COMPLETE (UC-01 T1003.001 PASS)

Tasks 1–6 complete. Task 7 (UC-01 T1003.001 LSASS) PASSED: custom rule 100010 (level 12, MITRE
T1003.001) caught rundll32+comsvcs MiniDump LSASS dumps twice (2 alerts per run: probe open 0x1410
+ dump open 0x1fffff), benign control silent. Shipped rule 92900 missed both dumps while firing
on Defender/svchost noise — the custom rule out-performs shipped. Full story: lab/cases/uc-01-t1003-lsass.md.
Task 8 (milestone wrap-up) is next.

| Task | State |
|---|---|
| 1. Repo scaffolding | DONE |
| 2. Host prep + SOC01 base VM | DONE |
| 3. Wazuh all-in-one install + tuning + G1 | DONE |
| 4. WIN01 Windows 11 install + fit tweaks | DONE |
| 5. Sysmon + Wazuh agent enrollment | DONE |
| 6. UC-00 FIM warm-up | DONE (PASS, see lab/cases/uc-00-fim.md) |
| 7. UC-01 T1003.001 LSASS access | DONE (PASS, see lab/cases/uc-01-t1003-lsass.md) |
| 8. Milestone 1 wrap-up + final G1 | next |

## UC-01 outcome in one screen

- Rule 100010 deployed on SOC01 (`/var/ossec/etc/rules/local_rules.xml`, repo `lab/soc01/local_rules.xml`):
  `if_group sysmon_event_10` + targetImage lsass.exe$ + sourceImage rundll32.exe$ +
  grantedAccess ^0x(1010|1410|1438|1fffff)$. Wazuh 4.14 has NO 61610 parent — use if_group.
- WIN01 lab controls (all reverted via pre-uc01 snapshot restore): Defender RT off via GUI
  (Set-MpPreference is AMSI-blocked), Tamper Protection already off, RunAsPPL 2->0 + reboot
  (Win11 24H2 default silently blocks the dump).
- 4 alerts: 22:16:33Z x2 (run 1), 22:19:56Z x2 (run 2). Notepad benign: silent.
- WIN01 reverted to pre-uc01 snapshot and booted; agent reconnects on its own.

## Key lessons from this session (recorded in lab/cases/lessons-learned.md)

- AMSI blocks Set-MpPreference -DisableRealtimeMonitoring ("malicious content") -> GUI toggle.
- Win11 24H2+: RunAsPPL=2 by default; comsvcs MiniDump fails SILENTLY (no dump, no error).
- 4.14 Sysmon EID 10: group sysmon_event_10 added by built-in windows_eventchannel decoder
  (compiled in, not an XML file); wazuh-logtest can't exercise it — verify with real events.
- Shipped 92900 grantedAccess regex is unanchored (0x1010 matches inside 0x101000) -> FP noise
  from MsMpEng/svchost; our anchored masks = zero FPs. Design rule: always anchor.
- One rundll32 dump = 2 EID 10 events (probe 0x1410 + dump 0x1fffff) = 2 alerts. Expected.
- Sysmon log read needs admin (Get-WinEvent UnauthorizedAccessException on medium token).
- WIN01 clock ~12s ahead of SOC01; small cross-host timestamp deltas are drift, not loss.

## Current lab state

- **SOC01**: RUNNING (headless). Rule 100010 live. FIM decoder fix + rule = detection baseline.
- **WIN01**: RUNNING (headless), reverted to pre-uc01 (clean: RunAsPPL=2, Defender on, no dumps).
  Agent reconnects automatically after the revert boot.
- Snapshots: WIN01 has pre-uc01 (clean, post-FIM-fix config). base-phase1 on both VMs still
  predates the Task 6 FIM fixes — refresh (base-phase1-fixed) as part of Task 8 if desired.
- **Repo**: Task 7 files ready to commit (uc-01 case doc, exercise-log rows, win01.md lab controls,
  setup.md §2.7/2.8, lessons-learned.md, local_rules.xml). Evidence screenshot pending (user).

## Next session — first steps

1. Commit Task 7 (once the dashboard screenshot lands in lab/cases/evidence/):
   `git add lab/ && git commit -m "feat: UC-01 T1003.001 detection rule and case doc"`.
2. Start Task 8 (plan lines ~1029+): final G1 run, verify both UC pass conditions vs spec §8,
   export evidence (milestone1-alerts.jsonl), finalize exercise log, update lab/README.md,
   commit. That declares Milestone 1 COMPLETE.

## Notes carried over

- Remote control: plink from host to SOC01 (`plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10`), <PW> from .local-credentials.md; sudo = `echo <PW> | sudo -S`; complex commands via base64 wrapper.
- Wazuh API helper: token=`curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token` then `-H "Authorization: Bearer $token"`. API password has a TRAILING PERIOD.
- WIN01 guest control: VBoxManage guestcontrol WIN01 run --username labadmin --password labadmin123 ...
- User is at the keyboard for GUI steps and runs the attack simulations themselves (AGENTS.md rule).
- Docs: plan `docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md`; runbooks `lab/runbook/{soc01,win01,setup}.md`; cases `lab/cases/*.md`; secrets `lab/runbook/.local-credentials.md` (gitignored).
