# Session state — resume here

Last updated: 2026-10-16 (session 5). Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — Task 6 of 8, COMPLETE (UC-00 FIM PASS)

Tasks 1–5 complete. Task 6 (UC-00 FIM) PASSED: realtime FIM on C:\lab\critical verified end-to-end
(rules 554 added / 550 modified / 553 deleted + benign read = silent). Case doc + exercise log committed.
Task 7 (UC-01 T1003.001) is next.

| Task | State |
|---|---|
| 1. Repo scaffolding | DONE |
| 2. Host prep + SOC01 base VM | DONE |
| 3. Wazuh all-in-one install + tuning + G1 | DONE |
| 4. WIN01 Windows 11 install + fit tweaks | DONE |
| 5. Sysmon + Wazuh agent enrollment | DONE |
| 6. UC-00 FIM warm-up | DONE (PASS, see lab/cases/uc-00-fim.md) |
| 7. UC-01 T1003.001 LSASS access | next |
| 8. Milestone 1 wrap-up + final G1 | pending |

## The big one: Wazuh 4.14.8 FIM alerting bug + fix (recorded in setup.md §2.5c)

4.14.8 ships rules 550/553/554 whose decoded_as names exist in NO decoder file. analysisd's FIM
alert path can never match a rule (events stored in fim_entry, zero alerts). Fix = 9 FIM decoder
stubs appended to /var/ossec/etc/decoders/local_decoder.xml + wazuh-control restart. DONE on SOC01.
Full diagnosis + XML in lab/runbook/setup.md §2.5c.

## Key lessons from this session (add to AGENTS.md)

- jq rule.id is a STRING ("550" not 550) — comparing to a number silently filters everything out.
- Windows Wazuh agent: a second <syscheck> block is ignored; per-directory frequency is ignored
  (warning 6701); realtime="yes" works and alerts instantly. Startup scans (scan_on_start) are
  silently baselined — no alerts by design; only realtime/scheduled deltas alert.
- Realtime events can be lost while the agent is disconnected; after a manager restart wait for
  agent reconnect (API status) before testing.
- guestcontrol processes run with a MEDIUM (filtered) token even as an admin user — can't restart
  services or write Program Files; service restarts need the user's elevated window
  (pattern: write .ps1 to C:\lab\tools via copyto, user runs `powershell -ExecutionPolicy Bypass -File ...`).
- guestcontrol run --exe cmd.exe -- '/c' '<single arg>' with single-quoted PowerShell args works;
  PowerShell -EncodedCommand (UTF-16LE base64) is the most robust quoting for guest scripts.
- VBoxManage 7.2: no --wait-exit; use --wait-stdout. modifyvm option is --drag-and-drop (not --draganddrop-mode).

## Current lab state

- **SOC01**: RUNNING (headless). Wazuh 4.14.8 healthy; FIM decoder fix applied; debug flags reverted.
- **WIN01**: RUNNING (headless, freshly rebooted — realtime FIM watch healthy). ossec.conf:
  C:\lab\critical merged into default syscheck block with realtime="yes".
- Snapshots `base-phase1` (both VMs) PREDATE the FIM fixes — refresh before Task 7.
- **Repo**: committed through Task 6 docs (uc-00-fim.md, exercise-log.md, setup.md §2.5b/2.5c, win01.md).

## Next session — first steps

1. Refresh snapshots (optional but recommended): power off both VMs, then
   `VBoxManage snapshot WIN01 take base-phase1-fixed` / same for SOC01 (or leave base-phase1 and note the deltas).
2. Start Task 7 (UC-01 T1003.001 LSASS): plan lines ~843+ in the plan doc.
   - Disable Defender real-time protection on WIN01 (control log row already in win01.md).
   - Run MiniDump against lsass, expect Sysmon EID 10 -> custom rule 100010 (level 12).
   - Files: lab/soc01/local_rules.xml, lab/cases/uc-01-t1003-lsass.md.

## Notes carried over

- Remote control: plink from host to SOC01 (`plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10`), <PW> from .local-credentials.md; sudo = `echo <PW> | sudo -S`; complex commands via base64 wrapper.
- Wazuh API helper: token=`curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token` then `-H "Authorization: Bearer $token"`. API password has a TRAILING PERIOD.
- WIN01 guest control: VBoxManage guestcontrol WIN01 run --username labadmin --password labadmin123 ...
- User is at the keyboard for GUI steps; I drive everything scriptable. ADHD output mode ON.
- Docs: plan `docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md`; runbooks `lab/runbook/{soc01,win01,setup}.md`; cases `lab/cases/*.md`; secrets `lab/runbook/.local-credentials.md` (gitignored).
