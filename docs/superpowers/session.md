# Session state — resume here

Last updated: 2026-10-16 (session 8). Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — MILESTONE 1 COMPLETE (Tasks 1–8)

Phase 0–1 DONE. Both use cases PASS:
- UC-00 FIM (rules 550/553/554 on C:\lab\critical realtime) — lab/cases/uc-00-fim.md
- UC-01 T1003.001 LSASS dump (custom rule 100010, level 12) — lab/cases/uc-01-t1003-lsass.md
Final gate G1 PASS: heap 53%, 2368 MB available, services active (yellow = accepted ISM shard state).
Evidence: lab/evidence/milestone1-alerts.jsonl + uc-01-alert.png committed (f8b036e).
Next: wrap-up review, then plan Phase 2 (identity — DC01, S2, 11 GB).

| Task | State |
|---|---|
| 1. Repo scaffolding | DONE |
| 2. Host prep + SOC01 base VM | DONE |
| 3. Wazuh all-in-one install + tuning + G1 | DONE |
| 4. WIN01 Windows 11 install + fit tweaks | DONE |
| 5. Sysmon + Wazuh agent enrollment | DONE |
| 6. UC-00 FIM warm-up | DONE (PASS) |
| 7. UC-01 T1003.001 LSASS access | DONE (PASS) |
| 8. Milestone 1 wrap-up + final G1 | DONE (f8b036e) |

## Current lab state

- **SOC01**: RUNNING (headless). Rule 100010 live + FIM decoder fix = detection baseline. G1 green-ish.
- **WIN01**: RUNNING (headless), clean post-revert (pre-uc01 snapshot restored: RunAsPPL=2, Defender on).
- Snapshots: WIN01 pre-uc01 (clean). base-phase1 on both VMs predates Task 6 FIM fixes — refresh
  (base-phase1-fixed) before Phase 2.
- **Repo**: all committed. Evidence gap: no dashboard screenshot for UC-00 (uc-00-alert.png) and no
  Event Viewer screenshot of the UC-01 source event (uc-01-sysmon-eid10.png) — the EID 10 text is
  in the case doc; WIN01's Sysmon log was wiped by the pre-uc01 revert.

## Next session — first steps

1. USER PRACTICE (planned): user does their first Wazuh UI rule edit — Server Management → Rules →
   Manage rules files → custom rules file. Suggested practice: tweak rule 100010's description,
   save; then I verify manager reloaded clean (is-active + ossec.log), pscp the file back to the
   repo, and commit (repo stays source of truth).
2. Evidence gap (optional): user screenshots UC-00 FIM alert (Discover `rule.id:550`) -> lab/evidence/uc-00-alert.png.
   EID 10 Event Viewer shot would need re-running the UC-01 simulation (lab controls + dump + screenshot + revert).
3. Milestone 1 wrap-up review with the user; then brainstorming + plan for Phase 2 (DC01, S2).
4. Before Phase 2: refresh snapshots to base-phase1-fixed on both VMs.

## Notes carried over

- Remote control: plink from host to SOC01 (`plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10`), <PW> from .local-credentials.md; sudo = `echo <PW> | sudo -S`; complex commands via base64 wrapper.
- Wazuh API helper: token=`curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token` then `-H "Authorization: Bearer $token"`. API password has a TRAILING PERIOD.
- WIN01 guest control: VBoxManage guestcontrol WIN01 run --username labadmin --password labadmin123 ...
- Custom rules: /var/ossec/etc/rules/local_rules.xml on SOC01 (repo: lab/soc01/local_rules.xml);
  recipe + lessons in lab/cases/howto-create-detection.md and lessons-learned.md.
- User runs the attack simulations themselves; I build/tune and verify (AGENTS.md rule).
- Docs: plan `docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md`; runbooks `lab/runbook/{soc01,win01,setup}.md`; cases `lab/cases/*.md`; secrets `lab/runbook/.local-credentials.md` (gitignored).

