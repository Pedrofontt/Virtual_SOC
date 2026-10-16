# Session state — resume here

Last updated: 2026-10-14 (session 4, end of day). User will compact context and resume tomorrow.
Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — Task 5 of 8, ~95% done

Tasks 1–4 complete. Task 5 (Sysmon + Wazuh agent) is functionally complete: Sysmon 15.22 installed with
EID 1 + EID 10(lsass) config, Wazuh agent 4.14.8 enrolled as agent 001 (status active), Sysmon telemetry
verified end-to-end (detections 92021/92031/92066 firing; EID 1/5/10 flowing to SOC01 archives).
SOC01 snapshot `base-phase1` taken. WIN01 snapshot + NAT detach pending (WIN01 is still shutting down
slowly — Windows updates apply at shutdown on a fresh install; do NOT force power-off).

| Task | State |
|---|---|
| 1. Repo scaffolding | DONE |
| 2. Host prep + SOC01 base VM | DONE |
| 3. Wazuh all-in-one install + tuning + G1 | DONE |
| 4. WIN01 Windows 11 install + fit tweaks | DONE |
| 5. Sysmon + Wazuh agent enrollment | ~95% (agent-verify-after-NAT + WIN01 snapshot pending) |
| 6. UC-00 FIM warm-up | pending |
| 7. UC-01 T1003.001 LSASS access | pending |
| 8. Milestone 1 wrap-up + final G1 | pending |

## Key lessons from this session (all in AGENTS.md too)

- Wazuh API (55000) authenticates with the `wazuh` API user (api_password from wazuh-passwords.txt),
  NOT indexer `admin` (admin only works on dashboard/9200). Token via POST /security/user/authenticate.
  API `?pretty` must be `?pretty=true`.
- Wazuh 4.14 dropped the old Sysmon rule numbering: "Sysmon - Event 1"/rule 61601 no longer exists.
  EID 1 detections = rules 92000-92100 (92021, 92031, 92066 observed). Level-0 rules (61600/61603) don't alert.
  Telemetry verified via archives.json (235+ Sysmon provider events) and fired rule IDs, not the plan's grep.
- Windows agent service name = `WazuhSvc`; ossec.log appears only after first start.
- plink quoting: NEVER `\"` in PowerShell double quotes; base64-wrap complex remote commands
  (`echo <b64> | base64 -d | bash`); wazuh-logtest outputs to STDERR (add inner `2>&1` when hiding sudo prompt).
- WIN01 graceful shutdown is very slow on fresh install (updates); VMState stays "running" while Windows is
  mid-shutdown (ping dead, agent keepalive stale). Just wait — don't force.

## Current lab state

- **SOC01**: POWERED OFF. Snapshots: `base-soc01` + `base-phase1` (stack tuned, win01 enrolled).
  Start: `VBoxManage startvm SOC01` (indexer ~90 s to go active).
- **WIN01**: shutdown in progress (running but Windows mid-shutdown as of last check). Pending:
  detach NAT, persist clipboard, snapshot `base-phase1`, then re-verify agent active over int-corp only.
- **Secrets**: lab/runbook/.local-credentials.md now includes WIN01 labadmin password.
- **Repo**: win01.md + setup.md updated with Sysmon/agent sections; commit pending in next session
  (session.md included in same commit).

## Next session — first steps

1. Check WIN01 VMState (should be "poweroff" by morning). If still running: it's stuck in updates —
   check screenshot/logs, wait more, force only as last resort.
2. `VBoxManage modifyvm WIN01 --nic2 none` (detach NAT) + `--clipboard-mode bidirectional --draganddrop-mode bidirectional`.
3. `VBoxManage snapshot WIN01 take base-phase1 --description "sysmon + wazuh agent enrolled, no tests run"`.
4. `git add lab/runbook/win01.md lab/runbook/setup.md docs/superpowers/session.md && git commit -m "docs: WIN01 sysmon + wazuh agent enrollment (Task 5)"`
   (Task 5 done. If desired, boot WIN01 headless and re-verify agent "active" via API — plan Step 7 —
   but the agent only ever used int-corp (10.10.10.5), so NAT detach cannot affect it; will be re-verified
   anyway at Task 6 power-on.)
5. Start Task 6 (UC-00 FIM): plan steps at lines ~718+ in the plan doc. Needs SOC01 + WIN01 running (S1).

## Notes carried over

- Remote control: plink from host to SOC01 (`plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10`), <PW> from .local-credentials.md; sudo = `echo <PW> | sudo -S`; complex commands via base64 wrapper.
- Wazuh API helper: token=`curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token` then `-H "Authorization: Bearer $token"`.
- User is at the keyboard for GUI steps; I drive everything scriptable. ADHD output mode ON.
- Docs: plan `docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md`; runbooks `lab/runbook/{soc01,win01,setup}.md`; secrets `lab/runbook/.local-credentials.md` (gitignored).
