# Session state — resume here

Last updated: 2026-10-19 (session 10). Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — MILESTONE 1 COMPLETE + UC-02 DONE

Phase 0–1 DONE. Three use cases PASS:
- UC-00 FIM (rules 550/553/554 on C:\lab\critical realtime) — lab/cases/uc-00-fim.md
- UC-01 T1003.001 LSASS dump (custom rule 100010, level 12) — lab/cases/uc-01-t1003-lsass.md
- UC-02 T1059.001 PowerShell encoded command (custom rule 100020, level 12 — FIRST USER-CREATED RULE,
  written via dashboard UI) — lab/cases/uc-02-t1059-powershell-enc.md
Final gate G1 PASS: heap 53%, 2368 MB available, services active (yellow = accepted ISM shard state).
Evidence: lab/evidence/milestone1-alerts.jsonl, uc-01-alert.png, uc-02-alert.png.
Next: Phase 2 brainstorming (identity — DC01, S2, 11 GB).

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
| UC-02 T1059.001 PS -enc (user-created via UI) | DONE (PASS) |

## Current lab state

- **SOC01**: RUNNING (headless). Rules 100010 + 100020 live + FIM decoder fix = detection baseline.
  UI rule editing proven end-to-end: save -> auto reload -> pscp back -> commit.
- **WIN01**: RUNNING (headless), clean (pre-uc01 baseline — RunAsPPL=2, Defender on). UC-02 needed no
  lab controls (benign payload only), no snapshot revert.
- **Repo**: all committed. Evidence gap remaining: no dashboard screenshot for UC-00
  (uc-00-alert.png) — Discover `rule.id:550` still has the FIM alert in the 7-day index window if
  taken soon-ish. UC-01 Event Viewer EID 10 shot would need re-running the simulation.
- Snapshots: WIN01 pre-uc01 (clean). base-phase1 on both VMs predates Task 6 FIM fixes — refresh
  (base-phase1-fixed) before Phase 2.

## Next session — first steps

1. ~~Phase 2 brainstorm/design/plan~~ DONE — spec `2026-10-18-phase2-identity-design.md` (f5e761a),
   plan `2026-10-18-phase2-identity.md` (44d3c96). User authorized autonomous infra build (Tasks
   0-5); Tasks 6-9 stay user-run.
2. ~~Task 0 snapshots~~ DONE — base-phase1-fixed on both VMs; power outage hit mid-task; SOC01
   recovered via full `wazuh-control restart` (stale wdb socket fixed), all services + API healthy.
3. ~~Task 1 DC01 VM~~ DONE — unattended Ubuntu 24.04.5 install (user away; deviations from plan:
   installer made plain ext4, no LVM resize needed; no gw route via 10.10.10.5 — SOC01 ip_forward=0
   and has no dnsmasq; DC01 DNS=127.0.0.1 set per plan; internet via NAT nic2 until detached).
   DC01: 10.10.10.10/24, ssh natpf 127.0.0.1:2222, creds in .local-credentials.md.
4. NEXT: Task 3 SOC01 impacket (pip bootstrap still pending — get-pip.py failed on network;
   wheels already in /tmp/wheels/) + Task 4 DC01 Wazuh agent (deb already on DC01 /tmp,
   enroll -m 10.10.10.5, localfile json audit.json + syslog log.samba + FIM sam.ldb).
   ~~Task 2 Samba AD DC~~ DONE (51d4e24): CORP.LAB provisioned, accounts + SPN + victim
   DONT_REQUIRE_PREAUTH, auth JSON audit to /var/log/samba/audit.json, NAT detached, snapshot
   base-phase2. DC01 SSH now ONLY via SOC01 hop (key auth: socadmin@SOC01 -> dcadmin@10.10.10.10).

## Notes carried over

- Remote control: plink from host to SOC01 (`plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10`), <PW> from .local-credentials.md; sudo = `echo <PW> | sudo -S`; complex commands via base64 wrapper (works reliably — build script with NO nested quotes, base64 it locally, run `echo <b64> | base64 -d | bash` remotely).
- Grepping alerts.json gotcha: sudo audit alerts self-match your grep command (+1 per check), and
  `id:100020` does NOT match JSON `"id":"100020"`. Grep the description phrase and filter `COMMAND`
  lines; compensate counts for prior greps.
- Wazuh API helper: token=`curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token` then `-H "Authorization: Bearer $token"`. API password has a TRAILING PERIOD.
- WIN01 guest control: VBoxManage guestcontrol WIN01 run --username labadmin --password labadmin123 ...
- Custom rules: /var/ossec/etc/rules/local_rules.xml on SOC01 (repo: lab/soc01/local_rules.xml);
  recipe + lessons in lab/cases/howto-create-detection.md and lessons-learned.md.
  UI path: Server Management → Rules → Manage rules files → local_rules.xml (pencil). NO raw quotes
  in regex text (API error 1113) — use \x22/\x27.
- User runs the attack simulations themselves; I build/tune and verify (AGENTS.md rule).
- Docs: plan `docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md`; runbooks `lab/runbook/{soc01,win01,setup}.md`; cases `lab/cases/*.md`; secrets `lab/runbook/.local-credentials.md` (gitignored).
