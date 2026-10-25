# Session state — resume here

Last updated: 2026-10-24 (Phase 2 complete). Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — PHASE 2 (identity) COMPLETE

Phase 0–1 PASS (UC-00/01/02) + Phase 2 PASS (UC-03/03b/04/05):
- UC-03 T1110 logon burst — rules 100029/100030/100031 — lab/cases/uc-03-t1110-logon-burst.md
- UC-03b sam.ldb FIM (privileged group change) — rule 100032 — (folded into UC-03 + exercise log)
- UC-04 T1558.003 Kerberoasting — rule 100033 — lab/cases/uc-04-t1558-003-kerberoasting.md
- UC-05 T1558.004 AS-REP roasting — rule 100034 — lab/cases/uc-05-t1558-004-asrep.md (PASS w/ known FPs)
Exit gate: UC-03 PASS (3 fails + success -> 100030 with endpoint IP + attacker@CORP.LAB identity);
UC-04/05 PASS (bonus). Evidence: lab/evidence/uc-0{3,4,5}-alert.png.
Next: Phase 3 NDR brainstorming.

| Task | State |
|---|---|
| 0–5 (Phase 2 infra + capture) | DONE |
| 6. UC-03a logon rules 100029/100030/100031 | DONE (PASS) |
| 7. UC-03b sam.ldb FIM rule 100032 | DONE (PASS) |
| 8. UC-04/05 rules 100033/100034 | DONE (PASS) |
| 9. WIN01 domain join + UC-03 re-verify | DONE (PASS) |
| 10. Documentation + exit gate + close-out | DONE (this commit) |

## Current lab state

- **SOC01**: RUNNING (headless). Rules 100010 + 100020 live + FIM decoder fix = detection baseline.
  UI rule editing proven end-to-end: save -> auto reload -> pscp back -> commit.
- **WIN01**: RUNNING (headless), DOMAIN-JOINED to corp.lab (DESKTOP-I4QI720). Snapshots
  `pre-domain-join` + `win01-joined`.
- **Repo**: all committed. Evidence gap remaining: no dashboard screenshot for UC-00
  (uc-00-alert.png) — Discover `rule.id:550` still has the FIM alert in the 7-day index window if
  taken soon-ish. UC-01 Event Viewer EID 10 shot would need re-running the simulation.
- Snapshots: WIN01 pre-uc01 (clean). base-phase1 on both VMs predates Task 6 FIM fixes — refresh
  (base-phase1-fixed) before Phase 2.

## Next session — first steps

Phase 2 DONE (all Tasks 0–10). Next: **Phase 3 NDR brainstorming** — run the brainstorming skill to
design the next milestone before any build. No open Phase 2 items; 100034 FP/duplicate tuning is
documented as future work (not blocking).

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
- ssh inside a piped remote script: `echo $b64 | base64 -d | bash` + any `ssh` call WITHOUT
  `< /dev/null` silently consumes the rest of the script (ssh eats stdin). ALWAYS add
  `< /dev/null` to ssh lines in remote scripts.
- Indexer queries (no API token needed): curl -sku 'admin:<pw>' -H 'Content-Type: application/json'
  -d '{"query":...}' https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search (Wazuh API GET /events = 405).
  Archives (all events, pre-rule) live in /var/ossec/logs/archives/archives.json (logall_json=yes);
  rules at level >= 3 (log_alert_level) reach the indexer; level 1-2 only in archives.
- DC01 hop from SOC01 needs `ssh -o BatchMode=yes dcadmin@10.10.10.10 "<cmd>"` + sudo via
  `echo dcadmin123 | sudo -S`. Impacket runs FROM SOC01 (/usr/local/bin/*.py).
- Docs: plan `docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md`; runbooks `lab/runbook/{soc01,win01,setup}.md`; cases `lab/cases/*.md`; secrets `lab/runbook/.local-credentials.md` (gitignored).
- SAVESTATE GOTCHA (hit 2026-10-23): resuming a savestate'd Linux VM can leave its clock frozen
  at the save time (SOC01 was 13.5h behind, "up 2:23" but `date` stuck). Symptom: manager stops
  collecting (archives stop growing) while services report "active". Fix: `date` on every VM after
  resume; if wrong, `sudo timedatectl set-ntp off && sudo date -s <utc> && sudo hwclock -w --utc`,
  then `systemctl restart wazuh-manager`. WIN01 (Windows) self-syncs via VBox on boot, so only
  Linux VMs that resumed-from-savestate (not rebooted) are affected.
- **FIM rule field is `file`, not `syscheck.path`.** The alert JSON nests the path under
  `syscheck.path`, but the RULE engine matches the FIM field `file` (wazuh-logtest vs analysisd
  disagreement, wazuh#26327). Custom FIM rule: `if_sid 550` + `<field name="file">`.
- **Logon-burst correlation field = `Authentication.mappedAccount`.** `remoteAddress` includes the
  ephemeral srcport (changes per connection -> `same_field` never matches) and `clientAccount` is
  `attacker@CORP` (Kerberos) vs `attacker` (NTLM). `mappedAccount` is normalized on both paths.
- **Windows negative-caches a failed credential per server name.** Repeated `net use \\IP\IPC$`
  sends only one auth attempt; the rest return cached 1326. Force fresh 4625s by targeting the DC
  under 3 names (`\\dc01`, `\\dc01.corp.lab`, `\\10.10.10.10`).
- **Wazuh 4.14 rotates alerts/archives daily into `…/logs/{alerts,archives}/<year>/<Mon>/ossec-*-<day>.json(.gz)`.**
  Yesterday's alerts are NOT in the live `alerts.json` — search the rotated file with `zgrep`.
