# Exercise log

| Date | Exercise | Expected | Observed | Cleanup done |
|---|---|---|---|---|
| 2026-10-16 | UC-00 FIM modify | rule 550 on secret.txt | 550 fired (multiple, realtime) | yes |
| 2026-10-16 | UC-00 FIM add | rule 554 on new file | 554 fired for secret2.txt | yes |
| 2026-10-16 | UC-00 FIM delete (bonus) | rule 553 on delete | 553 fired for secret2.txt | n/a |
| 2026-10-16 | UC-00 benign read | no alert | no alert (45s window) | n/a |
| 2026-10-16 | UC-01 LSASS dump run 1 | rule 100010 | 100010 x2 (0x1410 + 0x1fffff), 22:16:33Z | yes (snapshot revert) |
| 2026-10-16 | UC-01 LSASS dump run 2 | rule 100010 | 100010 x2 (0x1410 + 0x1fffff), 22:19:56Z | yes (snapshot revert) |
| 2026-10-16 | UC-01 benign (Notepad) | no 100010 | no 100010 | n/a |
| 2026-10-16 | Gate G1 (baseline, Task 3) | green / heap <75 / >=300 MB headroom | yellow (accepted, ISM shard) / heap 51% / 2506 MB avail | n/a |
| 2026-10-16 | Gate G1 (final, Task 8) | still green / heap <75 / >=300 MB | yellow (accepted, ISM shard) / heap 53% / 2368 MB avail | n/a |
| 2026-10-18 | UC-02 PS -enc capture (pre-rule) | shipped coverage check | 92027 only; 92057 missed -Enc (bug proof) | n/a |
| 2026-10-18 | UC-02 PS -enc run 1 (PS parent) | rule 100020 | 100020 lvl 12, 06:25:14Z | n/a |
| 2026-10-18 | UC-02 PS -enc run 2 (cmd parent) | rule 100020 | 100020 lvl 12, 07:00:36Z | n/a |
| 2026-10-18 | UC-02 benign (plain -Command, PS + cmd) | no 100020 | no 100020 | n/a |
| 2026-10-24 | UC-03 failed logon | rule 100029 | 100029 fired (attacker@CORP, 10.10.10.20) | n/a |
| 2026-10-24 | UC-03 logon burst (3 fails) | rule 100030 | 100030 lvl 12 "3+ failed logons in 60s for attacker" 23:19:25Z | n/a |
| 2026-10-24 | UC-03 success | rule 100031 | 100031 fired (attacker@CORP) | n/a |
| 2026-10-24 | UC-03b privileged group change (FIM) | rule 100032 | 100032 lvl 12 T1565.001 (sam.ldb.d modified) | n/a (kept for study — attacker left in Domain Admins) |
| 2026-10-24 | UC-03b benign (read-only samba-tool) | no 100032 | no 100032 | n/a |
| 2026-10-24 | UC-04 Kerberoasting | rule 100033 | 100033 lvl 12 "TGS-REQ for MSSQLSvc/... by attacker" 04:01:52Z | n/a (kept for study) |
| 2026-10-24 | UC-05 AS-REP roasting | rule 100034 | 100034 lvl 12 (multiple; duplicate + normal-Kerberos FP noted) | n/a (kept for study) |
