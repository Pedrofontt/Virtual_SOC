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
