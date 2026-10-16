# UC-00 — File Integrity Monitoring warm-up

Status: PASS

## Hypothesis
A change to a monitored lab file is visible in Wazuh without any third guest.

## Scope
- Detector: WIN01 Wazuh agent 001, syscheck on `C:\lab\critical` (`realtime="yes"`, `check_all="yes"`, merged into the default `<syscheck>` block).
- Telemetry path: WIN01 agent (10.10.10.20) -> int-corp:1514 -> SOC01 manager -> alerts.json -> filebeat -> wazuh-alerts index -> dashboard.

## Prerequisites
- S1 powered on: SOC01 + WIN01
- Wazuh agent syscheck watching C:\lab\critical (lab/win01/ossec.conf.additions.xml)
- Manager fix required by Wazuh 4.14.8 (see Observations): FIM decoders restored in /var/ossec/etc/decoders/local_decoder.xml

## Test procedure
1. Create C:\lab\critical\secret.txt with content lab-secret-v1
2. Edit the file to lab-secret-v2

## Expected
- Rule 554 on file add
- Rule 550 on modification, fields: agent.name=win01, syscheck.path=C:\lab\critical\secret.txt, syscheck.event=modified

## Observed
- Rule 554 ("File added to the system.") fired for `secret2.txt` at 2026-10-16T20:14:55Z (realtime add).
- Rule 550 ("Integrity checksum changed.") fired repeatedly on every realtime modification, e.g. 2026-10-16T20:22:04Z and 20:24:33.904Z for `secret.txt`.
- Bonus: rule 553 ("File deleted.") fired for `secret2.txt` at 20:24:33.950Z.
- Alerts present in indexer `wazuh-alerts-4.x` (verified via ES API; visible in dashboard Discover with `rule.id:550 and agent.name:win01`).

Example alert JSON (alerts.json):
```json
{"timestamp":"2026-10-16T20:24:33.904+0000","rule":{"level":7,"description":"Integrity checksum changed.","id":"550"},
 "agent":{"id":"001","name":"win01","ip":"10.10.10.20"},
 "full_log":"File 'c:\\lab\\critical\\secret.txt' modified\nMode: realtime\n...",
 "syscheck":{"path":"c:\\lab\\critical\\secret.txt","mode":"realtime","event":"modified",...}}
```

## Benign control
Read-only access: Get-Content. Result: no alert (expected) — 45s observation window after the read produced zero 550/554/553 alerts.

## Cleanup
File content restored to lab-secret-v1; restore produced its own 550 at 20:24:33.904Z as verification.
secret2.txt (test artifact) removed; removal produced 553 at 20:24:33.950Z.

## Troubleshooting notes (4.14.8-specific, kept for posterity)
- Wazuh 4.14.8 ships rules 550/553/554 whose `decoded_as` names (syscheck_new_entry etc.) do not exist anywhere in the shipped decoder files. analysisd's built-in FIM decoder lookup (`fim_init()` -> `getDecoderfromlist`) therefore returns no decoder and FIM alerts can never match a rule. FIX: re-add the 9 classic FIM decoder stubs to `/var/ossec/etc/decoders/local_decoder.xml` (see lab/runbook/setup.md section for exact XML).
- Windows agents ignore per-directory `frequency` (log warning 6701). Use `realtime="yes"` for instant change detection instead.
- Do NOT add a second `<syscheck>` block: duplicate sections are silently ignored. Merge directories into the existing block.
- Startup scans (`scan_on_start`) are silent by design (baseline reconciliation, no alerts). Only scheduled/realtime events alert.
- Realtime events are dropped while the agent is disconnected from the manager; retry after reconnect or reboot the agent VM.
