# Virtual SOC Lab — lab notes

Free, isolated, reproducible SOC lab on a 16 GB Windows host. Start with the
[repository README](../README.md); this file is the quick operational reference.

- Architecture spec: [`docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md`](../docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md)
- Rebuild from scratch: [`runbook/setup.md`](runbook/setup.md)
- Replication + test checklist: [`runbook/replicate.md`](runbook/replicate.md)
- Networks and addressing: [`network/networks.md`](network/networks.md)

## Power-on matrix

| ID | Guests on | Guest RAM | Used for |
|---|---|---|---|
| S1 | SOC01 + WIN01 | 9 GB | Phase 1 detections |
| S1-tune | SOC01 (6 GB) + WIN01 | 10 GB | Indexer OOM troubleshooting only |
| S2 | SOC01 + WIN01 + DC01 | 11 GB | Phase 2 identity |
| S3 | SOC01 + WIN01 + NDR01 | 10 GB | Phase 3 NDR |
| S4 | SOC01 + WIN01 + SOAR01 | 11 GB | Phase 4 automation |

Rules: never exceed 11 GB of running guests. Boot SOC01 first, wait for the API, then the
others. Shut down in reverse.

Per-VM RAM: SOC01 5 GB, WIN01 4 GB, DC01 2 GB, NDR01 1 GB, SOAR01 2 GB.

## Portfolio limits

- 16 GB forces phased power-on; this is not a 24/7 SOC
- Samba AD is not Windows Server AD
- Wazuh + Sysmon is not a commercial EDR
- Suricata here is a single-segment IDS, not a full NDR platform
- Free-tool coverage is not commercial-product parity

## Current state

**Phase 4 COMPLETE.** SOC01 + WIN01 + DC01 + NDR01 + SOAR01 are built and snapshotted
(`base-phase1` … `base-phase4`). All use cases UC-00…UC-13 pass with recorded evidence;
UC-13 (DNS query → Wazuh rule 100047 → n8n → VirusTotal → incident/notification/audit)
has passed end to end twice.

Detections: [`cases/`](cases/) · Evidence: [`evidence/`](evidence/) ·
Expected vs observed: [`cases/exercise-log.md`](cases/exercise-log.md).

Phase 5 (MAIL01/ETP, SRV01, Velociraptor) is not scheduled.
