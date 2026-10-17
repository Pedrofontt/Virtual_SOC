# Virtual SOC Lab

Free, isolated, reproducible SOC lab on a 16 GB host. Design: docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md

## Power-on matrix (from the spec)

| ID | Guests on | Guest RAM | Used for |
|---|---|---|---|
| S1 | SOC01 + WIN01 | 9 GB | Milestone 1 detections (this plan) |
| S1-tune | SOC01 (6 GB) + WIN01 | 10 GB | Indexer OOM troubleshooting only |
| S2 | SOC01 + WIN01 + DC01 | 11 GB | Phase 2 identity |
| S3 | SOC01 + WIN01 + NDR01 | 10 GB | Phase 3 NDR |
| S4 | SOC01 + WIN01 + SOAR01 | 11 GB | Phase 4 automation |

Rules: never exceed 11 GB of running guests. Boot SOC01 first, wait for the API, then others. Shut down in reverse.

## Portfolio limits

- 16 GB forces phased power-on; this is not a 24/7 SOC
- Samba AD is not Windows Server AD
- Wazuh + Sysmon is not a commercial EDR
- Suricata here is a single-segment IDS, not a full NDR platform
- Free-tool coverage is not commercial-product parity

## Current state

Milestone 1 COMPLETE: SOC01 + WIN01 (S1) detect UC-00 FIM and UC-01 T1003.001.
Evidence in evidence/, use cases in cases/. Next: Phase 2 identity (DC01, S2).
