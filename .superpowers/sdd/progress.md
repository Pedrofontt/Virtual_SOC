# Phase 2 SDD ledger

Plan: docs/superpowers/plans/2026-10-18-phase2-identity.md
Start: 2026-10-18 (user stepped out; infra tasks executed by controller, per-task verification gates)


Task 0: complete (snapshots base-phase1-fixed on SOC01+WIN01, old merged; power outage recovery: wazuh-control restart after stale wdb socket)
Task 1: complete (DC01 VM + unattended Ubuntu 24.04.5 install, dcadmin/dcadmin123, 10.10.10.10/24 static on int-corp, dns 127.0.0.1, ssh natpf 127.0.0.1:2222. Deviations: no LVM (plain ext4 full disk), no gw route via 10.10.10.5 (SOC01 ip_forward=0, no dnsmasq on SOC01 — corp.lab DNS comes from DC01 Samba DNS), NIC2 NAT kept for internet until detach step. Creds recorded in .local-credentials.md)
