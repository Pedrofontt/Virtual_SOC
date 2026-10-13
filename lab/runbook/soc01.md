# SOC01 runbook

Build: Ubuntu Server 24.04 minimal, 3 vCPU, 5 GB RAM, 50 GB VDI.
VM created via VBoxManage (not the GUI wizard): registered at C:\lab-vms\SOC01\soc01.vdi.
NICs: host-only "VirtualBox Host-Only Ethernet Adapter" 10.10.30.10, int-corp 10.10.10.5, NAT (temporary).
Boot order: dvd first.

Local credentials (DO NOT COMMIT):
- socadmin password: <fill in locally>
- wazuh admin password: set during Task 3

## OOM runbook (S1-tune)

If the indexer OOMs or the API times out during testing:
1. SOC01: sudo systemctl stop wazuh-dashboard   # frees 0.8-1 GB guest RAM
2. Host browser https://10.10.30.10 will error - expected, not a crash
3. Verify headless: curl -ks https://127.0.0.1:9200/_cluster/health?pretty
4. After the test: sudo systemctl start wazuh-dashboard
5. If still OOMing: power off WIN01, raise SOC01 to 6 GB (S1-tune), re-run

## Build deviations from the plan (log only, not a problem)

- VM created with VBoxManage commands instead of the GUI wizard (same parameters).
- Host-only adapter "VirtualBox Host-Only Ethernet Adapter" pre-existed at 10.10.30.1 with DHCP disabled; a
  duplicate "#2" created by mistake was removed.
- Ubuntu point release used: 24.04.5 (newest noble ISO at build time).
