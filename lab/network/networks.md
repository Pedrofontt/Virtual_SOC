# Lab networks

Two VirtualBox networks. No bridged adapters. No DHCP on lab networks. All IPs static.

## vboxnet0 — host-only, LAB-MGMT, 10.10.30.0/24

| Node | Address | Role |
|---|---|---|
| Host (Windows) | 10.10.30.1 | Analyst browser |
| SOC01 nic0 | 10.10.30.10 | Wazuh dashboard :443, API :55000 |
| SOAR01 nic0 (phase 4) | 10.10.30.20 | n8n :5678 |

## int-corp — internal, LAB-CORP, 10.10.10.0/24

| Node | Address | Role |
|---|---|---|
| SOC01 nic1 | 10.10.10.5 | Agent events :1514, enrollment :1515 |
| WIN01 | 10.10.10.20 | Endpoint (Sysmon + Wazuh agent) |
| DC01 (phase 2) | 10.10.10.10 | Samba AD DC + DNS, domain corp.lab |
| NDR01 (phase 3) | 10.10.10.40 | Suricata sensor; bridge model on gate G2 failure |
| SRV01 (phase 5) | 10.10.10.30 | Reserved, not built |

## Guest NICs

- SOC01: host-only + int-corp + NAT (NAT detached after Task 3 checklist)
- WIN01: int-corp + NAT (NAT detached after Task 5 checklist)
- NAT adapters are for package installs only. When detached, the lab has no Internet path.
