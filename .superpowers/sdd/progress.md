# Phase 2 SDD ledger

Plan: docs/superpowers/plans/2026-10-18-phase2-identity.md
Start: 2026-10-18 (user stepped out; infra tasks executed by controller, per-task verification gates)


Task 0: complete (snapshots base-phase1-fixed on SOC01+WIN01, old merged; power outage recovery: wazuh-control restart after stale wdb socket)
Task 1: complete (DC01 VM + unattended Ubuntu 24.04.5 install, dcadmin/dcadmin123, 10.10.10.10/24 static on int-corp, dns 127.0.0.1, ssh natpf 127.0.0.1:2222. Deviations: no LVM (plain ext4 full disk), no gw route via 10.10.10.5 (SOC01 ip_forward=0, no dnsmasq on SOC01 — corp.lab DNS comes from DC01 Samba DNS), NIC2 NAT kept for internet until detach step. Creds recorded in .local-credentials.md)
Task 2: complete (Samba 4.19.5 AD DC CORP.LAB; accounts attacker/svc-sql/victim; SPN MSSQLSvc/dc01.corp.lab:1433; victim UAC=4194816; auth_json_audit->/var/log/samba/audit.json pure JSON via rsyslog template; kdc:10->log.samba; DNS forwarder 192.168.100.1; NAT detached; snapshot base-phase2 f1061239; SOC01->DC01 ssh key. Deviations: disabled systemd-resolved (port 53), provision non-interactive flags, rm package smb.conf, masked smbd/nmbd/winbind, deleted bogus A/AAAA records from NAT NIC, extra pkg ldb-tools, audit.json pre-owned syslog:adm. Repo: lab/dc01/ 51d4e24. SOC01 hung again mid-task -> hard reset, recovered healthy)
Task 3: complete (SOC01 impacket offline: pip bootstrapped from pip-26.2.1 wheel, impacket 0.13.1 + ldapdomaindump 0.10.0 installed via /tmp/wheels, GetUserSPNs.py/GetNPUsers.py/secretsdump.py in /usr/local/bin, /etc/hosts dc01.corp.lab added. Gotchas: /tmp tmpfs wiped by reboot; apt blinker/flask removal needed; typing-extensions extra wheel; impacket has no __version__. Repo: soc01.md ff4ee55)
Task 4: complete (DC01 wazuh-agent 4.14.8 installed via host->SOC01->DC01 chain, enrolled -A dc01, agent 002 active; MANAGER_IP placeholder fixed; localfile json audit.json + syslog log.samba + FIM realtime sam.ldb; FIM scan ran clean. Repo: ossec.conf.additions.xml 8c21341)
