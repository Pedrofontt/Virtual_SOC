# Phase 2 SDD ledger

Plan: docs/superpowers/plans/2026-10-18-phase2-identity.md
Start: 2026-10-18 (user stepped out; infra tasks executed by controller, per-task verification gates)


Task 0: complete (snapshots base-phase1-fixed on SOC01+WIN01, old merged; power outage recovery: wazuh-control restart after stale wdb socket)
Task 1: complete (DC01 VM + unattended Ubuntu 24.04.5 install, dcadmin/dcadmin123, 10.10.10.10/24 static on int-corp, dns 127.0.0.1, ssh natpf 127.0.0.1:2222. Deviations: no LVM (plain ext4 full disk), no gw route via 10.10.10.5 (SOC01 ip_forward=0, no dnsmasq on SOC01 — corp.lab DNS comes from DC01 Samba DNS), NIC2 NAT kept for internet until detach step. Creds recorded in .local-credentials.md)
Task 2: complete (Samba 4.19.5 AD DC CORP.LAB; accounts attacker/svc-sql/victim; SPN MSSQLSvc/dc01.corp.lab:1433; victim UAC=4194816; auth_json_audit->/var/log/samba/audit.json pure JSON via rsyslog template; kdc:10->log.samba; DNS forwarder 192.168.100.1; NAT detached; snapshot base-phase2 f1061239; SOC01->DC01 ssh key. Deviations: disabled systemd-resolved (port 53), provision non-interactive flags, rm package smb.conf, masked smbd/nmbd/winbind, deleted bogus A/AAAA records from NAT NIC, extra pkg ldb-tools, audit.json pre-owned syslog:adm. Repo: lab/dc01/ 51d4e24. SOC01 hung again mid-task -> hard reset, recovered healthy)
Task 3: complete (SOC01 impacket offline: pip bootstrapped from pip-26.2.1 wheel, impacket 0.13.1 + ldapdomaindump 0.10.0 installed via /tmp/wheels, GetUserSPNs.py/GetNPUsers.py/secretsdump.py in /usr/local/bin, /etc/hosts dc01.corp.lab added. Gotchas: /tmp tmpfs wiped by reboot; apt blinker/flask removal needed; typing-extensions extra wheel; impacket has no __version__. Repo: soc01.md ff4ee55)
Task 4: complete (DC01 wazuh-agent 4.14.8 installed via host->SOC01->DC01 chain, enrolled -A dc01, agent 002 active; MANAGER_IP placeholder fixed; localfile json audit.json + syslog log.samba + FIM realtime sam.ldb; FIM scan ran clean. Repo: ossec.conf.additions.xml 8c21341)
Task 5: complete — capture step. Five evidence files exported to lab/evidence/phase2-capture-{logon-fail,logon-ok,tgs-req,asrep,samldb}.json. KDC pipeline fixed + VERIFIED (975 Kerberos lines, agent 002). Field map + FIM target corrected in howto-create-detection.md. Post-savestate clock-skew session (2026-10-23) fixed SOC01/DC01 clocks + FIM config (deviations h,i).
  Task 5 fixes/deviations (all repo-synced or noted):
  a) rsyslog 30-samba-audit.conf broken since Task 2 (legacy \" escapes -> parse error, rsyslogd -N1); rewritten RainerScript: JSON (contains "\"type\": \"") -> audit.json raw; text -> log.samba RFC3164 (SambaText); RepeatedMsgReduction off. log.samba chown syslog:adm 664 + logrotate.d/samba create line patched (rsyslog opens as root but writes post-privdrop; root:root 644 made omfile suspend).
  b) Samba debug dual-channels: direct raw writes to log.samba + syslog (Debian 12 /dev/log -> journald -> rsyslog). Agent 002 also has default journald localfile -> KDC lines arrive TWICE (location journald raw, log.samba prefixed). Rules must plan dedup.
  c) Field names preserve JSON case: Authentication.* and KDC Authorization.* (NOT lowercase); log.samba lines have EMPTY decoder -> only full_log + predecoder (no `message` field; Task 8 rule template must use full_log).
  d) Kerberoast needs impacket patch (AP-REQ authenticator checksum, KU 6 RC4 cksumtype -138) -> kerberosv5-tgs-cksum.patch on SOC01 ~/phase2/; GetUserSPNs.py patched too.
  e) AS-REP blocked on Samba 4.19.5 (AS-REQ always ERR_PREAUTH_REQUIRED, even UAC 4194816). User decision: UC-05 detects on AS-REQ ERR_PREAUTH_REQUIRED + client-pa=128 pattern instead of hash.
  f) Wazuh API GET /events = 405; use indexer directly: curl -sku admin:<pw> https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search. KDC events hit rule 1002 (lvl 2) so are in archives.json but NOT the indexer (log_alert_level 3) until custom rules exist.
   g) Remote-script gotcha: ssh inside a `base64|bash` piped script consumes remaining stdin -> add `< /dev/null` to every ssh call.
   h) Savestate resume froze SOC01's clock ~13.5h behind (05:40 vs real 19:20 UTC) -> manager stopped collecting; WIN01 logon attempts were lost. Fix: `timedatectl set-ntp off` + `date -s` + `hwclock -w --utc` on SOC01/DC01, then `systemctl restart wazuh-manager`. Lesson: after any VM savestate/shutdown, check `date` on all VMs first.
   i) FIM on sam.ldb was doubly broken: (1) config watched the top-level /var/lib/samba/private/sam.ldb file, but Samba 4.19 writes to the DOMAIN PARTITION /var/lib/samba/private/sam.ldb.d/DC=CORP,DC=LAB.ldb (top-level sam.ldb mtime never changes); (2) TDB writes are mmap/msync — mtime updates but inotify/realtime never fires, so only the periodic checksum scan detects changes. Fix: watch `sam.ldb.d`, `<frequency>60</frequency>` (near-realtime). Rule 100032 must match the sam.ldb.d path, not sam.ldb. Also removed DUPLICATE samba localfile+syscheck blocks (additions had been appended twice, once per <ossec_config> block).
    Correct creds: attacker/Attacker!lab123, victim/Victim!lab123 (no-preauth), svc-sql/SvcSQL!lab123.

Task 6: complete — UC-03a logon rules authored (dashboard) + verified firing: 100029 (field Authentication.status NT_STATUS_WRONG_PASSWORD, lvl 8), 100030 (burst if_matched_sid 100029 freq 3/60s, lvl 12), 100031 (Authentication.status NT_STATUS_OK, lvl 3). 100029/100031 verified via WIN01 `net use`; 100030 had a latent `same_field` bug (uncovered + fixed in Task 9). Fixed XML attr->child (if_matched_sid/same_field) for 100030; field names Authentication.* (verbatim JSON case).
Task 7: complete — UC-03b sam.ldb FIM rule 100032. ROOT-CAUSE: rule used `<field name="syscheck.path">` (alert field) instead of FIM rule field `<field name="file">`; swapped `if_group syscheck` -> `if_sid 550`. Verified: `samba-tool user setexpiry victim --days=90` on DC01 -> alert 100032 (lvl 12, T1565.001, agent 002). Corrected local_rules.xml synced to repo (lab/soc01/). Gotcha added to howto + lessons-learned.
Task 8: complete (verified) — 100033 (KDC Authorization.serviceDescription MSSQLSvc, lvl 12) fired after clock fix; 100034 (match AS-REQ ERR_PREAUTH_REQUIRED, lvl 12) fired (duplicate alerts journald+log.samba, cosmetic).
Task 9: complete — WIN01 joined corp.lab (DESKTOP-I4QI720; NETLOGON+Kerberos computer-account auth seen, rule 100031). UC-03 burst re-verified: fixed 100030 `same_field Authentication.remoteAddress` (ephemeral port) + `clientAccount` (Kerberos "attacker@CORP" vs NTLM "attacker") -> `same_field Authentication.mappedAccount`. Windows negative-caches failed creds per server name, so re-run uses 3 DC names (dc01 / dc01.corp.lab / 10.10.10.10). Verified alert 100030 (lvl 12, T1110) fired from agent 002. Snapshots pre-domain-join + win01-joined taken. Remaining: Task 10 documentation/close-out.
Task 10: complete — 3 case docs (uc-03/04/05), exercise log, dc01 runbook, session state, 3 evidence screenshots; committed 65fbacc. Exit gate: UC-03 PASS, UC-04/05 PASS (bonus). DEVIATION: the Domain Admins cleanup was REVERTED per user — lab intentionally left attack-ready for study/reproducibility (attacker restored to Domain Admins). 100034 duplicate/FP tuning left as documented future work.

Phase 2 follow-up (2026-10-29, user hands-on + tuning):
- Hands-on verified full identity chain: 100032 (samba-tool user create Pedro -> AD DB FIM), 100031 (success), 100029 (failed), 100030 (burst 3/60s) all fired live.
- 100034 tuned: match narrowed from `AS-REQ ERR_PREAUTH_REQUIRED` to `AS-REQ ERR_PREAUTH_REQUIRED.*victim[0-9]*@CORP` (was `victim[0-9]*@CORP\.LAB`, but Samba logs the NetBIOS realm form `victim@CORP` too, so `\.LAB` dropped). Verified: 20 victim/victim2 log.samba lines match, 0 machine-account lines match. Deployed to SOC01 local_rules.xml.
- DC01 guest clock ran ~60x fast after savestate restore (tsc miscalibrated) -> Kerberos/LDAP broken. Fix: cold reboot + persist `clocksource=acpi_pm` via GRUB. Lesson added to lessons-learned.
- Docs: setup.md §3 DC01 + dc01-walkthrough.md (commit 4b5823d). uc-05 + lessons-learned updated with tuning rationale.

Phase 3 NDR — design + plan (2026-10-29, planning only, build not started):
- Brainstorming complete. Design spec `docs/superpowers/specs/2026-10-29-phase3-ndr-design.md`; plan `docs/superpowers/plans/2026-10-29-phase3-ndr.md` (15 tasks). Commits `04d1c5d` + `fce9592`.
- Locked decisions: full suite (marker UC-06 + 6 detections UC-07..12: T1046/T1571/T1095/T1071.004/T1110/T1040); custom-only ruleset (no ET); passive capture first (G2 gate) with bridge fallback; S3 power-on (DC01 OFF all phase).
- KEY DEVIATION from first draft: DC01 must stay off in S3 (12 GB > 11 GB ceiling if all 4 guests on). SMB brute force (T1110) retargeted to SOC01→WIN01:445 via impacket; port scan/ICMP/DNS/FTP retargeted to SOC01. Design spec was updated to match before plan.
- Mapping: Suricata sids 7000001–7000007 ↔ Wazuh rules 100040–100046 (field `alert.signature_id`). NDR01: 1 vCPU/1 GB/15 GB, 10.10.10.40, agent 003, ndradmin/ndradmin123.
- Next: execute plan (subagent-driven recommended), Task 0 first; Task 1 is interactive user step.

Phase 3 NDR — build + verification (2026-10-30/31, executing):
- Task 0: complete (DC01 off, SOC01+WIN01 healthy, WIN01 snapshot `pre-uc06`). Commit 6180240.
- Task 1: complete (NDR01 VM + Ubuntu 24.04, static 10.10.10.40/24 on int-corp NIC1 promisc allow-all,
  NIC2 NAT ssh fwd 127.0.0.1:2223; ndradmin/ndradmin123; GRUB `clocksource=acpi_pm`; RAM bumped 1→2 GB
  after 1 GB froze install — MUST drop back to 1 GB in Task 14). Commit 23410f5.
- Task 2: complete (Suricata 8.0.8 OISF PPA; Wazuh agent 4.14.8 enrolled as ndr01/003; eve.json localfile;
  ossec.conf manager IP). 
- Task 3: complete (Suricata configured: af-packet enp0s3, HOME_NET 10.10.10.0/24, 7 local.rules sids
  7000001-7000007, eve.json types alert/http/dns/smb/ftp/flow/stats). Commit 6927f98.
- Task 4: complete (G2 capture gate PASS — passive promiscuous capture works, no bridge). Marker field
  confirmed `alert.signature_id`. Commit d153a80.
- Task 5: complete (user authored rules 100040-100046 via dashboard; synced to repo). Commit d5851db.
- Task 6: complete (tools staged: WIN01 beacon.ps1/dns-exfil.ps1/port-scan.ps1 at C:\lab\;
  SOC01 mini_ftpd.py replacing pyftpdlib 2.2.0 which is incompatible with Python 3.12 asynchat).
  Commit df775fc.
- **ROOT CAUSE (custom rules fired nothing) + FIX**: Wazuh built-in Suricata chain 86600→86601 consumes
  eve.json `alert` events, so top-level custom rules never matched. Fix: `<if_sid>86601</if_sid>` +
  `<field name="alert.signature_id" type="pcre2">^700000N$</field>` on all 7 rules. Verified via
  wazuh-logtest + end-to-end marker→100040. Commit 3ded236.
- Task 7 (UC-06 marker): PASS — 100040 lvl 8 fires on `lab-ndr-test` UA; benign (default PowerShell UA)
  silent. Verified dashboard + alerts.json + eve.json.
- **Clock fix (blocked UC visibility)**: SOC01 clock ~27 h behind (no NTP) → alerts stamped in past →
  dashboard default window hid them ("nothing on dashboard"). Fixed `timedatectl set-ntp off` +
  `set-time` to real UTC. Re-fire after fix.
- Task 8 (UC-07 port scan, T1046): PASS — port-scan.ps1 (60 SYNs) → 7000002 → 100041 lvl 10.
  Benign (single Test-NetConnection to open 1514) silent.
- Task 9 (UC-08 beaconing, T1571): PASS — beacon.ps1 → 7000003 → 100042 lvl 12. **DEVIATION**: plan's
  benign control `Test-NetConnection -Port 4444` retransmits SYN ~5× (closed port) and trips the
  count-5/60s threshold (false positive). Replaced with single non-blocking BeginConnect SYN
  (`pkts_toserver:1`, alerted:false). Noted for docs.
- Task 10 (UC-09 ICMP, T1095): PASS — `ping -n 3 -l 1200` → 7000004 → 100043 lvl 12
  (2026-11-01T05:01:55Z, src 10.10.10.20→10.10.10.5, ICMP). Benign 32-byte ping silent.
- Task 11 (UC-10 DNS, T1071.004): PASS — `dns-exfil.ps1` → 7000005 → 100044 lvl 12
  (05:09:59Z, UDP 10.10.10.20→10.10.10.5:53). Benign `nslookup corp.lab` silent.
- Task 12 (UC-11 SMB, T1110): PASS — impacket ×12 → 7000006 → 100045 lvl 12
  (2026-11-02T01:42:38Z, src 10.10.10.5→10.10.10.20:445). **Lab controls**: opened 445 on WIN01
  (default filtered); used non-existent local user `nosuchuser` to avoid re-locking a real account;
  fired 12 attempts CONCURRENTLY (Windows SMB rate-limiter ~2s/failure defeats sequential);
  recovered an accidental `labadmin` lockout via `pre-uc06` snapshot restore. Benign single
  successful logon silent.
- Task 13 (UC-12 FTP, T1040): PASS — WIN01 `ftp` → SOC01:21 → 7000007 → 100046 lvl 10
  (01:54:03Z). pyftpdlib 2.2.0 is incompatible with Python 3.12 (asynchat/asyncore) → replaced by
  `mini_ftpd.py` (repo `lab/soc01/mini_ftpd.py`). Suricata `ftp_flow:1 ftp_tx:5`. Benign silent
  by construction.
- Task 14 (close-out): complete — 7 case docs (uc-06..uc-12), exercise-log rows, 8 new
  lessons-learned entries, `ndr01-walkthrough.md` + `setup.md` §4, evidence
  `lab/evidence/phase3-alerts.json`. NDR01 NAT detached + RAM 1 GB + snapshot `base-phase3`
  (clock + Suricata + wazuh-agent re-verified after headless reboot). session.md updated.
  Final commit pending.

Phase 3 follow-up notes (2026-11-02, user hands-on):
- Clock drift recurred: after the host was off/sleeping, SOC01 + NDR01 were ~18 h behind real
  time (Linux VMs stall; WIN01 stays synced via Guest Additions). Fixed both; lesson recorded.
- UC-11 re-run required opening 445 and concurrent impacket attempts; first sequential run locked
  `labadmin` (realistic T1110 impact) — recovered via `pre-uc06` snapshot restore.
- NDR01 reachability changed: NAT (127.0.0.1:2223) is detached, so NDR01 is now SOC01-hop only.
