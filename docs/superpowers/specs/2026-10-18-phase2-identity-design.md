# Phase 2 — Identity detection design

Date: 2026-10-18
Status: approved design, pending implementation plan
Follows: `2026-10-12-virtual-soc-phase-architecture-design.md` (section 7, Phase 2 — Identity)

## 1. Goal and scope

Add DC01 (Samba AD DC, domain `corp.lab`) to the lab, join WIN01 to the domain, and build
identity-attack detections in Wazuh. Three custom rules, all authored by the user via the dashboard
UI (same workflow as rule 100020), all in `lab/soc01/local_rules.xml`.

| UC | Detection | MITRE | Role |
|---|---|---|---|
| UC-03 | Failed-logon burst then success (a) + privileged group change (b) | T1110 / T1098 | **Exit gate** |
| UC-04 | Kerberoasting (TGS requests for SPN service accounts) | T1558.003 | Portfolio bonus |
| UC-05 | AS-REP roasting (AS-REQ against a no-preauth account) | T1558.004 | Portfolio bonus |

Exit gate (architecture spec section 7): UC-03 PASS — three failed logons then a success produce a
Wazuh alert with both the endpoint and the domain identity in the evidence; a privileged group
change produces a separate alert. UC-04/05 are bonuses, not the gate.

## 2. Architecture decisions (locked with user)

- **Platform**: Samba AD DC on Ubuntu Server 24.04 LTS. Windows Server DC rejected: 4 GB minimum
  breaks the S2 RAM ceiling.
- **Attack simulation**: impacket (`GetUserSPNs.py`, `GetNPUsers.py`) from SOC01 for UC-04/05; plain
  wrong-password logons for UC-03. No Defender interference on Linux. Documented as lab controls.
- **Telemetry**: Wazuh agent on DC01 (Approach A). Rejected: WIN01-side-only (can't see KDC or
  sam.ldb) and rsyslog-forward (FIM impossible remotely).
- **Group-change detection**: FIM on `/var/lib/samba/private/sam.ldb`. Samba has no 4728/4732-style
  events; dsdb audit coverage is version-dependent and unreliable. FIM works regardless.
- **Rule authorship**: user writes all three custom rules via the dashboard UI; assistant verifies,
  syncs back to repo, commits.

## 3. DC01 build and network

- VM: Ubuntu Server 24.04 LTS, 1 vCPU, 2 GB RAM, ~20 GB disk, NICs `int-corp` + NAT.
- Network: static `10.10.10.10/24`, gateway `10.10.10.5` (SOC01), DNS `127.0.0.1`. NAT detached
  after provisioning (pre-isolation checklist first).
- NAT-window installs: `samba` AD DC stack, `krb5-user`, updates, Wazuh agent deb copied from
  SOC01 `/var/ossec/packages`.
- Provision: `samba-tool domain provision` — domain `corp.lab`, NetBIOS `CORP`, RFC2307.
- smb.conf audit: `log level = 1 auth_json_audit:3` plus KDC request audit class if the installed
  Samba version supports it (capture step confirms).
- Accounts:
  - `svc-sql` — SPN `MSSQLSvc/dc01.corp.lab:1433`, weak password (Kerberoast target)
  - `victim` — `UF_DONT_REQUIRE_PREAUTH` set (AS-REP target)
  - `attacker` — normal domain user (logon-burst identity)
- SOC01: impacket installed offline (wheel bundle from host via pscp; temporary NAT only as a
  documented fallback). `/etc/hosts`: `dc01.corp.lab → 10.10.10.10`.
- WIN01: static DNS → `10.10.10.10`; snapshot before domain join.

Power-on: **S2** = SOC01 + WIN01 + DC01 = 11 GB, exactly at the ceiling. If the host swaps during
provisioning: WIN01 to console session, close host browser (spec rule).

## 4. Telemetry pipeline

1. Wazuh agent on DC01 → manager `10.10.10.5:1514`.
2. Agent localfile: Samba JSON auth audit (success/failure, NTLM + Kerberos: `status`,
   `clientAccount`, `remoteAddress`, service description) and KDC request audit (AS-REQ/TGS-REQ,
   preauth, client, service) if available.
3. FIM realtime on `/var/lib/samba/private/sam.ldb`.
4. **Capture step before any rule is written**: generate one of each event (failed logon, success,
   TGS-REQ, AS-REQ, sam.ldb write), export sample JSON from Wazuh, and design rules against real
   field names — same discipline as rule 100020's `win.eventdata.commandLine` discovery.
5. KDC JSON fallback: if `kdc_json_audit` does not exist in the installed Samba, parse `log.samba`
   text lines (TGS-REQ/AS-REQ) instead. Detection semantics unchanged.

## 5. Detection rules (user-authored, dashboard UI)

All in `local_rules.xml`, groups include `identity_attack,lab,<tactic>`, level 12, `\x22`-escape
discipline (no raw quotes in regex text — API error 1113).

| Rule | UC | Trigger | Correlation |
|---|---|---|---|
| 100030 | UC-03a logon burst | 3+ failed auths, same source IP, 60 s window | `same_source_ip` + frequency |
| 100032 | UC-03b group change | FIM modified on sam.ldb | none |
| 100033 | UC-04 Kerberoasting | 3+ TGS-REQs for an SPN service account from one client in window | frequency |
| 100034 | UC-05 AS-REP | AS-REQ with preauth disabled / against no-preauth account | none |

- 100031/100035 reserved for stretch chained rules (success-after-burst, corroboration) if capture
  data supports them. Not gate-critical.
- Thresholds are initial guesses, tuned from real capture volumes during testing (documented).
- Field names (JSON paths, status strings like `NT_STATUS_WRONG_PASSWORD`, KDC JSON keys) are
  finalized in the capture step, before rule authoring.

## 6. Testing per detection

User runs attacks; assistant verifies alerts, syncs files, commits. Pass = expected alert with
expected evidence + benign control silent.

| UC | Attack (user) | Expected alert evidence | Benign control |
|---|---|---|---|
| UC-03a | 3x wrong-password smbclient logons from WIN01, then 1 success | 100030, WIN01 IP + `attacker@corp.lab` | 2 failures only → silent |
| UC-03b | `samba-tool group addmembers "Domain Admins" attacker` | 100032, sam.ldb path + timestamp | unrelated AD read → silent |
| UC-04 | `GetUserSPNs.py corp.lab/attacker` from SOC01 | 100033, client + service account | single TGS-REQ → silent |
| UC-05 | `GetNPUsers.py corp.lab/ -usersfile ...` from SOC01 | 100034, no-preauth account | normal preauth kinit → silent |

Failures follow the systematic-debugging workflow; no rule is called done until the control is
silent and the attack fires twice.

## 7. Constraints, risks, fallbacks

- RAM: S2 = 11 GB ceiling. DC01 stays 2 GB. No third guest joins.
- Samba audit maturity is the main unknown: capture step decides JSON vs text fallback before any
  rule is written.
- sam.ldb FIM noise: any AD write fires 100032 (provisioning, password changes). Acceptable in a
  small lab; FPs documented in lessons-learned.
- Impacket offline install may hit dependency issues → documented temporary NAT attach, then
  detach (architecture spec's documented-exception pattern).
- WIN01 domain join changes endpoint state permanently until revert → snapshot first.
- No new internet dependencies; SOC01 stays offline.

## 8. Sequencing

1. Snapshot refresh: both VMs → `base-phase1-fixed`; session-state commit.
2. Build DC01: NAT window → provision `corp.lab` → detach NAT → snapshot `base-phase2`.
3. Agent enroll; capture step: sample JSON for all four event types.
4. User writes 100030 → test UC-03a → sync + commit.
5. User writes 100032 → test UC-03b → sync + commit.
6. User writes 100033 + 100034 → test UC-04/05 → sync + commit.
7. WIN01 domain join (snapshot first) → re-run UC-03 with WIN01 as the endpoint.
8. Exit-gate review: UC-03 PASS.
9. House-rule docs: case docs `lab/cases/uc-03-*.md`, `uc-04-*.md`, `uc-05-*.md`; exercise-log
   rows; lessons-learned; evidence screenshots `lab/evidence/uc-0x-alert.png`; session state.
   Final commit.
