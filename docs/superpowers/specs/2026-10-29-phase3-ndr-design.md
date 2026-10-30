# Virtual SOC Lab — Phase 3 NDR Design

Status: design, approved
Date: 2026-10-29
Source: `docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md` §7 (Phase 3), §12 (gate G2)
Precedes: implementation plan (writing-plans)

## 1. Purpose

Add an NDR sensor (NDR01 running Suricata) that observes `int-corp` traffic and ships alerts to Wazuh. Prove that a network-level attack — invisible to host/identity logs — produces a SIEM alert. The portfolio story is "host (Sysmon), identity (Samba), network (Suricata) converge in one SIEM."

Phase 3 delivers the exit-gate marker plus a full suite of six real network detections, distinct from Phase 2 identity detections.

## 2. Locked constraints (inherited)

| Item | Value |
|---|---|
| Host RAM ceiling (all guests) | 11 GB |
| NDR01 profile | Ubuntu Server 24.04 LTS, 1 vCPU / 1 GB / 15 GB, static `10.10.10.40` on `int-corp`, NIC promiscuous "Allow All", temp NAT detached after build |
| Power-on | S3: SOC01 + WIN01 + NDR01 = 10 GB (DC01 off) |
| Isolation | No bridged NICs, no inbound port forwards, no pcap retention |
| Suricata | Ubuntu PPA, stable 8.0.x (fallback 7.0.x), AF_PACKET IDS mode (passive) |
| Capture | Passive promiscuous first; on G2 failure re-plumb to inline bridge (§7) |

## 3. Architecture & components

### 3.1 NDR01 guest

- Ubuntu Server 24.04 LTS; 1 vCPU / 1 GB / 15 GB disk.
- NIC0 `int-corp`, promiscuous Allow All, static `10.10.10.40/24`.
- Temp NAT for package install only, then detached.
- GRUB `clocksource=acpi_pm` persisted (same fast-clock fix as DC01).
- Wazuh agent 4.14.x, enrolled as agent **003**, `MANAGER_IP 10.10.10.5`.

### 3.2 Suricata

- Installed from Ubuntu PPA; pinned to stable 8.0.x (7.0.x acceptable).
- Interface: the `int-corp` NIC, AF_PACKET IDS mode, passive (not NFQUEUE).
- Ruleset: shipped default rules + `local.rules` with 7 custom rules (§4). No ET Open/Pro.
- `eve.json` (JSON) with log types `http`, `dns`, `smb`, `ftp`, `flow`, `stats` — the minimum our rules need, to keep the 1 GB guest happy.
- No pcap retention. A short `tcpdump` ring is allowed only while collecting evidence for one test, then deleted.

### 3.3 Detection → Wazuh bridge

- Wazuh agent `localfile` reads `/var/log/suricata/eve.json` with the JSON decoder (same proven pattern as Samba `audit.json`).
- Suricata rules emit `event_type: alert` with `alert.signature_id` + `alert.signature`.
- One Wazuh rule per detection, keyed on `alert.signature_id`, each with its own MITRE ID + level.
- Mapping: **7 Suricata sids ↔ 7 Wazuh rules (100040–100046)**.

### 3.4 Build-time staging (NAT window, before detach)

| Target | Tool | Purpose |
|---|---|---|
| WIN01 | nmap for Windows (zip) | T1046 port scan |
| WIN01 | beacon PowerShell script | T1571 beaconing |
| WIN01 | DNS-exfil PowerShell script | T1071.004 DNS anomalies |
| SOC01 | `pyftpdlib` (pip) | T1040 cleartext FTP server |
| NDR01 | Suricata PPA + package, Wazuh agent, `local.rules` | sensor |

Notes:
- impacket is already installed on SOC01 (Phase 2) — reused for UC-11 SMB brute force. No DC01 staging at all; **DC01 stays off for the whole phase (S3).**
- All attack targets below are SOC01 (`10.10.10.5`) or WIN01 — never DC01 — because S3 keeps DC01 powered off.

## 4. Detection suite (7 rules)

SIDs `7000001–7000007`. All targets are lab-internal. No public exploit traffic.

| # | UC | Detection | Technique | Trigger | Suricata rule logic |
|---|---|---|---|---|---|
| 1 | UC-06 | Marker | — | WIN01 HTTP `User-Agent: lab-ndr-test` to SOC01 | `http.user_agent` content match |
| 2 | UC-07 | Port scan | T1046 | WIN01 nmap SYN sweep of SOC01 | SYN threshold, `track by_src` |
| 3 | UC-08 | Beaconing | T1571 | WIN01 periodic connect to `10.10.10.5:4444` every ~10 s | connection threshold to non-standard dst port, `track by_src` |
| 4 | UC-09 | ICMP tunneling | T1095 | WIN01 oversized `ping -l` to SOC01 | `dsize` > threshold on ICMP echo |
| 5 | UC-10 | DNS anomalies | T1071.004 | WIN01 scripted long-label DNS queries to SOC01:53 | `pcre` on `dns.query` (name length) |
| 6 | UC-11 | SMB brute force | T1110 | SOC01 impacket repeated failed SMB auth to WIN01:445 | SMB connection threshold, `track by_src` |
| 7 | UC-12 | Cleartext protocol | T1040 | WIN01 plaintext FTP `USER`/`PASS` to SOC01 (`pyftpdlib`) | `ftp` app-layer, `USER`/`PASS` content match |

### Rule intent (exact values validated at build)

| # | Pinned parameters |
|---|---|
| 1 | `http.user_agent; content:"lab-ndr-test"; nocase;` |
| 2 | `flags:S; threshold: type threshold, track by_src, count 20, seconds 5;` (dst = SOC01) |
| 3 | `dst port 4444; flags:S; threshold: type threshold, track by_src, count 5, seconds 60;` |
| 4 | `itype:8; dsize:>1000;` (normal ping ~32 B payload; tunneled ~1500 B) |
| 5 | `dns.query; pcre:"/^.{40,}$/";` (long random-label FQDN, query sent to SOC01:53) |
| 6 | `dst port 445; flags:S; threshold: type threshold, track by_src, count 10, seconds 30;` |
| 7 | `app-layer-protocol:ftp; content:"USER "; content:"PASS "; nocase;` |

Exact pcre/threshold syntax is confirmed against Suricata 8 at build; the intent above is normative.

### Wazuh rule mapping

| Suricata sid | Wazuh rule | Level | MITRE |
|---|---|---|---|
| 7000001 | 100040 | 8 | — (lab marker) |
| 7000002 | 100041 | 10 | T1046 |
| 7000003 | 100042 | 12 | T1571 |
| 7000004 | 100043 | 12 | T1095 |
| 7000005 | 100044 | 12 | T1071.004 |
| 7000006 | 100045 | 12 | T1110 |
| 7000007 | 100046 | 10 | T1040 |

### Notes

- UC-11 (SMB brute force) runs from **SOC01 via impacket against WIN01:445** — it detects SMB brute force against a Windows endpoint, distinct from Phase 2's WIN01→DC01 logon detection. `track by_src` keys on SOC01 as the source; each impacket `smbclient` invocation opens a fresh connection (no negative-cache issue).
- UC-12 needs `pyftpdlib` running on SOC01 (`10.10.10.5:21`); WIN01 logs in with a plaintext lab credential.
- All other detections (UC-06/07/08/09/10) originate from WIN01 and target SOC01, keeping DC01 off.

## 5. Data flow

1. WIN01 sends traffic → NDR01 sees it on `int-corp` (promiscuous).
2. Suricata matches a rule → writes `event_type: alert` (with `signature_id`) to `eve.json`.
3. NDR01 Wazuh agent tails `eve.json` → forwards to SOC01 `10.10.10.5:1514`.
4. Wazuh manager decodes JSON, matches `alert.signature_id` → fires the mapped rule (MITRE + level).
5. Analyst reads it at `https://10.10.30.10`.

Phase 3 is a parallel source to Phase 1 (Sysmon) and Phase 2 (Samba auth JSON). NDR events are not required to reach n8n in the first automation demo.

## 6. Verification

### G2 — capture gate (before any rule is trusted)

`tcpdump -i <int-corp nic>` on NDR01 must show a WIN01→SOC01 flow. If it fails, re-plumb to the inline bridge model (§7) before proceeding. Do not leave promiscuous capture as an unverified dependency.

### Per-detection gates

| UC | Pass | Benign control (must NOT fire) |
|---|---|---|
| UC-06 | marker alert visible in Wazuh | a normal browser request without the UA |
| UC-07 | port-scan alert on nmap sweep of SOC01 | a few normal connections below threshold |
| UC-08 | beacon alert on periodic connects | a single one-off connect to 4444 |
| UC-09 | ICMP-tunnel alert on `ping -l 1500` | a normal `ping` (~32 B) |
| UC-10 | DNS-anomaly alert on long-label queries | a normal short DNS query to SOC01:53 |
| UC-11 | SMB brute-force alert on repeated failed auth | a single successful SMB logon to WIN01 |
| UC-12 | cleartext-FTP alert on USER/PASS | no plaintext FTP session |

### Simulation flow

1. I build NDR01 + Suricata + Wazuh agent, verify G2.
2. You stage/run each trigger one at a time (WIN01 for UC-06..UC-10/12; SOC01 impacket for UC-11).
3. I confirm the alert in Wazuh, capture the evidence screenshot, then we move to the next.

## 7. G2 fallback — inline bridge

If passive capture fails:

1. Split `int-corp` into `int-corp-east` (WIN01, DC01) and `int-corp-west` (SOC01).
2. NDR01 gets one NIC on each segment and bridges them (`ip link add br0 type bridge`, enslave both, up).
3. All hosts keep existing `10.10.10.0/24` addresses (no renumbering; phases 1–2 keep working).
4. Suricata binds `br0` in AF_PACKET IDS mode; the kernel bridge forwards, Suricata observes.

Bridge caveats: sensor is in the forwarding path, so a stopped NDR01 stops east↔west traffic; Suricata restarts must keep `br0` up. S3 boot order becomes NDR01-on-before-WIN01, off-last.

Second fallback (routed) only if bridging fails: move WIN01 to `10.10.20.0/24` with NDR01 (`10.10.20.1`) as gateway, NDR01 also on `int-corp`, routing between segments; Suricata sniffs both interfaces.

## 8. Risks & error handling

- **Promiscuous capture may not work (G2).** Mitigation: tcpdump gate first; bridge fallback (§7).
- **1 GB guest.** Mitigation: default + custom-only ruleset, trimmed `eve.json` log types, no pcap retention.
- **Clock drift (known gotcha).** After any NDR01 savestate/resume, check `date` first; persist `clocksource=acpi_pm`.
- **eve.json decoding.** Reuse the proven JSON-decoder + `localfile` pattern; remember Wazuh JSON fields carry no `data.` prefix.
- **Duplicate alerts.** Suricata writes only to `eve.json` (no syslog/journald path), so no duplicate ingestion (unlike 100034's log.samba issue).

## 9. Acceptance — Phase 3 done when ALL

1. G2 capture gate passes (or bridge fallback in place).
2. Marker UC-06 fires and is visible in Wazuh.
3. All 6 real detections (UC-07..UC-12) fire on trigger, each with a documented benign control that does not fire.
4. Evidence screenshots exported to `lab/evidence/uc-0{6..12}-alert.png`.
5. Docs updated + committed: `ndr01-walkthrough.md`, `setup.md` §4, `lessons-learned.md`, `progress.md`, one use-case doc per detection.
6. Lab stays isolated: NAT detached after build; no pcap retained.
