# Session state — resume here

Last updated: 2026-10-29 (Phase 3 NDR BUILD IN PROGRESS — Task 0 done, starting Task 1). Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — PHASE 3 NDR: BUILD IN PROGRESS (Task 0 complete)

Phase 3 NDR build started. Task 0 pre-flight done: DC01 powered off (S3), SOC01+WIN01 running and healthy, WIN01 snapshot `pre-uc06` taken. Next: Task 1 (create NDR01 VM + interactive Ubuntu install, needs user present).

Phases 0–1 PASS + Phase 2 PASS. Phase 3 NDR is fully designed and planned, **nothing built yet**.

- **Design spec:** `docs/superpowers/specs/2026-10-29-phase3-ndr-design.md` (commit `04d1c5d`, then `fce9592`)
- **Implementation plan:** `docs/superpowers/plans/2026-10-29-phase3-ndr.md` (commit `fce9592`, 15 tasks)
- Master architecture: `docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md` §7 + §12 G2

### Phase 3 decisions locked today (do not re-litigate)

| Topic | Decision |
|---|---|
| Scope | Full suite: exit-gate marker + 6 real detections (T1046, T1571, T1095, T1071.004, T1110, T1040) |
| Ruleset | Custom-only + Suricata shipped default (no ET Open/Pro) |
| Tooling | Stage nmap (Windows) + beacon.ps1 + dns-exfil.ps1 on WIN01; pyftpdlib on SOC01 (at build, NAT window) |
| Capture | Passive promiscuous first (Approach A), G2 tcpdump gate, inline-bridge fallback (§7 of design) |
| Power-on | **S3 only: SOC01 + WIN01 + NDR01 = 10 GB. DC01 stays OFF all phase.** |
| SMB brute force (T1110) | Source = **SOC01 via impacket → WIN01:445** (DC01 off; no DC-targeting) |
| Other targets | All retargeted to SOC01 `10.10.10.5` (port scan, ICMP, DNS, FTP) |
| Mapping | Suricata sids 7000001–7000007 ↔ Wazuh rules 100040–100046 (keyed on `alert.signature_id`) |
| NDR01 | Ubuntu 24.04, 1 vCPU / 1 GB / 15 GB, `10.10.10.40/24` on `int-corp` promiscuous allow-all, `ndradmin/ndradmin123`, Wazuh agent **003**, GRUB `clocksource=acpi_pm` |

Detection suite (full details in design §4):
- UC-06 marker: WIN01 `Invoke-WebRequest` UA `lab-ndr-test` → SOC01 (needs `python3 -m http.server 80` on SOC01)
- UC-07 T1046: WIN01 nmap `-sS` sweep of SOC01
- UC-08 T1571: WIN01 `beacon.ps1` → SOC01:4444 every 10s
- UC-09 T1095: WIN01 `ping -n 3 -l 1200` SOC01
- UC-10 T1071.004: WIN01 `dns-exfil.ps1` long-label queries → SOC01:53
- UC-11 T1110: SOC01 impacket `smbclient.py` ×12 failed → WIN01:445
- UC-12 T1040: WIN01 `ftp` → SOC01 `pyftpdlib` (:21)

## Current lab state

- **SOC01**: RUNNING (headless). Rules 100010 + 100020 + 100029–100034 live. impacket installed (`/usr/local/lib/python3.12/dist-packages/examples/`). Clock fixed.
- **WIN01**: RUNNING (headless), DOMAIN-JOINED. Snapshots `pre-domain-join`, `win01-joined`, `base-phase1-fixed`, **`pre-uc06`** (Phase 3 rollback point).
- **DC01**: POWERED OFF (correct — Phase 3 needs it off).
- **NDR01**: does not exist yet (Task 1).
- **Repo**: all committed. HEAD = `fce9592`.

## Next session — first steps

1. Read this file, then the plan `docs/superpowers/plans/2026-10-29-phase3-ndr.md`.
2. Pick execution approach: **subagent-driven** (recommended) or **inline** (executing-plans skill).
3. Start **Task 0** (confirm DC01 off, SOC01/WIN01 healthy, snapshot WIN01 `pre-uc06`).
4. Task 1 is an **interactive user step** (NDR01 Ubuntu install) — user must be present for the install.
5. G2 capture gate (Task 4) is the go/no-go: if `tcpdump` on NDR01 doesn't see WIN01→SOC01, branch to bridge re-plumb before trusting any rule.

## Notes carried over

- Remote control: plink from host to SOC01 (`plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10`), <PW> from `.local-credentials.md`; sudo = `echo <PW> | sudo -S`; complex commands via base64 wrapper (`echo <b64> | base64 -d | bash`). NDR01 = hop SOC01 → `ssh ndradmin@10.10.10.40`.
- ssh inside a piped remote script consumes stdin → ALWAYS add `< /dev/null` to ssh lines.
- Grepping alerts.json gotcha: `sudo grep` self-matches (+1 rule 5402 per check); `id:100020` does NOT match JSON `"id":"100020"`. Grep the description phrase + filter `COMMAND`.
- Wazuh API helper: `token=$(curl -ks -u 'wazuh:<apiPw>' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token)`. API password has a TRAILING PERIOD (in `.local-credentials.md`).
- Custom Wazuh rules: `/var/ossec/etc/rules/local_rules.xml` on SOC01 (repo: `lab/soc01/local_rules.xml`); authored ONLY via dashboard UI by user; NO raw quotes in regex (API error 1113) — use `\x22`/`\x27`; after save, restart manager + API check (dashboard saves sometimes skip reload).
- JSON decoder field names have NO `data.` prefix: nested keys become dotted (`Authentication.status`, `alert.signature_id`). **Phase 3 Wazuh rules key on `alert.signature_id` — verify exact name in Task 4 Step 4 before authoring Task 5.**
- **FIM rule field is `file`, not `syscheck.path`** (wazuh#26327).
- Windows negative-caches failed creds per server name (Phase 2). Not relevant to Phase 3 UC-11 (impacket opens fresh SMB connections each time).
- User runs all attack simulations; assistant builds/tunes/verifies (AGENTS.md rule).
- Clock gotcha: no NTP; savestate/resume can freeze or fast-forward a Linux VM's clock (tsc). After any resume, `date` on all VMs first. NDR01 gets `clocksource=acpi_pm` persisted.
- Wazuh 4.14 rotates alerts/archives daily → yesterday's in rotated files, `zgrep` them.
- Indexer queries: `curl -sku 'admin:<pw>' -H 'Content-Type: application/json' -d '{"query":...}' https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search`.
- Secrets: `lab/runbook/.local-credentials.md` (gitignored). NDR01 `ndradmin/ndradmin123`; SOC01 `socadmin/socadmin123`; WIN01 `labadmin/labadmin123`; Wazuh API `wazuh:<apiPw>`.
- Docs: design `docs/superpowers/specs/2026-10-29-phase3-ndr-design.md`; plan `docs/superpowers/plans/2026-10-29-phase3-ndr.md`; runbooks `lab/runbook/*.md`; cases `lab/cases/*.md`; ledger `.superpowers/sdd/progress.md`.
