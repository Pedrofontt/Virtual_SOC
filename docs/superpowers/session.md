# Session state — resume here

Last updated: 2026-10-12 (session 1). User went to sleep; resume by reading this file, then continue executing the Phase 0–1 plan.

## Where we are

Brainstorming and planning are DONE. The design spec went through a review round (3 findings + 2 clarifications) and is committed. The Phase 0–1 implementation plan is written, self-reviewed, and committed. **Zero implementation has started** — no VMs, no lab files created yet.

## What is decided (do not re-litigate unless reality breaks)

- Hypervisor: **VirtualBox 7.1.x** (lightest, free, no account). Analyst console = the Windows host itself.
- SOAR: **n8n** (not Shuffle) — Shuffle idles at 3–4 GB and breaks the 11 GB simultaneous-VM ceiling.
- WIN01: **Windows 11 Enterprise Evaluation** — Windows 10 Eval ISOs were decommissioned after Oct 2025 EOL. Needs EFI + virtual TPM 2.0 + Secure Boot (VBox 7 provides all). Fit tweaks on 4 GB: Memory Integrity off, effects off.
- Wazuh **4.14.x** all-in-one on Ubuntu Server 24.04 LTS; SOC01 = 3 vCPU / 5 GB / 50 GB. Indexer heap pinned 1g/1g (the 4.14 installer falls back to 1 GB heap anyway). 7-day indices, 30-day/5 GB archives.
- Milestone 1 = S1 only (SOC01 + WIN01 = 9 GB): UC-00 FIM warm-up (rule 550), then UC-01 T1003.001 LSASS via Sysmon EID 10 with custom rule **100010** (level 12, MITRE T1003.001, parent rule expected 61610 — VERIFY parent id on the real ruleset first).
- Networks: vboxnet0 10.10.30.0/24 (host .1, SOC01 .10); int-corp 10.10.10.0/24 (SOC01 .5, WIN01 .20, DC01 .10, NDR01 .40). Static IPs everywhere, no DHCP, no bridged NICs, NAT detached after pre-isolation checklists.
- Phase 3 capture fallback: if promiscuous tcpdump gate fails, pivot to inline **bridge** model (split int-corp, NDR01 bridges, AF_PACKET on br0, no renumbering). "NDR01 as router" alone was rejected (on-link traffic bypasses it).
- Write phase 2–4 plans ONLY after Milestone 1 passes. Update spec + exercise log when implementation diverges.

## Review feedback already incorporated into the spec

- Finding A: VirtualBox intnet promiscuous capture is version-dependent → gate G2 + bridge fallback (spec §12).
- Finding B: 5 GB indexer OOM → runbook: `sudo systemctl stop wazuh-dashboard` (frees ~1 GB; browser shows connection error at https://10.10.30.10 — expected, not a crash; verify headless via G1 API checks).
- Finding C: pre-isolation software checklist before detaching NAT (ISOs, Sysinternals, Sysmon config, curl/jq/tmux/htop).
- Sysmon schemaversion must match the downloaded binary or the service won't start ("invalid manifest" in Application log; reload via `Sysmon64.exe -c`).
- UC-01 PowerShell block must run in one continuous session (`$lsassPid` nulls if the console closes).

## Git state

Branch `main`, clean working tree (except untracked `docs/DFD.PNG` + `docs/initial_info.md` — user's originals, left untracked on purpose). Commits (newest first):

- `b36737f` Sysmon manifest + PowerShell session failure modes in plan
- `443a914` Phase 0–1 implementation plan
- `3c41d15` Suricata bridge-mode nuance + dashboard-stop UI note
- `713ac83` Design review: NDR fallback, OOM runbook, pre-isolation checklist, gates G1/G2
- `df04642` Design spec
- `9c69ebe` Initial commit

## The plan: 8 tasks (docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md)

1. Repo scaffolding (lab/README.md, lab/network/networks.md, lab/evidence/) — **pure file creation, agent can do alone**
2. Host prep + SOC01 base VM — user installs VirtualBox + Extension Pack, downloads Ubuntu 24.04 ISO to C:\iso\; GUI wizard for VM; netplan static IPs; host-only net via VBoxManage
3. Wazuh all-in-one install + tuning (heap, retention, archives) + G1 baseline + detach NAT + snapshot `base-soc01`
4. WIN01 Windows 11 Eval install (GUI-heavy; bypassnro if MS account forced) + fit tweaks + Sysinternals
5. Sysmon config apply + Wazuh agent MSI + enrollment + telemetry verify + detach NAT + snapshots `base-phase1`
6. UC-00 FIM: create C:\lab\critical\secret.txt, modify, expect rule 550; benign read silent; case doc
7. UC-01: deploy local_rules.xml (rule 100010), snapshot `pre-uc01`, Defender off → MiniDump lsass → Defender on, verify EID 10 + alert ×2 runs, benign notepad silent, cleanup + revert; case doc
8. Milestone wrap-up: final G1, evidence exports, exercise log, README state

## Next session — first steps

1. Ask the user: start with **Task 1** (I can execute the file creation solo) or **Task 2** (user installs VirtualBox, downloads ISOs)? User leaned toward starting now; execution is **inline** (they do GUI steps, I drive everything scriptable) — subagents can't do the GUI.
2. If Task 1: create `lab/` files per plan, verify against spec values, commit `docs: add lab scaffolding...`.
3. Keep the todo list mirrored in the session; one task at a time, commit per task.

## Open questions / notes for the user

- DFD.PNG could not be read (no image support). If any DFD detail matters (e.g., edge zone layout), user should paste it as Mermaid/ASCII.
- Spec §13 acceptance criteria were never formally confirmed but are treated as accepted (user approved plan writing after review rounds).
- The exercise-log.md "fill" cells and runbook credential placeholders are intentional local-only fields — never commit real passwords.
