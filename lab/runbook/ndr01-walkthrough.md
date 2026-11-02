# NDR01 walkthrough

Network sensor for Phase 3. Passive Suricata (af-packet) sniffing int-corp; nothing is
injected into the traffic path — detection is observe-only.

Rebuild commands: `lab/runbook/setup.md` §4. Config artifacts: `lab/ndr01/suricata.yaml.additions.txt`
+ `lab/ndr01/local.rules`.

## Decisions & why

- **Passive promiscuous capture, not a bridge.** Task 4 gate G2 proved VirtualBox NIC1
  promisc "allow-all" delivers other hosts' int-corp traffic to the guest, so no bridge/SPAN
  was needed. This is verified (tcpdump) at build time, never assumed.
- **Custom-only ruleset.** `rule-files: [local.rules]` — no Emerging-Threats/ET-Open. Keeps
  the exercise's 7 detections (sids 7000001–7000007) as the sole alert source.
- **`clocksource=acpi_pm` persisted in GRUB.** Same savestate-restore clock-race lesson as
  DC01 (Phase 2); the VM clock is checked (`date`) after every resume.
- **eve.json as the single export.** Types `alert,http,dns,smb,ftp,flow,stats` feed Wazuh
  agent 003, which tails the file (`localfile`, `json`). `stats` events cause harmless
  analysisd "too many fields" errors — ignored, alert events flow fine.
- **2 GB install RAM dropped to 1 GB.** 1 GB froze the installer; 2 GB was used for install
  only and is removed at snapshot `base-phase3` (host RAM ceiling across the 4-guest lab).

## Gotchas

- SYN-only rules 7000003/7000006 warn "disabling for toclient direction" at startup — expected.
- `defrag: yes` under `af-packet` re-triggers a benign "Configuration node 'defrag' redefined"
  warning (a top-level `defrag:` section also exists).
- eve.json is owned by root; read it with `sudo`. It rotates only on restart (not time-based).
- `signature_id` in eve.json is a NUMBER (`7000006`); in Wazuh alerts it is the string `"7000006"`.

## Snapshots

- `base-phase3` — Suricata + agent 003 enrolled, NAT detached, RAM 1 GB, no tests run.
