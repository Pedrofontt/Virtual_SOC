# NDR01 runbook

Build: Ubuntu Server 24.04.5 minimal, 1 vCPU, 1 GB RAM (2 GB during install only), 15 GB VDI.
NIC: int-corp static `10.10.10.40/24` with `--nicpromisc1 allow-all`; NAT temporary (install-time only,
ssh forward `127.0.0.1:2223`, detached before snapshot). Host key
`SHA256:RcRl+dhZx3qks9o3j6HxnS32ZU6QGcfWIGCI1ylXHxA`. Reach from SOC01: `ssh ndradmin@10.10.10.40`.

Local credentials (DO NOT COMMIT — see `lab/runbook/.local-credentials.md`): `ndradmin`.

## Provision (Suricata 8.0.8 passive NDR)

- Suricata 8.0.8 from OISF `ppa:oisf/suricata-stable`. Passive sensor — observe-only, nothing inline.
- `af-packet` capture on `enp0s3` (int-corp), `defrag: yes`, mmap + tpacket-v3, flow-cluster.
- `HOME_NET: "[10.10.10.0/24]"`.
- Custom-only ruleset: `rule-files: [local.rules]` (no ET/ET-Open) — sids `7000001-7000007` are the
  sole alert source.
- `eve.json` output types: `alert, http, dns, smb, ftp, flow, stats` (`/var/log/suricata/eve.json`).
- `clocksource=acpi_pm` persisted in GRUB (tsc mis-calibrates after savestate restore).
- Config artifacts: `lab/ndr01/suricata.yaml.additions.txt` + `lab/ndr01/local.rules`.
- Snapshot `base-phase3` (UUID 27c9406e) taken after isolation (NAT detached, RAM dropped to 1 GB).

## Detection chain (Suricata -> Wazuh)

Suricata raises a raw alert with a `signature_id`; Wazuh rules on SOC01 map it to a severity + technique:

| SID | Wazuh rule | Detects | Technique |
|---|---|---|---|
| 7000001 | 100040 (lvl 8) | HTTP `User-Agent` = `lab-ndr-test` canary | (pipeline check) |
| 7000002 | 100041 (lvl 10) | TCP port scan (20 SYNs / 5 s) | T1046 |
| 7000003 | 100042 (lvl 12) | beaconing (5 SYNs to 4444 / 60 s) | T1571 |
| 7000004 | 100043 (lvl 12) | ICMP tunnel (echo, dsize > 1000) | T1095 |
| 7000005 | 100044 (lvl 12) | DNS anomaly (query ≥ 40 chars) | T1071.004 |
| 7000006 | 100045 (lvl 12) | SMB brute force (10 SYNs to 445 / 30 s) | T1110 |
| 7000007 | 100046 (lvl 10) | cleartext FTP (`USER` + `PASS`) | T1040 |

## Wazuh agent

- Agent 4.14.8 installed (host -> SOC01 -> NDR01 chain), enrolled as agent `003` (name `ndr01`).
- `ossec.conf` addition: localfile `/var/log/suricata/eve.json` (`log_format=json`) — the agent tails
  Suricata's export, nothing more.
- Wazuh rules `100040-100046` (on SOC01, `lab/soc01/local_rules.xml`) are children of the Suricata
  chain (`<if_sid>86601</if_sid>`), keyed on `<field name="alert.signature_id" type="pcre2">^700000N$</field>`.

## Gotchas

- **`signature_id` is a NUMBER in `eve.json` but a STRING in Wazuh alerts** — the root-cause bug. Field
  name is `alert.signature_id` (dotted path, no `data.` prefix). Fixed in commit `3ded236`.
- **SYN-only rules warn at startup** (`7000003`/`7000006`): "disabling for toclient direction" — expected.
- **`defrag: yes` under `af-packet`** re-triggers a benign "Configuration node 'defrag' redefined" warning.
- **`stats` events** cause analysisd "too many fields" errors every ~8 s — harmless, alert events flow fine.
- **`eve.json`** is root-owned (read with `sudo`) and rotates only on Suricata restart, not time-based.
- **Clock skew** (recurring): check `date` after any resume; restart Suricata if the clock jumped.
- **Reachability** — once NAT is detached the `2223` forward is gone; NDR01 is reachable only via the
  SOC01 hop. Right after a headless boot, give the 1 GB box ~30 s before SSH.

## Snapshot layout

- `base-phase3` (27c9406e) — Suricata + agent 003 enrolled, NAT detached, RAM 1 GB, no tests run.
