# NDR01 — the network sensor, explained step by step

> Companion to the terse `ndr01.md` runbook and the command-only `setup.md` §4.
> This doc teaches the *what* and *why* behind each step, so you can read it like a lesson.

## 1. What this box is

**NDR01 is the lab's network eyes — an NDR (Network Detection and Response) sensor.** It runs
**Suricata**, an open-source intrusion detection engine, in *passive* mode: it silently sniffs the
`int-corp` network and raises alerts when it sees attack patterns in the traffic.

Think of it as the CCTV camera watching the office corridors, while the other tools watch the desks:

- SOC01 (the SIEM) sees the *logs* each machine reports about itself.
- NDR01 sees the *network itself* — the actual packets flying between machines, whether or not the
  machines report anything.
- The two are complementary: a compromised machine can lie about its own logs, but it can't hide
  the packets it sends.

| Box | Role |
|---|---|
| **NDR01** (`10.10.10.40`) | Passive Suricata sensor — sniffs `int-corp`, sends alerts to SOC01 |
| **WIN01** (`10.10.10.20`) | Source of most attack traffic (the simulated attacker/victim) |
| **DC01** (`10.10.10.10`) | Target of some attacks (e.g. SMB brute force on port 445) |
| **SOC01** (`10.10.10.5`) | SIEM — receives Suricata alerts via Wazuh agent 003 |

## 2. The big idea: host detection vs network detection

A SIEM like Wazuh is fundamentally **host-based**: agents run *on* each machine and report what that
machine observes about itself. That's powerful, but it has a blind spot — if a box is compromised or
its logs are turned off, it can go quiet.

A network sensor flips the perspective. It doesn't ask machines anything; it just **watches the wire**:

1. **Capture** — grab every packet crossing the network (promiscuous mode).
2. **Decode** — parse protocols (TCP, HTTP, DNS, FTP, SMB, ICMP…) into structured events.
3. **Match** — run rules against those events (a port scan, a beacon, a tunnel).
4. **Alert** — emit a machine-readable event (Suricata writes `eve.json`) for the SIEM to collect.

Key concept — **passive vs inline**: Suricata can sit *inline* (in the traffic path, able to drop
packets, like a firewall) or *passive* (off to the side, only observing). NDR01 is **passive**: it
can *detect* but never *disrupt*. That's the safest choice for a learning lab, and it's why "NDR"
detection is described as observe-only — nothing is ever injected into the traffic path.

## 3. Step 0 — Create the VM

Standard VirtualBox Ubuntu guest — with one crucial difference: the capture NIC is set **promiscuous
"allow-all"**. Without this, a passive sensor only ever sees packets addressed to *itself*, which
would make the whole box useless.

```powershell
VBoxManage createvm --name NDR01 --ostype Ubuntu_64 --register
VBoxManage modifyvm NDR01 --memory 2048 --cpus 1 --vram 16   # 2 GB for install; drop to 1024 in step 6
VBoxManage modifyvm NDR01 --nic1 intnet --intnet1 int-corp --nicpromisc1 allow-all \
  --nic2 nat --natpf2 "ssh,tcp,127.0.0.1,2223,,22"
VBoxManage createmedium disk --filename C:\lab-vms\NDR01\ndr01.vdi --size 15360
VBoxManage storagectl NDR01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach NDR01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\NDR01\ndr01.vdi
VBoxManage storageattach NDR01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\ubuntu-24.04.5-live-server-amd64.iso
VBoxManage startvm NDR01
```

Notes:

- `--nicpromisc1 allow-all` is the whole point. We *proved* this works (gate G2, Task 4) by running
  `tcpdump` on NDR01 and confirming it saw *other* hosts' traffic — never assumed, always verified.
- NIC2 is a NAT adapter for install-time internet, with an SSH port-forward (`127.0.0.1:2223`) so you
  can reach the box from the host during provisioning. It's detached before the snapshot.

## 4. Step 1 — Install Ubuntu

Ubuntu Server 24.04.5, minimal, user `ndradmin`, OpenSSH enabled. Full disk (no LVM — this box
doesn't need the extra disk flexibility, and it's one less thing to go wrong).

## 5. Step 2 — Static IP, and a stable clock

Two things happen here:

```bash
sudo netplan apply   # enp0s3 -> 10.10.10.40/24 on int-corp
```

- The sensor needs a **static IP** on `int-corp` so its Wazuh agent can reach the manager and so you
  can SSH to it (via SOC01 after NAT is removed).

```bash
# persist a stable clocksource (tsc mis-calibrates after savestate restore):
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 clocksource=acpi_pm"/' /etc/default/grub
sudo update-grub
```

- **Clock accuracy matters for a sensor** — Suricata timestamps every event, and those timestamps must
  line up with SOC01's clock for correlation to make sense. The default TSC clocksource mis-calibrates
  after a VM savestate/restore, so we pin `clocksource=acpi_pm`. (This is the same clock-race lesson
  as DC01 in Phase 2 — Linux VMs drift after a resume; always check `date` first.)

## 6. Step 3 — Install Suricata and configure it (the big one)

Suricata ships from the OISF stable PPA (so we get a recent version, 8.0.8):

```bash
sudo add-apt-repository -y ppa:oisf/suricata-stable && sudo apt update
sudo apt install -y suricata jq
```

Then we make four edits to `/etc/suricata/suricata.yaml` (kept in the repo as
`lab/ndr01/suricata.yaml.additions.txt`):

1. **`HOME_NET: "[10.10.10.0/24]"`** — tells Suricata which side of traffic is "ours". Many rules use
   `$HOME_NET`; ours mostly match `any`, but it's good hygiene to declare the lab network.
2. **af-packet capture on `enp0s3`** — Suricata reads raw frames straight from the NIC (kernel
   bypass) in passive mode, with `defrag: yes` so fragmented packets are reassembled before matching.
3. **A custom-only ruleset** — `rule-files: [local.rules]`. No Emerging-Threats/ET-Open feed, so the
   exercise's 7 detections (SIDs 7000001–7000007) are the *sole* alert source. That keeps tests
   deterministic: any alert is attributable to our rules.
4. **`eve.json` output types** — Suricata writes every event (alert, http, dns, smb, ftp, flow, stats)
   as JSON lines to `/var/log/suricata/eve.json`. This single file is the export the Wazuh agent reads.

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml   # config test before restart
sudo systemctl enable --now suricata
```

## 7. Step 4 — Point the Wazuh agent at eve.json

NDR01 enrolls as Wazuh **agent 003**. Instead of reading a host log, its job is to *tail* the Suricata
event file:

```bash
sudo WAZUH_MANAGER='10.10.10.5' WAZUH_AGENT_NAME='ndr01' dpkg -i ./wazuh-agent_4.14.8-1_amd64.deb
# append before </ossec_config> in /var/ossec/etc/ossec.conf:
#   <localfile><location>/var/log/suricata/eve.json</location><log_format>json</log_format></localfile>
sudo systemctl restart wazuh-agent
```

So the pipeline is: **packets → Suricata → eve.json → Wazuh agent 003 → SOC01 manager → Wazuh rules
→ alerts.** The NDR sensor doesn't run its own alerting logic in Wazuh — it just forwards Suricata's
structured alerts, and Wazuh's *rules* (on SOC01) decide what becomes an alert in the dashboard.

## 8. Step 5 — Isolate, drop RAM, snapshot

```powershell
VBoxManage controlvm NDR01 acpipowerbutton
VBoxManage modifyvm NDR01 --memory 1024        # drop the install-time 2 GB back to 1 GB
VBoxManage modifyvm NDR01 --nic2 none          # detach NAT (removes the 2223 forward)
VBoxManage snapshot NDR01 take base-phase3
VBoxManage startvm NDR01 --type headless
```

- The 2 GB RAM was only to survive the installer (1 GB froze during install). After install we drop
  back to 1 GB to respect the host's RAM ceiling across all four guests.
- Detaching NAT **removes the `127.0.0.1:2223` forward** — after this, the only way to reach NDR01 is
  by hopping through SOC01: `ssh socadmin@10.10.30.10` then `ssh ndradmin@10.10.10.40`.
- `base-phase3` = Suricata + agent 003 enrolled, NAT detached, RAM 1 GB, **no tests run yet** (clean
  starting point to roll back to).

## 9. How a detection flows (recap)

```
[packets on int-corp] --promiscuous--> af-packet (enp0s3) --> Suricata (decode + rule match)
                                                                  |
                                                                  v
                                                     eve.json (JSON lines: alert, http, dns, ...)
                                                                  |
                                                                  v
                                                     Wazuh agent 003 (tails eve.json)
                                                                  |
                                                                  v  :1514
                                                     SOC01 manager -> Wazuh rules 100040..100046
                                                                  |
                                                                  v
                                                     dashboard alert (rule id + severity)
```

Two ideas worth remembering:

- **Suricata decides *what happened*; Wazuh decides *what to alert on*.** Suricata's rule
  (`sid:700000N`) triggers a raw detection event with a `signature_id`. A separate Wazuh rule
  (`10004N`) on SOC01 matches that `signature_id` and assigns a severity level + MITRE technique.
- **`eve.json` is the ground truth for the sensor**, just like `alerts.json` is for the SIEM. It's
  owned by root (read with `sudo`), and it only rotates on Suricata restart (not time-based).

## 10. The detections this powers

Seven Suricata rules (`lab/ndr01/local.rules`) mapped to seven Wazuh rules (`lab/soc01/local_rules.xml`).
Each Wazuh rule is a **child of the Suricata chain** (`<if_sid>86601</if_sid>`) and keys on the
Suricata `signature_id`:

| Suricata SID | Wazuh rule | Detects | Technique |
|---|---|---|---|
| 7000001 | 100040 (lvl 8) | canary: HTTP `User-Agent` = `lab-ndr-test` | (pipeline check) |
| 7000002 | 100041 (lvl 10) | TCP port scan (20 SYNs / 5 s from one source) | T1046 |
| 7000003 | 100042 (lvl 12) | beaconing (5 SYNs to port 4444 / 60 s) | T1571 |
| 7000004 | 100043 (lvl 12) | ICMP tunnel (echo request with payload > 1000 bytes) | T1095 |
| 7000005 | 100044 (lvl 12) | DNS anomaly (query name ≥ 40 chars) | T1071.004 |
| 7000006 | 100045 (lvl 12) | SMB brute force (10 SYNs to 445 / 30 s) | T1110 |
| 7000007 | 100046 (lvl 10) | cleartext FTP (both `USER` and `PASS` seen) | T1040 |

What each Suricata rule means, in plain words:

- **7000001 (marker)** — an HTTP request whose `User-Agent` header contains the string `lab-ndr-test`.
  This is a *canary*: it's not an attack, it's a smoke test proving the entire NDR pipeline works
  end-to-end before we trust the other six rules.
- **7000002 (port scan)** — `flags:S` matches only SYN packets (a connection attempt, not an
  established session), and `threshold:type threshold, track by_src, count 20, seconds 5` fires when
  one source sends 20 SYN attempts within 5 seconds. That's the classic "scanning for open ports" shape.
- **7000003 (beaconing)** — SYN packets to **port 4444** (a non-standard port, commonly used by
  Metasploit/Cobalt Strike listeners). A slow trickle (5 per 60 s) is the *heartbeat* shape of
  command-and-control, as opposed to a burst.
- **7000004 (ICMP tunnel)** — ICMP *echo request* (`itype:8`, i.e. ping) with a data payload larger
  than 1000 bytes (`dsize:>1000`). Normal pings are tiny; a huge payload suggests data is being
  smuggled inside ICMP.
- **7000005 (DNS anomaly)** — a DNS *query* name 40+ characters long (`pcre:"/^.{40,}$/"`). Legit
  domain names are short; long names suggest data encoded into the subdomain (DNS tunneling).
- **7000006 (SMB brute force)** — SYN packets to **port 445** (SMB), 10 in 30 s. A credential-guessing
  storm against a Windows box or the Samba DC.
- **7000007 (cleartext FTP)** — any FTP session where both `USER ` and `PASS ` appear. FTP sends
  credentials in plaintext; seeing them means a password was transmitted unencrypted (policy violation).

## 11. Gotchas we hit (the interesting lessons)

- **`signature_id` is a NUMBER in eve.json but a STRING in Wazuh — the root-cause bug.** Suricata
  writes `"signature_id":7000006`; after Wazuh's decoder runs, the alert field is the *string*
  `"7000006"`. The first version of the Wazuh rules keyed on the wrong field and never matched. The
  fix: `<field name="alert.signature_id" type="pcre2">^700000N$</field>` (dotted path, no `data.`
  prefix). This was the commit `3ded236` fix.
- **`if_sid`/`field` are child elements, not attributes** — the same XML trap as SOC01's rules. A rule
  that doesn't declare `if_sid` as a child silently never fires.
- **SYN-only rules warn at startup.** Rules 7000003/7000006 match `flags:S` only, so Suricata logs
  "disabling for toclient direction" — expected, they only care about connection attempts.
- **`defrag: yes` under `af-packet` re-triggers a benign warning** ("Configuration node 'defrag'
  redefined") because a top-level `defrag:` section also exists. Harmless; the config still loads.
- **`stats` events cause "too many fields" errors in Wazuh analysisd.** The `stats` eve type emits a
  huge object every ~8 s; analysisd grumbles but *alert* events flow fine — safe to ignore.
- **`eve.json` is root-owned and only rotates on restart.** Read it with `sudo`. If you need to search
  history, it accumulates until Suricata restarts.
- **Reachability after isolation.** Once NAT is detached the `2223` forward is gone — reach NDR01 only
  via the SOC01 hop. If that SSH times out right after a headless boot, the 1 GB box may just still be
  booting; give it ~30 s and retry.

## 12. How to test it yourself

1. From SOC01, confirm NDR01 is up and the agent connected:
   ```bash
   ssh ndradmin@10.10.10.40 "date; systemctl is-active suricata wazuh-agent"
   sudo /var/ossec/bin/agent_control -l          # agent 003 ndr01 active
   ```
2. Fire the **marker** (proves the whole pipeline), from WIN01:
   ```powershell
   Invoke-WebRequest -Uri http://10.10.10.5 -Headers @{ "User-Agent" = "lab-ndr-test" }
   ```
   → dashboard should show rule **100040** (`LAB NDR: marker - lab-ndr-test User-Agent`).
3. Fire a **port scan**, from WIN01 (script in `lab/ndr01/win01/port-scan.ps1`) → rule **100041**.
4. Fire an **ICMP tunnel**, from WIN01:
   ```cmd
   ping -n 3 -l 1200 10.10.10.5
   ```
   → rule **100043**.
5. For each attack, also run its **benign control** (a single SYN, a normal `nslookup`, a short ping,
   one successful login, a normal `ftp` without credentials) and confirm it stays **silent** — that's
   what proves the rule isn't just crying wolf.

## 13. Snapshots

- `base-phase3` — Suricata + agent 003 enrolled, NAT detached, RAM 1 GB, no tests run.
