# Replicate and test the lab

Step-by-step checklist for rebuilding this lab on another host and proving that each
detection works. `runbook/setup.md` is the command reference; this file is the order of
operations and the test plan.

Read first: [repository README](../../README.md) · [`../network/networks.md`](../network/networks.md) ·
[architecture spec](../../docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md)

---

## 0. Prerequisites checklist

- [ ] Windows host, 16 GB RAM, 4+ cores, ~120 GB free disk, CPU virtualisation enabled
- [ ] VirtualBox 7.2.20 + Extension Pack installed **elevated**
- [ ] Memory Integrity off; `bcdedit /set hypervisorlaunchtype off` (elevated) + reboot
- [ ] Host-only adapter `VirtualBox Host-Only Ethernet Adapter #2` = `10.10.30.1/24`, DHCP off
- [ ] ISOs in `C:\iso\`: Ubuntu 24.04.5 live-server (amd64), Windows 11 Enterprise Eval (x64)
- [ ] PuTTY (`plink`, `pscp`) installed
- [ ] Free VirusTotal API key (UC-13 only)
- [ ] Credentials file created from the template:
      copy `lab/runbook/.local-credentials.example.md` → `lab/runbook/.local-credentials.md`
      (gitignored; never commit it)

Verify the hypervisor and network before building:

```powershell
VBoxManage --version
VBoxManage list extpacks
VBoxManage list hostonlyifs   # expect 10.10.30.1/24 on Adapter #2
```

---

## 1. Build order

Build and snapshot one phase at a time. Do not start the next phase until its smoke test
passes.

| Phase | Build (setup.md) | Guests | Snapshot after build | Smoke test |
|---|---|---|---|---|
| 1 | §1 SOC01, §2 WIN01 | SOC01 + WIN01 | `SOC01: base-soc01`, `WIN01: base-phase1` | UC-00, UC-01 |
| 2 | §3 DC01 | + DC01 | `DC01: base-phase2` | UC-03, UC-04, UC-05 |
| 3 | §4 NDR01 | SOC01 + WIN01 + NDR01 | `NDR01: base-phase3` | UC-06 … UC-12 |
| 4 | §5 SOAR01 | SOC01 + WIN01 + SOAR01 | `SOAR01: base-phase4` | UC-13 |

Deploy the custom rules to SOC01 once (all phases use the same file):

```powershell
# host → SOC01
& "C:\Program Files\PuTTY\pscp.exe" -batch `
  -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw <SOCADMIN_PW> `
  lab\soc01\local_rules.xml socadmin@10.10.30.10:/tmp/local_rules.xml
```

```bash
# SOC01
sudo install -o root -g wazuh -m 640 /tmp/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-control restart
```

---

## 2. Power-on discipline

| Scenario | Guests | RAM |
|---|---|---|
| S1 | SOC01 + WIN01 | 9 GB |
| S2 | SOC01 + WIN01 + DC01 | 11 GB |
| S3 | SOC01 + WIN01 + NDR01 | 10 GB |
| S4 | SOC01 + WIN01 + SOAR01 | 11 GB |

- Never exceed 11 GB of running guests.
- Boot SOC01 first; wait for the dashboard/API before starting the others.
- Shut down in reverse order (endpoint/DC/sensor first, SIEM last).
- DC01 and NDR01 are never on at the same time as SOAR01 in the documented scenarios.

Confirm the WIN01 agent is connected before running any test:

```bash
# SOC01
sudo /var/ossec/bin/agent_control -l
```

Expected: agent `001` (win01) `Active`. Phase 2 checks agent `002` (dc01); phase 3 checks
agent `003` (ndr01).

---

## 3. Test matrix

Run the procedure in the linked case note, then verify the expected rule fires and the
benign control stays silent.

| Use case | Scenario | Expected rule | Benign control |
|---|---|---|---|
| UC-00 FIM add/modify/delete | S1 | `550` / `553` / `554` (built-in) | reading a file → no alert |
| UC-01 LSASS access | S1 | `100010` ×2 (0x1410 + 0x1fffff) | Notepad → no `100010` |
| UC-02 PowerShell `-enc` | S1 | `100020` | plain `-Command` → no `100020` |
| UC-03 failed logons / burst / success | S2 | `100029` / `100030` / `100031` | single failed logon → no `100030` |
| UC-03b privileged group change | S2 | `100032` | read-only `samba-tool` → no `100032` |
| UC-04 Kerberoasting | S2 | `100033` | normal TGS request → no `100033` |
| UC-05 AS-REP roasting | S2 | `100034` | normal Kerberos → no `100034` |
| UC-06 NDR marker | S3 | `100040` | default user-agent → silent |
| UC-07 port scan | S3 | `100041` | single SYN → silent |
| UC-08 beaconing | S3 | `100042` | single connection → silent |
| UC-09 ICMP tunnel | S3 | `100043` | single ping → silent |
| UC-10 DNS anomaly | S3 | `100044` | `nslookup` → silent |
| UC-11 SMB brute force | S3 | `100045` | single logon → silent |
| UC-12 cleartext FTP | S3 | `100046` | benign traffic → silent |
| UC-13 DNS → VirusTotal → SOAR | S4 | `100047` | `example.com` query → no `100047` |

Case notes: [`../cases/`](../cases/). Simulated-attack scripts for phase 3 live in
[`../ndr01/win01/`](../ndr01/win01/).

### Verify an alert

In the Wazuh dashboard (host browser → `https://10.10.30.10`):

1. Open **Discover** and filter `rule.id: 100010` (or the rule for your case).
2. Confirm the timestamp, agent (`win01`/`dc01`/`ndr01`), and the evidence fields used by
   the rule (e.g. `win.eventdata.queryName` for UC-13).
3. Record expected vs observed in [`../cases/exercise-log.md`](../cases/exercise-log.md).
4. Export evidence as described in [`../evidence/README.md`](../evidence/README.md).

### UC-13 specifics

UC-13 needs the Internet only for the VirusTotal lookup:

1. Power off SOAR01, then: `VBoxManage modifyvm SOAR01 --nic2 nat`.
2. Boot S4 (SOC01, WIN01, SOAR01) and wait for the WIN01 agent to be `Active`.
3. On WIN01 (elevated): disable Defender real-time **for the test window only**; reboot if
   the test domain is stuck in the DNS negative cache.
4. Run the DNS lookup from the case note; confirm `100047` in Wazuh and the three files in
   `/srv/soar/` on SOAR01.
5. Afterwards: power off SOAR01 and run `VBoxManage modifyvm SOAR01 --nic2 none`; re-enable
   Defender.

Known pitfalls (DNS negative cache, Defender blocking the test domain, VirusTotal 404 for
unknown domains, n8n 2.x "Publish") are listed in
[`../cases/lessons-learned.md`](../cases/lessons-learned.md).

---

## 4. Reset between runs

Use snapshots; do not repair a dirty guest by hand.

```powershell
VBoxManage snapshot WIN01 list
VBoxManage snapshot WIN01 restore base-phase1   # VM must be off
```

Rules of thumb:

- Revert WIN01 after tests that change security settings (Defender, LSA protection).
- Revert any guest before rebuilding a later phase on top of it.
- Keep phase base snapshots untouched; create dated snapshots for long investigations.

---

## 5. Record the result

For each run:

- [ ] Expected rule fired (or the benign control stayed silent)
- [ ] Alert has timestamp, agent, and the fields the rule depends on
- [ ] Evidence exported to `lab/evidence/` (small, non-sensitive)
- [ ] Row added to `lab/cases/exercise-log.md`
- [ ] Any deviation documented in the case note's troubleshooting section

When all rows in the test matrix pass on your host, the lab is reproduced.
