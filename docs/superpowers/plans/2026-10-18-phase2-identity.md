# Phase 2 Identity Detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up DC01 (Samba AD DC, `corp.lab`), join WIN01, and build three user-authored Wazuh detections: UC-03 logon burst + group change (exit gate), UC-04 Kerberoasting, UC-05 AS-REP roasting.

**Architecture:** Wazuh agent on DC01 ships Samba JSON auth audit + `log.samba` to the existing SOC01 manager; FIM watches `sam.ldb`. Four new custom rules (100029–100034) in `local_rules.xml`, authored by the user via the dashboard UI (same workflow as rule 100020). Impacket runs offline from SOC01 for UC-04/05.

**Tech Stack:** VirtualBox 7.2.20, Ubuntu Server 24.04.5 (Samba 4.19 AD DC), Wazuh 4.14.8, impacket, plink/pscp, PowerShell 5.1.

**Spec:** `docs/superpowers/specs/2026-10-18-phase2-identity-design.md`

## Global Constraints

- Power-on scenario **S2 only**: SOC01 (5 GB) + WIN01 (4 GB) + DC01 (2 GB) = 11 GB ceiling. No other guest. If the host swaps: WIN01 to console session + close host browser during DC provisioning.
- User runs all attack simulations; assistant builds infrastructure and verifies (AGENTS.md rule).
- Custom rules are edited ONLY via the dashboard UI by the user, then synced back to the repo (repo = source of truth) and committed. No raw quote chars in UI regex text — use `\x22`/`\x27` (API error 1113).
- SOC01 stays offline (NAT detached). Impacket installed from wheels via pscp. Temporary NAT is a documented exception only.
- Secrets never in git: passwords go only into `lab/runbook/.local-credentials.md` (gitignored).
- Every detection gets: case doc + exercise-log rows + lessons + evidence screenshot + commit (house lifecycle).
- Remote control of DC01 = SSH hop: host → plink SOC01 (10.10.30.10) → `ssh dcadmin@10.10.10.10`. Host cannot reach int-corp directly.
- Verify ruleset changes with `sudo systemctl restart wazuh-manager` + API check (dashboard saves sometimes skip the reload log line).
- Grep self-match gotcha: `sudo grep` generates rule-5402 alerts containing the grep command. Always pipe `grep -v COMMAND` when grepping alerts.json for rule hits, and grep the description phrase, not the rule id.
- New lab passwords (record in `.local-credentials.md`, do NOT commit): DC01 local `dcadmin/dcadmin123`; domain `Administrator/DomAdmin!lab123`; `svc-sql/SvcSQL!lab123` (SPN); `victim/Victim!lab123` (no preauth); `attacker/Attacker!lab123`.

---

### Task 0: Snapshot refresh to base-phase1-fixed

**Files:**
- Modify: `docs/superpowers/session.md` (state update)
- No repo file for snapshots themselves (host state).

**Interfaces:**
- Produces: rollback point `base-phase1-fixed` on SOC01 and WIN01 (includes Task 6 FIM decoder fix + rules 100010/100020). Old `base-phase1` snapshots deleted to reclaim host disk.

- [ ] **Step 1: Shut down both VMs gracefully**

```powershell
VBoxManage controlvm WIN01 acpipowerbutton   # can take 10+ min (Windows updates at shutdown)
VBoxManage controlvm SOC01 acpipowerbutton
# Poll until both report powered off:
VBoxManage showvminfo WIN01 --machinereadable | Select-String "VMState="
VBoxManage showvminfo SOC01 --machinereadable | Select-String "VMState="
```
Expected: `VMState="poweroff"` for both.

- [ ] **Step 2: Take new snapshots and delete the old ones**

```powershell
VBoxManage snapshot SOC01 take base-phase1-fixed
VBoxManage snapshot WIN01 take base-phase1-fixed
VBoxManage snapshot SOC01 delete base-phase1
VBoxManage snapshot WIN01 delete base-phase1
```
Expected: commands print `0%...100%` and finish without error. `VBoxManage snapshot <VM> list` shows only `base-phase1-fixed` (plus `pre-uc01` on WIN01).

- [ ] **Step 3: Boot both VMs and verify health**

```powershell
VBoxManage startvm SOC01 --type headless
VBoxManage startvm WIN01 --type headless
Start-Sleep 120
& "C:\Program Files\PuTTY\plink.exe" -batch -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 socadmin@10.10.30.10 "echo socadmin123 | sudo -S systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard 2>/dev/null"
```
Expected: three `active` lines. (WIN01 agent status checked in Task 9; it has no console access from host.)

- [ ] **Step 4: Update session state and commit**

Edit `docs/superpowers/session.md`: note snapshots refreshed to `base-phase1-fixed`, Phase 2 plan started.
```powershell
git add docs/superpowers/session.md
git commit -m "chore: snapshot refresh to base-phase1-fixed, Phase 2 kickoff"
```

---

### Task 1: Create DC01 VM and install Ubuntu (interactive, user)

**Files:**
- Create: none in repo yet (VM state on host).
- Modify: `lab/network/networks.md` (DC01 row already exists at line 19 — verify, no change needed).

**Interfaces:**
- Produces: DC01 VM with Ubuntu 24.04.5, user `dcadmin`, OpenSSH server, static IP `10.10.10.10/24` (gw `10.10.10.5`, dns `127.0.0.1`), NICs `int-corp` (nic1) + NAT (nic2).

- [ ] **Step 1: Create VM, disk, and attach ISO (host)**

```powershell
VBoxManage createvm --name DC01 --ostype Ubuntu_64 --register
VBoxManage modifyvm DC01 --memory 2048 --cpus 1 --vram 16
VBoxManage modifyvm DC01 --nic1 intnet --intnet1 int-corp --nic2 nat
VBoxManage createmedium disk --filename C:\lab-vms\DC01\dc01.vdi --size 20480
VBoxManage storagectl DC01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach DC01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\DC01\dc01.vdi
VBoxManage storageattach DC01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\ubuntu-24.04.5-live-server-amd64.iso
VBoxManage startvm DC01
```
Expected: window opens with the Ubuntu installer.

- [ ] **Step 2: Interactive install (user, ~15 min)**

Choices (must match exactly — everything downstream depends on them):
- Language: English; installer update: Continue without updating.
- Guided storage: use entire disk, default LVM layout (20 GB).
- Profile: name `dcadmin`, server name `dc01`, username `dcadmin`, password `dcadmin123`.
- Ubuntu Pro: skip.
- **OpenSSH server: check Install OpenSSH server.**
- Third-party packages: skip.
- Static IP during install OR after (next step) — pick after via netplan.

- [ ] **Step 3: Set static IP (netplan) and finish base config**

In the installer shell or after first SSH from SOC01 (see Step 4), on DC01:
```bash
sudo nano /etc/netplan/50-cloud-init.yaml   # or 00-installer-config.yaml
# enp0s3 (int-corp):
#   dhcp4: no
#   addresses: [10.10.10.10/24]
#   routes: [{to: default, via: 10.10.10.5}]
#   nameservers: {addresses: [127.0.0.1]}
sudo netplan apply
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv && sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
ip -4 addr show enp0s3
```
Expected: `inet 10.10.10.10/24` on enp0s3. LVM resize succeeds (Ubuntu LVM gives `/` half the disk — same pitfall as SOC01).

- [ ] **Step 4: Verify SSH hop works**

From host:
```powershell
& "C:\Program Files\PuTTY\plink.exe" -batch -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 socadmin@10.10.30.10 "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes dcadmin@10.10.10.10 'hostname; date'"
```
Expected: prompts once for `dcadmin` password is NOT possible with BatchMode — run interactively the first time:
```powershell
& "C:\Program Files\PuTTY\plink.exe" -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 socadmin@10.10.30.10 "ssh dcadmin@10.10.10.10 'hostname'"
```
Expected: `dc01` (accept host key, enter `dcadmin123` when prompted).

- [ ] **Step 5: Record DC01 credentials in the secrets file**

Append to `lab/runbook/.local-credentials.md` (gitignored):
```markdown
# DC01
DC01 SSH: dcadmin / dcadmin123  (10.10.10.10, reachable only via SOC01 hop)
Domain Administrator: Administrator / DomAdmin!lab123
svc-sql / SvcSQL!lab123        (SPN MSSQLSvc/dc01.corp.lab:1433)
victim / Victim!lab123         (UF_DONT_REQUIRE_PREAUTH)
attacker / Attacker!lab123
```
No commit for this file (gitignored).

---

### Task 2: Provision Samba AD DC `corp.lab`, audit logging, isolate, snapshot

**Files:**
- Modify: `lab/network/networks.md` (confirm DC01 row: 10.10.10.10, Samba AD DC + DNS, corp.lab)
- Create: `lab/dc01/rsyslog-samba-audit.conf` (repo copy of the rsyslog rule)
- Create: `lab/dc01/smb.conf.additions.txt` (repo copy of the audit-related smb.conf lines)

**Interfaces:**
- Produces: working domain `CORP` (realm `CORP.LAB`), DNS on DC01, accounts `svc-sql` (SPN), `victim` (no preauth), `attacker`; auth events as JSON in `/var/log/samba/audit.json`; KDC logs in `/var/log/samba/log.samba`; NAT detached; snapshot `base-phase2`.

- [ ] **Step 1: Install Samba AD DC stack (DC01, NAT still attached)**

```bash
sudo apt update && sudo apt install -y samba smbclient krb5-user winbind net-tools dnsutils
```
Expected: no errors; `samba --version` prints `4.19.x`.

- [ ] **Step 2: Provision the domain**

```bash
sudo samba-tool domain provision --use-rfc2307 --interactive
```
Answers: Realm `CORP.LAB`, Domain `CORP`, Server Role `dc`, DNS backend `SAMBA_INTERNAL`, DNS forwarder IP: leave empty, Administrator password `DomAdmin!lab123` (confirm).
Expected: `A Kerberos configuration suitable for Samba AD has been generated at /var/lib/samba/private/krb5.conf`.

```bash
sudo systemctl unmask samba-ad-dc
sudo systemctl enable --now samba-ad-dc
sudo systemctl is-active samba-ad-dc
```
Expected: `active`.

- [ ] **Step 3: DNS sanity check**

```bash
sudo resolvectl status | grep -A2 "DNS Server"
nslookup dc01.corp.lab 127.0.0.1
```
Expected: DC01 uses 127.0.0.1; `dc01.corp.lab` resolves to `10.10.10.10`.

- [ ] **Step 4: Create lab accounts and SPN**

```bash
sudo samba-tool user create attacker 'Attacker!lab123'
sudo samba-tool user create svc-sql 'SvcSQL!lab123'
sudo samba-tool spn add MSSQLSvc/dc01.corp.lab:1433 svc-sql
sudo samba-tool user create victim 'Victim!lab123'
sudo samba-tool user show victim | grep -i userAccountControl
```
Expected: three `User 'X' created successfully` lines; SPN added; victim UAC shows `512` (normal account).

- [ ] **Step 5: Set UF_DONT_REQUIRE_PREAUTH on victim (AS-REP target)**

```bash
sudo ldbmodify -H /var/lib/samba/private/sam.ldb <<'EOF'
dn: CN=victim,CN=Users,DC=corp,DC=lab
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
EOF
sudo samba-tool user show victim | grep -i userAccountControl
```
Expected: `4194816` (512 + 4194304 DONT_REQUIRE_PREAUTH). If the value differs (provision defaults changed), compute: `<shown value> + 4194304` and re-run with that sum.

- [ ] **Step 6: Enable Samba auth JSON audit + KDC logging**

Edit `/etc/samba/smb.conf`, `[global]` section, append:
```ini
log level = 1 auth_json_audit:3 kdc:10
logging = syslog
log file = /var/log/samba/log.samba
```
(`kdc:10` also writes TGS-REQ/AS-REP lines to `log.samba` — the text fallback for UC-04/05. If Samba 4.19 accepts `kdc_json_audit:5`, capture step may prefer it; text fallback is guaranteed.)

```bash
sudo systemctl restart samba-ad-dc && sudo systemctl is-active samba-ad-dc
sudo tail -5 /var/log/samba/log.samba
```
Expected: `active`; log.samba shows startup lines with timestamps in `[2026/10/18 ...]` format.

- [ ] **Step 7: Route samba syslog JSON to a dedicated file**

On DC01 create `/etc/rsyslog.d/30-samba-audit.conf`:
```
:programname, isequal, "samba" /var/log/samba/audit.json
& stop
```
```bash
sudo systemctl restart rsyslog && sudo systemctl is-active rsyslog
sudo chmod 644 /var/log/samba/audit.json
```
Expected: `active`; `/var/log/samba/audit.json` exists (empty is fine until first auth).
NOTE: if `programname` is not exactly `samba` (check with `grep samba /var/log/syslog | tail -3`), change the rule to `:msg, contains, "\"type\":\"Authentication\"" /var/log/samba/audit.json` and re-verify in Task 5.

- [ ] **Step 8: Copy Wazuh agent deb from SOC01 (while both reachable)**

From SOC01 (check first):
```bash
ls /var/ossec/packages/
```
Expected: `wazuh-agent-4.14.8-1.x86_64.deb` (or similar). If missing: on DC01 (NAT still on): `curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.8-1_amd64.deb` (fallback).
Copy:
```bash
# on SOC01:
scp /var/ossec/packages/wazuh-agent*.deb dcadmin@10.10.10.10:/tmp/
```
Expected: file transfers; on DC01 `ls /tmp/wazuh-agent*.deb` shows it.

- [ ] **Step 9: Save repo copies of config artifacts**

Write the rsyslog rule and the smb.conf additions into `lab/dc01/` (repo), commit:
```powershell
git add lab/dc01/ lab/network/networks.md
git commit -m "feat: DC01 provisioned as Samba AD DC corp.lab (config artifacts)"
```

- [ ] **Step 10: Isolate and snapshot**

```powershell
VBoxManage controlvm DC01 acpipowerbutton
# wait for poweroff:
VBoxManage showvminfo DC01 --machinereadable | Select-String "VMState="
VBoxManage modifyvm DC01 --nic2 none
VBoxManage snapshot DC01 take base-phase2
VBoxManage startvm DC01 --type headless
```
Expected: `VMState="poweroff"`; snapshot listed; VM boots headless.

---

### Task 3: SOC01 — impacket offline install + /etc/hosts

**Files:**
- Modify: `lab/runbook/soc01.md` (document the offline impacket procedure)

**Interfaces:**
- Produces: impacket importable on SOC01 (no internet), `GetUserSPNs.py` + `GetNPUsers.py` runnable; `dc01.corp.lab` resolvable from SOC01.

- [ ] **Step 1: Download Linux wheels on the host**

```powershell
py -m pip download --dest C:\lab-vms\impacket-wheels --platform manylinux_2_17_x86_64 --python-version 3.12 --implementation cp --abi cp312 --only-binary=:all: impacket ldapdomaindump
Get-ChildItem C:\lab-vms\impacket-wheels
```
Expected: ~10–15 `.whl` files (impacket, ldap3, ldapdomaindump, pyasn1, pycryptodomex, dnspython, future, six, ...). If host lacks Python: `winget install -e --id Python.Python.3.12` first.
If `pip download` fails on abi/format errors: documented fallback — re-attach SOC01 NAT (`VBoxManage modifyvm SOC01 --nic3 nat`), `sudo pip3 install impacket ldapdomaindump --break-system-packages`, verify, then detach NAT and log the exception in the exercise log.

- [ ] **Step 2: Transfer wheels and install on SOC01**

```powershell
& "C:\Program Files\PuTTY\pscp.exe" -batch -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 C:\lab-vms\impacket-wheels\*.whl socadmin@10.10.30.10:/tmp/wheels/
& "C:\Program Files\PuTTY\plink.exe" -batch -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 socadmin@10.10.30.10 "sudo pip3 install --break-system-packages --no-index --find-links /tmp/wheels/ impacket ldapdomaindump"
```
Expected: `Successfully installed impacket-0.x ...`.

- [ ] **Step 3: Verify impacket and add hosts entry**

```bash
# on SOC01:
python3 -c "import impacket; print(impacket.__version__)"
echo "10.10.10.10 dc01.corp.lab dc01" | sudo tee -a /etc/hosts
getent hosts dc01.corp.lab
```
Expected: version printed; `10.10.10.10  dc01.corp.lab dc01`.

- [ ] **Step 4: Document and commit**

Add the offline-wheel procedure to `lab/runbook/soc01.md`, then:
```powershell
git add lab/runbook/soc01.md
git commit -m "docs: SOC01 offline impacket install procedure"
```

---

### Task 4: DC01 Wazuh agent — enroll, config, verify

**Files:**
- Create: `lab/dc01/ossec.conf.additions.xml` (localfile + syscheck additions, repo copy)

**Interfaces:**
- Produces: agent `dc01` connected to manager, shipping `/var/log/samba/audit.json` (json) and `/var/log/samba/log.samba` (syslog), FIM realtime on `/var/lib/samba/private/sam.ldb`.

- [ ] **Step 1: Check manager enrollment settings (SOC01)**

```bash
sudo grep -A6 "<auth>" /var/ossec/etc/ossec.conf
```
Expected: `<use_password>no</use_password>` (AIO default — WIN01 enrolled without a password). If `use_password` is `yes`: log an exercise-log exception, set it to `no` (`sudo sed -i 's/<use_password>yes<\/use_password>/<use_password>no<\/use_password>/' /var/ossec/etc/ossec.conf`), `sudo systemctl restart wazuh-manager`.

- [ ] **Step 2: Install and enroll the agent (DC01)**

```bash
sudo dpkg -i /tmp/wazuh-agent*.deb
sudo /var/ossec/bin/agent-auth -m 10.10.10.5 -A dc01
sudo systemctl enable --now wazuh-agent && sudo systemctl is-active wazuh-agent
```
Expected: deb installs; `Agent enrollment successfully completed` or similar; `active`.

- [ ] **Step 3: Agent localfile + FIM config (DC01)**

Append BEFORE `</ossec_config>` in `/var/ossec/etc/ossec.conf`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/samba/audit.json</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/samba/log.samba</location>
</localfile>
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <directories check_all="yes" realtime="yes">/var/lib/samba/private/sam.ldb</directories>
</syscheck>
```
Then:
```bash
sudo systemctl restart wazuh-agent && sudo systemctl is-active wazuh-agent
sudo grep -a "syscheck\|localfile" /var/ossec/logs/ossec.log | tail -5
```
Expected: `active`; no errors mentioning duplicate syscheck blocks (single block, unlike the Windows 2.5b pitfall).

- [ ] **Step 4: Verify agent in the manager API (SOC01)**

```bash
token=$(curl -ks -u 'wazuh:1O58pEByLzeNx27aHgsZYp2L+R5pyga.' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token)
curl -ks -H "Authorization: Bearer $token" "https://127.0.0.1:55000/agents?pretty=true" | jq '.data.affected_items[] | {name, ip, status, id}'
```
Expected: `dc01` listed with `status: active`, id `002` (or next free).

- [ ] **Step 5: Save repo copy and commit**

Write the localfile/syscheck additions to `lab/dc01/ossec.conf.additions.xml`; commit:
```powershell
git add lab/dc01/ossec.conf.additions.xml
git commit -m "feat: DC01 wazuh-agent enrolled (samba json audit + log.samba + sam.ldb FIM)"
```

---

### Task 5: Capture step — sample events and decoded field names

**Files:**
- Create: `lab/evidence/phase2-capture-logon-fail.json`, `-logon-ok.json`, `-tgs-req.json`, `-asrep.json`, `-samldb.json` (exported raw alert JSON, one event each)
- Modify: `lab/cases/howto-create-detection.md` (append the Samba decoded-field map once confirmed)

**Interfaces:**
- Produces: confirmed Wazuh field names for rule authoring:
  - JSON audit: `authentication.status`, `authentication.clientAccount`, `authentication.clientDomain`, `authentication.remoteAddress`, `authentication.eventId` (4625/4624), `authentication.serviceDescription`
  - log.samba: decoded field holding the message text (expected `message`)
  - FIM: `file` field carrying `/var/lib/samba/private/sam.ldb`

- [ ] **Step 1: User generates a failed logon (WIN01)**

User, WIN01 admin PowerShell:
```powershell
net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass
```
Expected: `System error 1326` (bad password).

- [ ] **Step 2: User generates a successful logon (WIN01)**

```powershell
net use \\10.10.10.10\IPC$ /user:CORP\attacker 'Attacker!lab123'
net use * /delete /y
```
Expected: `The command completed successfully.`

- [ ] **Step 3: User generates a sam.ldb write (DC01, via SOC01 hop)**

```bash
# on DC01:
sudo samba-tool user show victim >/dev/null; sudo samba-tool user setexpiry victim --noexpiry
```
Expected: command completes; this rewrites sam.ldb (FIM event).

- [ ] **Step 4: Export raw alerts and inspect fields (SOC01)**

```bash
sudo grep -a '"type":"Authentication"' /var/ossec/logs/alerts/alerts.json | tail -1
sudo grep -a 'audit.json' /var/ossec/logs/alerts/alerts.json | tail -1
sudo grep -a 'sam.ldb' /var/ossec/logs/alerts/alerts.json | grep -v COMMAND | tail -1
```
Expected: three JSON lines — the failed/success auth alert (decoded `authentication.*` fields visible), a log.samba syslog event, a syscheck event with `file` = `/var/lib/samba/private/sam.ldb`.
Copy one clean example of each into `lab/evidence/phase2-capture-*.json` (via pscp `sudo cat` pattern; strip none — keep raw).

- [ ] **Step 5: Trigger TGS-REQ and AS-REP for capture (SOC01 impacket)**

```bash
# from SOC01:
python3 /usr/local/lib/python3.12/dist-packages/examples/GetUserSPNs.py corp.lab/attacker:'Attacker!lab123' -dc-ip 10.10.10.10 -request
echo -e "victim\n" > /tmp/users.txt
python3 /usr/local/lib/python3.12/dist-packages/examples/GetNPUsers.py corp.lab/ -dc-ip 10.10.10.10 -usersfile /tmp/users.txt -no-pass -format hashcat
```
Expected: GetUserSPNs prints `svc-sql` + `$krb5tgs$...` hash; GetNPUsers prints `$krb5asrep$...` for victim.
Then check DC01 logs (via hop):
```bash
sudo grep -a "TGS-REQ" /var/log/samba/log.samba | tail -2
sudo grep -a "AS-REP" /var/log/samba/log.samba | tail -2
```
Expected: TGS-REQ line mentioning `svc-sql` or `MSSQLSvc`; AS-REP line for `victim`. Export each line's Wazuh-decoded alert (repeat Step 4 grep for `TGS-REQ`) into `lab/evidence/phase2-capture-tgs-req.json` / `-asrep.json`.

- [ ] **Step 6: Record the field map and commit**

Append the confirmed field names to `lab/cases/howto-create-detection.md`; commit:
```powershell
git add lab/evidence/phase2-capture-*.json lab/cases/howto-create-detection.md
git commit -m "feat: phase 2 capture step - samba decoded field map + sample events"
```

---

### Task 6: UC-03a — logon burst rules 100029/100030/100031 (user-authored UI)

**Files:**
- Modify: `lab/soc01/local_rules.xml` (rules appended — via dashboard UI, synced back)

**Interfaces:**
- Consumes: Task 5 field map (`authentication.status`, `authentication.remoteAddress`, `authentication.clientAccount`, `authentication.clientDomain`).
- Produces: rules 100029 (failed logon, lvl 8), 100030 (burst 3/60s same source, lvl 12, T1110), 100031 (success, lvl 3) live on manager + repo synced.

- [ ] **Step 1: User opens the rules editor**

Dashboard → Server Management → Rules → Manage rules files → `local_rules.xml` → pencil.

- [ ] **Step 2: User pastes the three rules BEFORE `</group>`**

```xml
<rule id="100029" level="8">
  <field name="authentication.status" type="pcre2">(?i)^NT_STATUS_(WRONG_PASSWORD|LOGON_FAILURE|NO_SUCH_USER|ACCOUNT_LOCKED_OUT|ACCOUNT_DISABLED|UNSUCCESSFUL)$</field>
  <description>LAB: failed domain logon - $(authentication.clientAccount)@$(authentication.clientDomain) from $(authentication.remoteAddress)</description>
  <group>authentication_failure,lab,identity_attack,</group>
  <mitre><id>T1110.001</id></mitre>
</rule>

<rule id="100030" level="12" frequency="3" timeframe="60" if_matched_sid="100029" same_field="authentication.remoteAddress">
  <description>LAB: logon burst - 3+ failed domain logons in 60s from $(authentication.remoteAddress) for $(authentication.clientAccount)@$(authentication.clientDomain)</description>
  <group>authentication_failure,lab,identity_attack,</group>
  <mitre><id>T1110</id></mitre>
</rule>

<rule id="100031" level="3">
  <field name="authentication.status" type="pcre2">^NT_STATUS_OK$</field>
  <description>LAB: successful domain logon - $(authentication.clientAccount)@$(authentication.clientDomain) from $(authentication.remoteAddress)</description>
  <group>authentication_success,lab,</group>
</rule>
```
No raw quote characters in the regex (rule 100020 lesson). Save.

- [ ] **Step 3: Verify reload and running ruleset (assistant)**

```bash
# SOC01:
sudo systemctl restart wazuh-manager
token=$(curl -ks -u 'wazuh:1O58pEByLzeNx27aHgsZYp2L+R5pyga.' -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token)
curl -ks -H "Authorization: Bearer $token" "https://127.0.0.1:55000/rules?rule_ids=100029,100030,100031&limit=10" | jq '.data.affected_items[] | {id, level, groups}'
```
Expected: three rules listed with levels 8/12/3 and groups including `identity_attack`.

- [ ] **Step 4: User runs the attack (WIN01) — 3 fails then success**

```powershell
net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass
net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass
net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass
net use \\10.10.10.10\IPC$ /user:CORP\attacker 'Attacker!lab123'
net use * /delete /y
```
Expected: three `System error 1326`, one success.

- [ ] **Step 5: Verify alerts (SOC01)**

```bash
sudo grep -a '"LAB: logon burst"' /var/ossec/logs/alerts/alerts.json | grep -v COMMAND | tail -2
sudo grep -a '"LAB: failed domain logon"' /var/ossec/logs/alerts/alerts.json | grep -v COMMAND | tail -3
```
Expected: one 100030 alert whose JSON contains `rule.id:100030`, the WIN01 source (`remoteAddress: ipv4:10.10.10.20:...`), and `clientAccount: attacker, clientDomain: CORP`. Three 100029 alerts. If only two 100029 appear: the third failure and success may share a window — re-run.

- [ ] **Step 6: User runs the benign control — 2 fails only**

```powershell
net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass
net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass
```
Verify on SOC01: no new `"LAB: logon burst"` alert since the attack (compare timestamps). Expected: 100029 fires twice, 100030 silent.

- [ ] **Step 7: Sync repo + commit**

```powershell
# host: pull the file back (pscp can't read it as socadmin — use sudo cat):
$out = & "C:\Program Files\PuTTY\plink.exe" -batch -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 socadmin@10.10.30.10 "echo socadmin123 | sudo -S cat /var/ossec/etc/rules/local_rules.xml 2>/dev/null"
[IO.File]::WriteAllText("C:\Users\pedro\OneDrive\Documents\GitHub\Code\Virtual_SOC\lab\soc01\local_rules.xml", ($out -join "`n") + "`n")
git add lab/soc01/local_rules.xml
git commit -m "feat: UC-03a logon burst rules 100029/100030/100031 PASS"
```

---

### Task 7: UC-03b — sam.ldb FIM rule 100032 (user-authored UI)

**Files:**
- Modify: `lab/soc01/local_rules.xml`

**Interfaces:**
- Consumes: Task 5 FIM field (`file`), Task 0's deployed FIM decoder fix (setup 2.5c — already live since Task 6 of Phase 1).
- Produces: rule 100032 (FIM modified sam.ldb, lvl 12, T1098).

- [ ] **Step 1: User pastes rule 100032 via UI (before `</group>`) and saves**

```xml
<rule id="100032" level="12">
  <if_group>syscheck</if_group>
  <field name="file" type="pcre2">/var/lib/samba/private/sam\.ldb$</field>
  <description>LAB: AD database modified (possible privileged group change) - $(file) on $(hostname)</description>
  <group>account_manipulation,lab,identity_attack,</group>
  <mitre><id>T1098</id></mitre>
</rule>
```

- [ ] **Step 2: Verify reload (assistant)** — same restart + API check as Task 6 Step 3, rule id 100032. Expected level 12, group `account_manipulation`.

- [ ] **Step 3: User runs the attack (DC01 via SOC01 hop)**

```bash
sudo samba-tool group addmembers "Domain Admins" attacker
sudo samba-tool group listmembers "Domain Admins"
```
Expected: `Added members to group "Domain Admins"`; `attacker` listed. (This is the privileged group change.)

- [ ] **Step 4: Verify alert (SOC01)**

```bash
sudo grep -a '"LAB: AD database modified"' /var/ossec/logs/alerts/alerts.json | grep -v COMMAND | tail -2
```
Expected: 100032 alert with `file: /var/lib/samba/private/sam.ldb` and DC01 as agent.

- [ ] **Step 5: User runs the benign control**

```bash
sudo samba-tool user show victim
sudo samba-tool group listmembers "Domain Admins"
```
Reads only — no sam.ldb write. Verify no new 100032 (timestamp comparison). Expected: silent.

- [ ] **Step 6: Sync repo + commit** — same sudo-cat pattern as Task 6 Step 7.

```powershell
git commit -m "feat: UC-03b sam.ldb FIM rule 100032 PASS"
```

---

### Task 8: UC-04/05 — Kerberoasting + AS-REP rules 100033/100034 (user-authored UI)

**Files:**
- Modify: `lab/soc01/local_rules.xml`

**Interfaces:**
- Consumes: Task 5 TGS-REQ/AS-REP decoded field (expected `message` — verify against the capture artifact before pasting).
- Produces: 100033 (3 TGS-REQs for SPN account in 60s, lvl 12, T1558.003), 100034 (AS-REP for no-preauth account, lvl 12, T1558.004).

- [ ] **Step 1: User checks the capture artifact and pastes both rules via UI**

```xml
<rule id="100033" level="12" frequency="3" timeframe="60">
  <field name="message" type="pcre2">TGS-REQ.*(?:MSSQLSvc|svc-sql)</field>
  <description>LAB: Kerberoasting - repeated TGS requests for SPN service account</description>
  <group>credential_access,lab,identity_attack,</group>
  <mitre><id>T1558.003</id></mitre>
</rule>

<rule id="100034" level="12">
  <field name="message" type="pcre2">AS-REP</field>
  <description>LAB: AS-REP roasting - AS-REP issued to no-preauth account</description>
  <group>credential_access,lab,identity_attack,</group>
  <mitre><id>T1558.004</id></mitre>
</rule>
```
If the capture artifact shows the TGS line decoded into a different field (e.g. `full_log` or a json field from kdc audit), substitute that field name — confirm with the capture JSON before saving.

- [ ] **Step 2: Verify reload (assistant)** — restart + API check for 100033/100034.

- [ ] **Step 3: Check clock skew (Kerberos preauth tolerance)**

```bash
# SOC01 vs DC01:
date -u
ssh dcadmin@10.10.10.10 'date -u'
```
Expected: within 5 minutes. If skew larger: `sudo date -s "<dc01 time>"` on SOC01.

- [ ] **Step 4: User runs the Kerberoasting attack (SOC01) — 3 requests**

```bash
python3 /usr/local/lib/python3.12/dist-packages/examples/GetUserSPNs.py corp.lab/attacker:'Attacker!lab123' -dc-ip 10.10.10.10 -request
python3 /usr/local/lib/python3.12/dist-packages/examples/GetUserSPNs.py corp.lab/attacker:'Attacker!lab123' -dc-ip 10.10.10.10 -request
python3 /usr/local/lib/python3.12/dist-packages/examples/GetUserSPNs.py corp.lab/attacker:'Attacker!lab123' -dc-ip 10.10.10.10 -request
```
Expected: `$krb5tgs$...` hash printed each run.

- [ ] **Step 5: Verify 100033 (SOC01)**

```bash
sudo grep -a '"LAB: Kerberoasting"' /var/ossec/logs/alerts/alerts.json | grep -v COMMAND | tail -1
```
Expected: 100033 alert. Control: a SINGLE GetUserSPNs run produces 1 TGS-REQ → below frequency → no new 100033 (timestamp check). Note in lessons: frequency=3 is the lab's FP mitigation; real environments need tuning.

- [ ] **Step 6: User runs the AS-REP attack (SOC01)**

```bash
python3 /usr/local/lib/python3.12/dist-packages/examples/GetNPUsers.py corp.lab/ -dc-ip 10.10.10.10 -usersfile /tmp/users.txt -no-pass -format hashcat
```
Expected: `$krb5asrep$...` hash for victim.

- [ ] **Step 7: Verify 100034 (SOC01)**

```bash
sudo grep -a '"LAB: AS-REP roasting"' /var/ossec/logs/alerts/alerts.json | grep -v COMMAND | tail -1
```
Expected: 100034 alert. Control: run `getTGT.py corp.lab/attacker:'Attacker!lab123' -dc-ip 10.10.10.10` (preauth-required account → no AS-REP) → no new 100034.

- [ ] **Step 8: Sync repo + commit**

```powershell
git commit -m "feat: UC-04/05 Kerberoasting + AS-REP rules 100033/100034 PASS"
```

---

### Task 9: WIN01 domain join + re-verify UC-03

**Files:**
- Modify: `lab/runbook/win01.md` (join procedure + DNS change, lab control noted)

**Interfaces:**
- Produces: WIN01 joined to `corp.lab`; UC-03 verified with a domain-joined endpoint; snapshot `win01-joined`.

- [ ] **Step 1: Snapshot WIN01 pre-join (host)**

```powershell
VBoxManage snapshot WIN01 take pre-domain-join
```

- [ ] **Step 2: Point WIN01 DNS at DC01 (user, WIN01 admin PowerShell)**

```powershell
netsh interface ip set dns name="Ethernet" static 10.10.10.10
nslookup dc01.corp.lab
```
Expected: resolves to 10.10.10.10. (If "Ethernet" name differs: `Get-NetAdapter` first.)

- [ ] **Step 3: Join the domain (user)**

```powershell
Add-Computer -DomainName corp.lab -Credential CORP\Administrator -Restart
```
Expected: reboot; logon screen shows `CORP` domain. Log back in as local `labadmin` (lab control noted in exercise log).

- [ ] **Step 4: Re-run UC-03 attack as domain flow (user)**

On WIN01 (as `labadmin`, still valid local account):
```powershell
net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass   # x3
net use \\10.10.10.10\IPC$ /user:CORP\attacker 'Attacker!lab123'
net use * /delete /y
```
Verify on SOC01: new 100030 burst alert (Step 5 pattern of Task 6). Expected: PASS — endpoint evidence now from a domain member.

- [ ] **Step 5: Snapshot the joined state**

```powershell
VBoxManage snapshot WIN01 take win01-joined
```

- [ ] **Step 6: Document + commit**

Update `lab/runbook/win01.md` (DNS change + join + lab controls), commit:
```powershell
git commit -m "feat: WIN01 joined corp.lab, UC-03 re-verified domain-joined"
```

---

### Task 10: Documentation, exit gate, close-out

**Files:**
- Create: `lab/cases/uc-03-t1110-logon-burst.md`, `lab/cases/uc-04-t1558-003-kerberoasting.md`, `lab/cases/uc-05-t1558-004-asrep.md`
- Modify: `lab/cases/exercise-log.md`, `lab/cases/lessons-learned.md`, `lab/runbook/dc01.md` (new full DC01 runbook), `docs/superpowers/session.md`
- Create: `lab/evidence/uc-03-alert.png`, `uc-04-alert.png`, `uc-05-alert.png` (user screenshots)

**Interfaces:**
- Produces: Phase 2 exit-gate evidence + full documentation; final commit.

- [ ] **Step 1: User captures dashboard screenshots**

Discover `rule.id:100030` → `lab/evidence/uc-03-alert.png`; `rule.id:100033` → `uc-04-alert.png`; `rule.id:100034` → `uc-05-alert.png`. (Save via browser; assistant verifies files exist.)

- [ ] **Step 2: Write the three case docs**

Follow the UC-01 case doc template: hypothesis, MITRE technique, source, trigger, lab controls (impacket tools from SOC01, clock sync check, no-preauth flag on victim, weak SPN password), expected source fields, rule, expected alert, benign control, false positives to document, cleanup (attacker out of Domain Admins: `sudo samba-tool group removemembers "Domain Admins" attacker` — note it as Task 10 Step 4), pass conditions. Fill in observed values from the verified alerts.

- [ ] **Step 3: Exercise log + lessons**

Exercise-log rows for UC-03a/03b/04/05 (expected vs observed, timestamps, lab controls). Lessons-learned additions: (a) Samba JSON audit decoded field map + rsyslog routing trick; (b) logon-burst correlation uses `same_field` because remoteAddress isn't parsed as `srcip`; (c) AS-REP exists only for no-preauth accounts → text match is sufficient; (d) dashboard saves sometimes skip the reload log → restart + API check; (e) Kerberoasting control = repeat count (frequency 3), not a different tool.

- [ ] **Step 4: Cleanup lab controls (DC01)**

```bash
sudo samba-tool group removemembers "Domain Admins" attacker
sudo samba-tool group listmembers "Domain Admins"
```
Expected: attacker removed. (Victim keeps the no-preauth flag — documented, harmless in isolated lab.)

- [ ] **Step 5: DC01 runbook**

Write `lab/runbook/dc01.md` mirroring setup.md: VM creation, install choices, provision command, accounts, audit config, agent config, snapshot layout. Commit with the rest.

- [ ] **Step 6: Exit-gate review with user**

Gate check (spec section 1): UC-03 PASS = three failed logons then a success produced a Wazuh alert with endpoint (WIN01 IP) AND domain identity (`attacker@CORP.LAB`) in evidence (100030 confirmed); privileged group change produced a separate alert (100032 confirmed). UC-04/05 PASS as bonuses. All controls silent.

- [ ] **Step 7: Session state + final commit**

Update `docs/superpowers/session.md` (Phase 2 done, snapshots list, next = Phase 3 NDR brainstorming). Then:
```powershell
git add -A
git commit -m "feat: Phase 2 identity detection complete - UC-03 PASS (exit gate), UC-04/05 PASS"
```

---

## Self-review notes

- Spec coverage: all spec sections 1–8 mapped to Tasks 0–10; capture-first rule authoring enforced by Task 5 preceding Tasks 6–8; fallbacks encoded (kdc text path, agent deb source, pip wheels platform, auth password check, clock skew).
- Field-name uncertainty is contained in exactly one place (Task 5) and each rule task references the confirmed artifact.
- IDs consistent throughout: 100029/100030/100031 (UC-03a), 100032 (UC-03b), 100033/100034 (UC-04/05); reserved 100035 unused.
