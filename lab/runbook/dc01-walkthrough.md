# DC01 — the domain controller, explained step by step

> Companion to the terse `dc01.md` runbook and the command-only `setup.md` §3.
> This doc teaches the *what* and *why* behind each step, so you can read it like a lesson.

## 1. What this box is

**DC01 is the lab's identity authority.** It runs Samba (a Linux reimplementation of Microsoft
Active Directory) acting as a **domain controller** for the domain `corp.lab` (NetBIOS short name
`CORP`).

Think of it as the company HR system:

- It keeps the directory of **who exists** (users) and **what exists** (computers, groups).
- It **authenticates** people: when you type a username + password, DC01 is what says "yes, this is
  really alice" and hands out a ticket proving it.
- Every other machine trusts DC01's word.

That's the whole point of a "domain": **identity is centralized in one place** instead of living
separately on every computer.

| Box | Role |
|---|---|
| **DC01** (`10.10.10.10`) | Domain controller — holds the directory + authenticates (Kerberos/LDAP/NTLM) |
| **WIN01** (`10.10.10.20`) | A Windows workstation that **joined** the domain (`DESKTOP-I4QI720`) |
| **SOC01** (`10.10.10.5`) | The SIEM (Wazuh) — collects DC01's auth logs and raises alerts |

## 2. The big idea: what "create a domain" means

A common confusion: a **domain** is not a network/VLAN, and not a "group". It's the **top-level
identity namespace** — the whole directory under one authority. A **group** is a membership list
*inside* a domain, and a **user** is an individual *inside* a domain.

Hierarchy: **Domain → (Groups, Users, Computers)**

You create a domain once, by standing up a domain controller (this whole walkthrough). After that,
you freely create users/groups/computers inside it — one-liners.

## 3. Step 0 — Create the VM

Standard VirtualBox Linux guest. Two NICs:

- `int-corp` (the isolated lab "corporate" network) → static `10.10.10.10`.
- `nat` → temporary internet access during provisioning only (detached before snapshot).

```powershell
VBoxManage createvm --name DC01 --ostype Ubuntu_64 --register
VBoxManage modifyvm DC01 --memory 4096 --cpus 2 --vram 16
VBoxManage modifyvm DC01 --nic1 intnet --intnet1 int-corp --nic2 nat
VBoxManage createmedium disk --filename C:\lab-vms\DC01\dc01.vdi --size 40960
VBoxManage storagectl DC01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach DC01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\DC01\dc01.vdi
VBoxManage storageattach DC01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\ubuntu-24.04.5-live-server-amd64.iso
VBoxManage startvm DC01
```

## 4. Step 1 — Install Ubuntu

Ubuntu Server 24.04.5, minimal. User `dcadmin`, enable OpenSSH. Full disk (no LVM — this box
doesn't need the extra disk flexibility, and it's one less thing to go wrong).

## 5. Step 2 — Static IP, and freeing port 53

Two important things happen here:

```bash
sudo netplan apply                              # enp0s3 -> 10.10.10.10/24
sudo systemctl disable --now systemd-resolved   # frees port 53
```

- The DC must use a **static IP** — everything points *to* it, so its address can't change.
- The DC runs its **own DNS server** (Samba's internal DNS). DNS listens on UDP/TCP port **53**,
  but Ubuntu's `systemd-resolved` also grabs port 53. We disable it so Samba can own DNS.
- The DC's DNS points at itself (`127.0.0.1`), because it is the authoritative DNS for `corp.lab`.

## 6. Step 3 — Provision the domain (the big one)

This single command **creates the domain**:

```bash
sudo apt update && sudo apt install -y samba
sudo samba-tool domain provision --use-rfc2307 --server-role=dc \
  --dns-backend=SAMBA_INTERNAL --realm=corp.lab --domain=CORP --adminpass='<ADMINPW>'
sudo systemctl unmask samba-ad-dc && sudo systemctl enable --now samba-ad-dc
sudo systemctl mask smbd nmbd winbind
```

What `domain provision` actually does:

- Builds the **directory database** (`/var/lib/samba/private/sam.ldb` — "sam" = Security Account
  Manager), an LDAP-style store of users/groups/computers.
- Creates the domain's **Administrator** account (the built-in domain admin).
- Sets up **Kerberos** (the ticket-granting service) and **LDAP**.
- Sets up **DNS** for `corp.lab` (SRV records so clients can *find* the domain controller).
- Creates the `krbtgt` account — Kerberos' master secret.

Note the AD DC runs as the `samba` binary; `smbd`/`nmbd`/`winbind` (the old file-sharing/legacy
services) are masked because the DC role doesn't use them.

## 7. Step 4 — Users, groups, SPNs, and a special flag

Now the domain exists; we populate it. This is the same "add a user" operation you practiced.

```bash
sudo samba-tool user create attacker 'Attacker!lab123'
sudo samba-tool user create svc-sql  'SvcSQL!lab123'
sudo samba-tool user create victim   'Victim!lab123'
sudo samba-tool group add  "Domain Admins"      # groups are created the same way
```

Two extra objects make the lab interesting:

**A Service Principal Name (SPN)** — a label that names a *service*, so Kerberos can issue tickets
to it. `svc-sql` owns an SPN for a (fictional) SQL Server. This makes `svc-sql` a realistic
**service account** — and a **kerberoasting** target (its weak password can be cracked offline from
the ticket it's issued).

```bash
sudo samba-tool spn add MSSQLSvc/dc01.corp.lab:1433 svc-sql
```

**A "no pre-authentication" flag** — normally, before Kerberos hands you a ticket, it makes you
prove you know the password by encrypting a timestamp (pre-auth). For accounts flagged
`UF_DONT_REQUIRE_PREAUTH`, that check is skipped — which is exactly what **AS-REP roasting** abuses.
We flag `victim` this way:

```bash
sudo ldbmodify -H /var/lib/samba/private/sam.ldb --controls=relax:0 <<'EOF'
dn: CN=victim,CN=Users,DC=corp,DC=lab
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
EOF
```

`4194816` = `0x400200` = `NORMAL_ACCOUNT (0x200)` + `DONT_REQUIRE_PREAUTH (0x400000)`. The
`userAccountControl` value is a **bitmask** — a single number where each bit is a yes/no flag.

## 8. Step 5 — Turn Samba's auth events into log files Wazuh can read

This is the detection plumbing. By default Samba doesn't tell us much. We make it log every
authentication in a machine-readable form:

```bash
# added to [global] in /etc/samba/smb.conf:
log level = 1 auth_json_audit:3 kdc:10
logging = syslog
log file = /var/log/samba/log.samba
dns forwarder = 192.168.100.1
```

- `auth_json_audit:3` → every auth event is emitted as a **JSON object** (fields like
  `"type": "Authentication"`, `"clientAccount"`, `"status"`).
- `logging = syslog` → send it to the system logger (journald).
- `kdc:10` → verbose Kerberos debug lines (the `Kerberos: AS-REQ ...` text).

Then **rsyslog** (the system logger's router) splits that stream into two files:

- JSON lines (`"type": "..."`) → `/var/log/samba/audit.json`
- everything else (KDC text) → `/var/log/samba/log.samba`

```bash
sudo systemctl restart samba-ad-dc
sudo systemctl restart rsyslog
```

The split is done by `/etc/rsyslog.d/30-samba-audit.conf` (see repo `lab/dc01/`). The `stop`
directive there means "don't also dump these into the default syslog file."

## 9. Step 6 — Point the Wazuh agent at those files

Each box runs a **Wazuh agent** that ships logs to the SOC01 manager. On DC01 we tell the agent to
read:

1. `/var/log/samba/audit.json` (parsed as JSON → structured fields like `Authentication.status`)
2. `/var/log/samba/log.samba` (parsed as syslog → the raw KDC text)
3. **File integrity monitoring (FIM)** on `/var/lib/samba/private/sam.ldb.d` — watch the AD database
   for changes, so we can detect tampering (e.g. someone adding themselves to Domain Admins).

```bash
sudo WAZUH_MANAGER='10.10.10.5' WAZUH_AGENT_NAME='dc01' dpkg -i ./wazuh-agent_4.14.8-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

Now every logon on DC01 lands in Wazuh as structured events, ready to be turned into alerts.

## 10. Step 7 — Isolate and snapshot

Detach the NAT adapter (no more internet — the lab is sealed) and take a snapshot so we can roll
back.

```powershell
VBoxManage controlvm DC01 acpipowerbutton
VBoxManage modifyvm DC01 --nic2 none
VBoxManage snapshot DC01 take base-phase2
```

## 11. How authentication actually flows (recap)

When `alice` logs in, the flow is:

1. **DNS** — the client asks "where's the Kerberos KDC for corp.lab?" (SRV record) → `10.10.10.10:88`.
2. **AS-REQ/AS-REP** — client gets a Ticket-Granting Ticket (TGT). Pre-auth proves the password.
3. **TGS-REQ/TGS-REP** — trade the TGT for a ticket to a specific service (e.g. `cifs/`).
4. **AP-REQ** — present the service ticket to the target.

Two things worth remembering:
- The password is **never sent over the network** — only tickets encrypted with keys.
- Kerberos is **time-sensitive** — tickets carry timestamps, so if client and DC clocks disagree,
  auth fails (`KRB_AP_ERR_SKEW`). That's why clock drift breaks our lab after a VM savestate.

When you authenticate by **IP** instead of hostname, Windows falls back to **NTLM** (challenge/
response) instead of Kerberos — same outcome, different wire protocol.

## 12. The detections this powers

| Rule | What it detects | Technique |
|---|---|---|
| 100029 | failed domain logon (wrong password) | T1110 brute force |
| 100030 | 3+ failed logons / 60s for one account | T1110 logon burst |
| 100031 | successful domain logon | (situational awareness) |
| 100032 | AD database modified (FIM on sam.ldb.d) | T1565.001 |
| 100033 | Kerberoasting (TGS-REQ for `MSSQLSvc`) | T1558.003 |
| 100034 | AS-REP roasting (pre-auth-less AS-REQ for a no-pre-auth account) | T1558.004 |

## 13. Gotchas we hit (the interesting lessons)

- **Clock skew (recurring):** no NTP. After any savestate/resume, `date` drifts. Fix before Kerberos
  work: `sudo timedatectl set-ntp off; sudo date -s "<UTC>"`, then restart `wazuh-manager`.
- **Duplicate events:** because `logging = syslog` sends Samba to journald *and* rsyslog re-writes
  the text into `log.samba`, and the Wazuh agent reads *both* — any KDC-text rule fires twice.
- **FIM on a TDB database is hard:** `sam.ldb` uses memory-mapped writes, so file-watchers don't
  fire. We watch the *domain partition* inside `sam.ldb.d` and rely on a periodic 60s checksum scan.
- **Samba 4.19.5 never hands out an AS-REP hash:** it always replies `ERR_PREAUTH_REQUIRED`, so
  AS-REP roasting here is detected by *log pattern*, not by cracking a returned hash.
- **`smbd` vs `samba`:** SMB logon events come from the `smbd` program name, not `samba` — the
  rsyslog filter must match both or logons are dropped.

## 14. How to test it yourself

1. SSH to DC01 (via SOC01) and add a user:
   ```bash
   sudo samba-tool user create alice 'Passw0rd!'
   ```
2. From WIN01, authenticate as her:
   ```cmd
   net use \\dc01.corp.lab\IPC$ /user:CORP\alice Passw0rd!   # success -> rule 100031
   net use * /delete /y
   net use \\dc01.corp.lab\IPC$ /user:CORP\alice wrongpass    # fail -> rule 100029
   ```
3. Watch the Wazuh dashboard for the alert — `alice` with source IP `10.10.10.20`.
