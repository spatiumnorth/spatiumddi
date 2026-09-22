---
layout: default
title: Windows Server Setup
---

# Windows Server Setup (DNS + DHCP)

SpatiumDDI can manage Windows Server DNS and DHCP agentlessly — no software installed on the Windows side. DNS has two tiers (RFC 2136 always-on, WinRM unlocks more); DHCP runs entirely over WinRM — lease and scope mirroring into IPAM, plus per-object scope / reservation / exclusion writes.

This page is the **Windows-side checklist**. The SpatiumDDI-side config is covered in [features/DNS.md §13](../features/DNS.md#13-windows-dns--path-a--b) and [features/DHCP.md §15](../features/DHCP.md#15-windows-dhcp--path-a-read-only).

> **You do not install anything on the Windows server.** Everything runs remotely over WinRM (DNS zone management + DHCP reads) or RFC 2136 / dnspython over UDP/TCP 53 (DNS record writes + AXFR).

---

## TL;DR — the minimum

Both DNS Path B and DHCP Path A use WinRM, so they share most of the setup:

1. **Enable WinRM** on the Windows server (`winrm quickconfig` — usually already on for domain controllers).
2. **Open the firewall** — TCP 5985 (HTTP) or 5986 (HTTPS) from the SpatiumDDI host.
3. **Create a service account** in the right security group:
   - DNS Path B → in `DnsAdmins` on the DC (or a delegated group with the same DNS rights).
   - DHCP → in `DHCP Administrators` if SpatiumDDI should write scopes / reservations / exclusions; `DHCP Users` is enough to mirror leases and scopes read-only.
4. **Configure the account in SpatiumDDI** when you add the server — username / password / transport (`ntlm` recommended for domain-joined, `basic` if you must, `kerberos` if you run the AD side).
5. (DNS only) **Enable dynamic updates** on each zone you want SpatiumDDI to write records to — **Nonsecure and secure** for Path A's unsigned RFC 2136, or **Secure only** if you're using Path B exclusively for zone management and don't need per-record writes.
6. (DNS Path A only) **Allow AXFR** from the SpatiumDDI host, or use Path B (WinRM) to sidestep AXFR entirely.

Test from the SpatiumDDI UI with the **Test Connection** button on the server create form before saving.

---

## 1. WinRM prerequisites

### On the Windows server

WinRM is usually already enabled on domain controllers. If not:

```powershell
winrm quickconfig
winrm set winrm/config/service/Auth '@{Basic="true"}'     # only if using basic auth
winrm set winrm/config/service '@{AllowUnencrypted="true"}' # only if using HTTP + basic; prefer HTTPS
```

Check what's listening:

```powershell
winrm enumerate winrm/config/listener
```

You want a listener on port **5985** (HTTP) or **5986** (HTTPS). SpatiumDDI prefers HTTPS — use HTTP only on isolated management networks.

### Transport choices

| Transport | Port | Cert needed? | When to use |
|---|---|---|---|
| `ntlm` | 5985 or 5986 | No | Domain-joined AD environments — default. Works from Linux via `pywinrm`. |
| `kerberos` | 5985 or 5986 | No (but needs Kerberos tickets) | If the SpatiumDDI host is domain-joined and running `kinit`. Not typical — and the published images carry no GSSAPI / Kerberos libraries, so today this choice fails at connect time. |
| `basic` | 5985 or 5986 | Recommended HTTPS | Non-domain use. Requires `AllowUnencrypted=true` on HTTP — avoid. |
| `credssp` | 5985 or 5986 | Yes | The "second hop": the one transport whose logon on the Windows server can authenticate onward to another server. **Required to manage Windows DHCP failover relationships from SpatiumDDI** (see [More than one Windows DHCP server in a group](#more-than-one-windows-dhcp-server-in-a-group)). Enable it on each server with `Enable-WSManCredSSP -Role Server`. |

SpatiumDDI stores these on `DNSServer.credentials_encrypted` / `DHCPServer.credentials_encrypted` as a Fernet-encrypted dict:

```json
{
  "username": "CORP\\spatium-dns",
  "password": "…",
  "winrm_port": 5986,
  "transport": "ntlm",
  "use_tls": true,
  "verify_tls": true
}
```

`verify_tls: false` is acceptable for self-signed WinRM certs; it's a per-server setting so you can opt-out per host without globally disabling verification.

### Firewall

Allow inbound TCP 5985/5986 from the SpatiumDDI host only:

```powershell
New-NetFirewallRule -DisplayName "SpatiumDDI WinRM HTTPS" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 `
  -RemoteAddress <spatium-host-or-subnet>
```

For DNS Path A (RFC 2136 + AXFR) you also need UDP + TCP 53 from the SpatiumDDI host.

---

## 2. DNS — Windows Server side

### Path A (RFC 2136, no credentials)

This is the baseline — no WinRM needed, just record-level RFC 2136 dynamic updates.

**On each zone you want SpatiumDDI to write to:**

1. Open **DNS Manager** on the DC.
2. Right-click the zone → **Properties** → **General** tab.
3. Set **Dynamic updates** to **Nonsecure and secure**.
   > **Note:** AD-integrated zones default to "Secure only", which rejects unsigned RFC 2136. Either change it, or use Path B (WinRM) for zone management and accept that record writes will fail until you also enable Nonsecure. See "Secure-only zones" below for the GSS-TSIG path.

4. **Zone transfers** tab → allow transfers to the SpatiumDDI host's IP (this enables AXFR for `pull_zone_records`).

That's it. Create a `windows_dns` server in SpatiumDDI **without credentials** pointing at the DC's IP; it will drive the zone via `dnspython` over port 53.

### Path B (WinRM + PowerShell, credentials required)

Path B adds zone create/delete and a WinRM-based zone record pull (which sidesteps AXFR ACLs on AD-integrated zones).

**On the DC:**

1. Make sure WinRM is reachable (§1 above).
2. Create a service account (an AD user, not a local user on the DC):
   ```
   New-ADUser -Name "spatium-dns" -SamAccountName "spatium-dns" `
     -AccountPassword (Read-Host -AsSecureString) -Enabled $true `
     -UserPrincipalName "spatium-dns@corp.example.com"
   ```
3. Add it to `DnsAdmins`:
   ```
   Add-ADGroupMember -Identity DnsAdmins -Members spatium-dns
   ```
   `DnsAdmins` is enough for `Add-DnsServerPrimaryZone`, `Remove-DnsServerZone`, and `Get-DnsServerResourceRecord`.

4. **Don't skip the zone dynamic-update setting.** Path B uses WinRM for zone topology, but record-level writes still go over RFC 2136. If the zone is "Secure only", record writes fail — same as Path A.

**On the SpatiumDDI side:**

When you add the server in **DNS → Server Groups → Add Server**, fill in:

- **Host** — the DC's FQDN or IP
- **Driver** — `windows_dns`
- **WinRM credentials** section — username (use `DOMAIN\user` or `user@corp.example.com`), password, port (5985 or 5986), transport, TLS options.

Click **Test Connection** to run a `(Get-DnsServerSetting -All).BuildNumber` probe before saving. Green = Path B is live. Red = check the error; common failures are firewall, bad transport (try `ntlm` instead of `basic`), or the account not being in `DnsAdmins`.

### Secure-only zones (GSS-TSIG — future)

AD-integrated zones in "Secure only" mode require GSS-TSIG (Kerberos-signed RFC 2136). SpatiumDDI doesn't implement GSS-TSIG yet — it's on the roadmap. Today's options:

- Change the zone to "Nonsecure and secure".
- Or, manage the zone via Path B (zone CRUD only) and skip per-record writes.

---

## 3. DHCP — Windows Server side

### Path A (WinRM, read-only)

SpatiumDDI polls each Windows DHCP server for its leases and scopes and mirrors them into IPAM. With a `DHCP Administrators` account it also **writes through**: creating or editing a scope, pool or reservation in SpatiumDDI runs the matching `*-DhcpServerv4*` cmdlet on the server before the change is committed, so a WinRM failure rolls the change back instead of leaving SpatiumDDI and Windows disagreeing.

**On the DHCP server:**

1. WinRM reachable (§1 above).
2. Create an AD service account (same as DNS — but a separate account if you want to scope permissions independently).
3. Add it to the right local group on the DHCP server:
   ```
   # On the DHCP server, not the DC
   Add-LocalGroupMember -Group "DHCP Administrators" -Member "CORP\spatium-dhcp"
   ```
   `DHCP Users` instead of `DHCP Administrators` is enough if SpatiumDDI only mirrors leases and scopes and never writes.

4. No other configuration needed — `Get-DhcpServerv4Scope` / `Get-DhcpServerv4Lease` work out of the box.

**On the SpatiumDDI side:**

- **DHCP → Server Groups → Add Server**
- **Driver** — `windows_dhcp`
- **WinRM credentials** — same shape as the DNS Path B credentials.
- **Test Connection** runs `(Get-DhcpServerVersion).ToString()` to verify.

Then enable **DHCP Lease Sync** in **Settings**. Beat ticks every 10s; the task gates on the enabled toggle + a per-server interval stored in seconds (default 15s, floored at 10s), so you can change cadence without restarting anything.

Each lease upserts by `(server_id, ip_address)` and mirrors into IPAM as a row with `status="dhcp"` and `auto_from_lease=True` — the existing lease-cleanup sweep handles expiry uniformly.

### More than one Windows DHCP server in a group

A SpatiumDDI server group says *every member serves every scope of the group*. For Kea that is what the HA hook makes true. For Windows it is only true where a **failover relationship** covers the scope — two Windows servers holding the same scope **without** one are two independent DHCP servers handing out the same addresses, and neither server reports a problem. So a group with two or more Windows members behaves differently from a single-server group (#1110):

| You do in SpatiumDDI | What happens on the Windows members |
|---|---|
| Edit a scope that a failover relationship covers | Written to **both** partners — see below — and to no other member. |
| Edit a scope that one member holds, outside any relationship | Written to that member only. It is **never** created on the others. |
| Create a scope no member holds yet | Goes to **one** member, chosen by the scope's **Windows placement**: *into a failover relationship* (created on one side — the hot-standby Active server, else the lowest-named — then added to the relationship, which makes Windows copy it to the partner), or *on one server only*. With no placement, a group whose members share exactly one relationship uses it; otherwise the create is **refused (422)** with the choices listed. Creating it on every member is the duplicate-address outage. |
| Activate a scope several members hold that no relationship covers | **Refused (422)** — put it in a relationship, or remove it from all but one server. Deactivating it is allowed; that is the remedy. |
| Delete a scope that a failover pair in this group covers | Taken out of the relationship on one side (Windows deletes the partner's copy), then deleted there. Needs CredSSP — otherwise **refused (409)** with the Windows step. A scope whose partner is **not** in this group is always refused: that step deletes a copy on a server SpatiumDDI does not manage. |
| Change the range, or remove an exclusion, on a **split scope** | **Refused (422)** when the servers' parts would then overlap — see below. |
| Add / edit a reservation or exclusion | Written to every member that holds the scope, skipped on members that do not. **Refused (409)** if no member holds it — there is nowhere for it to go. |

**Why a covered scope is written to both partners.** Windows failover keeps **leases** in sync between partners continuously, but not **configuration**: option values, exclusions and reservations only reach the partner when someone runs `Invoke-DhcpServerv4FailoverReplication` or *Replicate Scope* in the DHCP console. Writing one partner and waiting for Windows to replicate would leave the other partner serving stale reservations after a failover. Microsoft's own IPAM writes both partners for the same reason. When the partners drift anyway — a change made in the DHCP console — the scope is flagged **Config drift**, and **Replicate** on the group's panel copies the side you choose over the other.

**What SpatiumDDI reads.** The lease-sync poll also runs `Get-DhcpServerv4Failover` on each Windows server and records its relationships (name, mode, partner, role, state, load-balance share, MCLT, whether message authentication is on — never the shared secret) and which scopes it holds. The group's page shows them under **Windows DHCP failover**, with any scope that needs attention; each scope carries a **Windows** badge. When a relationship's partner is not a member of the group, changes made in SpatiumDDI reach only the member that is — register the partner in the same group so both receive them.

#### Managing relationships from SpatiumDDI

The group's **Windows DHCP failover** panel creates, edits and deletes relationships, adds scopes to and removes them from a relationship, and replicates one partner's configuration over the other's; each is also a REST route under `/api/v1/dhcp/server-groups/{id}/failover/relationships` (superadmin, audited). Every one of them runs a single cmdlet on **one** member, which then acts on the partner from there — that is how the Windows cmdlets are built. So:

* **The member's WinRM transport must be CredSSP.** An NTLM or Basic logon over WinRM is a network logon with no credential to pass on (the PowerShell remoting "second hop"), and the partner half of the cmdlet would be denied. SpatiumDDI refuses the action (422) before sending anything when the transport is anything else. Enable CredSSP on each DHCP server with `Enable-WSManCredSSP -Role Server`, switch the server's transport to **CredSSP** in SpatiumDDI, and give the account `DHCP Administrators` on **both** partners — the cmdlet writes to both.
* **Where it runs decides what it does to the other server.** Creating a relationship, or adding a scope to one, *copies* each scope from the member it runs on to the partner — so it runs on the member that holds the scope, and the partner must **not** already hold it (Windows refuses; remove it there first — its leases come back from the partner over the failover protocol). Removing a scope, or deleting the relationship, *deletes the partner's copy* — you choose which member keeps serving. A load-balance share and a hot-standby role are the values of the member the change runs on, so an edit names that member.
* **Windows requires a scope to create a relationship.** On a fresh pair: create the scope in SpatiumDDI with the placement *on one server only*, then create the relationship with that scope from the panel.
* **The shared secret** is passed to Windows and nothing else — it is never stored, logged, returned or written to the audit log.

These actions change Windows directly and then re-read both members; nothing reconciles Windows towards a stored copy, so a change made later in the DHCP console is simply read back on the next poll.

**Split scopes** (two servers, one scope, their parts kept apart by exclusions or ranges, no relationship — the pre-2012 pattern) are recognised and reported rather than flagged as the outage. SpatiumDDI models one range and one set of exclusions per scope and writes them to every server that holds it, so it refuses any change that would make the parts overlap — a new range, or removing or moving an exclusion that keeps them apart — and tells you to make that change on each server in Windows. Adding an exclusion, and every other edit, goes through.

**Kea and Windows in one group** are refused: Kea serves every active scope of its group and its HA cannot coordinate with Windows failover, so a scope a Windows member also holds would be handed out twice. Creating or moving a server into a group that already has the other kind is a 422; an existing mixed group is flagged on the panel, and each shared scope is reported **uncoordinated**.

**Alert.** The default-on **DHCP scope served uncoordinated** alert rule fires (critical) for each scope the panel reports uncoordinated, and resolves when the scope is put in a relationship or left on one server.

> **Reading failover may need more than `DHCP Users`.** `Get-DhcpServerv4Failover` has been reported failing with access denied (`WIN32 5`) for an under-privileged account, and whether `DHCP Users` membership is enough to read relationships has not been established. If the read is denied, SpatiumDDI shows it as failed and keeps the last relationships it read — it never takes a denied read to mean "no failover" — and on a multi-server group it refuses to activate a shared scope whose coordination it cannot see. `DHCP Administrators` avoids the question, and managing relationships needs it anyway.

> **Not yet verified against a live failover pair.** The failover reads and the management cmdlets follow Microsoft's documented shapes and parameters; the exact JSON Windows returns, and the cmdlets' behaviour over CredSSP, have not been captured from a real pair yet.

---

## 4. Diagnosing problems from Linux

Test WinRM reachability independently of SpatiumDDI:

```bash
# From the SpatiumDDI host (or any Linux box with python3):
pip install pywinrm
python3 - <<'PY'
import winrm
s = winrm.Session(
    "https://dc01.corp.example.com:5986",
    auth=("CORP\\spatium-dns", "…"),
    transport="ntlm",
    server_cert_validation="ignore",
)
r = s.run_ps("(Get-DnsServerSetting -All).BuildNumber")
print("stdout:", r.std_out.decode())
print("stderr:", r.std_err.decode())
print("rc:", r.status_code)
PY
```

Common failures:

| Symptom | Cause |
|---|---|
| `WinRMTransportError: 401` | Wrong username/password, wrong transport, or `AllowUnencrypted=false` with `use_tls: false`. |
| `WinRMTransportError: 500 ... Access is denied.` | Account is authenticated but not in `DnsAdmins` / `DHCP Users`. |
| Connection timeout | Firewall, wrong port, or WinRM listener not running. |
| `SSL CERTIFICATE_VERIFY_FAILED` | Self-signed WinRM cert — set `verify_tls: false` on the credentials. |

For DNS Path A (RFC 2136), check the zone's "Dynamic updates" setting and try `nsupdate` by hand from the SpatiumDDI host:

```bash
nsupdate -d <<EOF
server dc01.corp.example.com
zone corp.example.com.
update add test.corp.example.com. 60 A 10.1.2.3
send
EOF
```

A `REFUSED` response points at the dynamic-updates setting; a `NOTAUTH` points at the zone's primary NS value in SpatiumDDI not matching the server.

---

## 5. Hardening checklist (production)

- [ ] Use **HTTPS WinRM** (port 5986) with a cert from your internal CA — verify it with `verify_tls: true`.
- [ ] Dedicated service accounts — one for DNS (`DnsAdmins`), one for DHCP (`DHCP Administrators`, or `DHCP Users` for read-only mirroring) — not Domain Admins.
- [ ] Firewall inbound 5985/5986 from the SpatiumDDI host only — `Get-NetFirewallRule`.
- [ ] For DNS Path A, restrict AXFR to the SpatiumDDI host IP (zone **Zone Transfers** tab → "Only to the following servers").
- [ ] Rotate the service account password on a schedule — SpatiumDDI re-encrypts when you save the server, no restart needed.
- [ ] Audit WinRM access via Windows event log (`Microsoft-Windows-WinRM/Operational`).
- [ ] Disable unused transports on the WinRM listener (don't leave `Basic` on if you're using NTLM).

---

## Related docs

- [Getting Started](../GETTING_STARTED.md) — setup order: servers → zones/scopes → subnets → addresses.
- [DNS Features](../features/DNS.md) — zones, records, views, sync jobs.
- [DHCP Features](../features/DHCP.md) — scopes, pools, leases.
- [DNS Drivers](../drivers/DNS_DRIVERS.md) — driver internals including `WindowsDNSDriver`.
- [DHCP Drivers](../drivers/DHCP_DRIVERS.md) — driver internals including `WindowsDHCPReadOnlyDriver`.
