---
layout: default
title: Getting Started
---

# Getting Started — Setup Order

SpatiumDDI has a few internal dependencies between modules (records need zones, scopes need subnets, etc.). This guide walks you through the **recommended order** to get from a fresh install to a useful working system — whether your DNS/DHCP servers are the built-in Kea + BIND9 containers, a Windows Server DC, or a mix.

> If you haven't installed SpatiumDDI yet, start with the [Docker Compose quick start](deployment/DOCKER.md) or [README Quick start](https://github.com/spatiumnorth/spatiumddi/blob/main/README.md#quick-start-with-docker-compose), then come back here.

---

## Pick your path

Three kinds of readers land on this page. Start where you actually are:

- **"I'm evaluating whether this fits my org."** Read [Project status](#project-status) for what to expect from a beta and the lowest-risk way to trial it, then [Concepts in two minutes](#concepts-in-two-minutes) for what a [DDI](#ddi) platform does, then skim [Common setup shapes](#common-setup-shapes) to see which deployment matches your environment. You can stop there — everything in between is the how.
- **"I know DDI. Get me running."** Go straight to the [TL;DR](#tldr--the-order) and work down the numbered steps. Plain-language framing sits in one lead sentence per step and in collapsible blocks — skip past both and the mechanics read as before.
- **"I run networks, but DDI vocabulary is new to me."** Read [Concepts in two minutes](#concepts-in-two-minutes) first, then work through [Before you start](#before-you-start) and follow the numbered steps in order. Each step opens with what it does and why, a [worked example](#the-worked-example--ridgeline-college) runs through the whole sequence, and unfamiliar terms link to the [glossary](#glossary).

---

## Project status

SpatiumDDI is **beta software** under active development. Core IPAM / DNS / DHCP / appliance surfaces have stabilised since the `2026.04.16-1` alpha cut, but expect occasional schema changes between releases and roadmap features still in flight. It is a good fit today for labs, homelabs, and pilots in front of non-critical client populations; production deploys in front of business-critical DHCP should pin to a tested release and snapshot Postgres before upgrading.

**The lowest-risk way to try it: IPAM-only evaluation.** You do not have to hand SpatiumDDI control of anything on day one. Run it as the source of truth for your address plan — spaces, blocks, subnets, allocations — while your existing DNS and DHCP servers keep serving live traffic untouched. If you run Windows DHCP, register it read-only (Path A) so live [leases](#dhcp-lease) mirror into IPAM and you get real visibility with zero write path to production. That is the third of the [Common setup shapes](#common-setup-shapes) below. When you're ready, enable write paths one subnet or one zone at a time.

**And you can put the subsystems you are not using away entirely.** DNS and DHCP are each a feature module (`core.dns` / `core.dhcp`) under **Settings → Features**. Both ship on; turning one off removes its sidebar section, its dashboard tab, its REST surface, its scheduled jobs and its copilot tools — so an IPAM-only or DNS-only install stops carrying affordances that point at nothing. Two things it deliberately does *not* do: agent registration and config polling keep working, so a running fleet is never cut off; and disabling is refused while the subsystem still owns servers, zones or scopes, since hiding live state behind a 404 is worse than leaving the module on. Delete those first, or just leave it enabled.

---

## Concepts in two minutes

If you already know what a zone, a scope and a PTR record are, skip this.

<details markdown="1">
<summary>What DNS, DHCP and IPAM each do — and why one source of truth matters</summary>

Three systems keep a network's addressing coherent. An office-campus analogy holds for all three:

- **IPAM** (IP Address Management) is the **floor plan and seating chart**: the authoritative record of what address space exists, how it is divided up, and which addresses are assigned to what. Without it, that record is usually a spreadsheet.
- **DHCP** (Dynamic Host Configuration Protocol) is the **front desk**: when a device joins the network, DHCP hands it an unoccupied address from a defined range, plus the settings it needs (router, DNS servers, domain), for a limited time.
- **DNS** (Domain Name System) is the **directory**: it turns names people use (`print-01.corp.example.edu`) into addresses machines use (`10.20.21.10`), and — via [reverse zones](#forward-and-reverse-zones) — addresses back into names.

The analogy stops there; desks don't expire, but DHCP [leases](#dhcp-lease) do.

**Why one source of truth matters.** When the seating chart, the front desk and the directory are maintained separately — a spreadsheet, a DHCP console, a DNS console — they drift. The spreadsheet says an address is free, DHCP has leased it, DNS still points a name at it. [DDI](#ddi) means running all three off one record, so allocating an address in IPAM *is* what creates its DNS records, and DHCP ranges are defined against the same subnets IPAM tracks.

**The IPAM hierarchy.** SpatiumDDI organises address space top-down, and the setup steps below follow the same order:

- **Space** → the whole estate (campus): your entire addressing universe, e.g. everything corporate.
- **Block** → a building: a large aggregate like `10.20.0.0/16`, carved out of the space.
- **Subnet** → a floor: an operating network like `10.20.21.0/24`, usually mapped to one [VLAN](#vlan).
- **Address** → a desk: one IP, assigned to one device.

**Control plane vs data plane.** SpatiumDDI itself never answers a DNS query or a DHCP request. It is the [control plane](#control-plane-and-data-plane): the API, database and UI that decide what the configuration should be. The actual answering is done by the data plane — BIND9/Kea containers it deploys, or Windows servers it drives remotely. Managed containers cache their last-known-good configuration locally, so the data plane keeps serving even if the control plane is down.

</details>

---

## Before you start

Have these in hand before step 1:

- **A running SpatiumDDI.** The quickest path is the [OS appliance ISO](deployment/APPLIANCE_INSTALL.md): boot it, answer the installer, and the full stack is on HTTPS a few minutes after the reboot with nothing to install by hand. Prefer containers you manage yourself? A Docker host with Docker Engine 25+ and Docker Compose v2.20+, 2 GB RAM minimum (4 GB recommended), ports 8077 (frontend) and optionally 8000 (API) free — see the [Docker prerequisites](deployment/DOCKER.md#prerequisites). Kubernetes is the third option; see the [deployment topologies](deployment/TOPOLOGIES.md).
- **Admin access** to that host, and credentials to log in to SpatiumDDI (`admin` / `admin` on first boot; you will be forced to change it).
- **Your list of subnets and [VLANs](#vlan)**, even a rough one, in [CIDR](#cidr) notation (`10.20.21.0/24`). You will enter these in steps 6–8, and a written plan beats improvising in the create form.
- **Whether you have existing Windows DNS or DHCP.** This decides your backend choice in steps 3 and 5. If yes, you will need [WinRM](#winrm) enabled and a service account on the Windows side — read [WINDOWS.md](deployment/WINDOWS.md) first, since those prerequisites need Windows-admin time. If no, the built-in [agent](#agent-and-agentless) containers cover everything.
- **Whether you need SSO on day one.** If people other than you will log in from the start, decide the provider (LDAP / OIDC / SAML) now — OIDC and SAML need the External URL set correctly in step 1 before their redirect flows work. Local accounts work fine without any of this.
- **For live DHCP service from the built-in Kea:** clients reach a DHCP server by broadcast, so the server must share a layer-2 segment with them or be reachable via an IP helper / DHCP relay on your router. Not needed for the read-only Windows mirroring shape.

---

## TL;DR — the order

```
1. Platform settings        (app title, defaults, sync cadences)
2. Auth providers           (LDAP / OIDC / SAML / RADIUS / TACACS+)   ← optional, do later if you want
3. DNS server groups + servers
4. DNS zones                (forward first, reverse second)
5. DHCP server groups + servers
6. IPAM — IP Space
7. IPAM — IP Block(s)       (optional — aggregates that own inherited settings)
8. IPAM — Subnets           (pin the DNS + DHCP group here, OR let them inherit)
9. DHCP scopes              (per subnet, per DHCP server)
10. Addresses               (start allocating; A/AAAA/PTR follow automatically)
```

The cleanest mental model is: **servers → zones/scopes → subnets → addresses**. Addresses are the leaf; everything above them has to exist before SpatiumDDI can push a record or a reservation anywhere useful.

---

## The worked example — Ridgeline College

Steps 3–10 each carry a short worked example so you can watch one setup come together end to end. The scenario: **Ridgeline College**, a fictional small college with one campus. Its internal domain is `corp.example.edu`; its campus network is `10.20.0.0/16` (a private [RFC 1918](#rfc-1918) range) carved into one /24 per VLAN using the convention `10.20.<VLAN>.0/24`. Ridgeline runs the built-in BIND9 + Kea containers. The first subnet brought under management is staff VLAN 21 — `10.20.21.0/24`.

---

## 1. Platform settings (first login)

*What this does: sets the platform-wide defaults that every later form pre-fills — deciding them once here saves re-typing them on every zone and scope you create.*

After logging in as `admin` / `admin` and changing your password:

1. Go to **Settings**.
2. Set **Branding & URL** — especially **External URL** if you're going to use OIDC or SAML (those redirect flows need it).
3. Tune **DNS Defaults** (default zone [TTL](#ttl), [DNSSEC](#dnssec) mode) and **DHCP Defaults** (default DNS servers, search domain, lease time) — these are the pre-filled values when you later create zones and scopes, so setting them up front saves repetition.
4. Leave the two sync jobs **off** for now:
   - *IPAM → DNS Reconciliation* — turn this on once you have zones + subnets.
   - *Zone ↔ Server Reconciliation* — turn this on once at least one Windows DNS server with credentials is registered.
5. **Utilization thresholds** are cosmetic — set them if you care about the colour of the bars.

Each section has a **Reset to defaults** button at the top. It populates the section with the built-in defaults but still requires **Save** — you can back out by navigating away.

> **How you know it worked:** reload the Settings page — your values persist. Later, in steps 4 and 9, the new-zone and new-scope forms come pre-filled with the defaults you set here.

---

## 2. (Optional) Auth providers

*What this does: connects sign-in to your existing identity system so people use their normal accounts; skip it and local accounts keep working.*

If you want SSO before anyone logs in, do it now. Otherwise, skip and come back later.

- **LDAP** — fastest to set up. Add a service account, point at your DC, test the connection, map groups.
- **OIDC** — needs your External URL from step 1. The redirect URL is `https://<External URL>/api/v1/auth/{provider_id}/callback`.
- **SAML** — needs External URL and an IdP that can consume the SP metadata at `/api/v1/auth/{provider_id}/metadata`.
- **RADIUS / TACACS+** — point at your network-device auth infra. Primary + optional backup hosts share the same shared secret.

See [AUTH.md](features/AUTH.md) for the full provider matrix.

> **How you know it worked:** the provider's **Test connection** succeeds, and a test user can sign in and lands with the groups you mapped. Note that a user whose groups match no mapping is rejected at login by design — if a test login fails, check the group mappings before anything else.

---

## 3. DNS — server groups + servers

*What this does: registers the DNS servers SpatiumDDI manages and how it talks to them — every [zone](#zone) you create in step 4 must live on one of these groups.*

Zones live under server groups, so this has to come before zones.

1. **DNS → Server Groups → New Group**. Give it a name (`default`, `internal`, `corp`, whatever) and pick the [recursion](#recursion) / DNSSEC defaults.
2. **Add a server** to the group.

   **Choosing a backend — two questions.** If you'd rather read the full matrix, it follows below unchanged.

   1. **Does your org already run DNS on Windows Server / Active Directory?** If yes, keep it — register the DC as a `windows_dns` server rather than migrating anything. Provide WinRM credentials if your Windows admins allow it (**Path B** — full experience: zone create/delete, server-side reads without [AXFR](#axfr)); without credentials you still get record-level writes via [RFC 2136](#rfc-2136) dynamic updates (**Path A**). If no, use a built-in container — question 2.
   2. **Using the built-in stack: which of the three?** Take **PowerDNS** if you need ALIAS records (CNAME-at-apex) or LUA computed records — nothing else serves them. Take **Technitium** if you want to serve or forward encrypted DNS without a sidecar; it is the only backend that forwards over DoH and DoQ, not just DoT. Otherwise take **BIND9**, the default — it is the only one with split-horizon views and RPZ blocklists. All three do online DNSSEC and catalog zones, so those no longer pick for you.

   | Backend | Setup | When to choose |
   |---|---|---|
   | **Built-in BIND9** (`bind9`) | Run `docker compose --profile dns-bind9 up -d` (legacy `--profile dns` also works). The container auto-registers using `DNS_AGENT_KEY` and shows up in the group automatically. | New deployments; you want SpatiumDDI to own the whole DNS plane and the BIND ecosystem. The only backend with split-horizon **views** and **RPZ** blocklists. |
   | **Built-in PowerDNS** (`powerdns`, issue #127) | Run `docker compose --profile dns-powerdns up -d`. Same `DNS_AGENT_KEY` bootstrap; auto-registers under group `default-powerdns`. | You want ALIAS records (CNAME-at-apex), LUA computed records, or PowerDNS's REST-native operational model. |
   | **Built-in Technitium** (`technitium`, issue #746) | Run `docker compose --profile dns-technitium up -d`. Same `DNS_AGENT_KEY` bootstrap; auto-registers under group `default-technitium`. | You want DoT / DoH / **DoQ** served natively with no dnsdist-style sidecar, encrypted *upstream* forwarding over any of the three, or the smallest footprint — Technitium keeps zone state in its own store, so there is no config file and no external database. No views, no RPZ (it blocks natively from a per-domain set instead), no ALIAS / LUA. |
   | **Windows DNS — Path A** (`windows_dns`, no credentials) | Point at an existing Windows DC. Enable "Secure and Nonsecure" dynamic updates on each zone in Windows DNS Manager and allow AXFR to SpatiumDDI's host. | You have an AD-integrated DNS already and just want record-level writes from SpatiumDDI. |
   | **Windows DNS — Path B** (`windows_dns` + credentials) | Same as above, but also provide WinRM credentials. Unlocks zone create/delete and lets SpatiumDDI list + pull zones without relying on AXFR. | You want the full experience without giving up Windows DNS Manager. Best for AD environments. |

   See [WINDOWS.md](deployment/WINDOWS.md) for the Windows-side prerequisites (WinRM, service accounts, firewall).

3. Click **Sync with Servers** on the group header. For Windows servers this AXFRs/WinRM-pulls every zone on the wire, auto-imports zones that aren't in SpatiumDDI yet, and pushes any DB-only zones back to the server.

<details markdown="1">
<summary>Background: how the built-in containers register themselves</summary>

The BIND9 / PowerDNS / Technitium / Kea containers are [agents](#agent-and-agentless): each starts with a pre-shared key from its environment (`DNS_AGENT_KEY` / `DHCP_AGENT_KEY`), exchanges it with the control plane for a rotating token, and appears as a registered server without manual entry. From then on the agent polls for configuration changes and keeps a local copy of its last-known-good config, so DNS and DHCP keep answering even if the control plane is down. Details in [DNS_AGENT.md](deployment/DNS_AGENT.md).

</details>

> **Worked example — Ridgeline College.** Ridgeline creates one server group named `default`, leaves the group defaults as-is, and runs `docker compose --profile dns-bind9 up -d` on the SpatiumDDI host. The BIND9 container auto-registers and appears in the group.

> **How you know it worked:** the server appears in the group's server list, enabled, and **Sync with Servers** completes with a healthy per-server status. A group with zero enabled servers can't push anything — that state is the top cause of "my record never appeared" later.

---

## 4. DNS — zones

*What this does: creates the containers your records will live in — [forward zones](#forward-and-reverse-zones) for name → IP lookups, reverse zones for IP → name.*

Zones come in two flavours, and the order matters a little:

1. **Forward zones first.** Create `corp.example.com`, `lab.example.com`, etc. These are what your [A/AAAA](#a-and-aaaa-records) records live in.
2. **Reverse zones second.** These back [PTR](#ptr-record) records. You can either:
   - Create them manually now (`20.10.in-addr.arpa` for `10.20.0.0/16`, or `21.20.10.in-addr.arpa` for `10.20.21.0/24` — the zone name is the network octets reversed under [`in-addr.arpa`](#in-addrarpa-and-ip6arpa)), or
   - Let SpatiumDDI auto-create them when you create the subnet in step 8 — the matching `in-addr.arpa` (or `ip6.arpa`) zone is created automatically once the subnet has an effective DNS group/zone, unless you opt out with `skip_reverse_zone`.

Zones that SpatiumDDI didn't create itself can be imported by clicking **Sync with Servers** on the group — anything present on the wire but not in the DB is auto-imported as `is_auto_generated=False` (so it won't be touched by stale-record cleanup).

<details markdown="1">
<summary>Background: how reverse zone names map to subnets</summary>

Reverse DNS stores IP-to-name mappings in ordinary zones under the special domains `in-addr.arpa` (IPv4) and `ip6.arpa` (IPv6), with the address octets written in reverse: the PTR record for `10.20.21.10` lives at `10.21.20.10.in-addr.arpa`, inside a zone such as `21.20.10.in-addr.arpa` (covering `10.20.21.0/24`). Reverse zones split cleanly only on octet boundaries — /8, /16, /24 — so for a subnet that isn't octet-aligned (a /23, say) SpatiumDDI creates the zone at the nearest enclosing octet boundary, the standard BIND convention for an aggregated reverse zone covering several smaller subnets.

</details>

> **Worked example — Ridgeline College.** Ridgeline creates one forward zone, `corp.example.edu`, in the `default` group — and stops there. Rather than hand-creating reverse zones, they let SpatiumDDI auto-create `21.20.10.in-addr.arpa` when the `10.20.21.0/24` subnet is created in step 8.

> **How you know it worked:** the zone appears in the group's zone list with SOA/NS records, and after **Sync with Servers** the per-server state on the zone shows it present on the wire.

---

## 5. DHCP — server groups + servers

*What this does: registers the servers that will answer lease requests — the [scopes](#dhcp-scope) you define in step 9 attach to these.*

Same pattern as DNS. Do this before you start pinning subnets to DHCP servers.

1. **DHCP → Server Groups → New Group**.
2. **Add a server**.

   **Choosing a backend — two questions.** The matrix follows below unchanged.

   1. **Do you have an existing Windows DHCP server that must keep serving leases?** If yes, register it read-only (**Path A**): SpatiumDDI polls its leases into IPAM for visibility, and you keep managing scopes in the Windows DHCP console. Nothing about the running service changes.
   2. **Otherwise — greenfield, or ready to serve DHCP from SpatiumDDI?** Run the built-in **Kea** container and let SpatiumDDI own scopes, pools and [reservations](#dhcp-reservation) end to end.

   | Backend | Setup | When to choose |
   |---|---|---|
   | **Built-in Kea** (`kea`) | `docker compose --profile dhcp up -d`. Auto-registers via `DHCP_AGENT_KEY`. | New deployments; you want SpatiumDDI to own DHCP. |
   | **Windows DHCP — Path A** (`windows_dhcp`, read-only) | Point at an existing Windows DHCP server with WinRM credentials. SpatiumDDI polls leases and mirrors them into IPAM as `dhcp` rows. All writes (`/sync`, scope push) are rejected. | You want lease visibility in IPAM without giving SpatiumDDI write control over the Windows DHCP server. |

   See [WINDOWS.md](deployment/WINDOWS.md) for Windows DHCP Server prerequisites.

3. Toggle **DHCP Lease Sync** on in Settings once you have at least one agentless server — the Celery beat task pulls leases on a short polling interval (15 s by default, tunable in Settings, 10 s minimum).

> **Worked example — Ridgeline College.** Ridgeline creates a DHCP group named `default` and runs `docker compose --profile dhcp up -d`. The Kea container auto-registers into it. No Windows DHCP exists, so lease sync stays off.

> **How you know it worked:** the server appears in the DHCP group's server list, enabled and healthy. For a Windows Path A server, leases start appearing in IPAM (as `dhcp` rows) within a polling interval of enabling **DHCP Lease Sync**.

---

## 6–8. IPAM — space → block → subnet

*What this does: builds the address ledger, top-down — the record of what address space you have and how it's carved up, which everything else (scopes, records, allocations) hangs off.*

IPAM is the root of the hierarchy everything else hangs off. The top-down order is:

### 6. IP Space

An **IP Space** is the top-level container — think "address universe". Most orgs have one or two:
- `Corporate` — all IPs your org announces.
- `Lab` — disposable / isolated ranges.
- `Cloud-AWS` / `Cloud-Azure` — per-cloud RFC1918 ranges.

Create a space with **IPAM → New Space**. You can pin a default DNS group + DHCP group here; anything below will inherit unless overridden.

> **Worked example — Ridgeline College.** One space: `Campus`. Ridgeline pins nothing here, choosing to pin groups on the block below instead.

### 7. IP Blocks (optional)

A **Block** is an aggregate — a `10.0.0.0/8` under Corporate, broken into `10.1.0.0/16` for HQ and `10.2.0.0/16` for datacentre, etc. Blocks exist to:
- Own inherited settings (DNS group, DHCP group, custom fields, tags).
- Give the tree shape when you have dozens of subnets.

You can skip blocks entirely if your network is small — subnets can live directly under a space.

> **Worked example — Ridgeline College.** One block: `10.20.0.0/16` under `Campus`. This is where Ridgeline pins the `default` DNS group and `default` DHCP group, so every per-VLAN subnet created under it inherits both and needs no per-subnet pinning.

### 8. Subnets

A **Subnet** is where DHCP scopes attach and where individual addresses are allocated.

On the subnet create form:

- **CIDR** (e.g. `10.20.0.0/24`) — required.
- **VLAN ID** (optional) — if you manage VLANs in SpatiumDDI, link it here.
- **Primary DNS zone** — forward zone for A/AAAA records auto-created from IP allocations.
- **Additional DNS zones** — other zones you want the IP allocation form to offer in its dropdown.
- **DNS server group** — leave blank to inherit from block/space. Pin it here to override.
- **DHCP server group** — same. Pin it here if this subnet needs a different DHCP server than its parents.
- **DNS inherit settings** / **DHCP inherit settings** — toggle these back on if you pinned something and want to return to inheritance.
- **Reverse zone** — SpatiumDDI auto-creates the right `in-addr.arpa` (or `ip6.arpa`) zone on the effective DNS group once the subnet has one; opt out with `skip_reverse_zone`.

**Important:** subnets and blocks respect inheritance independently for DNS and DHCP. If you want a subnet to inherit DNS from its parent but use a different DHCP group, that works — toggle `dns_inherit_settings` on, `dhcp_inherit_settings` off, and pin the DHCP group.

> **Worked example — Ridgeline College.** First subnet: `10.20.21.0/24`, VLAN ID 21, primary DNS zone `corp.example.edu`. Both server-group fields stay blank — the subnet inherits the `default` DNS and DHCP groups from the `10.20.0.0/16` block. On save, SpatiumDDI auto-creates the reverse zone `21.20.10.in-addr.arpa` in the `default` group.

> **How you know it worked:** the IPAM tree shows `Campus → 10.20.0.0/16 → 10.20.21.0/24`, the subnet detail shows the effective (inherited) DNS and DHCP groups, and the new reverse zone is listed under the DNS group alongside your forward zone.

---

## 9. DHCP scopes

*What this does: turns a documented subnet into a range the DHCP server actually serves — until now the subnet only exists on paper.*

With a subnet and a DHCP server group in place, open the subnet → **DHCP** tab → **New Scope**. The form pre-fills the subnet's gateway as the router, the defaults from Settings (DNS servers, domain, search list, NTP, lease time) and, on an IPv4 subnet of /28 or larger, a suggested **Initial pool**: a dynamic range from the tenth host address to the last usable one (`.10–.254` on a /24). Most scopes are a one-click save; change or clear the initial pool when part of that range is meant for static addresses.

[Pools](#dhcp-pool) go under scopes:
- **Dynamic** — handed out to clients.
- **Reserved** — held for static assignments only.
- **Excluded** — this range exists in the subnet but DHCP will never offer it (e.g. infrastructure).

For Windows DHCP servers in Path A (read-only) you can't create scopes from SpatiumDDI — you create them in the Windows DHCP MMC, and SpatiumDDI auto-imports them on the next lease sync.

> **Worked example — Ridgeline College.** On `10.20.21.0/24`, Ridgeline creates one scope and accepts the pre-filled defaults except the suggested initial pool: it replaces `10.20.21.10–10.20.21.254` with `10.20.21.100–10.20.21.199`, a **dynamic** pool for staff laptops. Kept as suggested, the pool would take in `10.20.21.10`, the address step 10 gives `print-01`, and that allocation would stop to ask for confirmation. Then **Add Pool** on the new scope creates an **excluded** pool `10.20.21.1–10.20.21.9` for network infrastructure. Everything else is left for static allocation in step 10.

> **How you know it worked:** the scope and its pools are listed on the subnet's DHCP tab, and the subnet's IP grid marks the pool boundaries — allocating an address inside the dynamic pool by hand asks you to confirm first: a reminder to pin a matching static reservation on the scope, so the DHCP server doesn't lease that address to another client.

---

## 10. Addresses

*What this does: allocating an address is what makes DNS records appear — this is the step the previous nine were setting up.*

Now the fun part. In the subnet view:

- Click **Allocate IP** and pick **Next available** to auto-pick the next free address.
- Or click any row in the IP grid and fill in hostname, status, tags.

When you save an IP with a hostname + DNS zone:

1. SpatiumDDI creates an A/AAAA record in the forward zone.
2. SpatiumDDI creates a PTR record in the reverse zone (if one is linked).
3. For BIND9, the update goes over RFC 2136; for Windows, record writes go over RFC 2136 in both Path A and Path B (WinRM in Path B is used only for zone create/delete and server-side reads, not for hot record writes).

<details markdown="1">
<summary>Background: why updates ride RFC 2136 instead of rewriting zone files</summary>

RFC 2136 dynamic update changes individual records on a live server — no zone-file editing, no service restart, no full-zone push. That is what makes a record write cheap enough to happen automatically on every allocation, and it is the same mechanism in both Windows paths, which is why the "allow nonsecure dynamic updates" zone setting matters in the troubleshooting list below.

</details>

If anything ever drifts between IPAM and your DNS servers, the **Sync DNS** option (under the `[Sync ▾]` menu on the subnet/block/space header) opens a drift report, and two scheduled reconciliation jobs you can enable in Settings:

| Job | What it reconciles |
|---|---|
| **IPAM → DNS Reconciliation** | IPAM's expected records vs SpatiumDDI's DNS DB — fills in records the live sync missed. |
| **Zone ↔ Server Reconciliation** | SpatiumDDI's DNS DB vs the authoritative server's wire — imports out-of-band edits, pushes DB-only records back. |

Both are off by default and additive-only.

> **Worked example — Ridgeline College.** Ridgeline allocates `10.20.21.10` with hostname `print-01`, zone `corp.example.edu`. On save, an A record `print-01.corp.example.edu → 10.20.21.10` lands in the forward zone and a PTR record appears in `21.20.10.in-addr.arpa`. A staff laptop joining VLAN 21 picks up a lease from the `10.20.21.100–199` pool.

> **How you know it worked:** both records are visible in the zone record lists, and a query against the DNS server answers — for Ridgeline, `dig @<bind9-host> print-01.corp.example.edu` returns `10.20.21.10` and `dig @<bind9-host> -x 10.20.21.10` returns the name. The subnet's **Sync DNS** drift report shows the subnet in sync. If the record didn't appear, work through [Troubleshooting the first IP](#troubleshooting-the-first-ip).

---

## Common setup shapes

### All-SpatiumDDI (fresh greenfield)

1. Compose profiles on: `COMPOSE_PROFILES=dns,dhcp`
2. Add the auto-registered `dns-bind9` and `dhcp-kea` containers to groups.
3. Create zones, then spaces/blocks/subnets, then scopes, then allocate.

### Hybrid — Windows DNS + SpatiumDDI DHCP

1. Run `dhcp-kea` (compose profile `dhcp`).
2. Register the Windows DC as a `windows_dns` server **with** WinRM credentials (Path B).
3. Click **Sync with Servers** — zones auto-import.
4. Build your subnets pinning the Windows DNS group + the Kea DHCP group.

### Hybrid — Windows DNS + Windows DHCP (read-only mirroring)

1. Don't enable the built-in compose profiles.
2. Register Windows DC(s) as `windows_dns` (Path A or B) + `windows_dhcp` (Path A, read-only).
3. Enable **DHCP Lease Sync** in Settings so leases mirror into IPAM as `status=dhcp`.
4. Manage scopes in Windows DHCP MMC; SpatiumDDI auto-imports them on each lease poll.

This third shape is also the [lowest-risk evaluation pattern](#project-status): SpatiumDDI becomes the source of truth for the address plan while the servers your users depend on keep running exactly as before.

---

## Troubleshooting the first IP

**Symptom: you allocated an IP with a hostname, but no DNS record appeared.**

Work through these in order — each is a likely cause, how to check it, and the fix:

1. **The subnet has no primary DNS zone.** Without one, SpatiumDDI has nowhere to put the A record. *Check:* open the subnet and look at the DNS zone field. *Fix:* set a primary zone on the subnet (or on a parent block/space and let it inherit).
2. **The zone isn't on a server group.** Every zone has to belong to a group; a zone that exists only in the DB reaches no server. *Check:* open the zone and confirm its group. *Fix:* assign it to the group whose servers should serve it.
3. **The group has no enabled server.** A group with zero `is_enabled=True` servers won't push anything — the write succeeds in the DB and goes nowhere. *Check:* the group's server list. *Fix:* enable a server, or add one (step 3).
4. **The server is unhealthy or unreachable.** *Check:* hit **Sync with Servers** and watch the per-server status column. *Fix:* whatever the status reports — network path, service down, credentials.
5. **(Windows Path A) The zone only accepts secure dynamic updates.** Secure-only zones reject SpatiumDDI's unsigned RFC 2136 updates, so record writes silently fail. *Check:* the zone's dynamic-updates setting in Windows DNS Manager. *Fix:* set it to "Nonsecure and secure".
6. **(Windows Path B) Credentials aren't stored — and the same update setting applies.** *Check:* the server detail page shows whether WinRM credentials are configured. Credentials unlock zone create/delete and server-side reads; record writes ride RFC 2136 in both paths, so check that the zone allows nonsecure updates regardless. *Fix:* store the credentials, and apply the fix from item 5.

If a record is expected but missing, the subnet's **Sync DNS** drift report will tell you exactly what's missing and let you apply it with one click.

---

## Glossary

Definitions in setup-order context — each is linked from its first use above.

#### DDI

Industry shorthand for **D**NS + **D**HCP + **I**PAM run as one integrated system, so that names, leases and the address ledger can't drift apart. SpatiumDDI is a DDI platform.

#### Control plane and data plane

The **control plane** decides what the configuration should be — in SpatiumDDI, the API, database and UI. The **data plane** does the actual serving: BIND9/Kea containers or Windows servers answering queries and handing out leases. SpatiumDDI's managed containers cache their last-known-good config, so the data plane keeps serving if the control plane goes down.

#### Zone

The unit of DNS ownership: a portion of the namespace (such as `corp.example.edu`) served authoritatively as one set of records, by one set of servers.

#### Forward and reverse zones

A **forward zone** maps names to addresses (`print-01.corp.example.edu → 10.20.21.10`). A **reverse zone** maps addresses back to names, lives under [`in-addr.arpa` / `ip6.arpa`](#in-addrarpa-and-ip6arpa), and holds [PTR](#ptr-record) records.

#### A and AAAA records

The name-to-address record types: **A** for an IPv4 address, **AAAA** for IPv6.

#### PTR record

The address-to-name record type, stored in a reverse zone. Mail servers, logging and monitoring commonly resolve PTRs, which is why keeping them in sync with A records matters.

#### TTL

Time To Live — how many seconds resolvers may cache a record before asking again. Low TTLs propagate changes fast at the cost of more queries; high TTLs the reverse.

#### DNSSEC

Cryptographic signatures on DNS data so resolvers can verify records weren't forged or tampered with in transit. Adds key material and signing to zone management.

#### Recursion

A **recursive** DNS server chases down answers on behalf of clients, querying other servers as needed. An **authoritative-only** server answers solely for its own zones. Mixing the roles on one server is possible but widens what that server will answer for.

#### AXFR

Full zone transfer — a standard mechanism for pulling a zone's complete contents from a server over TCP. SpatiumDDI uses it to import and compare zones on backends that support it.

#### RFC 2136

The dynamic DNS update protocol: changes individual records on a live server without editing zone files or restarting anything. SpatiumDDI's record writes ride RFC 2136 on BIND9 and on both Windows paths.

#### TSIG

Transaction SIGnature — a shared-secret signature that authenticates DNS messages, commonly required for zone transfers and dynamic updates between parties that must trust each other.

#### in-addr.arpa and ip6.arpa

The special DNS domains where reverse zones live. The zone name is the network portion of the address reversed: `21.20.10.in-addr.arpa` is the reverse zone for `10.20.21.0/24`. IPv6 uses `ip6.arpa` with the address's hex digits reversed one nibble at a time.

#### DHCP scope

A DHCP server's configuration for one subnet: which ranges to serve and with what options (router, DNS servers, domain, lease time).

#### DHCP pool

A contiguous range of addresses inside a scope, with a role: **dynamic** (offered to clients), **reserved** (held for static use), or **excluded** (never offered).

#### DHCP lease

A temporary assignment of an address to a client, with an expiry time. The client must renew before expiry or the address returns to the pool.

#### DHCP reservation

A standing rule that a specific client (usually identified by MAC address) always receives the same IP from DHCP.

#### CIDR

The `network/prefix-length` notation for IP ranges: `10.20.21.0/24` means the first 24 bits are fixed, leaving 256 addresses. A larger number after the slash means a smaller network.

#### RFC 1918

The reserved private IPv4 ranges — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — usable inside any organisation but never routed on the public internet.

#### VLAN

Virtual LAN — a layer-2 network segment isolated by switch configuration. In most designs each VLAN carries exactly one IPv4 subnet, which is why SpatiumDDI lets you link a VLAN ID to a subnet.

#### WinRM

Windows Remote Management — the remote-management channel (remote PowerShell) SpatiumDDI uses to drive existing Windows DNS/DHCP servers without installing anything on them.

#### Agent and agentless

An **agent** backend is a container SpatiumDDI deploys and configures itself (built-in BIND9, PowerDNS, Technitium, Kea). An **agentless** backend is an existing server SpatiumDDI drives remotely over that server's own protocols ([WinRM](#winrm), [RFC 2136](#rfc-2136), cloud provider APIs) with nothing installed on it.

---

## Next steps

- **Tag your subnets** — custom fields and tags propagate to IPs, and bulk-edit respects them.
- **Set up audit log filtering** — every mutation is already logged; the admin **Audit** page gives per-column filters.
- **Enable the health dashboard** — the **System** section surfaces server/agent status and recent errors.
- **Turn on the reconciliation jobs** once the system is stable.

For deeper dives:

- [IPAM features](features/IPAM.md) — custom fields, tags, bulk operations, import/export.
- [DNS features](features/DNS.md) — views, ACLs, blocklists, DDNS, zone import.
- [DHCP features](features/DHCP.md) — pools, client classes, options, static assignments.
- [Permissions](PERMISSIONS.md) — how to delegate subnets, zones, and scopes to different groups.
- [Windows setup](deployment/WINDOWS.md) — WinRM, service accounts, firewall rules.
