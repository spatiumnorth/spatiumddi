# DNS Feature Specification

> **Implementation status (snapshot):** Full CRUD for groups / servers / zones / records / views / ACLs / trust anchors; BIND9 driver with TSIG + RFC 2136 dynamic updates; agent auto-registration and long-poll config sync with ETag; RPZ blocklists actively rendered by the agent (nxdomain / sinkhole / redirect / passthru; wildcard + exceptions); **curated 19-source RPZ blocklist catalog** with one-click subscribe, plus built-in **templates** (SafeSearch enforcement) and one-click **profiles** (Family filter) — issue #878; per-entry `reason` and `is_wildcard` toggles; zone import/export (RFC 1035); **conditional forwarders as a first-class zone type**; **zone delegation wizard** (auto-stamps NS + glue records in the parent zone); **four starter zone-template wizards** (Email / Active Directory / Web / k8s external-dns target); **operator-managed TSIG keys** with Fernet-encrypted secrets and one-shot reveal modal; query logging + **clickable analytics strip** (top qnames + top clients + qtype distribution); **multi-resolver propagation check** (Cloudflare / Google / Quad9 / OpenDNS in parallel); **BIND9 catalog zones (RFC 9432)** with producer / consumer roles auto-derived from the group's primary; per-server zone serial reporting + drift pill; health checks; IPAM ↔ DNS drift detection & reconciliation (`Check DNS Sync` on subnet/block/space); reverse-zone auto-create + backfill; **Windows DNS driver shipped** — Path A (agentless, RFC 2136) and Path B (agentless, WinRM + PowerShell for zone CRUD and zone-record pull that sidesteps AXFR); group-level "Sync with Servers" button performs bi-directional zone reconciliation; **BIND9 Response Rate Limiting (RRL) + amplification toggles** (responses-per-second / window / slip / qps-scale / exempt-clients / log-only dry-run + minimal-responses / tcp-clients / clients-per-query; group-level, default-off — issue #146 Phase 1); **BIND9 + PowerDNS + Technitium DNSSEC** — inline-signing policies, DS export, manual rollover on BIND9 (issue #49 — see §3.3a); **Technitium driver shipped** — REST-API-driven authoritative agent with primary / secondary / stub / forward zones, catalog zones as producer *and* consumer, online DNSSEC, and native DoT / DoH / **DoQ** listeners plus encrypted upstream forwarding over all three, with no dnsdist-style sidecar (issues #746 / #740 / #741 / #743 / #744 — see §0 and [`DNS_DRIVERS.md` §4B](../drivers/DNS_DRIVERS.md)); **encrypted transports shipped** — DoT / DoH served and forwarded, per-group and default-off (issue #50 — see §20). **Deferred:** Technitium query-log shipping (issue #742), secondary-zone (AXFR/IXFR) full support, GSS-TSIG (Kerberos-signed RFC 2136), Windows DNS Path B record-level writes.

## Overview

SpatiumDDI manages DNS servers as first-class resources. It acts as the **authoritative source of truth** for all DNS configuration, pushing changes to backend DNS servers via their respective drivers. The DNS subsystem supports:

- Forward and reverse zones organized in a **tree hierarchy**
- **Multiple DNS server groups** (e.g., internal, external, DMZ)
- **DNS views** (split-horizon) per server group
- **Dynamic DNS (DDNS)** — automatic record creation from DHCP leases
- **Incremental record updates** — no server restarts for record changes
- **Blocking lists** — integrated ad/malware blocking similar to Pi-hole
- **Per-zone assignment** to IP ranges/subnets
- Role-based access control on zones

---

## 0. Driver choice — BIND9, PowerDNS, Technitium, or Windows DNS

SpatiumDDI ships five authoritative DNS drivers (Technitium in two shapes — see below), plus the eight cloud providers in §0a. Pick **per server group** — every server inside a group runs the same driver, but mixed installs (one group on BIND, another on PowerDNS, a third on Technitium, a fourth on Windows) are first-class. The driver registry is in [`drivers/dns/__init__.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/__init__.py); the per-driver internals are in [`docs/drivers/DNS_DRIVERS.md`](../drivers/DNS_DRIVERS.md).

| Capability | BIND9 | PowerDNS | Technitium | Windows DNS |
|---|:---:|:---:|:---:|:---:|
| Authoritative zone serving | ✅ | ✅ | ✅ | ✅ |
| Recursive resolver | ✅ | — (recursor is a separate daemon) | ✅ (own daemon, not exposed in v1) | ✅ |
| Record CRUD wire protocol | RFC 2136 + rndc | REST API (PATCH rrsets) | REST API (per-record add/delete) | RFC 2136 (Path A) / WinRM (Path B) |
| Zone CRUD wire protocol | rndc addzone / delzone | REST API | REST API | WinRM (Path B only) |
| ALIAS records (CNAME at apex) | — | ✅ | — (has ANAME/APP instead — deferred) | — |
| LUA records (computed responses) | — | ✅ | — | — |
| Online DNSSEC signing | ✅ inline-signing (#49) | ✅ one-toggle | ✅ one-toggle (#740) | manual |
| Native DoT / DoH (no sidecar) | ✅ (issue #50) | — (needs dnsdist sidecar) | ✅ + DoQ (issue #741) | — |
| Encrypted *upstream* forwarding | DoT only (no client-side HTTP) | — | DoT / DoH / DoQ (#741) | — |
| Catalog zones (RFC 9432) — producer | ✅ | ✅ | ✅ | — |
| Catalog zones (RFC 9432) — consumer | ✅ | — (not wired up in the agent) | ✅ | — |
| First-class views / split-horizon | ✅ | tag-based, not surfaced as views in UI | — | — (replication scope) |
| RPZ blocklists | ✅ | — (recursor feature only) | native blocking, not RPZ (#744) | — |
| AD-integrated zones | — | — | — | ✅ |
| Agent shape | sidecar agent + named | sidecar agent + pdns_server | sidecar agent + DnsServerApp.dll | agentless (control plane → WinRM) |

**Default driver: BIND9.** It is the reference implementation, ubiquitous in operator muscle memory, and runs the catalog-zone consumer + RPZ paths SpatiumDDI ships.

**Pick PowerDNS when** you need ALIAS records (CNAME-at-apex without the BIND-side workaround), LUA records (geo-routing / weighted answers / `pickrandom` / `ifportup`), or the simpler one-toggle online DNSSEC story. The shipped image (`ghcr.io/spatiumnorth/dns-powerdns`) bundles `pdns 5.0 + pdns-backend-lmdb` for an agent-isolated zone store with no external Postgres dependency. See [issue #127](https://github.com/spatiumnorth/spatiumddi/issues/127) for the full driver rationale.

**Pick Technitium when** you want a minimal-footprint REST-driven authoritative host and don't need ALIAS/LUA. It covers primary / secondary / stub / forward zones, catalog zones (producer and consumer), TSIG-authenticated zone transfer, and the standard record types (A/AAAA/CNAME/MX/TXT/NS/PTR/SRV/CAA/TLSA/SSHFP/NAPTR/URI/SVCB/HTTPS/DNAME) — see [`docs/drivers/DNS_DRIVERS.md` §4B.3a](../drivers/DNS_DRIVERS.md). Its real differentiator is native DNS-over-TLS/HTTPS/QUIC with no dnsdist-style sidecar (PowerDNS's approach), *and* encrypted upstream forwarding over all three — BIND9 forwards over DoT only, and PowerDNS does not forward at all. That wiring shipped in [#741](https://github.com/spatiumnorth/spatiumddi/issues/741); see §20 below. Online DNSSEC signing ([#740](https://github.com/spatiumnorth/spatiumddi/issues/740)) and the live-pull importer ([#744](https://github.com/spatiumnorth/spatiumddi/issues/744)) shipped too. The one thing still outstanding is query-log shipping — [#742](https://github.com/spatiumnorth/spatiumddi/issues/742) — so a Technitium group's queries don't reach the Logs page's DNS Queries tab yet.

**Pick `technitium_api` when the Technitium server already exists** and should stay where it is. It is the same daemon and a different *ownership* model: agentless, nothing deployed, and the control plane drives Technitium's HTTP API directly with an operator-supplied bearer token — the same shape as Windows DNS Path B. Zones and records only; DNSSEC, encrypted transports, forwarders and blocklists stay managed in Technitium's own console, because those are the agent-managed driver's surface. Add it under **Add DNS server → Technitium (agentless, remote API)** with the API URL (`https://host:53443`, or `:5380` for plain HTTP) and a permanent token from Administration → Sessions → Create Token. Create that token against a limited user with **Zones: Modify** + **DnsClient: View** rather than the admin account — it inherits that user's permissions, including per-zone ACLs. Shipped in [#810](https://github.com/spatiumnorth/spatiumddi/issues/810); internals in [`DNS_DRIVERS.md` §4C](../drivers/DNS_DRIVERS.md).

> A group is single-driver, so `technitium` and `technitium_api` servers live in separate groups. If you want SpatiumDDI to run the daemon, use `technitium`; if it is already running, use `technitium_api`.

**Pick Windows DNS when** the zone is AD-integrated and operators expect to keep using DNS Manager / `Add-DnsServerResourceRecord` directly. Path A (RFC 2136 + AXFR) works without admin credentials; Path B (WinRM + PowerShell) unlocks zone CRUD and a JSON record-pull that sidesteps AXFR ACL configuration.

Driver-gated features are enforced server-side by the API's `_DRIVER_GATED_RECORD_TYPES` and `_DRIVER_GATED_OPERATIONS` maps. Calling one against a group with no member on a supporting driver returns 422 with a remediation message — move the zone to a group on a supporting driver, or add such a server to the group, before retrying. The current gates:

| Gated thing | Allowed drivers |
|---|---|
| `ALIAS`, `LUA` records | `powerdns` |
| `SVCB`, `HTTPS`, `DNAME` records | `bind9`, `powerdns`, `technitium` |
| `dnssec_sign` / `dnssec_unsign` | `bind9`, `powerdns`, `technitium` |
| `dnssec_rollover` (manual key rollover) | `bind9` |

Manual rollover stays BIND9-only on purpose: PowerDNS and Technitium each roll on their own schedule (Technitium carries `rolloverDays` per key), so exposing a manual rollover against them would fight the daemon.

The Operator Copilot's `propose_create_dns_zone` tool accepts an explicit `driver_hint` argument (`bind9` / `powerdns` / `technitium` / `windows_dns`) so the LLM can route a zone to a matching group without operators having to specify the group UUID by hand. See `app.services.ai.operations.CreateDNSZoneArgs`.

Its `dnssec_enabled=true` path reads the same `dnssec_sign` row of the table above rather than restating it, with the same subset rule — *every* server in the group must run a signing driver, and an empty group passes — so the tool accepts exactly the groups the REST API accepts (issue #798; a test asserts the two agree for every driver, because they had drifted once).

Creating a zone with `dnssec_enabled=true` signs it in the same request ([#811](https://github.com/spatiumnorth/spatiumddi/issues/811)): both `POST /api/v1/dns/groups/{id}/zones` and the Copilot tool enqueue the same `dnssec_sign` op the zone's **Sign** action does. BIND9 ignores the op and converges from the rendered config alone (inline-signing); PowerDNS and Technitium sign in response to it. Flipping `dnssec_enabled` through the generic zone-update endpoint behaves identically. The one caveat is a group with no servers yet: the create succeeds (nobody to disagree) but there is no agent to queue against, so signing starts from a manual **Sign** once servers join. Turning the flag **off** is allowed on any group — a zone flagged on a group that could never have signed has nothing to unsign, and clearing the stale flag must stay possible.

### 0a. Cloud DNS providers — Cloudflare / Route 53 / Azure DNS / Google Cloud DNS (issue #37)

**Add DNS server** also offers four cloud-hosted authoritative-DNS providers as driver choices: **Cloudflare**, **Amazon Route 53**, **Azure DNS**, and **Google Cloud DNS**. Once added, their zones and records are managed exactly like a local BIND9 / PowerDNS / Technitium zone — same Zones / Records / group surfaces, same CRUD — but the control plane drives the provider's REST/SDK API directly instead of an agent (an *agentless* driver, the same shape as Windows DNS Path B). A cloud DNS server lives in a normal `DNSServerGroup`; credentials are a provider-specific dict (Cloudflare API token, Route 53 access keys, an Azure service-principal triple + subscription / resource group, or a GCP service-account JSON + project id) entered in the Add DNS server modal and Fernet-encrypted in `DNSServer.credentials_encrypted`.

The modal renders a per-driver **in-modal setup guide** for the required credential fields and a **Test** button that does a cheap auth + list-zones probe before save. No cloud driver advertises *online* DNSSEC sign/unsign — cloud DNSSEC is a provider-level zone toggle, not the per-record online signing SpatiumDDI's `dnssec_sign`/`unsign` ops model, so those operations stay gated to BIND9 / PowerDNS / Technitium (#29 follow-up). Full per-driver internals (credential shapes, capability matrix, per-provider wrinkles) are in [DNS_DRIVERS.md §4A](../drivers/DNS_DRIVERS.md).

**Bringing existing zones in.** A cloud account that already hosts zones imports through the DNS importer's cloud source (preview → commit; see [MIGRATION.md](MIGRATION.md)). After that, ongoing drift is reconciled the same way as any other server — the **sync-from-server** path pulls the provider's live zone/record state via the driver's `pull_zones_from_server` / `pull_zone_records` reads.

A **token-only tier** (DigitalOcean / Hetzner / Linode / Vultr, issue #327) ships alongside the four headline providers as agentless first-class drivers with the same import-existing-zones flow.

These cloud-DNS drivers are distinct from the *Cloud (AWS / Azure / GCP)* read-only **infrastructure** mirror (issue #37 Part A — VPCs / subnets / instance IPs into IPAM; see [INTEGRATIONS.md](INTEGRATIONS.md)). One is authoritative-DNS management; the other is an IPAM reconciler. They share a provider vocabulary, not a code path.

---

## 1. DNS Server Groups

DNS servers are organized into named **groups** representing logical server clusters (not just individual servers). This reflects real-world deployments where you may have multiple resolvers per role.

### Group Model

```
DNSServerGroup
  id, name, description
  type: enum(internal, external, dmz, custom)
  default_view: str           -- which view clients in this group see by default
  is_recursive: bool          -- whether servers in group act as resolvers
  servers: [DNSServer]        -- one or more physical/virtual servers

DNSServer
  id, group_id, name
  driver: enum(bind9, powerdns, windows_dns, cloudflare, route53, azuredns, googledns, digitalocean, hetzner, linode, vultr)
  host, port
  credentials (encrypted)
  roles: [enum(authoritative, recursive, forwarder)]  -- server can have multiple roles
  status, last_sync_at, last_health_check_at
```

### Example Topology

```
Groups:
  "internal-resolvers"  → 2x BIND9 servers, recursive, serves internal view
  "dmz-resolvers"       → 1x BIND9, forwarder for DMZ hosts
```

A server may belong to only one group but may have **multiple roles** (e.g., both authoritative and recursive).

### Moving a server between groups (#934)

An auto-registered agent lands in the group its `AGENT_GROUP` names, or in
`default` when it names none — which is rarely the group the operator wants
it in permanently. Send `group_id` on
`PUT /api/v1/dns/groups/{current_group_id}/servers/{server_id}`, or use the
**Server group** picker in the server's edit modal. Note the URL names the
group the server is *leaving* and the body the one it is joining; addressing
it under the target group is a 404.

Re-sending the server's current `group_id` is a no-op, so an idempotent PUT
that echoes the whole row back is safe.

The move is not just a column write. It also:

* **Purges the server's `DNSServerZoneState` rows and its pending
  `DNSRecordOp`s.** Both reference the *old* group's zones — left behind, the
  Zone Sync pill reports convergence for zones this server no longer serves,
  and the queued RFC 2136 updates would be shipped to a daemon that has never
  heard of those zones. Already-applied ops are history and stay.
* **Clears the `config_apply_*` verdict (#882).** `ok` means "the live config
  is the saved one"; a move changes the saved one, so carrying it across is
  false at the instant of commit. NULL is UNKNOWN, never ok.
* **Re-elects primaries on both sides.** Moving a group's primary out elects
  the oldest enabled, unpaused survivor — a group with none silently drops
  every record write to its zones. In the target the server is elected only
  if there is no primary already; an existing one is never demoted, because
  two primaries in one group is not a tie-break, it raises inside the agent
  long-poll and stops the whole group converging.
* **Generates the target group's TSIG key if it has none.** A group created
  in the UI has never been through agent registration, where that key was
  historically generated.
* **Wakes both groups and the server's own channel.** The server channel is
  what reaches an agent already parked in a long-poll — its subscription was
  built from the old group, so a group wake alone would not reach it.

Two refusals: a **name collision** in the target group (409 — server names are
unique per group), and a move that would leave the target **mixed-driver**
(422). The second fails closed here even though a mixed group is still
reachable by other paths: a group is single-driver (see
[`DNS_DRIVERS.md` §5.1](../drivers/DNS_DRIVERS.md)) and the driver-gated
operations only notice at DNSSEC-sign / ALIAS time, long after the mistake.
Moving into an *empty* group is always allowed, whatever its driver — that is
the common case.

The move survives agent re-registration, on both deployment shapes — but for
two different reasons, and the difference matters if you are debugging one.

On a **standalone agent** (Docker / Kubernetes), the group comes from the
container's own `AGENT_GROUP`. `/register` resolves an existing row by
`agent_id` first, with no group filter, and never writes `group_id` on a row
it finds — so a stale `AGENT_GROUP` neither drags the server back nor forks a
second row in the old group. There is no need to edit the agent's environment
after moving it, though leaving it accurate is tidier.

On an **appliance** (#170), the agent is not configured from its own
environment at all: the supervisor derives both `AGENT_GROUP` and the per-role
nftables ports from `Appliance.assigned_dns_group_id`. The move therefore
**repoints that field too**, and wakes the supervisor's heartbeat so it
re-applies rather than waiting out its interval. Without that the firewall
would keep the *old* group's DoT/DoH/DoQ ports open while the agent listens on
the new group's — a failure that leaves every config valid and the listener
simply unreachable. The pointer is only moved when it currently names the
group being left; an appliance deliberately assigned elsewhere is not
redirected on the strength of one server row moving.

### Moving a zone between groups (#935)

Zones are group-bound too, but a zone is a much sharper thing to move than a
server: it holds references **into** its group, and the sharpest of those is
the view. Preview → commit rather than a single call, at
`POST /api/v1/dns/groups/{gid}/zones/{zid}/move/{preview,commit}` or the
**Move** button on the zone detail. The preview writes nothing and is safe to
re-run; the commit re-derives the same plan inside an advisory lock, so a view
or key created in between changes the answer rather than being applied against
a stale reading.

**Clearing a view widens exposure — this is the property to understand.**
Under split-horizon a record with a view set renders in exactly that view; one
with no view is *shared* and renders in **every** view. So when the target
group has no view of the same name, dropping the reference does not remove the
zone from a view, it adds it to all of them. A zone that answered only on
`internal` starts answering on `external`, with no operator-visible symptom.
Views are therefore remapped **by name** wherever the target has a match
(a view called `internal` in each group is the operator's own statement that
the two mean the same thing), and where it does not, the move refuses until
the operator acknowledges the widening explicitly.

Three acknowledgements exist, each its own checkbox rather than one blanket
"I understand", so the DNSSEC warning cannot be accepted by someone who only
read the view one:

| Key | When | Why it is not just a warning |
|---|---|---|
| `view_widening` | a view reference cannot be resolved in the target, which renders views | the zone or record goes from answering in one view to answering in all of them |
| `dnssec_rollover` | the zone is signed | the private keys live on the **current** group's servers and do not move; the target signs from scratch, so the DS at the registrar is wrong until republished and validation fails in the interval |
| `lost_update_grants` | a dynamic-update grant names a TSIG key absent from the target | the row cannot be kept (`num_nonnulls(tsig_key_id, ip_cidr) = 1` forbids clearing the key) so it is deleted, and the clients using it lose the ability to update the zone |

The commit also requires the zone name typed back, the way the IPAM block move
requires a typed CIDR.

What the move does besides reassigning the row:

* **Views and TSIG keys remap by name**, per the above. Dynamic-update grants
  matched to a same-named key in the target keep working with no operator
  action.
* **Pools follow the zone.** They are attached by `zone_id` and their health
  checks run from the control plane rather than the group's agents, so nothing
  about them is bound to the old group.
* **Per-server zone state and queued record updates are purged** — both
  describe the old group's servers.
* **DNSSEC key state is deleted.** It is a read-only mirror of what the old
  group's agents reported; leaving it would show the operator keys that no
  server holds.
* **Both group channels are woken** so each side converges immediately.

Refusals, none of them waivable by acknowledgement — each would leave a state
the operator could not inspect and fix afterwards:

* a **name collision** in the target (409), checked against the *resolved*
  view rather than the original: the constraint is `(group_id, view_id, name)`,
  so a zone whose view is cleared lands at `(target, NULL, name)` and can
  collide with an unviewed zone a `(group, name)` check would have missed —
  while the same name in two different views is not a collision at all;
* a move to the group the zone is already in (422);
* a **signed zone onto a group that cannot sign** (422). The row would keep
  reporting `dnssec_enabled` while the zone is served unsigned, indefinitely,
  with nothing to notice — the same driver gate every other path into a signed
  zone goes through;
* a **named ACL** cited in the zone's `allow_query` / `allow_transfer` /
  `also_notify` that the target group does not define (422). `DNSAcl` is
  per-group, so the name becomes an undefined symbol — and BIND rejects the
  file *whole*, which stops the entire target group converging rather than
  just this zone;
* a **forwarders-less forward zone onto a Technitium group** (422), the same
  #743 guard every create and update runs.

A zone owned by an integration reconciler (Tailscale, NetBird) cannot be moved
at all — the next sync would recreate it in the group the integration is bound
to. That one is refused on the *preview* as well, so it is learned before the
modal is filled in.

**Agentless groups are driven at both ends.** When either side runs
`windows_dns`, a cloud driver or `technitium_api`, the zone lives in a system
the ConfigBundle never reaches, so the move creates it on the target's servers
and deletes it from the source's. Create runs first: if either call fails the
whole move rolls back, and a failed create leaves nothing changed where a
failed delete would have removed the zone from the old server while the
database still said it lived there.

A **driver change warns rather than refuses**, unlike the server move: a zone
is data, not a driver-bound thing, so moving one from a BIND9 group to a
PowerDNS group is a legitimate migration — but driver-specific features
(ALIAS, DNSSEC signing, per-driver record types) may not survive, so it says
so. An **ACME DNS-01 delegation** on the zone is also flagged: its TXT records
will be written by the target's servers while the NS delegation at the
registrar still points at the old group's, so issuance fails until repointed.

### Designating the group primary (#934)

`is_primary` marks the one server per group that DDNS and record writes are
applied at. It is auto-elected on create and on first agent registration when
the group has none; send `is_primary: true` on the same PUT to move it, which
demotes whichever server currently holds it. **Clearing the last primary is
refused (422)** — it re-creates the footgun the auto-election exists to
prevent, and the resulting dropped writes are silent (a log line; no error
reaches whoever made the change). Promote a replacement instead; that demotes
the incumbent as a side effect.

---

## 2. DNS Views (Split-Horizon)

Views allow the same zone name to return **different data** depending on the source IP of the DNS query. This is a native BIND9 feature.

### View Model

```
DNSView
  id, server_group_id, name
  description
  match_clients: [CIDR list]     -- source IPs that see this view
  match_destinations: [CIDR list]
  recursion: bool
  zones: [DNSZone]               -- zones present in this view (may differ per view)
  order: int                     -- views are evaluated in order (first match wins)
```

### Common View Pattern

| View Name | match_clients | What It Returns |
|---|---|---|
| `internal` | 10.0.0.0/8, 192.168.0.0/16 | Full internal zone data, internal IP for split names |
| `external` | any (0.0.0.0/0) | Public IP only, limited record set |
| `dmz` | 172.16.0.0/12 | DMZ-specific overrides |

### BIND9 Implementation
- Views map directly to BIND9 `view {}` blocks in `named.conf`
- Each view has its own set of `zone {}` directives
- Config is generated by the driver and pushed via `rndc reconfig` (no restart)

---

## 3. DNS Server Options & ACLs

Server-level options control how each DNS server (or server group) behaves globally — independent of any individual zone. These map to BIND9 `options {}` / `view {}` blocks. All settings are stored in the `DNSServerOptions` model and pushed to the server by the driver on change.

### 3.1 Forwarders

Forwarders are upstream resolvers used when the server cannot answer from its own zones.

```
DNSServerOptions.forwarders: list[str]          -- e.g. ["1.1.1.1", "8.8.8.8"]
DNSServerOptions.forward_policy: enum(
  first,     -- try forwarders first, fall back to recursion (BIND9 "forward first")
  only,      -- send all queries to forwarders, never recurse (BIND9 "forward only")
)
```

- **BIND9:** `forwarders { 1.1.1.1; 8.8.8.8; }; forward first|only;` in `options {}` or per-view
- Per-zone forward overrides (stub/forward zone type) take precedence over global forwarders

### 3.2 Recursion

Controls whether the server will follow referrals to resolve names it is not authoritative for.

```
DNSServerOptions.recursion_enabled: bool        -- default true for internal resolvers
DNSServerOptions.allow_recursion: list[str]     -- CIDR list; who may use this server as a resolver
                                                --   e.g. ["10.0.0.0/8", "192.168.0.0/16"]
                                                --   "any" or "none" are also valid literals
```

- **BIND9:** `recursion yes|no;` + `allow-recursion { <acl>; };` in `options {}` or per-view
- Authoritative-only servers must have `recursion_enabled: false` + `allow_recursion: ["none"]`

### 3.3 DNSSEC Resolution

Controls whether the server validates DNSSEC signatures when resolving.

```
DNSServerOptions.dnssec_validation: enum(
  auto,      -- validate using built-in / managed-keys (recommended)
  yes,       -- validate; trust anchors must be manually configured
  no,        -- do not validate DNSSEC
)

DNSServerOptions.trust_anchors: list[DNSTrustAnchor]

DNSTrustAnchor
  id, server_options_id
  zone_name: str          -- e.g. "." for root, "example.com." for island trust
  algorithm: int          -- DNSKEY algorithm number (e.g. 13 = ECDSAP256SHA256)
  key_tag: int
  public_key: str         -- base64-encoded DNSKEY public key
  is_initial_key: bool    -- true = initial-key (RFC 5011 managed), false = static-key
  added_at, added_by
```

- **BIND9:** `dnssec-validation auto|yes|no;` in `options {}` or per-view; trust anchors go in `managed-keys {}` or `trust-anchors {}`
- The root DNSSEC trust anchor (ICANN KSK) is pre-loaded automatically when `dnssec_validation: auto`
- UI shows DNSSEC chain validation status for each zone

> **Validation vs. signing.** The setting above controls whether the
> server *validates* answers as a resolver. *Signing* your own zones is a
> separate feature — see §3.3a (BIND9) / §0 (PowerDNS).

### 3.3a Zone signing — BIND9 inline-signing (issue #49)

BIND9 9.16+ `dnssec-policy` inline-signing. A **DNSSECPolicy** maps 1:1
to a BIND `dnssec-policy "<name>" { ... };` block — algorithm, NSEC3
params, KSK/ZSK lifetimes — and a zone references one. **BIND owns and
auto-rotates the private keys** (the modern, recommended model); SpatiumDDI
stores only the *public* state it reports back (DS rrset + per-key status),
so there is no private-key custody.

- **Policies** are managed at **DNS → DNSSEC Policies** (`/dns/dnssec-policies`).
  A built-in `default` policy (ECDSAP256SHA256, NSEC, unlimited KSK +
  90-day auto-rolled ZSK) is seeded and read-only.
- **Sign a zone** from its DNSSEC card (`POST .../dnssec/sign` with an
  optional `policy_id` — null ⇒ `default`). Signing is **config-driven**:
  flipping `dnssec_enabled` (+ policy) reshapes the agent ConfigBundle, the
  agent renders `dnssec-policy "<name>"; inline-signing yes;` into the zone
  stanza (and a top-level `dnssec-policy { }` block for custom policies),
  BIND auto-generates keys in `key-directory` and signs.
- **DS export.** After signing the agent runs `rndc dnssec -status` +
  `dnssec-dsfromkey` and reports the DS rrset + per-key state back via
  `POST /dns/agents/dnssec-state`; the card surfaces the DS records to
  paste at the parent registrar, plus a per-key table (tag / type / state).
- **Manual rollover.** The card's per-key **Roll** button
  (`POST .../dnssec/rollover`) enqueues a `dnssec_rollover` op; the agent
  runs `rndc dnssec -rollover -key <tag>`. Routine rollover is automatic
  per the policy — this is the "roll now" escape hatch.
- **Driver gating.** Sign/unsign are allowed on BIND9 + PowerDNS groups,
  rollover on BIND9 only; Windows DNS is refused (422). NSEC3 follows
  RFC 9276 (iterations 0 + salt-length 0 recommended) — the policy editor
  warns when iterations > 0.

### 3.4 GSS-TSIG

GSS-TSIG enables Kerberos-based authentication for secure DNS updates, used primarily with Active Directory / Windows DNS integration.

```
DNSServerOptions.gss_tsig_enabled: bool        -- default false
DNSServerOptions.gss_tsig_keytab_path: str     -- path to keytab on DNS server host
DNSServerOptions.gss_tsig_realm: str           -- e.g. "CORP.EXAMPLE.COM"
DNSServerOptions.gss_tsig_principal: str       -- e.g. "DNS/ns1.corp.example.com@CORP.EXAMPLE.COM"
```

- **BIND9:** `tkey-gssapi-keytab "/etc/bind/dns.keytab";` + `tkey-domain "CORP.EXAMPLE.COM";`
- When enabled, DDNS updates from Windows clients use Kerberos tickets rather than HMAC-TSIG keys
- The keytab file is deployed to the DNS server host by the SpatiumDDI agent; the path is stored (not the keytab content itself)
- Required for seamless AD/DNS integration and Windows Secure Dynamic Update

### 3.5 Notify

Controls whether the primary server notifies secondaries when a zone changes.

```
DNSServerOptions.notify_enabled: bool | enum(explicit, master-only, yes, no)
                                                -- "explicit" = only servers in also-notify list
DNSServerOptions.also_notify: list[str]         -- extra IPs to notify beyond NS records
                                                --   e.g. ["10.0.0.53", "10.0.1.53"]
DNSServerOptions.allow_notify: list[str]        -- who may send NOTIFY to this server
                                                --   (for secondary servers receiving notifies)
                                                --   e.g. ["10.0.0.1", "10.0.0.2"]
```

- **BIND9:** `notify yes|explicit|master-only|no;` + `also-notify { ... };` + `allow-notify { ... };`
- Notify settings can be overridden per-zone (the zone model inherits from server defaults)
- `also_notify` is useful when secondaries are stealth (not listed in zone NS records)
- `allow_notify` on secondaries controls which primaries are trusted to trigger a zone transfer

### 3.6 Query & Transfer Access Controls

Fine-grained controls over who can query, use the cache, transfer zones, and what gets blackholed.

```
DNSServerOptions.allow_query: list[str]         -- who may submit DNS queries
                                                --   default: ["any"]
DNSServerOptions.allow_query_cache: list[str]   -- who may use the recursive cache
                                                --   default: ["localhost", "localnets"]
DNSServerOptions.allow_transfer: list[str]      -- who may receive full zone transfers (AXFR/IXFR)
                                                --   default: ["none"]
DNSServerOptions.blackhole: list[str]           -- queries from these addresses are dropped silently
                                                --   e.g. ["192.0.2.0/24", "198.51.100.0/24"]
```

- **BIND9:** `allow-query { <acl>; };`, `allow-query-cache { <acl>; };`, `allow-transfer { <acl>; };`, `blackhole { <acl>; };` in `options {}` or per-view
- All values accept BIND9 ACL names (see §3.7), CIDRs, or literals (`any`, `none`, `localhost`, `localnets`)
- Can be overridden at the **view** level and further overridden at the **zone** level
- `blackhole` is applied before any ACL processing — matching queries receive no response (useful for DoS mitigation)
- `allow_query_cache` should be restricted to internal clients on authoritative-only servers (`none`)

### 3.7 DNS ACLs (Named Access Control Lists)

Named ACLs are reusable address match lists that can be referenced in any option above. They avoid repeating long CIDR lists across multiple settings.

```
DNSAcl
  id, server_group_id (nullable — global ACLs apply to all groups in the server group)
  name: str             -- e.g. "internal-clients", "trusted-secondaries"
  description: str
  entries: list[DNSAclEntry]

DNSAclEntry
  id, acl_id
  value: str            -- CIDR, IP, key name (e.g. "!10.0.0.5", "key my-tsig-key")
  negate: bool          -- if true, prefix with ! in generated config
  order: int            -- entries evaluated in order; first match wins
```

**Predefined ACL literals (no definition needed):**

| Literal | Meaning |
|---|---|
| `any` | All addresses |
| `none` | No addresses |
| `localhost` | All loopback addresses on the server |
| `localnets` | All directly attached networks |

**Example usage:**

```
ACL "internal-clients": 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12
ACL "trusted-secondaries": 10.0.0.53, 10.0.1.53

allow_query:       ["internal-clients", "any"]   -- queries from anywhere allowed (auth server)
allow_query_cache: ["internal-clients"]           -- only internal clients use cache
allow_transfer:    ["trusted-secondaries"]        -- only known secondaries get AXFR
blackhole:         ["198.51.100.0/24"]            -- silently drop known bad actor range
```

- **BIND9:** ACLs are emitted as `acl "<name>" { ... };` blocks at the top of `named.conf`, before `options {}` and `view {}` blocks
- ACLs are managed at the **server group** level; views and zones within that group reference them by name
- UI: ACL editor under DNS Server Group settings — list of named ACLs, each with an ordered entry list; drag-to-reorder entries; inline negation toggle

### 3.8 Rate limiting (RRL) + amplification defenses (issue #146)

BIND9 Response Rate Limiting (RRL) and the related amplification-reduction knobs are exposed on `DNSServerOptions` (group-level; they apply to every view on the group) and render into the `options {}` block of `named.conf`. RRL is the single most effective in-process defense against DNS amplification — it drops or truncates duplicate responses to the same client `/24` + qname within a sliding window.

```
DNSServerOptions.rrl_enabled: bool                  -- default false (feature off — no rate-limit{} block rendered)
DNSServerOptions.rrl_responses_per_second: int      -- 1–1000; per-client-/24 response budget
DNSServerOptions.rrl_window: int                    -- 1–3600 seconds; the accounting window
DNSServerOptions.rrl_slip: int                      -- 0–10; every Nth dropped response is truncated (TC=1)
                                                    --   instead of dropped, so legit clients can retry over TCP
DNSServerOptions.rrl_qps_scale: int | null          -- optional; tighten the limit as overall QPS rises
DNSServerOptions.rrl_exempt_clients: list[str]      -- CIDRs / ACL names never rate-limited (e.g. your secondaries)
DNSServerOptions.rrl_log_only: bool                 -- default false; DRY RUN — count + log would-be drops without
                                                    --   actually dropping. Use to size the limit before enforcing.

DNSServerOptions.minimal_responses: bool            -- default false; emit "minimal-responses yes;" to shrink the
                                                    --   amplification payload (omit the extra section unless required)
DNSServerOptions.tcp_clients: int | null            -- optional; max simultaneous TCP clients
DNSServerOptions.clients_per_query: int | null      -- optional; starting per-query duplicate-client cap
DNSServerOptions.max_clients_per_query: int | null  -- optional; ceiling for clients_per_query
```

- **BIND9:** renders into `options {}`:
  ```
  rate-limit {
      responses-per-second 15;
      window 15;
      slip 2;
      qps-scale 250;                       // only when set
      exempt-clients { 10.0.0.0/8; };      // only when non-empty
      log-only yes;                        // only when rrl_log_only
  };
  minimal-responses yes;                   // only when minimal_responses
  tcp-clients 150;                         // only when set
  clients-per-query 10;                    // only when set
  max-clients-per-query 100;               // only when set
  ```
- **Defaults are a no-op.** With `rrl_enabled=false`, `minimal_responses=false`, and the optional knobs unset, the rendered `named.conf` is byte-identical to before the feature existed — adding it never changes an existing group's behavior until an operator opts in.
- **PowerDNS:** authoritative `pdns_server` has no RRL equivalent; the project's answer there is a **dnsdist front** (Phase 2 — see below). These RRL/amplification knobs are BIND9-only.
- **Recommended starting point** for an internet-facing authoritative server: `rrl_enabled=true`, `responses-per-second≈15`, `window=15`, `slip=2`, exempt your own secondaries. Run with `log-only=true` first and watch the drop counters before enforcing.
- UI: **DNS → Server Group → Server Options → "Rate limiting (RRL) & amplification"** card.
- MCP: `find_dns_rate_limit_settings` (read-only) reports the posture per group.
- **Observability (Phase 3 — shipped):** the BIND9 agent ships `RateDropped` + `RateSlipped` from the statistics-channels XML as `rate_dropped` / `rate_slipped` on the per-minute `dns_metric_sample`; the server detail modal's Stats tab draws an **"RRL drops/s"** line (shown once a server has dropped anything), and the default-off **`dns_rate_limit_dropping`** alert rule fires when drops over a 15-minute window clear a floor (`min_free_addresses`, default 100) — i.e. the server is actively shedding a flood. Auto-resolves when it subsides.

#### dnsdist front for PowerDNS (Phase 2)

PowerDNS Authoritative has no RRL, so rate limiting / DDoS defense in front of a PowerDNS group is provided by an opt-in **dnsdist sidecar** that binds `:53` and forwards to pdns. Configured group-level on `DNSServerOptions` (PowerDNS groups), default-off:

```
DNSServerOptions.dnsdist_enabled: bool                   -- default false
DNSServerOptions.dnsdist_max_qps_per_client: int | null  -- per-source-IP QPS cap (MaxQPSIPRule)
DNSServerOptions.dnsdist_action: enum(truncate, drop)    -- over-cap action; truncate sets TC=1 so a
                                                         --   legit client retries over TCP (default)
DNSServerOptions.dnsdist_dynblock_qps: int | null        -- sustained-rate dynamic block (exceedQRate over 10s)
DNSServerOptions.dnsdist_dynblock_seconds: int           -- dynamic block duration (default 60)
```

- The PowerDNS agent renders only the **rate-limit rules** (`MaxQPSIPRule` + `TCAction`/`DropAction`, `dynBlockRulesGroup:setQueryRate`) into a shared `dnsdist-rules.conf`; the dnsdist **front is a separate container** whose entrypoint composes those rules onto its base (`setLocal(:53)` + `newServer → dns-powerdns:53`) and reloads on change. **pdns never moves port** — the front forwards to pdns:53 over the network, fully decoupled from pdns's lifecycle. With dnsdist disabled the front is a plain pass-through (safe no-op).
- **Deploy the front:** compose `--profile dns-powerdns-with-dnsdist` (alongside `--profile dns-powerdns`); point DNS clients at the front (host `:5455` in the dev compose). **docker-compose only for now** — the k8s/appliance front (a dnsdist Deployment fronting the hostNetwork pdns DaemonSet) is a follow-up.
- UI: **DNS → Server Group → Server Options → "dnsdist front (PowerDNS)"** card. MCP `find_dns_rate_limit_settings` reports the dnsdist posture alongside RRL.

### 3.9 Options Precedence

Settings can be defined at three levels and are evaluated from most-specific to least-specific:

```
Zone override  (per-zone notify, allow-transfer, also-notify)
    ↓
View override  (per-view recursion, allow-query, allow-query-cache, forwarders)
    ↓
Server default (DNSServerOptions — applies to all views/zones on that server)
```

The driver is responsible for generating the correct BIND9 config that reflects this layered precedence. Service-layer code must not hard-code driver specifics.

---

## 4. DNS Zone Tree

Zones are displayed and managed in a **tree hierarchy** that mirrors the DNS namespace naturally.

<p align="center">
  <img src="../assets/diagrams/dns-namespace-views.svg" alt="DNS zone tree — namespace hierarchy with view scoping" width="900"/>
</p>

### Zone Model

```
DNSZone
  id, server_group_id, view_id (nullable)
  name (FQDN with trailing dot, e.g., "example.com.")
  type: enum(primary, secondary, stub, forward)
  kind: enum(forward, reverse)    -- forward or reverse lookup zone
  ttl (default SOA TTL)
  refresh, retry, expire, minimum (SOA fields)
  primary_ns, admin_email         (SOA fields)
  is_auto_generated: bool         -- created automatically for a subnet
  linked_subnet_id (nullable FK)  -- if reverse zone, tied to a subnet
  dnssec_enabled: bool
  last_serial: int
  last_pushed_at: timestamp
```

### Zone ↔ Subnet Binding

Every subnet can be assigned:
- A **forward DNS zone** (for auto-creating A/AAAA records)
- A **reverse DNS zone** (for auto-creating PTR records)

When a subnet is created or edited, the UI prompts: *"Auto-create reverse zone for 10.1.2.0/24?"* — which generates `2.1.10.in-addr.arpa.` on the designated server group.

> **Overlapping IP spaces (#844).** The same CIDR in two IP spaces computes the same reverse zone name, and a DNS group can hold only one zone by that name — sharing it would merge two tenants' PTRs into one RRset (cross-tenant hostname disclosure). SpatiumDDI therefore refuses to attach a second space's subnet to a reverse zone another space's subnet created (the IPs get no PTR, logged as `reverse_zone_cross_space_conflict`), and PTR sync skips reverse zones linked to a different space's subnet. **Overlapping IP spaces need a separate DNS server group per space.** Operator-created reverse zones with no linked subnet stay shared — no space can be attributed to them.

---

## 5. DNS Records

### Supported Record Types

`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR`, `SRV`, `CAA`, `TLSA`, `SSHFP`, `NAPTR`, `LOC`, `SVCB`, `HTTPS`, `DNAME`

Plus the PowerDNS-only `ALIAS` (CNAME-at-apex) and `LUA` (computed responses) types, which are driver-gated — see §0 and `_DRIVER_GATED_RECORD_TYPES` in `backend/app/api/v1/dns/router.py`.

### Record Model

```
DNSRecord
  id, zone_id, view_id (nullable)
  name (relative to zone, e.g., "host1" for host1.example.com.)
  fqdn (computed, stored for search)
  type: enum(A, AAAA, CNAME, ...)
  value
  ttl (overrides zone default if set)
  priority (for MX, SRV)
  weight, port (for SRV)
  auto_generated: bool   -- set true when created by DDNS or IPAM allocation
  ip_address_id (nullable FK) -- links back to IPAddress if auto-generated
  created_by_user_id, created_at
  last_modified_at
```

---

## 6. Incremental DNS Updates (No Restarts)

> See also: [`docs/deployment/DNS_AGENT.md`](../deployment/DNS_AGENT.md) for
> how the SpatiumDDI-shipped agent applies record ops over loopback and
> reports zone-serial telemetry back to the control plane.

**BIND9:**
- Record add/modify/delete → RFC 2136 `nsupdate` via `dnspython`
- Zone creation/deletion → `rndc addzone` / `rndc delzone`
- Config changes (views, options) → regenerate `named.conf`, push via SSH/SCP, then `rndc reconfig`
- **A full `named` restart is never required** for normal operations
- Serial is auto-incremented on every change (YYYYMMDDNN format)

**PowerDNS:**
- Record add/modify/delete → `PATCH /api/v1/servers/localhost/zones/<zone>` rrset patch via the REST API
- Record changes are atomic and immediate — no restart, no reload
- Zone creation/deletion via the REST API; PowerDNS handles the serial bump internally

### Driver Method: `apply_record_change()`

```python
async def apply_record_change(
    self,
    zone: str,
    record: DNSRecordData,
    operation: Literal["create", "update", "delete"]
) -> None:
    # Must NOT restart the service
    # Must increment zone serial
    # Must be atomic (or roll back on failure)
```

---

## 7. Dynamic DNS (DDNS) — DHCP Lease → DNS Record

> **Implementation status:** Subnet-level opt-in DDNS has shipped. When a lease lands via the agentless pull path (Windows DHCP) *or* an agent lease event (Kea), SpatiumDDI resolves a hostname per the subnet's policy and publishes A/AAAA + PTR via the same RFC 2136 / WinRM path static allocations use. The Kea path runs through `apply_ddns_for_lease` in the `POST /api/v1/dhcp/agents/lease-events` handler.

### Architecture

DDNS is a thin layer on top of the IPAM → DNS sync pipeline. The DNS side is identical to what a static allocation produces; the only DDNS-specific logic is picking a hostname from the lease.

<p align="center">
  <img src="../assets/diagrams/dns-ddns-lease-flow.svg" alt="DDNS — DHCP lease to DNS record" width="900"/>
</p>

On lease expiry, `dhcp_lease_cleanup` sweeps the DHCPLease row past its grace period; before deleting the mirrored `auto_from_lease` IPAM row it calls `revoke_ddns_for_lease`, which fires `_sync_dns_record(..., action="delete")` to tear down the A/AAAA + PTR.

### Subnet-level configuration

DDNS is opt-in per subnet. A subnet can also inherit its DDNS settings from its enclosing block / space: `IPSpace` and `IPBlock` carry the same four DDNS fields, and when `ddns_inherit_settings` is true `resolve_effective_ddns` (in `backend/app/services/dns/ddns.py`) walks subnet → block → space to find the effective values.

| Field | Default | Purpose |
|---|---|---|
| `ddns_enabled` | `False` | Master toggle. When off, leases on the subnet don't publish DNS. |
| `ddns_hostname_policy` | `client_or_generated` | See below. Only read when `ddns_enabled`. |
| `ddns_domain_override` | `NULL` | Publish into a different zone than the subnet's primary forward zone (e.g. `dhcp.corp.example.com` while manual allocations stay in `corp.example.com`). |
| `ddns_ttl` | `NULL` | Override the zone's default TTL for auto-generated records. |

### Hostname policies

| Policy | Behaviour |
|---|---|
| `client_provided` | Publish only if the lease has a client hostname. Skip if empty. |
| `client_or_generated` | Use client hostname if present, else generate `dhcp-<tail>`. **Default**. |
| `always_generate` | Ignore client hostname, always synthesise. |
| `disabled` | Never publish, even if `ddns_enabled`. (Useful for temporarily parking DDNS without losing your config.) |

**Generated hostnames:**
- IPv4 — `dhcp-<third-octet>-<fourth-octet>`. So `10.1.20.5` → `dhcp-20-5`.
- IPv6 — `dhcp-<low-32-bits-hex>`. Rare path; the format is ugly but unique.

**Static assignment override:** if the lease IP matches a `DHCPStaticAssignment` that has a hostname set, that hostname always wins — regardless of policy, including `always_generate`. Rationale: a static hostname is an explicit admin choice.

**Sanitisation:** all hostnames (client-provided or static) are folded to lower-case, non-`[a-z0-9-]` characters collapse to `-`, leading/trailing hyphens strip, and the result truncates at RFC 1035's 63-character label limit.

### Idempotency

DDNS is safe to call repeatedly. If the resolved hostname matches what's already on the `IPAddress` row and there's already a linked auto-generated DNS record, no ops are enqueued. The agentless lease-pull loop hits this path every poll; post-steady-state it's effectively a no-op.

### Security

- RFC 2136 updates to BIND9 use TSIG signing (key stored Fernet-encrypted).
- WinRM calls to Windows DNS go over HTTPS with cert validation by default.
- The DDNS service itself never touches manual IPAM allocations (it gates on `auto_from_lease=True` before doing anything).

### Enabling DDNS (quick walkthrough)

1. **Pick a subnet** with a DNS forward + reverse zone already assigned.
2. Open the subnet editor → **Dynamic DNS (from DHCP)** section → toggle **Enabled**, pick a policy, optionally set a domain override or TTL. Save.
3. Make sure the subnet's DNS group has at least one healthy server (BIND9 via agent, or Windows DNS — Path A or B).
4. Ensure **Settings → DHCP Lease Sync** is enabled (the agentless poll loop — currently the only lease source that fires DDNS).
5. Issue a lease on the Windows DHCP scope covering the subnet. Wait for the next poll (default 5 min) or hit **Sync Leases** on the server detail page.
6. The IPAM subnet page shows the IP with its hostname; the DNS zone shows the matching A + PTR.

### Not-yet (planned follow-ups)

- **Grace period** on revoke — today we delete A + PTR immediately when the lease-cleanup sweep removes the IPAM row. A short grace where we drop the TTL to 30 s first would help mid-transition clients.

---

## 8. DNS Blocking Lists

Inspired by Pi-hole, SpatiumDDI can configure DNS servers to **block domains** by responding with `NXDOMAIN` or a configurable sinkhole IP.

### Blocking List Model

```
DNSBlockList
  id, name, description
  source_type: enum(url, manual, file_upload)
  source_url: str (nullable)    -- e.g., https://someblocklistprovider.com/list.txt
  format: enum(hosts, domains, adblock)
  update_interval_hours: int    -- 0 = manual only
  last_updated_at: timestamp
  entry_count: int (computed)
  is_enabled: bool
  applied_to_groups: [DNSServerGroup]  -- which server groups enforce this list

DNSBlockListEntry
  id, list_id
  domain: str                   -- e.g., ads.example.com
  is_wildcard: bool             -- blocks *.example.com too
  source_line: str              -- original line from source for debugging

DNSBlockListException
  id, domain, reason
  created_by_user_id
  applied_to_groups: [DNSServerGroup]
```

### Supported List Formats
- **Hosts file** (`0.0.0.0 ads.example.com`)
- **Domain list** (one domain per line)
- **AdBlock format** (`||ads.example.com^`)

### Block Response Modes

| Mode | DNS Response | Use Case |
|---|---|---|
| `nxdomain` | NXDOMAIN | Cleanest; some clients retry on NXDOMAIN |
| `sinkhole` | Returns configured IP (e.g., 0.0.0.0) | Can serve a block page |
| `refused` | REFUSED | Strict policy environments |

### BIND9 Implementation
- Uses a `Response Policy Zone (RPZ)` — an industry-standard BIND9 feature
- Block list entries are written as RPZ zone records
- Updating the RPZ zone uses `rndc reload <rpz-zone>` (no full restart)
- Multiple RPZ zones can be chained (per-list)

### UI Features
- Dashboard showing blocked query stats (pulled from DNS server logs)
- Per-list enable/disable toggle
- Allow-list exceptions (whitelist specific domains)
- Manual domain addition to block list
- "Test a domain" — check if a domain would be blocked

### Scoping — where a list applies (issue #876)

A blocking list is applied through one of **two** independent
relationships, and the difference is the whole point of the feature:

| Scope | Relationship | Who it filters |
|---|---|---|
| Server group | `applied_group_ids` | every client the group answers |
| View | `applied_view_ids` | only clients matching that view's `match-clients` |

View scoping is what "the adult lists on the guest VLAN, threat lists
everywhere" means in practice. It shipped with the split-horizon work in
#24 and has been rendered end-to-end by the BIND9 agent since — but until
#876 the UI wrote only the group half, so per-subnet filtering was
unreachable from the product despite being fully implemented underneath.

A **view** is a set of clients, identified by source address. `match_clients`
is a BIND address-match-list: addresses, CIDR prefixes, a named ACL from
the ACLs tab, or one of `any` / `none` / `localhost` / `localnets`, each
optionally negated with a leading `!`. Views are evaluated in `order`
(low first) and a client is served by the **first** view it matches, so
the catch-all belongs last.

#### Worked example — filter one VLAN

The guest VLAN is `10.20.0.0/16`; everyone else should be unfiltered.

1. **DNS → group → Views → New View.** Name `guest`, order `0`,
   match clients `10.20.0.0/16`. *Add subnets…* fills that in from IPAM
   rather than retyping the prefix.
2. **New View** again: name `default`, order `10`, match clients `any`.
   This is load-bearing — once any view exists BIND serves every client
   from a view, so without a catch-all everyone outside the guest VLAN
   matches nothing and gets no answer.
3. **Blocklists tab** → the funnel icon on the adult/gambling list →
   tick `guest`, leave *Whole group* unticked → **Save scope**.
4. Threat lists stay on *Whole group*: they apply inside every view.

The rendered config puts the RPZ inside the matching view only:

```
view "guest" {
    match-clients { 10.20.0.0/16; };
    response-policy { zone "spatium-blocklist-guest.rpz"; } break-dnssec yes;
    ...
};
```

#### Constraints worth knowing

- **BIND9 only.** `render_rpz_zone` is a no-op on the Windows, PowerDNS
  and cloud drivers, and Technitium blocks natively with no per-view
  concept. The Views tab and the scope modal both say so when the group
  runs a non-BIND9 server; scoping is stored but never applied there.
- **Views are all-or-nothing for a group.** BIND forbids a top-level
  `zone {}` alongside views, so once one view exists every zone is served
  from inside a view. Zones with no view of their own render into all of
  them.
- **Named ACLs work in `match_clients`** as of
  [#899](https://github.com/spatiumnorth/spatiumddi/issues/899). Before that
  a `DNSAcl` row was stored, listed and editable and applied to nothing —
  the bundle carried `{id, name}` with no entries and the agent emitted no
  `acl {}` stanza — so a view citing one left an undefined symbol and the
  group stopped converging. See §8.2.
- **`match_clients` and the view name are validated server-side**
  (`app/services/dns/named_conf_validation.py`). Both are interpolated verbatim
  into `named.conf`, and the name additionally becomes a directory on the
  agent, so a malformed prefix, an undefined ACL or TSIG key name, or a
  name containing a path separator is rejected with a 422 naming the
  offending element. It has to be: the agent runs `named-checkconf` before
  swapping config in, so an accepted-but-invalid value would not corrupt
  one view — it would stop the whole group's config converging, silently.
  A view name is capped at **45 characters**, not 63: the per-view RPZ zone
  is named `spatium-blocklist-<view>.rpz.`, and that 18-character prefix
  has to fit inside the 63-octet DNS label limit with it.
- **Deleting a view** leaves its zones in place (they fall back to being
  served from the remaining views) but any list scoped *only* to it stops
  applying anywhere.
- **SpatiumDDI's own zone transfers pick their view by key, not by
  address** ([#920](https://github.com/spatiumnorth/spatiumddi/issues/920)).
  BIND chooses the view before it consults `allow-transfer`, and nothing
  in a view's `match_clients` names the control plane — so the drift
  report and *Sync with Servers* sign each transfer with a key that
  belongs to the view holding that zone's copy. The BIND9 agent admits
  that key first in its view's `match-clients` (and `match-destinations`,
  when set) and refuses it in every other view, so a broad `any` view
  cannot capture a transfer meant for a narrower one. Requests that carry
  none of these keys — every client, every DDNS update, any transfer an
  operator runs — are matched by your lists exactly as written. The keys
  are derived from the group's own TSIG key; they are never shown and need
  no setup. Before this, a view that did not happen to admit the api's
  address made both features fail with "The peer didn't know the key we
  used".

### 8.1 Content filtering / family filter (issue #878)

Two independent ways to filter adult content, and they compose:

| | RPZ blocklists (this feature) | Filtered upstream resolver |
|---|---|---|
| Where the policy lives | Your server, per view / group | The upstream provider |
| Maintenance | Feeds refresh on a cadence | None |
| Per-network scoping | Yes — assign a list to one view | No — applies to everything the group forwards |
| Works for authoritative zones | Yes | N/A |
| Requires | A BIND9 group | Any group that forwards |

Pick the resolver route when a whole site should be filtered identically
and you would rather not maintain lists — Cloudflare `1.1.1.3` and
OpenDNS FamilyShield are in the forwarder presets (§20.3.1). Pick RPZ
when different networks need different policy, which is the usual case:
the guest and kids' VLANs filtered, the server VLAN not.

**Catalog → Profiles → Family filter** applies both halves of the RPZ
route in one action:

- **Adult + gambling feeds** — Hagezi NSFW and Gambling (`recommended:
  false`, so they are opt-in rather than something a general install
  picks up by accident).
- **Bypass feeds** — public DoH endpoints, VPN and proxy services, and
  search front-ends with no SafeSearch mode. Without these the filter
  is one browser setting away from irrelevant: a client that speaks DoH
  to `1.1.1.1` never asks your resolver anything.
- **SafeSearch enforcement** — the template below.

Applying a profile creates the lists and assigns them to **nothing**.
That is deliberate: a profile that scoped itself would filter the server
VLAN too. Assign them under the list's **Assignments** tab.

#### SafeSearch enforcement

Each major search engine publishes a filtered endpoint and documents a
DNS rewrite that pins clients to it. These are RPZ **rewrites**, not
blocks — the engine still answers, from its safe endpoint — so they ride
`entry_type="redirect"` with the target as a CNAME.

| Group | Rewrites | To |
|---|---|---|
| Google Search | 194 country domains | `forcesafesearch.google.com` |
| YouTube — Strict | 5 hostnames | `restrict.youtube.com` |
| YouTube — Moderate | the same 5 | `restrictmoderate.youtube.com` |
| Bing | `www.` + `edgeservices.` | `strict.bing.com` |
| DuckDuckGo | 3 hostnames | `safe.duckduckgo.com` |
| Brave / Ecosia / Pixabay / Qwant | 1 each | provider's safe host |
| Yandex (off by default) | 56 hostnames | `familysearch.yandex.ru` |

Four things about this data are load-bearing:

- **Every Google country domain is covered.** A rule on `www.google.com`
  alone is bypassed by typing `google.de`.
- **`edgeservices.bing.com` is included.** It is the Edge sidebar /
  Copilot entry point; without it that surface answers unfiltered, which
  looks like the filter is broken rather than incomplete.
- **Exactly five YouTube hostnames, never more.** Google's own
  documentation warns that rewriting `youtube.com`, `youtu.be`,
  `s.ytimg.com` or `googleapis.com` breaks playback.
- **The entries are never wildcards.** A wildcard would also match the
  rewrite target's own subdomain — `*.youtube.com` catches
  `restrict.youtube.com` — and BIND resolves the resulting CNAME loop
  into SERVFAIL. The API emits `is_wildcard=false` with no knob to
  change it.

The Strict and Moderate YouTube groups cover the same five hostnames
with different targets, so selecting both is refused (422) rather than
letting one silently win.

#### Honest limits

- **BIND9 only.** RPZ rewrites need a response-policy zone. PowerDNS
  logs that blocklists are unsupported; Technitium's native blocking has
  no per-domain rewrite, so it skips redirect entries and logs them
  (before #878 it silently converted them into *allow* rules, inverting
  the intent); Windows and the cloud DNS drivers do not render RPZ.
- **DNS filtering is bypassable** — a browser with DoH enabled, a
  hard-coded resolver, or a VPN never consults your server. The bypass
  feeds in the profile are the mitigation, not a fix. Blocking outbound
  :53 and :853 to anything but your resolvers at the firewall is what
  actually closes it.
- **Blocklists disable DNSSEC validation** on a group that has any (RPZ
  rewriting is by definition answer tampering). The agent handles this
  automatically; it is why a filtered group cannot also validate.

#### Do feed entries block subdomains?

Yes by default, and it is a **per-list** setting — *Block subdomains of
feed entries* on the list's edit form (`feed_entries_are_wildcard`,
issue #894).

Leave it on for anything in the curated catalog. Every one of those 19
sources is a "block this domain and everything under it" list, and off
would mean a feed naming `tracker.example` leaves
`cdn.tracker.example` resolving — which is what these lists exist to
stop.

Turn it off only for a feed that lists **specific hosts** rather than
domains: a threat-intel drop of individual C2 FQDNs, say, where
blocking the parent domain would take out everything else hosted under
it. Toggling it restamps the entries already imported, so the change
takes effect immediately rather than waiting for the feed's contents to
churn — the save takes a few seconds on a large list (measured ~7 s on
a 464k-entry feed) because it rewrites every row in one transaction.

Two related behaviours worth knowing:

- Feeds published in wildcard syntax (`*.example.com` — OISD's
  `domainswild`, Hagezi's `wildcard/`) have the prefix **stripped on
  import**. Stored literally it produces an RPZ rule matching
  subdomains *only*, leaving the apex resolving — the opposite of what
  the feed means. The prefix is instead read as the feed declaring
  "and every subdomain", which is exactly what this setting expresses.
- If such a feed is imported into an apex-only list, the refresh logs
  `blocklist_feed_wildcard_intent_overridden` naming the count. That is
  a legitimate configuration, not an error — but it overrides something
  the feed stated, so it says so.

A **manual** entry's own *Include subdomains* checkbox is independent
and is never rewritten by this list-level switch.

#### Sizing

Feed-sourced entries block the named domain *and* its subdomains, which
takes two RPZ records each (`example.com` and `*.example.com`) — an RPZ
wildcard matches subdomains only, so the bare name is not redundant.
Budget roughly **two records per feed entry** (halve it for a list with
*Block subdomains* off):

| Profile feed | Entries | RPZ records |
|---|---|---|
| Hagezi Gambling | ~464 k | ~928 k |
| Hagezi NSFW | ~115 k | ~230 k |
| Hagezi DoH / VPN / Proxy Bypass | ~17 k | ~33 k |
| Hagezi No-SafeSearch | ~205 | ~410 |
| **Family filter total** | **~596 k** | **~1.2 M** |

BIND holds the whole zone in memory. Gambling is by far the largest —
drop it, or swap it for the `gambling.medium` / `gambling.mini` variants
Hagezi publishes, if the appliance is memory-constrained. The
utilization is visible per list as **Entries** on the Blocklists tab.

One caveat on overlapping lists: if the same domain appears in two
assigned lists with **different block modes**, only the first is
rendered and the agent logs `bind9_rpz_entry_collision`. Emitting both
would put two CNAMEs on one owner name, which makes BIND refuse the
entire zone — so the renderer picks one rather than enforcing nothing.
Reconcile the lists if you see that warning.

---

### 8.2 Named ACLs (issue #899)

An ACL is a reusable address-match-list: define `office` once on the group's
**ACLs tab**, then cite it by name from a view's `match_clients`, from
`allow-query`, or from another ACL.

They render as `acl "<name>" { … };` at the **top** of `named.conf`, above
`options`. Placement is the correctness property, not tidiness: BIND
resolves an `acl` statement where it is written, so a definition below its
first use is an error rather than a forward declaration. The control plane
emits the list dependency-ordered for the same reason — an ACL may
reference another, so `inner` has to precede `outer`.

Constraints, all enforced server-side with a 422 naming the offending
element:

- **Entry values get the same gate as a view's `match_clients`** — they end
  up in the same kind of statement. Addresses, CIDR prefixes, `key <name>`
  for a TSIG key the group ships, another ACL's name, or one of the
  built-ins, each optionally negated with `!`.
- **Cycles are refused.** `a → b → a` is rejected at the commit, not
  discovered when the next bundle build fails. Each edge is individually
  legal, so this needs a graph check rather than per-field validation.
- **Built-in names cannot be redefined** — `acl "any" { … };` is an error.
- **An ACL with no entries renders as `{ none; }`**, not skipped. BIND
  rejects `acl "x" { };`, but omitting the definition would be worse — the
  name may already be cited by a view, and dropping it re-creates the
  undefined-symbol outage. `none` is also the honest meaning of an empty
  address-match list.
- **Deleting or renaming an ACL something still cites is refused** (409).
  Write-time validation stops you *creating* a dangling reference; removing
  the target of one that already resolves breaks the group identically.
- **ACL names are per-group.** `DNSAcl.group_id` is nullable, but nothing
  creates a global ACL and the bundle is built per group, so a NULL-group
  row would be invisible to every agent. Treat global ACLs as unsupported.

> **History worth knowing.** ACLs were the third field found stored,
> persisted, editable and never rendered — after `allow_transfer` (#734)
> and alongside `forward_policy`, which #899's audit also caught: `forward
> only` was silently behaving as `forward first`, so an operator forcing
> every query through a filtering upstream was getting fall-through
> recursion instead. If you add a field an agent is supposed to act on,
> assert on the rendered config, not just on the stored row.

## 9. DNS UI Features

### Zone Tree View
- Collapsible namespace tree (same as the file explorer metaphor)
- Drag-and-drop zone organization (reorder, move between groups)
- Click zone → record list with inline editing

### Record Management
- Bulk import records from zone file (RFC 1035 format)
- Export zone as standard zone file
- Record diff view before pushing changes to server

### Zone Health Indicators
- Last successful sync timestamp
- Serial number displayed
- SOA consistency check across primary and secondaries
- DNSSEC validation status

### Server Group Dashboard
- All servers in group + their status
- Query rate (pulled from metrics)
- Block list hit rate
- Zone count

---

## 10. Permissions on DNS Resources

DNS zones inherit the standard permission model:

| Role | Capability |
|---|---|
| **superadmin** | Full DNS server, group, view, zone, record management |
| **admin** (scoped to zone) | Create/edit/delete records in zone, manage zone settings |
| **operator** (scoped to zone) | Create/edit/delete records; cannot change zone settings |
| **viewer** (scoped to zone) | Read zone and records; no modifications |

Zone permissions are assignable to groups via the standard Permission model, same as IP ranges.

---

## 11. Environment Variables for DNS

```bash
# DDNS defaults
DDNS_DEFAULT_TTL=300
DDNS_GRACE_PERIOD_SECONDS=60   # how long to keep record after lease expiry

# Blocking lists
BLOCKLIST_UPDATE_INTERVAL_HOURS=24
BLOCKLIST_SINKHOLE_IP=0.0.0.0

# BIND9 TSIG (global default — per-server keys stored in DB encrypted)
BIND_TSIG_ALGORITHM=hmac-sha256
```

---

## 12. "Sync with Servers" — group-level bi-directional reconciliation

Every DNS server group has a **Sync with Servers** button on its detail header. It iterates every enabled server in the group and runs a four-step reconciliation per server:

1. **List zones on the wire** — only the drivers that can enumerate zones from the authoritative side do this: Windows DNS with WinRM credentials (`Get-DnsServerZone | Where { -not $_.IsAutoCreated }`) and the cloud drivers (the provider's hosted-zone API). The agent-based drivers (BIND9 / PowerDNS / Technitium) have no topology read here, so steps 1–3 are no-ops for them and only step 4 runs.
2. **Auto-import server-only zones** — any zone present on the wire but missing from SpatiumDDI is created as `is_auto_generated=False`. System-only zones (TrustAnchors, RootHints, Cache, anything without a dot) are skipped.
3. **Push DB-only zones back to the server** — any SpatiumDDI zone not present on the wire is created via the driver's `apply_zone_change`. For Windows Path B, this is `Add-DnsServerPrimaryZone -ReplicationScope Domain -DynamicUpdate Secure`.
4. **Per-zone record sync** — for each zone, `pull_zone_records` reads what the server actually serves, reconciles against DB records, and applies the delta. Additive-only — never deletes. Only the drivers that implement it participate: AXFR for BIND9 and Technitium, `Get-DnsServerResourceRecord` over WinRM for Windows Path B, the provider API for cloud. **PowerDNS does not implement `pull_zone_records` at all** — `_resolve_primary_and_driver` guards on `hasattr` and raises, so record sync and the record-level drift report are both unavailable on a PowerDNS group today.

> **AXFR against an agent-managed BIND9 or Technitium group is TSIG-signed** ([#734](https://github.com/spatiumnorth/spatiumddi/issues/734)). Both agents grant `allow-transfer` to the group's TSIG *key* rather than to a source address — behind an HA VIP the request can come from any control-plane node, and on the appliance the address isn't knowable at render time — so the control plane signs with the group key, resolved by `resolve_group_transfer_key`. A group with **no** TSIG key can't be transferred from at all; that surfaces as `unsupported` naming the missing key, not as a generic error pointing at an `allow-transfer` the agent owns and you can't edit. A refused transfer is always surfaced as an error rather than an empty diff — an empty diff would read as "in sync", which is the worst possible answer.

The UI surfaces per-server results with zones-imported / zones-pushed / errors, plus a per-zone table.

Manual drift checks from the subnet / block / space side use **Check DNS Sync** which only covers IPAM-managed records (A/AAAA/PTR). The group-level reconciliation covers everything in a zone.

---

## 13. Windows DNS — Path A & B

SpatiumDDI supports Windows Server DNS as an **agentless** backend in two tiers that coexist on the same driver class. Which one applies at runtime depends on whether the server has WinRM credentials configured.

| Tier | Activation | Capabilities | Protocol |
|---|---|---|---|
| **Path A** | Always available | Record CRUD, AXFR pull | RFC 2136 + dnspython over UDP/TCP 53 |
| **Path B** | `DNSServer.credentials_encrypted` set | Zone create / delete, `Get-DnsServerResourceRecord`-based pull (AXFR-free), server-level probes | WinRM + `DnsServer` PowerShell module over 5985/5986 |

Record writes always ride RFC 2136 — Path B is not used for per-record writes (to avoid paying the PowerShell-per-record cost on hot writes). Zone topology writes use Path B when credentials are present, otherwise SpatiumDDI can't create zones on Windows (create them manually in DNS Manager, then click **Sync with Servers**).

### 13.1 When to choose which

| Situation | Recommendation |
|---|---|
| Existing AD environment, you want the full SpatiumDDI experience | **Path B** — register the DC with WinRM credentials. |
| Existing AD environment, you only need record writes and don't want to provision a WinRM service account | **Path A** — make sure zones are "Nonsecure and secure" dynamic updates. |
| "Secure only" AD-integrated zone that can't be changed | **Path B for zone management; record writes fail** until GSS-TSIG lands. Treat it as zone-only for now. |
| Greenfield, no AD | Use the built-in BIND9 container instead. |

### 13.2 Credentials shape

Windows DNS credentials match the Windows DHCP shape — same Fernet-encrypted dict, same transport options:

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

Stored on `DNSServer.credentials_encrypted`. The server create modal in the UI renders these fields when `driver=windows_dns`, with a **Test Connection** button that runs `(Get-DnsServerSetting -All).BuildNumber` as a cheap probe.

### 13.3 What Path B unlocks

**Zone create / delete:**

```powershell
Add-DnsServerPrimaryZone -Name "corp.example.com" -ReplicationScope Domain -DynamicUpdate Secure
Remove-DnsServerZone -Name "corp.example.com" -Force
```

Both are idempotent — the driver guards with `Get-DnsServerZone -ErrorAction SilentlyContinue` before acting, so a missing zone on delete is a no-op.

**Zone record pull (AXFR-free):**

When AD-integrated zones refuse AXFR (the default ACL), Path B pulls records via `Get-DnsServerResourceRecord -ZoneName "…"`. The driver normalises the output (`HostName`, `Type`, `TTL`, `Value`, optional `Priority` / `Weight` / `Port`) into the neutral `RecordData` shape. SOA and apex NS are filtered out.

**Zone list:**

`Get-DnsServerZone | Where { -not $_.IsAutoCreated }` returns every non-system zone. Feeds the group-level "Sync with Servers" step 1.

### 13.4 What Path B does *not* do (yet)

| Not yet | Reason |
|---|---|
| Per-record writes via WinRM | Paying a PowerShell round-trip per record is too slow for hot writes. RFC 2136 stays the write path. |
| GSS-TSIG (Kerberos-signed RFC 2136) | Lets Path A work against "Secure only" zones without changing them. On the roadmap. |
| SIG(0) authentication | Niche; not prioritised. |
| Server-level options (forwarders, recursion, allow-query) | Out of scope for agentless Windows — Windows manages these via Registry + DNS MMC. |

### 13.5 Zone transfer / AXFR for Path A

For Path A to pull records, AXFR from the SpatiumDDI host must be allowed. In Windows DNS Manager:

1. Right-click the zone → **Properties** → **Zone Transfers** tab.
2. **Allow zone transfers** → **Only to the following servers** → add the SpatiumDDI host IP.

If AXFR is refused, the per-zone sync in step 4 of "Sync with Servers" shows `Zone transfer error: REFUSED`. Switching that server to Path B (adding WinRM credentials) bypasses AXFR entirely.

See [WINDOWS.md](../deployment/WINDOWS.md) for full Windows-side prerequisites including WinRM enablement, service account creation, and firewall rules.

### 13.6 Migrating off Windows DNS entirely (issue #756)

Path A / B make Windows a supported *backend*. When the goal is to stop using it, the guided **Windows cutover** surface (feature module `migration.cutover`, ships **disabled**, `/api/v1/migration/cutover`, superadmin) walks the four phases: per-zone parity against the live server, a shadow-query parallel run replaying real BIND9 query-log traffic at both sides, a TTL pre-flight plus the switch with per-zone rollback, and a decommission checklist.

Note especially that it **refuses** any zone whose Windows dynamic-update mode is AD "Secure only" — a hard block `force` cannot bypass, for the reason in §13.4: GSS-TSIG is unimplemented ([#444](https://github.com/spatiumnorth/spatiumddi/issues/444)), and a DC that cannot register its SRV records breaks AD itself. See [MIGRATION.md](MIGRATION.md#windows--spatiumddi-cutover-756).

---

## 14. IPAM ↔ DNS synchronization jobs

Two scheduled reconciliation jobs complement the live sync path (`_sync_dns_record` runs on every IP mutation):

### 14.1 IPAM → DNS Reconciliation

Catches drift between IPAM's expected records (every IP with a hostname + DNS zone pinned) and SpatiumDDI's DNS DB. Creates missing A/AAAA/PTR records and (optionally) updates mismatched ones.

| Setting | Default | Description |
|---|---|---|
| `dns_auto_sync_enabled` | off | Master toggle. |
| `dns_auto_sync_interval_minutes` | 60 | How often the task runs. |
| `dns_auto_sync_delete_stale` | off | Also delete auto-generated records whose IP was deleted. Conservative default — leaves stale rows so you can review. |

Implementation: `app.tasks.ipam_dns_sync.auto_sync_ipam_dns` (Celery beat fires every 60s, task gates on the `enabled` flag + interval).

### 14.2 Zone ↔ Server Reconciliation

Catches drift between SpatiumDDI's DNS DB and the authoritative server's wire. Identical to pressing "Sync with Servers" on every group, on a timer. AXFR imports out-of-band edits, then any DB-only records are pushed back via RFC 2136. Additive only.

| Setting | Default | Description |
|---|---|---|
| `dns_pull_from_server_enabled` | off | Master toggle. |
| `dns_pull_from_server_interval_minutes` | 30 | AXFR + RFC 2136 is heavier than a DB diff; a low cadence is usually wrong. |

Implementation: `app.tasks.dns_pull.auto_pull_dns_from_server`.

Both jobs have **Last Run** indicators in Settings so you can confirm they're firing.

## 15. Rules & constraints

Server-side validations that reject requests with a human-readable
error. Clients should display the response `detail` to the operator —
most of these feed the IPAM / DNS / DHCP UI error banners directly.

### Zones

- **Duplicate zone name inside a group/view.** `(group_id, view_id,
  name)` is a unique constraint; create/update returns `409` with
  *"A zone with that name already exists in this group/view."* in
  `backend/app/api/v1/dns/router.py`.
- **`zone_type` enum.** One of `primary` / `secondary` / `stub` /
  `forward`. Pydantic validator in
  `backend/app/api/v1/dns/router.py`.
- **`color` enum.** Must be in `VALID_ZONE_COLORS` (`slate`, `red`,
  `amber`, `emerald`, `cyan`, `blue`, `violet`, `pink`). Free-form
  hex is deliberately not accepted so both themes stay legible.
  `backend/app/api/v1/dns/router.py`.
- **`notify_enabled` enum.** One of `yes` / `no` / `explicit` /
  `master-only`. `backend/app/api/v1/dns/router.py`.
- **Windows zone push-before-commit.** When a zone is created / deleted
  on a group that has an agentless `windows_dns` server with
  credentials, the WinRM push happens first — a WinRM failure rolls
  back the DB transaction and returns `502` so the operator never
  sees a SpatiumDDI zone that doesn't exist on the real DC.
  `backend/app/api/v1/dns/router.py`.

### Records

- **`record_type` enum.** Must be in `VALID_RECORD_TYPES` — A, AAAA,
  CNAME, MX, TXT, NS, PTR, SRV, CAA, TLSA, SSHFP, NAPTR, LOC, SVCB,
  HTTPS, DNAME, plus the PowerDNS-only ALIAS / LUA types.
  `backend/app/api/v1/dns/router.py`.
- **Record owner-name conformance (issue #597).** `DNSRecord.name` is
  validated against the **RFC 2181 §11** rule, *not* the RFC 1123 LDH host
  rule — deliberately looser, because the DNS protocol permits an
  underscore and RFC 1123 does not. That looseness is load-bearing: it is
  exactly what keeps `_acme-challenge` (SpatiumDDI's own ACME DNS-01
  client, #438), `_dmarc`, and `_443._tcp` SRV / TLSA owners legal. A naive
  RFC 1123 check here would have broken our own certificate issuance.
  Wildcards are accepted as a leftmost `*` label. What *is* rejected:
  whitespace, control characters (a raw newline can inject a second record
  into a zone-file line), the zone-file-dangerous punctuation
  (`;` `$` `(` `)` `"` `@` `\`), and a leading or trailing hyphen. Labels
  cap at 63 characters, the whole name at 253. `422` via
  `app.core.dns_names.validate_record_owner` at
  `backend/app/api/v1/dns/router.py:944` (create) / `:963` (update) — and
  the same validator on GSLB pool members at
  `backend/app/api/v1/dns/pool_router.py:140`. See §18.
- **Bare-name rdata targets.** The target of a CNAME / MX / NS / SRV / PTR /
  DNAME record is validated as an FQDN. `422` at
  `backend/app/api/v1/dns/router.py:1133`.
- **Zone-name FQDN validation (issue #597).** `DNSZone.name` goes through the
  FQDN rule — a dotted series of RFC 2181 labels, IDN-normalised to `xn--`
  A-labels, lower-cased, with the trailing root dot re-appended on the way
  into storage. Underscore labels are allowed (`_msdcs.example.com` is a real
  zone); wildcards are not. `422` via `app.core.dns_names.validate_fqdn` at
  `backend/app/api/v1/dns/router.py:785` (create) / `:832` (update). See §18.

### Servers & server groups

- **Duplicate server-group name.** `409` in
  `backend/app/api/v1/dns/router.py`.
- **Duplicate server name within a group.** `(group_id, name)` is
  unique — same name is fine across different groups. `409` in
  `backend/app/api/v1/dns/router.py`.
- **`group_type` enum.** `VALID_GROUP_TYPES` —
  `backend/app/api/v1/dns/router.py`.
- **`driver` enum.** Must be one of the registered drivers
  (`VALID_DRIVERS`, derived from the driver registry — `bind9` /
  `powerdns` / `windows_dns` / the cloud + token-only providers, plus
  `stub_resolver` for tests). `422` in
  `backend/app/api/v1/dns/router.py`.
- **Windows credentials must be complete on first set.** Creating a
  `windows_dns` server with Path B credentials requires both
  `username` and `password`; an incomplete pair returns `400`. Later
  updates may include just one field.
  `backend/app/api/v1/dns/router.py`.

### ACLs & views

- **Duplicate ACL name within a group.** `(group_id, name)` unique.
  `409` in `backend/app/api/v1/dns/router.py`.
- **Duplicate view name within a group.** Same pattern. `409` in
  `backend/app/api/v1/dns/router.py`.

### Server options

- **`forward_policy` enum.** `first` or `only`. Validator in
  `backend/app/api/v1/dns/router.py`.
- **`dnssec_validation` enum.** `auto`, `yes`, or `no`. Validator in
  `backend/app/api/v1/dns/router.py`.

## 16. Multi-group / split-horizon publishing at the IPAM layer (issue #25)

Distinct from §2's DNS Views (which split horizons at the
recursive-resolver layer): #25 splits at the **IPAM** layer so an
operator can publish the same address into both an internal zone
and a public zone simultaneously, with per-record routing overrides
when a single host should appear only inside.

**Block-level flag.** `IPBlock.dns_split_horizon` is a boolean. When
true, descendant subnets that inherit DNS settings publish records
to **both** `dns_zone_id` (the internal / primary zone) AND every
entry in `dns_additional_zone_ids` (DMZ / external zones). The
existing `dns_inherit_settings` walk picks this up, so flipping the
flag at the block level cascades down without per-subnet edits.

**Per-record override.** `IPAddress.dns_zone_overrides` is a JSONB
list of `[{zone_id, record_type}]` pairs. When set, the auto-sync
emits records only into the listed zones for the listed record
types — useful for "this one bastion should only have an A record
in the internal zone, no PTR, no external A".

**Auto-sync.** The scheduled IPAM ↔ DNS auto-sync respects the
split: each address that lands in a split-horizon subnet emits one
record per zone that survives the override filter. DDNS for DHCP
leases follows the same path.


## 17. GSLB pools (health-checked) + geo / topology-aware steering (issue #530)

DNS **pools** (GSLB-lite) map one DNS name (e.g. `www` →
`www.example.com`) to a set of A / AAAA target IPs and flip each
target in / out of the served record set based on a periodic health
check. Members render as regular `DNSRecord` rows (one per healthy +
enabled member, carrying `pool_member_id`) so BIND9 / PowerDNS /
Technitium / Windows DNS render unchanged. Config lives on `DNSPool` +
`DNSPoolMember`; the reconciler is `app.services.dns.pool_apply`.

A pool's DNS name must live in a **forward** zone. Reverse
(`in-addr.arpa` / `ip6.arpa`) zones are filtered out of the zone
picker and rejected server-side by the pool-create endpoint
(`pool_router.py` returns `400` on a `kind == "reverse"` zone),
because a pool member renders A / AAAA records and a reverse zone
holds only PTRs.

> **This is not a load balancer.** DNS is cached client-side, so a
> member dropping out doesn't take effect until the pool `ttl`
> expires — clients may keep hitting a dead / distant box for up to
> `ttl` seconds. Keep the TTL short (default 30 s). See the
> **TTL-race caveat** below.

### 17.1 Serving scope — steering one name to the nearest datacenter

By default every client gets the same healthy rrset. **Geo steering**
(issue #530) adds client-location awareness so one name resolves to
the nearest datacenter. Each pool member carries an optional
**serving scope**:

* `serving_cidrs` — a JSONB list of client CIDRs (`203.0.113.0/24`,
  `10.1.0.0/16`, …).
* `site_id` — an optional FK to a Network → **Site**. The site's
  linked subnets (`subnet.site_id`) contribute their CIDRs to the
  member's scope. `ON DELETE SET NULL` — deleting the Site just drops
  the association.

The two sources are **UNIONed**. A member with an empty scope
(`serving_cidrs == []` and `site_id IS NULL`) is a **default** target
served to everyone (the historical behaviour). A member with a scope
is served **only** to clients whose resolver source IP falls inside
that scope.

Result: a client from CIDR X resolves to `{geo members scoped to X} ∪
{default members}`; a client matching no geo scope resolves to
`{default members}`. Health-check gating composes cleanly — an
unhealthy member is never advertised regardless of scope.

**No-blackhole guarantee.** A pool where *every* member is geo-scoped
(the "each site serves its own region, no global fallback" config) has
no default members, so a client matching no geo CIDR would otherwise get
NODATA for a name that has healthy targets. To prevent that, an all-geo
pool's members are also served as a **union fallback** into the non-geo
views (operator views + the `spatium-geo-default` catch-all) — so an
unmatched client resolves to the union of all healthy members instead of
an empty rrset. A pool that has at least one default member keeps the
strict behaviour (geo members only in their geo view).

### 17.2 Rendering — synthesized BIND9 geo views

The mechanism is a BIND9 `view { match-clients … }` block: a "geo
view" == a view with a client-subnet match list. At ConfigBundle-build
time (`app.services.dns.pool_geo`) the control plane:

1. resolves each member's scope, groups members by distinct scope, and
   synthesizes one geo view per scope (`spatium-geo-1 …
   spatium-geo-N`, `match-clients` = the scope's CIDRs), ordered
   **before** any operator-defined split-horizon views (§2). BIND
   evaluates `view` blocks top-to-bottom, first-match-wins, so a
   geo-CIDR client must reach its geo view *before* a broad operator
   view (an `internal` view matching `10.0.0.0/8`, or any `any`/empty
   match) swallows the query and strips the geo member. Geo scopes are
   the more-specific match, so geo-first is most-specific-first in the
   common case (caveat: a narrow operator view — e.g. a `/32` mgmt host
   — that a broader geo view would shadow; split the geo scope if that
   bites);
2. appends a catch-all `spatium-geo-default` view (`match-clients {
   any; }`) **last**, so a client matching no specific geo view *and*
   no operator view still resolves;
3. scopes each geo-member's record into its own geo view, while
   default members (and every non-pool record) render as **shared**
   records visible in every view — reusing the same per-view record
   routing as the split-horizon path (`DNSRecord.view_id IS NULL` =
   shared). An all-geo pool's members are additionally rendered into
   the non-geo views as the no-blackhole union fallback (§17.1).

No `DNSView` / `DNSAcl` rows are persisted — geo views are a pure
render-time concern, kept out of the operator-managed split-horizon
view catalog so the two features don't collide in the admin UI. Geo
steering forces views mode on even for a group with no operator views;
the incremental RFC 2136 path can't target a view, so with geo active
the whole group re-renders view-correctly on each change (same as
split-horizon).

The Pools tab member editor exposes both scope inputs (client CIDRs +
Site picker) per member; scoped members show a `geo` chip. The
`list_dns_pools` MCP tool surfaces `serving_cidrs` + `site_id` on each
member so the Operator Copilot can answer "which datacenter does the
EU client get for www?".

### 17.3 Source-IP semantics (v1) and the ECS stretch goal

v1 keys purely on the **resolver source IP** — the address BIND sees
the query arriving from. When a recursive resolver sits between the
end client and the authoritative server (the common public-internet
case), that source IP is the *resolver's*, not the end client's, so
steering follows the resolver's location.

**EDNS Client Subnet (ECS, RFC 7871) is the future accuracy
improvement** and is deliberately **not implemented** in v1: it
carries a prefix of the real client's address so the authoritative
server can steer on the client rather than the resolver. Wiring it
needs `match-clients` driven off the ECS option rather than the
TCP/UDP source address, and is tracked as a stretch goal.

### 17.4 TTL-race caveat

As with all DNS-based steering, geo steering is subject to the pool
TTL cache window: a client that already cached an answer keeps using
it until the TTL expires, even after it crosses into a different geo
scope (e.g. a roaming laptop that moves between sites). Keep the pool
TTL short. This is the same caveat as the base pool feature — DNS
steering is a coarse, cache-bounded mechanism, not a per-request load
balancer.

## 18. DNS-name conformance (issue #597)

**There is no single "valid DNS name" rule.** The correct rule depends on
what the field *is* — a host name, a DNS record owner, and an FQDN are
three different grammars, and applying the strictest one everywhere breaks
legitimate DNS. `backend/app/core/dns_names.py` is the single place that
decides; nothing else hand-rolls a name regex.

| Context | Rule | Where |
|---|---|---|
| **Host names** — `IPAddress.hostname`, a DHCP reservation hostname | RFC 952 + RFC 1123 §2.1 **LDH**: letters, digits, hyphens; no leading / trailing hyphen. Internationalized input is normalised to its IDNA **A-label** (`xn--`) form rather than rejected. | `validate_hostname` / `validate_host_label` |
| **DNS record owners** — `DNSRecord.name` | RFC 2181 §11: LDH **plus underscore**, plus a leftmost `*` wildcard. | `validate_record_owner` / `validate_dns_label` |
| **FQDNs** — `DNSZone.name`, the DHCP `domain-name` / `domain-search` options, bare-name rdata targets | A dotted series of RFC 2181 labels (underscore allowed, wildcards not). | `validate_fqdn` |

The record-owner rule is deliberately the **looser** one. RFC 1123 forbids
an underscore; the DNS protocol does not — and `_acme-challenge`,
`_dmarc`, and `_443._tcp` SRV / TLSA owners all need it. Applying the host
rule to record owners would have broken SpatiumDDI's **own** ACME DNS-01
client (#438), which writes `_acme-challenge` TXT records into managed
zones to prove domain control. Underscore support here is a correctness
requirement, not a leniency.

Every `validate_*` helper both **rejects and canonicalises**: it raises
`ValueError` with an operator-facing message on a bad value, and returns
the *normalised* (IDNA-encoded, lower-cased, root-dot-stripped) value on
success — so a Pydantic `field_validator` does both in one pass. Common
caps across all three rules: label ≤ **63** characters, whole name ≤ **253**.

### 18.1 Validate on write — never auto-mutate

**The validators run on write only. Existing rows are never rewritten.**
Silently mutating an operator's stored name would be a worse failure than
leaving it alone — so a non-conforming legacy row stays exactly as it is
until someone edits it deliberately. §18.3 is how you find them.

The one place a bad name must *not* raise is the **DHCP lease path**. A
client-supplied hostname arriving off the wire (option 12 on a DISCOVER, a
lease event, a Windows lease pull) goes through the **non-raising**
`sanitize_hostname` instead, which folds it into a safe multi-label LDH
form (or `""` if nothing usable is left). A malformed hostname must never
drop a lease. Call sites: `backend/app/api/v1/dhcp/agents.py:166` and
`backend/app/services/dhcp/pull_leases.py:178`.

### 18.2 Defense in depth at the render boundary

The BIND9, PowerDNS and Technitium drivers run **every** rendered name and
rdata value through `strip_control_chars` before it reaches a zone-file
master line or the daemon's REST API (`backend/app/drivers/dns/bind9.py:71`
/ `powerdns.py:117` / `technitium.py:117`). A raw newline is the one
character that can inject a *second* record into a zone-file line, and no
legitimate name or rdata ever contains a control byte. This catches values
that never passed a field validator — an importer row, a legacy row, a
future code path — so they still cannot break out of their own record.
Spaces and quotes are left intact, so structured rdata (CAA / LOC / NAPTR /
SVCB) renders unharmed.

### 18.3 Auditing existing rows

`GET /api/v1/diagnostics/name-conformance` (**superadmin**, read-only,
mutates nothing) scans the live database for names today's validators would
reject and reports them by category:

| Category | Rows scanned | Rule applied |
|---|---|---|
| `ipam_hostname` | `IPAddress.hostname` (integration-owned rows excluded — an external mirror owns those names and the operator can't fix them here) | host |
| `dns_record_name` | `DNSRecord.name` | record owner |
| `dns_zone_name` | `DNSZone.name` | FQDN |
| `dhcp_static_hostname` | `DHCPStaticAssignment.hostname` | host |

Each category returns an exact `total` plus up to 100 examples
(`id` + `value` + the validator's own rejection `reason`), and a
`scanned_capped` flag when the per-category 200 000-row scan ceiling bit.
Implementation: `backend/app/services/dns_names_report.py`.

The same report is exposed to the Operator Copilot as the read-only
`find_nonconforming_names` MCP tool (default-enabled, superadmin-gated) —
*"which hostnames aren't valid DNS names?"* / *"do we have any records that
would break a zone file?"*.

## 19. Dynamic-update (RFC 2136) ACLs on zones (issue #641)

Operators can authorize **third-party dynamic-DNS writers** — an AD
domain controller, a DHCP server registering A/PTR — to update a managed
zone over RFC 2136, identified **by TSIG key** or **by source IP/CIDR**.
This is distinct from (and layered on top of) SpatiumDDI's own internal
loopback writes: the agent always keeps its group-key `allow-update` grant
so control-plane record ops keep flowing.

### 19.1 Data model

- `DNSZone.dynamic_update_enabled` (bool, default false) — the master
  gate. Off ⇒ only the internal loopback writer is authorized (today's
  behaviour).
- `dns_zone_update_acl` — one row per authorized writer, ordered by `seq`
  (first-match). Each row identifies a writer by *either* `tsig_key_id`
  (FK → `dns_tsig_key`) *or* `ip_cidr`; a `CHECK (num_nonnulls(...) = 1)`
  enforces exactly one. `action` / `name_scope` / `name_pattern` /
  `record_types` drive the fine-grained BIND9 `update-policy` path (P2).

Secrets never surface: a TSIG entry references a key by id/name, and the
Fernet-encrypted secret is resolved to a *name* only when the ACL renders
into the config bundle. API responses expose `tsig_key_name`, never the
secret.

### 19.2 Driver capability model

Backends differ in what they can express, so the driver ABC carries a
`DynamicUpdateCaps` descriptor (`supports_ip_acl`, `supports_tsig_acl`,
`supports_name_scoping`, `supports_per_type`, `coarse_enum_only`). The API
consults it **before** accepting an ACL:

| Backend | ip | tsig | name-scope | per-type | notes |
|---|---|---|---|---|---|
| **BIND9** | ✅ | ✅ | ✅ | ✅ | coarse `allow-update` + fine `update-policy` |
| **PowerDNS** | ✅ | ✅ | ⬜ | ⬜ | coarse per-zone metadata (`ALLOW-DNSUPDATE-FROM` / `TSIG-ALLOW-DNSUPDATE`) |
| **Windows DNS** | ⚠️ | ✅ | ⬜ | ⬜ | coarse zone enum (`None` / `Secure` / `NonsecureAndSecure`); an IP entry → `NonsecureAndSecure` + loud warning |
| **Route53 / Azure / Cloudflare / Google** | ⬜ | ⬜ | ⬜ | ⬜ | no RFC 2136 → 422 `DYNAMIC_UPDATE_UNSUPPORTED` |

An entry the group's driver can't honour is rejected (422); a
lossy-but-accepted mapping comes back as a `warnings[]` entry (e.g. an IP
entry is UDP-spoofable → recommend TSIG).

### 19.3 API

- `GET /dns/groups/{gid}/dynamic-update-caps` — what the group's driver(s)
  can express (the UI greys unsupported controls; `supported=false` ⇒ the
  whole feature 422s).
- `GET /dns/groups/{gid}/zones/{zid}/update-acl` — the current ACL +
  `dynamic_update_enabled` + resolved `tsig_key_name`s + standing warnings.
- `PUT /dns/groups/{gid}/zones/{zid}/update-acl` — full ordered replace
  (optionally flips `dynamic_update_enabled` in the same call). Superadmin;
  every mutation is audited; validation runs the driver capability gate.

All three gate behind the default-on `dns.dynamic_update_acl` feature
module. MCP: `find_zone_update_acls` (read, default-on) +
`propose_set_zone_update_acl` (write, preview/apply, **default-off** —
security-sensitive).

### 19.4 Rendering (BIND9)

The renderer picks **one** clause per zone by what the ACL needs:

- **Coarse (P1)** — all grants are unscoped, all-type, no `deny`: a single
  `allow-update` address-match-list mixing IP + TSIG:

  ```
  allow-update { 10.0.0.0/24; key "dc01-ddns."; };
  ```

- **Fine-grained (P2)** — any grant carries a `name_scope`, a `record_types`
  restriction, or is a `deny`: a BIND `update-policy` block (TSIG-identity
  only — IP entries are rejected at validation, since update-policy can't
  match on source IP):

  ```
  update-policy {
      grant spatium-loop. zonesub;                       # internal loopback
      grant dc01-ddns. subdomain wks.example.com. A AAAA;
      grant dhcp01-ddns. zonesub PTR;
      deny  dc01-ddns. name _locked.example.com.;
  };
  ```

  `name_scope` maps to the ruletype (`zonesub` / `subdomain` / `name` /
  `wildcard` / `self`); a name is required for the last four. `record_types`
  becomes the trailing type list (omitted ⇒ BIND's standard set).

Either way the internal loopback grant is always kept so control-plane
record ops keep flowing, and every TSIG key in the bundle renders a
`key { … }` block (previously only the group loopback key did) so an
operator key referenced in a clause is always defined.

### 19.5 Drift — ingest-back (Alt.1)

A dynamic zone accepts records the control plane didn't create; those live
only in the daemon journal and would be dropped on a full re-render (cold
boot, from-scratch re-seed). The BIND9 agent closes the loop: it AXFRs
each dynamic zone from loopback (signed with the group loopback key — the
zone stanza grants `allow-transfer { key … }` for exactly this, nothing is
opened to the network) and POSTs the live record set to
`POST /dns/agents/ingested-records`. The control plane mirrors any record
it doesn't already manage as an ordinary `DNSRecord` stamped
`import_source="ddns_external"`, so externally-injected records become
UI/IPAM-visible and survive a re-render.

**Conflict rule: control-plane-managed names win.** An incoming record
whose `(name, record_type)` collides with a managed row is skipped; only
external-only names are mirrored. Zone-management + DNSSEC RRs (SOA, apex
NS, RRSIG/NSEC*/DNSKEY/CDS/CDNSKEY, private-type 65534) are never ingested.

**P1 limitation:** live multi-server propagation of an ingested record
across every server in a group happens on the next full re-render, not
instantly (ingested rows aren't re-shipped as per-server record ops). The
record is durable + visible immediately; other servers converge on their
next structural reload.

---

## 20. Encrypted transports — DoT / DoH + encrypted forwarding (issue #50)

Two independent halves, each default-off so an existing install renders a
byte-identical `named.conf` until an operator opts in:

* **Inbound** — serve DNS-over-TLS (RFC 7858) and DNS-over-HTTPS
  (RFC 8484) to local clients.
* **Outbound** — forward to upstream resolvers over TLS instead of
  plaintext port 53.

Both are configured per **server group** under DNS → group → Options →
*Encrypted transports*, and both are **additive**: the plain Do53 listener
on :53 stays up, so turning DoT on never cuts off existing clients.

### 20.1 Certificates

The listeners serve a certificate from the existing
`appliance_certificate` store — the same one behind the Web UI cert and
the embedded ACME client (#438). Issue or upload once under
Appliance → Web UI Certificate, then point the group at it
(`dns_server_options.tls_certificate_id`).

The FK is `ON DELETE SET NULL`, so deleting a certificate can never delete
a group's options row. That leaves one state worth understanding: listener
flags on, certificate gone. **Both agent renderers treat that as
listener-off** and the server keeps serving Do53. This is deliberate — a
`tls` block whose `cert-file` doesn't exist makes `named` refuse to start,
which would take plain DNS down too. Degrading is the safe direction; the
agent logs `bind9_encrypted_listener_skipped_no_cert`.

Renewal rewrites `cert_pem` **in place** on the same row, so the group's
pointer stays valid. The cert material rides inside the hashed config
bundle, which means a rotation shifts the ETag and the long-poll delivers
it; `app.services.dns.cert_rotation.wake_dns_groups_serving_cert` publishes
an advisory wake from both the ACME renewal task and the manual
paste-back-signed-cert path so it lands in seconds rather than on the
safety tick.

### 20.2 Ports

| Knob | Default | Notes |
|---|---|---|
| `dot_port` | 853 | RFC 7858. |
| `doh_port` | 443 | RFC 8484 — but see below. |
| `doh_path` | `/dns-query` | Must be absolute; enforced by BIND's `endpoints`. |

The API rejects a listener on port 53 (the Do53 listener already binds
it), DoT and DoH sharing a port, and — **on appliance installs only** —
DoH on 443, where the web UI already serves HTTPS and the DNS workload
runs with `hostNetwork`. Use 8443 there and publish it in the DoH URL you
hand clients. Docker / Kubernetes operators own their own topology, so
443 is allowed there.

Firewall: DoT/DoH ports are operator-chosen, so unlike Do53's fixed 53
they can't live in the supervisor's static per-role port table. The
control plane derives the live ports from the assigned group's options
(only when a certificate is actually linked) and ships them on the role
assignment as `dns_encrypted_tcp_ports`; the supervisor opens exactly
those, so turning a listener off closes its port on the next apply.

### 20.2.1 Reaching the listener — per deployment

The listener port lives in the **database**. Everything below is about
making that port reachable from outside the DNS process, and each
topology needs a different thing:

| Deployment | What to change | 443 conflict? |
|---|---|---|
| **Appliance (k3s)** | Nothing — the DNS workload is `hostNetwork`, so it binds the host directly. The supervisor opens the port automatically (above). | **Yes** — the web UI owns 80/443. The API rejects either listener on those ports here; use 8443. |
| **Docker Compose (main stack)** | Add the `docker-compose.dns-encrypted.yml` overlay. It carries entries for `dns-bind9`, `dns-technitium` and `dns-dnsdist`; only the service in the profile you start comes up. | **No** — the frontend publishes `${HTTP_PORT:-8077}:80` and never binds 443. Container-side 443 is private to the DNS container. |
| **Compose (standalone agent files)** | Uncomment the port lines in `docker-compose.agent-dns-bind9.yml` / `-technitium.yml`. The overlay does **not** apply to these files — it names the main stack's services, and merging it here would try to create image-less `dns-bind9` / `dns-dnsdist` services. PowerDNS's standalone file has no dnsdist front, so DoT/DoH is unavailable there. | No. |
| **Kubernetes / Helm** | Set `dnsBind9.dotPort` / `dohPort` or `dnsTechnitium.dotPort` / `dohPort` / `doqPort` (appliance chart), or the same per-server keys (umbrella chart), to declare the containerPort + Service port. Raw manifests: uncomment the blocks in `k8s/dns/`. | Depends on your Ingress/LoadBalancer — you own the topology, so 443 is allowed. |

```bash
docker compose -f docker-compose.yml \
               -f docker-compose.dns-encrypted.yml \
               --profile dns-bind9 up -d
```

The ports are an **overlay**, not part of the base compose file, because
Compose cannot publish conditionally: binding 853 / 443 unconditionally
would break `up -d` on any host already using them — for a feature that
ships off by default. Opting in keeps the base stack a true no-op, the
same discipline the rest of #50 follows.

The vars split host and container side deliberately:

```
- "${DNS_DOT_HOST_PORT:-1853}:${DNS_DOT_PORT:-853}/tcp"
- "${DNS_DOH_HOST_PORT:-8443}:${DNS_DOH_PORT:-443}/tcp"
```

The **container** side must match the port configured in the UI — the
agent renders the daemon config from the DB, not from these variables, so
a mismatch publishes a mapping to a port nothing is listening on. The
**host** side is just where it lands; the DoH default is 8443 so nothing
has to bind a privileged port. Every variable is documented in
`.env.example`.

Technitium gets its own host-port band (`DNS_DOT_HOST_PORT_TECHNITIUM` and
friends, defaulting to 6853 / 6444 to match its 6053:53 base mapping) so
all three drivers can run side by side, plus a third mapping the other two
don't have:

```
- "${DNS_DOQ_HOST_PORT_TECHNITIUM:-6853}:${DNS_DOQ_PORT:-853}/udp"
```

DoQ shares DoT's port **number** and differs in protocol — 853 is the RFC
default for both — which is why `doq_port` is a separate field from
`dot_port` rather than a checkbox on the DoT listener, and why the two
defaults above collide on purpose.

### 20.3 Upstream forwarding

`forward_transport` is `do53` (default), `tls`, `https` or `quic`. The last
two are Technitium-only and the API refuses them for a group containing a
BIND9 server: **BIND has no client-side HTTP or QUIC transport**, so
DoH-upstream and DoQ-upstream are not expressible on that driver (#741).
See the driver table in §20.4.

With `tls`, forwarders default to port 853 unless an entry pins its own
(`ip@port`), and each renders with the generated `tls spatium-upstream-tls`
statement. Per-zone forwarders on `type forward` zones inherit the same
transport — a group forwarding over DoT shouldn't silently fall back to
plaintext for its zone-scoped upstreams.

`forward_tls_verify` (default on) adds `ca-file` + `remote-hostname` for
strict validation, and the API refuses verification-on without a hostname
— there would be no name to check the upstream certificate against.
Verification failures **fail closed** (SERVFAIL), never a silent downgrade
to plaintext. Turning verification off gives opportunistic DoT: encrypted
against a passive observer, but not against an active on-path attacker.

One hostname applies to every forwarder in the group, because the common
case is a single provider's anycast pair (1.1.1.1 + 1.0.0.1 both present
`cloudflare-dns.com`). Mixing upstreams that present different certificate
names means one of them fails validation — use one group per upstream.

Note the trap this creates: a brand's filtering variants sit on adjacent
addresses but do **not** share a certificate name. `1.1.1.1` presents
`cloudflare-dns.com`, `1.1.1.2` presents `security.cloudflare-dns.com` and
`1.1.1.3` presents `family.cloudflare-dns.com`; Quad9 splits the same way
across `dns.quad9.net` / `dns10.quad9.net` / `dns11.quad9.net`. So
`1.1.1.1` alongside `1.1.1.3` breaks exactly like Cloudflare alongside
Google, while looking deliberate. Since #877 the API refuses that
combination outright when verification is on, rather than letting it
SERVFAIL in production.

### 20.3.1 Resolver presets (#877)

Rather than expecting operators to remember both halves, `GET
/api/v1/dns/forwarder-presets` serves a curated catalogue of well-known
public upstreams — addresses, the DoT hostname each presents, and what it
filters by default. The Forwarders card offers them as a picker that fills
the address list and `forward_tls_hostname` in one action, with a one-click
"Switch to DoT" nudge when the group is still on plaintext 53.

The catalogue lives at `backend/app/data/dns_resolver_presets.json` behind
`app/services/dns/resolver_presets.py`, and is served from the backend
rather than hardcoded in the frontend so the picker, the API's conflict
check and the `list_resolver_presets` Copilot tool all read one table.
Entries are verified against each provider's own documentation; a preset
carrying a stale hostname is worse than no preset, because it fails closed
on every query.

Two levels of checking sit on top of it:

* **Hard refusal (422)** when the forwarder list spans two catalogued
  upstreams with different certificate names and verification is on. This
  case cannot work, so it is refused rather than warned about.
* **Advisory (UI only)** when the typed hostname is not the documented one
  for a recognised address set. Deliberately not a refusal: providers list
  several names in one certificate — Cloudflare's covers `one.one.one.one`
  as well as `cloudflare-dns.com` — and the catalogue records only the
  canonical one, so a hard error would reject working configurations.

Unrecognised addresses carry no opinion at either level. An internal
resolver or an uncatalogued provider must stay configurable.

### 20.4 Driver support

| Driver | Inbound DoT / DoH | Outbound over TLS |
|---|---|---|
| **BIND9** | Native (`tls` + `http` statements) | Yes (`forwarders { … tls … }`) |
| **PowerDNS** | Via the dnsdist front (#146 Phase 2) | N/A — pdns Authoritative doesn't recurse or forward |
| **Technitium** | DoT + DoH + DoQ served natively, no sidecar ([§4B.3c](../drivers/DNS_DRIVERS.md)). Cert must be PKCS #12 — the agent converts the PEM the bundle ships. | Forwards over DoT, **DoH and DoQ** — the only driver that can, since BIND has no client-side HTTP transport |
| Windows DNS, cloud drivers | Not supported — we don't run their listeners | — |

On PowerDNS the listeners are `addTLSLocal` / `addDOHLocal` on the dnsdist
sidecar, which terminates TLS and forwards plaintext to pdns over the
container network. That front is **docker-compose-only** today (see
`charts/spatiumddi-appliance/values.yaml`), so DoT/DoH on the PowerDNS
driver is docker-compose-only too. BIND9 needs no sidecar.

One dnsdist-specific hazard worth recording: `dnsdist --check-config`
reports OK for a config whose `addTLSLocal` cert path doesn't exist, and
the daemon then dies *fatally* on real startup. Because the front's reload
loop stops the running instance before starting the new one, trusting
`--check-config` alone would take the whole front down — Do53 included —
on nothing worse than a half-written cert. The entrypoint therefore
pre-flights every `*.crt` / `*.key` path referenced by the rendered rules
and keeps the current instance serving if any is unreadable.

### 20.5 Verifying

```bash
# DoT, with strict validation
kdig +tls @dns.example.com -p 853 www.example.com A
dig +tls +tls-hostname=dns.example.com @<ip> -p 853 www.example.com A

# DoH
dig +https=/dns-query @<ip> -p 8443 www.example.com A
curl -H 'accept: application/dns-message' \
     'https://dns.example.com:8443/dns-query?dns=<base64url-query>'

# Upstream is genuinely encrypted — capture on the upstream link and
# confirm no plaintext :53 leaves the box
tcpdump -ni any 'port 53'
```

---

## 21. Query outcomes — the answer half of the query log (issue #914)

`dns_query_log_entry` recorded the *question* and nothing about the
*response*. BIND's `queries` logging category is request-side by design:
it logs a query as it arrives and never mentions what was sent back. So
the Logs → DNS Queries surface could prove a query reached the server,
and could not distinguish the five outcomes an operator is actually
triaging:

| What happened | What it means | Where to look next |
|---|---|---|
| No row at all | the query never reached this server | resolver config, DHCP option 6, firewall |
| `NOERROR` with answers | DNS is fine | not DNS — routing, or the service itself |
| `NOERROR` with **0** answers (NODATA) | the name exists, but has no record of that type | the record type, or an AAAA-only client |
| `NXDOMAIN` | the record does not exist | the zone, or a typo |
| `REFUSED` | an ACL or view is rejecting this client | `allow-query`, view `match-clients` |
| `SERVFAIL` | DNSSEC validation or a broken forwarder | validation, the upstream |

All of them collapsed into "there is a row" or "there is not", and the
most common real outcome — a query that *was* answered, just not the way
the user expected — was indistinguishable from one that was refused.

### 21.1 Where the data comes from

BIND 9.20 ships `responselog`, a second logging category (`responses`)
carrying one line per response:

```
23-Aug-2026 13:20:09.490 responses: info: client @0x7f83 127.0.0.1#57018 \
    (www.example.com): view internal: response: www.example.com IN A \
    NOERROR 1 1 2 +E(0)K (127.0.0.1)
```

The trailing counts are answer / authority / additional. SpatiumDDI
parses the RCODE and the **answer count** — the second is what makes
NODATA visible, and NODATA is a genuinely different fault from NXDOMAIN
that reads identically without it.

The line is routed to the same `queries_channel` the query log already
uses, so no second shipper thread, log file or bind mount is involved.
The control plane tells the shapes apart at ingest by separator
(`: response: ` vs `: query: `, neither of which can occur inside a DNS
name or a view name) and stamps the outcome onto the query row it
belongs to, matched on client address + ephemeral source port + qname +
qtype. A response whose question cannot be found is **dropped, not
stored**: a row with an outcome and no question answers nothing, and
inventing a query row for it would double-count every query in the
analytics rollups the same table feeds.

### 21.2 Enabling it

Per DNS server group, under **Query Logging** → *Record the outcome of
each query*. Default **off**, and it requires query logging to be on,
because the response lines are written to the channel the query-log
block defines. A caller that explicitly asks for the impossible pair
gets a 422 rather than a toggle that rewrites `named.conf` and produces
nothing; a caller simply turning query logging *off* has asked for
nothing impossible, so response logging is cleared alongside it — the
only coherent resulting state, and the alternative would leave no single
call that disables query logging at all.

It roughly **doubles query-log volume**: named writes a second line per
query. That volume is why the query log is capped at a 24 h window in
the first place, so treat this as a troubleshooting switch rather than a
permanent setting on a busy resolver.

> **`rndc reconfig` does not apply `responselog`.** Verified against
> BIND 9.20.26: with `responselog yes;` in a freshly-swapped config and
> a clean reconfig, `rndc status` still reported
> `response logging is OFF`. It is a live switch, like `querylog`, and
> reconfig deliberately
> preserves whatever the running server was last told. Query logging
> escapes this only by accident of BIND's own defaulting — with no
> `querylog` statement it follows the presence of the `queries`
> category, which a reload does pick up. The agent therefore issues an
> explicit `rndc responselog on|off` after each structural reload,
> reading the desired state back off the config it just swapped in.
> Without that the toggle would appear to work and produce not one line
> until the daemon was next restarted.

### 21.3 Which drivers fill it

| Driver | `rcode` |
|---|---|
| BIND9 (agent-managed) | yes, when response logging is enabled |
| PowerDNS (agent-managed) | no — its detail log carries no RCODE field |
| Technitium | no — query-log polling is deferred (#742), and its API does expose the rcode when it lands |
| Windows DNS, cloud drivers | no — they ship no query log at all |

**`NULL` means UNRECORDED, never `NOERROR`.** Every surface keeps the
two apart: the API returns `null`, the grid renders *not recorded* in
italics rather than a dash beside a successful lookup, the analytics
breakdown counts them under an explicit `UNKNOWN` key rather than
omitting them, and the copilot tool spells the reason out in the field
itself. A server with the toggle off shows one honest bar instead of an
empty panel that reads as "no failures".

### 21.4 Individual RPZ hits

`GET /api/v1/dns-threat/rpz/hits` returns the per-hit rows behind the
blocklist rollups — timestamp, client, name, trigger, policy and the
feed that matched. Those rows have been stored since #699 and were
reachable from no endpoint, so "show me the three lookups this PC made
in the last ten minutes that were blocked" was unanswerable; only "this
client has N hits and its top name is X" was. PASSTHRU rows are excluded
by default, because a PASSTHRU is an explicit *allow* and listing it
among blocks makes a working allowlist read as an infection —
`include_passthru=true` answers the opposite question, why a listed name
got through.

> **The pipeline behind them was dead on the agent path.** named logs a
> policy rewrite to its own `rpz` category, and the agent's BIND9
> renderer — the one every agent-managed server actually runs — never
> emitted `category rpz { queries_channel; };`. The control-plane Jinja
> template has carried it since #699, which is why the gap survived
> review: the code was right in the file nothing renders from. Fixed in
> #914 along with `rpz-passthru`, whose absence left the entire
> exception half of the attribution dark and the `policy != PASSTHRU`
> filters in `services/dns_threat/rpz.py` unreachable. Same class as
> `allow_transfer` (#734) and `forward_policy` (#899): a setting that is
> stored, shipped, and rendered nowhere. The lesson from §8.2 applies
> unchanged — **assert on the rendered config, not the stored row**.

---

## 22. Zone name scope — public, private, undelegated (issue #986)

`validate_fqdn` only ever told you a zone name was *syntactically* a
domain. So `corp.example.com`, `ad.contoso.local`, `lab` and `acme.lan`
all rendered identically in the zone table — while the first is a name
the public internet resolves, the second collides with mDNS, and the last
two sit on top-level domains nobody has delegated.

Every zone is now classified against IANA's root-zone list and shown as a
pill in the zone table, an icon on the zone detail, a live hint under the
name field as you type, and a column on every importer preview. It is
derived at serialisation from the zone name — **no column, nothing
stored**, so it changes on its own when IANA delegates a new TLD and you
refresh the list.

### 22.1 The four scopes

| Scope | Rule | Examples | Pill |
|---|---|---|---|
| `reverse` | Under `in-addr.arpa` / `ip6.arpa` | `10.in-addr.arpa`, `8.b.d.0.1.0.0.2.ip6.arpa` | neutral **Reverse** |
| `reserved` | Matches the special-use table | `.local`, `.localhost`, `.test`, `.example`, `.invalid`, `.onion`, `.alt`, `home.arpa`, `example.com/.net/.org`, `.internal`, `.corp`, `.home`, `.mail` | **Private** (amber for `.local`) |
| `public` | Last label is a delegated IANA TLD | `.com`, `.io`, `.xn--p1ai`, `.arpa` | **Public** |
| `undelegated` | None of the above | `.lab`, `.lan`, `.intranet`, `.private`, typos | **Undelegated** |

**The order is load-bearing.** Reverse is tested first because `.arpa` is
a real delegated TLD, so a reverse zone would otherwise read as *Public* —
and they are always ours (#41 auto-creates them), so they must not read
as *Private* either. Reserved comes before public because `example.com`
sits under a delegated TLD and is still reserved, as does `home.arpa`.
Within reserved, the longest suffix wins, so `home.arpa` is not shadowed
by a one-label entry.

Matching is **label-wise, never a string `endswith`**: `mylocal` is not
under `.local`, and `notexample.com` is not `example.com`.

### 22.2 What the pills mean, and what they deliberately do not

Nothing here refuses anything. `.local` is a warning because Microsoft
told a generation of admins to build Active Directory on it and plenty of
real installs run it; an authoritative `.local` zone collides with
mDNS / Bonjour on the same LAN, and clients may get either answer. That
is worth saying once, in a tooltip — not worth a 422 that would lock an
existing estate out of its own DNS.

`undelegated` is the same shape. The name works today and is protected by
nothing: ICANN could delegate the TLD, and any query that escapes your
resolvers leaks to the root. The hint points at `.internal`, which ICANN
reserved in 2024 for exactly this.

> **`.lan`, `.intranet` and `.private` are deliberately *not* in the
> reserved table.** They are the three names operators most often assume
> are safe. SSAC's name-collision work considered them and did not
> protect them, so listing them as reserved would tell you they are
> blessed when they are exactly as unprotected as a typo.

### 22.3 Where the list comes from

Two sources, one effective answer:

* **Bundled** — `backend/app/data/iana_tlds.json`, regenerated at
  release-prep by `make tld-registry` (`scripts/refresh_iana_tlds.py`);
  `make tld-registry-check` answers "is the bundled copy behind IANA?"
  without writing anything. Always present, so classification works on an
  air-gapped install that has never made an outbound call.
* **Snapshot** — a one-row `tld_registry_snapshot` table filled by
  **Settings → DNS → TLD Registry → Refresh now**
  (`POST /api/v1/dns/tld-registry/refresh`, superadmin, audited).

The snapshot wins **only when its version is newer** than the bundled
one. That direction matters: a fresh release ships a newer bundled list
than a year-old snapshot, and silently preferring the stored copy would
make an upgrade lose TLDs. The Settings card says which one is in use and
why, so a refresh that appears to change nothing is explained rather than
mysterious.

In Postgres rather than on disk, because a node-local file does not
propagate across a multi-node control plane — one node would call `.foo`
public while its neighbour called it undelegated. Same reasoning as the
#886 branding logo.

**There is no scheduled fetch.** TLD churn is a handful of entries a
year, which does not justify a standing connection to a third party
(non-negotiable #17). The refresh is listed in
[`docs/PRIVACY.md`](../PRIVACY.md) §3.2 and sends nothing about the
install — it is an unauthenticated GET of one public file.

The **special-use table is never overridable by a refresh**. Those
entries change by RFC and by ICANN action, and none of that appears in
IANA's root-zone download; `scripts/refresh_iana_tlds.py` preserves the
table verbatim and refuses to run if it is missing.

> **The download guard is the load-bearing part.** A payload with fewer
> than 1,000 entries, or missing `com` / `net` / `org` / `arpa`, is
> rejected with a 502 and **nothing is written** — the previous snapshot,
> or failing that the bundled list, stays in force. Storing a truncated
> download would relabel every public zone in the estate as
> *Undelegated* in one action, with no error anywhere. The script and the
> product share one parser (`parse_tld_payload`) rather than keeping two
> copies of that guard, and a test asserts they resolve to the same
> source function — two validators meant to agree is the bug class §8.1
> catalogues.

### 22.4 Domains (#85) with no registry

A Domain with no registry behind it can never have RDAP data. Rather than
querying anyway and reporting "no RDAP server" as an outage, the refresh
**skips** it: `whois_state` goes to `n/a`, `whois_last_checked_at` and
`next_check_at` are still stamped so the beat sweep paces itself, and the
result carries a `skipped_reason`. This mirrors the ASN side, where a
private AS number sits at `n/a` and the RIR is never queried. The sweep
counts these under `skipped_no_registry`, never under `unreachable` —
folding them together would report every `.lan` row as a broken registry
on every tick, which is the mislabelling this exists to remove.

**The decision is made in two stages, and the split is load-bearing.**

A `reserved` or `reverse` name is settled locally: those namespaces have
never been served by a registry and never will be, so nothing outbound
happens at all.

`undelegated` is *not* settled locally, because the TLD list above is a
snapshot — the one bundled with this release, plus whatever the operator
last refreshed. A TLD delegated since that snapshot classifies
`undelegated` while RDAP would answer perfectly well, and skipping it
would freeze `expires_at` forever, leaving `domain_expiring` alerts
sitting on data that never updates and no hint on the Domains page that a
TLD-registry refresh is the cure. So the decision is handed to IANA's
**live** RDAP bootstrap, which is authoritative and self-heals. An
unreachable bootstrap is deliberately distinct from "no registry": it
falls through to the lookup, because reading an IANA outage as "no
registry exists" would mark every domain in the estate `n/a` in one tick.

The privacy improvement survives that: an internal-only name like
`corp.lan` still reaches no registry. The bootstrap is a cached GET of one
static public file that any real lookup fetches anyway, and it carries no
domain name.

### 22.5 Surfaces

| Where | What |
|---|---|
| `ZoneResponse.name_scope` + `name_scope_detail` | Every zone read, REST and MCP alike. Derived, never stored |
| Zone table | Scope column + an *All scopes* filter |
| Zone detail | Pill beside the name, reason in the tooltip |
| Create / edit zone | Live hint under the name field, classified server-side (`GET /dns/tld-registry/classify`) so there is exactly one implementation of the rules |
| Importer previews (#128 / #744) | Scope column per zone row — a bulk import is where an estate full of `.lan` zones first becomes visible, and the last point before it is committed |
| Domains (#85) | Same pill; non-public rows sit at `whois_state = n/a` |
| Copilot | `list_dns_zones` reports `name_scope` and accepts it as a filter |

No new MCP tool (non-negotiable #13 — one field on an existing read), and
none for the refresh, which is an off-prem call. Not a feature module
(#14) — it extends the existing zone resource rather than adding a
top-level family.
