# DHCP Feature Specification

> **Implementation status (2026-04-28):** Kea driver, agent runtime, container image, backend API, and frontend UI shipped in the `2026.04.16-1` release. Pool overlap validation, existing-IP warning, resize, static ↔ IPAM sync (including DNS forward/reverse), lease → IPAM mirror (with auto-cleanup on expiry), DHCP Pool membership column in the IPAM subnet view, per-scope DHCP defaults prefilled from Settings. **Windows DHCP driver shipped** — Path A (agentless, WinRM + PowerShell, read-only lease monitoring + per-object scope / pool / reservation CRUD). **DDNS pipeline shipped for both paths** — agentless lease pull (2026-04-19) and agent-side Kea lease events (2026-04-21). **Group-centric Kea HA shipped** (`2026.04.21-2`) — load-balanced or hot-standby pairs with self-healing peer-IP drift, supervised daemons, and live `status-get` reporting. **Scope authoring helpers (`2026.04.28-2`):** 95-entry RFC 2132 + IANA option-code library with autocomplete on the custom-options row, plus named group-scoped option templates (e.g. "VoIP phones", "PXE BIOS clients") with a one-click "Apply template…" picker on the scope create / edit modal. **PXE / iPXE provisioning profiles** (issue #51) and **passive DHCP fingerprinting** (Phase 2 device profiling) have since shipped — see §17 and §18. **Still deferred:** Option 82 (relay agent info) class matching, lease histogram by hour, reconciliation report, lease import. NTP (DHCP option 42) is a first-class option.

## Overview

SpatiumDDI manages DHCP servers as authoritative configuration sources. The IPAM database is the **source of truth** — DHCP server configs are pushed from IPAM, not read from the servers. DHCP servers are configured to report lease events back to SpatiumDDI for real-time IP status tracking and DDNS updates.

Supported backends: **ISC Kea DHCP** (preferred) and **Windows Server DHCP** (agentless). ISC DHCP v4 is intentionally **not** supported — upstream declared end-of-life in 2022; Kea is the successor.

---

## 1. DHCP Server Model

```
DHCPServer
  id, name, description
  driver: enum(kea, windows_dhcp)
  host, port
  credentials (encrypted Fernet)
  roles: [enum(dhcp4, dhcp6)]     -- server can run both
  server_group_id (nullable)      -- logical grouping for HA pairs
  status: enum(online, offline, degraded, syncing)
  last_sync_at, last_health_check_at
  config_cache_path: str          -- local path where agent caches last-good config
```

### DHCP Server Groups

**DHCPServerGroup is the primary configuration container.** Scopes, pools, statics, and client classes all belong to a group — every member server renders the same Kea config. A group with one member is a standalone DHCP service; a group with two Kea members is implicitly an HA pair, driving the `libdhcp_ha.so` hook.

```
DHCPServerGroup
  id, name, description
  mode: enum(standalone, hot-standby, load-balancing)
  dhcp_socket_mode: enum(direct, relay)   -- Kea dhcp-socket-type selector
  heartbeat_delay_ms, max_response_delay_ms, max_ack_delay_ms, max_unacked_clients
  auto_failover: bool
  servers: [DHCPServer]          -- 2 Kea members = HA pair
  scopes: [DHCPScope]            -- rendered on every member
  client_classes: [DHCPClientClass]
```

**Client reachability (`dhcp_socket_mode`, issue #365).** Kea's
`dhcp-socket-type` is a *per-daemon* setting — it can't vary per subnet —
so it lives on the group and applies to every member Kea. Two values,
surfaced in the create/edit modal as **Client reachability**:

| Mode | Renders | Use when |
|---|---|---|
| `direct` *(default)* | `dhcp-socket-type: raw` | The server is on the same L2 as its clients. Raw (AF_PACKET) sockets receive broadcast `DHCPDISCOVER`s from clients that have no IP yet **and** relayed traffic — the superset, and Kea's own default. Needs `CAP_NET_RAW` (granted on the appliance DaemonSet + the shipped compose Kea services). |
| `relay` | `dhcp-socket-type: udp` | Kea sits exclusively behind a DHCP relay (`ip helper-address` / `dhcrelay`), or the runtime can't grant raw-socket capability. UDP datagram sockets cannot receive direct L2 broadcasts. |

The value flows to every deploy path (k8s / compose / appliance) through
the ConfigBundle long-poll and is folded into the bundle ETag, so a
change re-renders the running Kea within a heartbeat. It is distinct from
`network_mode` (host vs bridged), which controls the *container's* network
namespace on supervisor-managed appliances — a directly-attached server
typically wants `network_mode: host` **and** `dhcp_socket_mode: direct`.
See [TROUBLESHOOTING.md](../TROUBLESHOOTING.md#dhcp-server-kea-doesnt-respond-to-discover)
for the "no DHCPOFFER" diagnosis flow.

---

## 2. DHCP Scopes and Pools

This is the most granular part of the DHCP model. Within a **subnet**, you can define:
- Multiple **pools** with different behaviors (dynamic, reserved, excluded)
- **Static assignments** (fixed IPs by MAC address)
- **Pool-level DHCP options** that override subnet defaults

### Hierarchy

<p align="center">
  <img src="../assets/diagrams/dhcp-scope-containment.svg" alt="DHCP scope hierarchy" width="900"/>
</p>

### DHCPScope Model

```
DHCPScope
  id, group_id, subnet_id
  is_active: bool
  lease_time: int (seconds, default 86400)
  max_lease_time: int
  options: JSONB {               -- scope-level options (override server defaults)
    "routers": ["10.1.2.1"],
    "dns-servers": ["10.0.0.53", "10.0.0.54"],
    "domain-name": "internal.example.com",
    "domain-search": ["internal.example.com", "example.com"],
    "tftp-server-name": "10.0.0.10",   -- for PXE
    "bootfile-name": "pxelinux.0",
    "vendor-class-identifier": "...",
    custom_options: { "176": "..." }   -- vendor-specific options by code
  }
  ddns_enabled: bool
  ddns_hostname_policy: enum(client_provided, client_or_generated, always_generate, disabled)
  dns_track_dynamic_leases: bool (default true)  -- see "Dynamic-lease DNS drift" below
  address_family: enum(ipv4, ipv6)   -- inferred from the bound subnet's CIDR
  v6_address_mode: enum(stateful, stateless, slaac)  -- v6 only (issue #52)
  ra_managed_flag: bool              -- intended RA M-flag (router-side intent)
  ra_other_flag: bool                -- intended RA O-flag (router-side intent)
  last_pushed_at: timestamp
```

#### Dynamic-lease DNS drift (`dns_track_dynamic_leases`)

When SpatiumDDI pulls active leases from an agentless DHCP server (Windows DHCP,
FortiGate) it mirrors each into IPAM as an `auto_from_lease` address row. A
pulled lease carries the client-supplied hostname, so the IPAM ↔ DNS drift
check (`services/dns/sync_check.compute_subnet_dns_drift`, surfaced as the "DNS"
column / "N out of sync" banner and the **Sync DNS** flow) would treat every
ephemeral lease with no forward/reverse record as **missing** — flagging the
whole dynamic pool as "out of sync" even though the operator has no intention of
publishing DNS for transient leases.

`dns_track_dynamic_leases` is the per-scope opt-out. When **false**, the drift
check ignores this scope's dynamic-pool lease mirrors (`auto_from_lease` IPs
whose address falls inside one of the scope's `dynamic` pools), and any leftover
auto-generated records for them are reported as `stale` so a Sync DNS run offers
to clean them up.

**Design decision (documented for the MR):** the flag defaults to **`true`** —
preserving the prior behaviour (dynamic-lease rows *are* drift-checked) so no
existing install silently changes. Operators opt out per scope when lease DNS is
noise. The gate is scope-level (not a global toggle) because dynamic pools —
and the decision to publish DNS for them — belong to a scope; and it keys on
`auto_from_lease` **and** dynamic-pool membership so a manually-allocated IP that
happens to sit in the pool is still tracked. Static reservations
(`status="static_dhcp"`) are never affected — only dynamic-lease mirrors.
Rejected alternatives: a global setting (too coarse — mixed scopes want
different policies) and suppressing the hostname on the mirror row (loses
operator-visible lease hostnames in IPAM).

#### DHCPv6 operating mode (issue #52)

For IPv6 scopes, `v6_address_mode` chooses how clients on the subnet get
their address, and drives what the Kea driver renders into the `subnet6`:

| Mode | Kea `subnet6` render | RA flags (set on the router) | Client behaviour |
|---|---|---|---|
| `stateful` | address `pools` + `option-data` + reservations | M=1, O=1 | DHCPv6 hands out the address (IA_NA) and options |
| `stateless` | **no pools**, `option-data` only + reservations | M=0, O=1 | Client SLAACs its address from the RA prefix, asks DHCPv6 (Information-Request) for DNS / domain-search |
| `slaac` | bare subnet — **no pools, no options, no reservations** | M=0, O=0 | The router's RA does everything; DHCPv6 is not involved |

The `ra_managed_flag` (M) / `ra_other_flag` (O) columns record the
intended Router-Advertisement flags, auto-suggested from the chosen mode
(and freely overridable). Historically these were pure "set this on your
router" intent — **as of issue #524 SpatiumDDI can also emit RAs itself**
by running radvd on the DHCP agent from control-plane-rendered config
(opt-in per scope via `ra_enabled`; see §19). The mode picker only appears on IPv6
scopes; v4 scopes ignore these columns and always serve addresses +
options. Changing the mode shifts the agent ConfigBundle ETag, so the
Kea agent re-pulls and re-renders.

#### DHCPv6 behind a relay, the firewall, and v6 leases (issues #1139–#1141)

**Unicast sockets (#1140).** `interfaces: ["*"]` makes kea-dhcp6 bind each
interface's link-local address and the `ff02::1:2` group, and nothing
else. A relay does not send there. It sends its Relay-Forward to the server
address it was configured with, which is a global unicast address, so a
relayed Solicit reached the NIC and found no socket. When a group has IPv6
scopes, the Kea agent now adds an `"<iface>/<address>"` entry for each
stable global IPv6 address it finds on the host (`/proc/net/if_inet6`;
temporary, deprecated, tentative and dad-failed addresses are skipped). The
render is `["*", "ens18/2001:db8:87::40"]`: the wildcard sockets stay and
the unicast one is added.

The addresses are detected, never configured. Measured on kea-dhcp6
3.0.3: an entry naming an address the interface does not hold makes Kea
refuse the whole config, which takes DHCPv6 down. So the agent reads them
immediately before each render, and re-renders when the set changes. The
bundle ETag cannot see host addresses, so nothing else would. To check a
node:

```bash
ss -ulpn6 | grep 547    # expect the global address, not only fe80::…%iface and ff02::1:2
```

**Firewall (#1139).** The appliance's `dhcp` role opens UDP **547** as well
as 67/68. Kea's v6 server has no raw-socket mode, so every DHCPv6 packet
goes through the `input` chain, and without the rule it hit the drop
policy. The port is always open, not gated on a v6 scope existing:
nothing in the role assignment carries scope families, and an idle
kea-dhcp6 answers nothing. The host's own DHCPv6-client return
(`udp sport 547 dport 546`) is in the base config's floor, next to the v4
one.

**Leases (#1141).** The agent tails `kea-leases6.csv` beside the v4 file
and walks `lease6-get-page` on start and after an outage. A v6 lease is
identified by **DUID + IAID**, so `dhcp_lease.mac_address` is nullable,
`duid` / `iaid` are stored, and a CHECK requires one identity or the other.
Kea records a hardware address on a v6 lease only when it can derive one.
When it does, it rides along as enrichment. v6 leases mirror into IPAM,
drive DDNS (AAAA + ip6.arpa PTR, through the same path as v4) and satisfy
`dns_track_dynamic_leases`. Only **IA_NA** is ingested. IA_TA addresses are
short-lived privacy addresses. An IA_PD lease delegates a *prefix*, which
is not a host address the mirror can hold, so it is deferred. The agent
sends v6 events in batches of their own: a control plane older than
#1141 requires a MAC and 422s a batch containing a MAC-less event. Kept
apart, the v4 leases beside them still land.

**Domain search (#1141).** A stateful or stateless v6 scope that sets no
`domain-search` (option 24) now gets one by the same fallback the RA's
DNSSL uses (`radvd.resolve_dnssl`): the scope's `domain-name`, then the
subnet's `domain_name`. The two can no longer disagree. A scope's own
`domain-search` always wins.

### DHCPPool Model (Dynamic Ranges)

Each scope can have **multiple pools**, each with its own range and optional class restrictions.

```
DHCPPool
  id, scope_id
  name: str (optional label, e.g., "Workstations", "Printers", "VoIP")
  start_ip: inet
  end_ip: inet
  pool_type: enum(dynamic, excluded, reserved)
    -- dynamic:   IPs handed out to any eligible client
    -- excluded:  range exists in subnet but DHCP will NOT offer these IPs
    -- reserved:  range held for static assignments only (not auto-assigned)
  class_restriction: str (nullable)   -- Kea client class
  lease_time_override: int (nullable) -- overrides scope lease_time for this pool
  options_override: JSONB (nullable)  -- additional options for this pool only
```

> Earlier revisions of this document listed `utilization_percent` and
> `current_lease_count` as computed model fields. Neither ever existed on the
> row — occupancy is derived at request time from mirrored lease and
> reservation state, and is served by the endpoints below (#913, corrected
> in #917).

### Pool occupancy over REST (issue #913)

```
GET /api/v1/dhcp/pools/{pool_id}/occupancy
GET /api/v1/dhcp/scopes/{scope_id}/pools/occupancy    # every pool, one call
```

```json
{
  "pool_id": "…", "scope_id": "…", "pool_name": "Workstations",
  "start_ip": "10.1.2.101", "end_ip": "10.1.2.200",
  "pool_type": "dynamic",
  "total": 100, "assigned": 97, "free": 3, "percent": 97.0,
  "computed_at": "2026-08-23T12:00:00.000Z"
}
```

`assigned` is the count of distinct in-range addresses **unavailable to
a dynamic client**: active leases *unioned* with in-pool static
reservations. Both halves matter and neither is obvious from outside:

* A reservation withholds its address whether or not the reserved device
  is currently online, so counting leases alone under-reports exhaustion
  (#631) — and a wrong "the pool is fine" sends the technician looking
  in the wrong place.
* A reserved-**and**-currently-leased address is one address, not two,
  which is why this is a union rather than a sum.

"Is this pool exhausted?" is one of the first questions asked when a
client cannot get an address, and until #913 the API could not answer it:
the computation had existed since #339 but was reachable only from the
`find_dhcp_pool_occupancy` copilot tool and the `dhcp_pool_exhaustion`
alert evaluator. Every consumer had to fetch pools, leases and
reservations separately and redo the range arithmetic — three round
trips and an easy thing to get subtly wrong.

The **scope-level** shape is the one that matters operationally: a scope
with several pools is exactly where a call-per-pool is wasteful, and also
where "the scope looks fine" hides one exhausted class-restricted pool.
It runs a single batched lease + reservation query for all of them.

**Dynamic pools only.** The scope listing omits every other type and the
per-pool route returns 422 for one, because each would produce a
misleading number — and because the `dhcp_pool_exhaustion` alert
evaluator and the `find_dhcp_pool_occupancy` copilot tool already filter
the same way, so answering differently here is how a wrong "the pool is
fine" gets produced:

* `excluded` — a range DHCP will never offer, so "percentage full" is
  not a fact about it.
* `reserved` — held for static assignments, so a correctly configured
  one is *supposed* to approach 100% and would render as a red
  exhaustion bar for doing its job.
* `pd` (#368) — `start_ip` / `end_ip` are NOT NULL placeholders holding
  the delegated prefix's network address rather than a range, so the
  arithmetic reports a one-address pool at 0%.

`computed_at` is returned because occupancy is derived from the mirrored
lease rows, so its freshness follows the last lease pull rather than
being instantaneous.

### Fleet-wide lease lookup (issue #917)

```
GET /api/v1/dhcp/leases          # active leases across every server
GET /api/v1/dhcp/lease-history   # expired / released, across every server
```

The per-server routes (`/dhcp/servers/{id}/leases` and
`/dhcp/servers/{id}/lease-history`) answer "what is this server handing out",
which is the server-detail question. They cannot answer the one a technician
*starts* from — **"does this MAC have a lease anywhere?"** — without a call per
server plus a client-side merge, and that merge is order-sensitive: page 1 of
server A and page 1 of server B are not the newest rows overall.

Both fleet routes take the same filters as their per-server counterparts, with
the server restriction moved to optional `server_id` / `group_id` query
parameters, and return the same row shapes (including the OUI vendor and
Fingerbank device fields). `/leases` additionally accepts **exact** `mac` and
`ip` filters alongside the substring `search`, because a substring match on a
MAC also returns unrelated devices whose address happens to contain the same
bytes.

`mac` is normalised before matching, so `AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff`
and `aa:bb:cc:dd:ee:ff` are the same query — a lookup that answers "no lease"
because the operator pasted a different separator is worse than one that
errors.

### Example: Multiple Pools in One Subnet (10.1.2.0/24)

| Pool Name | Range | Type | Notes |
|---|---|---|---|
| Infrastructure | 10.1.2.1–10.1.2.20 | excluded | Gateways, servers — never DHCP |
| Static Only | 10.1.2.21–10.1.2.50 | reserved | Printers with static assignments |
| VoIP Phones | 10.1.2.51–10.1.2.100 | dynamic | Class: VoIP, short lease, option 150 |
| Workstations | 10.1.2.101–10.1.2.200 | dynamic | Standard lease, all defaults |
| Guest WiFi | 10.1.2.201–10.1.2.240 | dynamic | Class: Guest, 2h lease, no internal DNS |
| Management | 10.1.2.241–10.1.2.254 | excluded | Network equipment |

---

## 3. Static DHCP Assignments

Static assignments bind a MAC address (or client identifier) to a specific IP, hostname, and optional per-host options.

```
DHCPStaticAssignment
  id, scope_id                  -- NOT NULL / ON DELETE CASCADE; part of the reservation's identity
  ip_address: inet              -- must fall inside the scope's subnet (422 if not — issue #619)
  mac_address: macaddr          -- primary identifier
  client_id: str (nullable)     -- DHCP client identifier (alternative to MAC)
  hostname: str
  description: str
  options_override: JSONB (nullable)  -- host-specific options
  ip_address_id (FK → IPAddress)      -- linked IPAM record
  deleted_at, deleted_by_user_id, deletion_batch_id  -- soft-delete, as a cascade child of the scope (#617)
  created_by_user_id, created_at
```

`scope_id` cannot be re-pointed. Kea renders a reservation *nested inside* its
scope's `subnet4` stanza and Windows binds it to the scope's network address, so
there is no renderable form of a relocated reservation — a body `scope_id` on
create/update is rejected with a `422` (issue #619). To move one, delete it and
re-create it under the target scope.

### Static Assignment UI Workflow

Static assignments are **created from the IPAM side**, at IP-allocation time. A
static is a child of a DHCP **scope** (it carries `scope_id`), and Kea renders
reservations per scope — so **a scope for the subnet must exist first**, or there
is nothing for the reservation to attach to and Kea's `reservations` array stays
empty.

**Prerequisite — create a scope for the subnet.** A scope lives on a DHCP
**server group** that has at least one Kea member (DHCP is group-centric —
scopes / pools / statics / classes all belong to the group). Create it from
**IPAM → the subnet → "DHCP Pools" tab → Create Scope**, or from
**DHCP → the server group → Scopes tab → New Scope**. A dynamic pool is optional;
the scope alone is enough to emit the `subnet4` block that reservations hang off.

**Create the reservation — two equivalent paths:**

*From the DHCP page:* **DHCP → the server group → "Static Assignments" tab →
New static assignment**. Pick the scope (a picker appears when the group has
more than one), then enter the MAC + IP + hostname and save. Edit and Delete
live on the per-row right-click menu. Creating / editing / deleting a
reservation requires a **superadmin**.

*From IPAM (at allocation time):*

1. **IPAM → select the subnet → "Allocate IP"** (the primary header button; also
   reachable from a free-range gap row or the subnet context menu).
2. In the **Allocate IP Address** modal set **Type / Status = `static_dhcp`**.
   This reveals the **DHCP Scope** picker.
3. Pick the **DHCP Scope**, enter the **MAC address** (required — see caveat
   below), and set the hostname. If no scope exists for the subnet yet, the
   picker offers a **Create a scope** button that opens the scope modal inline.
4. Click **Allocate**. IPAM creates the address row with
   `IPAddress.status = static_dhcp` and mirrors it into the scope as a
   `DHCPStaticAssignment` (via `POST /api/v1/dhcp/scopes/{scope_id}/statics`).

Either way, the Kea agent picks up the new `ConfigBundle` (a group wake fires +
the ETag shifts) and renders the host reservation within seconds. The **Static
Assignments** tab lists every reservation across the group's scopes.

**Caveats / common "nothing happened" traps:**

- **A MAC is mandatory — a blank MAC is rejected, not silent.** Allocating a
  `static_dhcp` address without a `mac_address` returns **422**
  (`mac_address is required when status is 'static_dhcp'`) from both the
  `create` and `next-address` endpoints, so **nothing is created** — neither the
  IPAM row nor the reservation.
- **`static_dhcp` with a MAC but no scope creates the IPAM row and silently skips
  the reservation.** If no DHCP scope is selected (e.g. none exists for the
  subnet yet), the IPAM address is created but the mirror to Kea is **not
  attempted** — this is the real "I set it static but nothing happened" trap.
  Create a scope first (see the prerequisite above).
- **Editing an existing IPAM row to `static_dhcp` does not create a reservation.**
  Flipping an *existing* IP to `static_dhcp` via **Edit** (or bulk-edit) updates
  the IPAM row but does **not** mirror it to Kea. Add the reservation from the
  DHCP **Static Assignments** tab, or delete and re-allocate via the IPAM flow.
- **Creating a static currently requires a superadmin.** A non-superadmin who
  allocates a `static_dhcp` IP gets the IPAM row but the mirror call returns 403.

### Troubleshooting — reservations render empty in Kea

Reservations are emitted **per subnet**, nested inside each `subnet4` / `subnet6`
object — there is no top-level reservations list, so check the `reservations`
array *inside* the relevant `subnet4`. If a reservation you created never shows
up, walk this checklist — each item is a real, mostly-silent drop point:

- **The static was never actually created.** Confirm it exists via
  `GET /api/v1/dhcp/scopes/{scope_id}/statics` or the group's Static Assignments
  tab. If it's absent, distinguish two cases: the allocation was
  **rejected** (a blank MAC 422s the whole allocation — nothing was created), or
  it **succeeded without mirroring** (a MAC was given but no scope was selected,
  or a non-superadmin hit 403 on the mirror call). See the caveats above.
- **The scope is inactive.** Only `is_active = true` scopes (and the statics
  under them) are assembled into the config bundle — a disabled scope silently
  drops every reservation it holds.
- **The scope's subnet was deleted.** If the `Subnet` backing a scope is gone but
  the scope survived, the scope and all its statics are silently skipped during
  bundle assembly.
- **The scope's group has no Kea member.** A server not attached to a group (or a
  group with zero Kea members) renders an empty bundle — nothing polls for the
  reservation.
- **The reservation IP is outside the scope's subnet.** Rejected with a `422`
  since issue #619 — but a row created *before* that landed (or written by an
  importer) can still be out of range, and Kea rejects the *entire* config at
  load when a host reservation falls outside its subnet, so one out-of-range IP
  makes **all** statics on that server silently fail while the agent keeps
  serving its last-good config. Keep the reserved IP inside the subnet CIDR.
- **Pure-SLAAC IPv6 scopes emit no reservations by design** — a v6 scope in
  SLAAC-only mode has no stateful addressing role, so its `reservations` is
  always empty.

### Conflict Detection

`create_static` / `update_static` reject (never silently) on:
- **Duplicate MAC within the server group** — a MAC can be reserved only once
  across every scope in the same group (409).
- **IP outside the scope's subnet** — 422 (issue #619). See §16 for the
  rationale.
- **A body `scope_id`** — 422 (issue #619). The scope comes from the path on
  create and cannot change on update.
- **Malformed IP** — 422.
- **Malformed hostname** — 422. The reservation hostname is operator-entered,
  so it is validated against the RFC 1123 host rule rather than sanitized (see
  `DNS.md` §18).

An IP inside a `dynamic` pool is **not** a conflict: a reservation there is the
normal way to pin a device, and every driver honours it (#631; see §16).

---

## 3a. Scope deletion, cascade, and restore

Deleting a DHCP scope is a **soft delete** by default: the row is stamped
(`deleted_at` / `deleted_by_user_id` / `deletion_batch_id`), disappears from
every read surface, and is recoverable from **Administration → Trash** for the
retention window (`PlatformSettings.soft_delete_purge_days`, default **30
days**) before the nightly purge sweep hard-deletes it. `DELETE
/api/v1/dhcp/scopes/{id}?permanent=true` skips the trash — but the UI never
sends that flag, so the soft path is what an operator actually exercises.

Four things happen on that path. Each was a shipped bug until `2026.07.11-1`
(issues #616–#619, migration `b3e7d21c9f04`).

### Pools and reservations cascade with the scope (#617)

`DHCPPool` and `DHCPStaticAssignment` carry `SoftDeleteMixin` and ride the
scope's `deletion_batch_id`
(`backend/app/services/soft_delete.py::_collect_descendants`), so one **Restore**
brings the scope back **whole** — its ranges and its reservations with it. They
are cascade-only children: never soft-deleted on their own, never listed in the
trash individually (`SOFT_DELETE_RESOURCE_TYPES` deliberately omits them), but
present in `TYPE_TO_MODEL` so `restore_batch` sweeps them.

Before this, a scope was treated as a cascade **leaf** — its pools and
reservations stayed live and un-stamped under a hidden parent:

- still answering `GET /api/v1/dhcp/scopes/{id}/statics`,
- still enforcing the group-wide MAC conflict check, which `409`'d naming a
  scope UUID the operator could no longer see,
- still visible to the `find_dhcp_statics` MCP tool,
- and the approval-workflow preview reported a **zero blast radius** for a scope
  holding hundreds of reservations.

Restore is conflict-checked per row: while the scope sat in the trash a live
scope in the same group may have claimed one of its MACs, so
`default_conflict_check` refuses the restore rather than resurrecting a
group-wide duplicate the create path would have refused. The two reservation
uniqueness rules are **partial** unique indexes (`WHERE deleted_at IS NULL`), so
a trashed reservation never holds the `(scope, mac)` / `(scope, ip)` slot against
a live one.

### Agentless write-through fires on the soft path (#616)

Soft-delete means *stop serving*, and that has to hold on every backend. Kea
members converge on their own — a stamped scope drops straight out of the
rendered `ConfigBundle` and the ETag shifts. **Agentless** members (Windows DHCP
today) only converge on an explicit push, and `push_scope_delete` previously ran
**only** on the `permanent=true` branch. Since the UI never sends that flag, a
UI-deleted scope vanished from SpatiumDDI and from Kea's rendered config while
the Windows DHCP server kept serving it — **and its reservations** — forever.
Nothing removed it later either: the trash permanent-delete skips the
write-through hooks, and the purge sweep is a Core `DELETE` that runs no Python.

The push is now driven off the **soft-delete batch**
(`backend/app/services/ai/operations_risky.py::_push_agentless_scope_deletes`)
rather than a hand-rolled per-handler query, so **every** delete whose cascade
can reach a scope — scope, subnet, block, space — is covered, and a new ancestor
type added to `_collect_descendants` cannot silently skip it. Order is
load-bearing: the push runs *before* `apply_soft_delete` stamps the batch, or the
global filter would hide the subnet the push needs to resolve the scope's CIDR.

**Restore pushes the inverse** — `push_scope_restore` re-creates the scope, its
non-dynamic pools, and its reservations on every Windows member. It is
best-effort by design (failures are logged, not raised): a `502` from an
unreachable Windows box would roll the DB restore back and make the row
*unrestorable*, which is the opposite of what a recovery action should do.

### The IPAM mirror is released on wholesale deletes (#618)

A reservation owns an `ip_address` row at `status="static_dhcp"`, back-linked via
`IPAddress.static_assignment_id`. `_detach_ipam_for_static` used to live in the
router, so it was only reachable from the per-reservation CRUD handlers — every
path that destroys reservations *in bulk* (FK `CASCADE`, or a Core `DELETE`: no
Python runs) stranded the mirror at `status="static_dhcp"` pointing at a
reservation Postgres had already dropped. Not allocated, not free, not
reclaimable by any sweeper.

It is now `backend/app/services/dhcp/static_ipam.py` —
`detach_ipam_for_static` + `detach_ipam_for_scope_statics` — and wired into every
wholesale path:

| Path | Where |
|---|---|
| Scope permanent-delete | `services/ai/operations_risky.py::_apply_delete_scope` |
| Trash permanent-delete | `api/v1/admin/trash.py::permanent_delete_from_trash` |
| Nightly purge sweep | `tasks/trash_purge.py::_release_ipam_mirrors` |
| DHCP server-group delete | `services/ai/operations_risky.py::_apply_delete_group` |
| DHCP importer `overwrite` mode | `services/dhcp_import/commit.py` |

The row is released to `available` (not `allocated`): a leftover `allocated` row
is skipped by the agent's lease-mirror refresh, so it would shadow a future
dynamic lease at that IP *and* never be reaped (#478). Migration `b3e7d21c9f04`
repairs the rows already stranded by pre-existing hard-deletes.

### Known gap — Windows scope sync (issue #620)

`services/dhcp/pull_leases.py::_upsert_scope` still Core-`DELETE`s a Windows
scope's reservations and re-inserts them from the wire without going through the
release path, so a **UI-created reservation's IPAM mirror can be stranded on the
next Windows scope sync**. It is deliberately *not* patched with a plain detach:
that reconciler runs on a schedule, and a detach would tear down and recreate the
forward A record on every pass for reservations that never changed. It needs a
re-point-by-IP reconcile instead.

The `IPAddress.static_assignment_id` `varchar` → `uuid` FK retype is deferred
alongside it — it breaks the #296 rolling-upgrade contract and needs a
two-release expand/contract.

---

## 4. DHCP Client Classes

Client classes let you define rules for how clients are categorized and which pool or options they receive.

```
DHCPClientClass
  id, group_id          -- all members of the group get the same classes
  name: str             -- e.g., "VoIPPhones"
  match_expression: str -- Kea expression
                        -- e.g., "option[60].hex == 'Cisco7960'"
  description: str
```

Classes are referenced by pool `class_restriction` field. The DHCP driver translates these to server-native syntax.

Hand-authoring a match expression is not the only way to get a class:
[§17a](#17a-fingerprint-driven-device-policies-issue-700) compiles one
from fingerbank device classes, so "printers get a short lease and a
restricted resolver" does not have to start from Kea syntax.

---

## 4a. DHCP MAC Blocklist

A group-level deny list. Any MAC address listed here is dropped on every scope served by every member of the group — no leases, no response packets at all.

```
DHCPMACBlock
  id, group_id             -- every member blocks every listed MAC
  mac_address: MACADDR     -- unique per (group_id, mac_address)
  reason: str              -- rogue | lost_stolen | quarantine | policy | other
  description: str
  enabled: bool            -- soft-disable toggle
  expires_at: timestamptz  -- nullable; expired rows stay in DB, stripped from rendered config
  created_at, created_by_user_id
  updated_at, updated_by_user_id
  last_match_at, match_count  -- telemetry (wiring deferred)
```

**How each driver enforces the block**

| Driver | Enforcement | Update mechanism |
|---|---|---|
| Kea | Packets matching the reserved `DROP` client class are silently dropped before allocation. The agent renders active blocks as `hexstring(pkt4.mac, ':') == '…'` OR-clauses inside `DROP.test`. | ConfigBundle — blocklist changes shift the bundle ETag; agent long-poll picks them up and re-renders. |
| Windows DHCP | Server-level deny filter list (`Add-DhcpServerv4Filter -List Deny`). Deny filter is server-global — every scope on the server enforces it. | 60 s Celery beat task diffs desired-set against `Get-DhcpServerv4Filter -List Deny` and ships one batched PS script per WinRM round trip. |

Group-global is deliberate. Kea supports per-subnet via class/pool pinning; Windows doesn't support per-scope deny at all. A single "this device is bad, nowhere gets to serve it" rule is the usage pattern — per-scope precision is deferred until a concrete need surfaces.

**MAC input shapes** — the API accepts the common operator formats (`aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`, or bare `aabbccddeeff`, any case) and canonicalizes to colon-separated lowercase server-side. Agents see canonical form only.

**Expiry** — null = permanent; setting `expires_at` in the past is idempotent with `enabled=False` (both filter the row out of the rendered config). The beat task scanning for Windows DHCP means expiry transitions propagate within 60 s even without a config push.

**UI** — DHCP server → "MAC Blocks" tab. Filter-as-you-type over MAC / vendor / IP / hostname; vendor column sourced from `oui_vendor` (opt-in feature, null when OUI lookup is disabled); IPAM cross-ref shows any `IPAddress` rows currently tied to the blocked MAC, with IP + subnet + hostname. Per-row edit toggles `enabled`, `expires_at`, `reason`, and `description` — the MAC itself is immutable so the audit trail for each MAC stays linear (rename = delete + re-add).

**Permission** — `dhcp_mac_block`. The built-in "DHCP Editor" role gets it automatically.

---

## 4b. Kea Lease Cache (#637)

Kea 3.0 (shipped from Alpine 3.23) enables **lease caching** by default —
`cache-threshold: 0.25`. When a client re-requests a lease that still has more
than 75% of its lifetime remaining, Kea hands back the *same* lease with an
**unchanged expiry** and skips the lease-database write entirely.

That is a sensible default for a standalone Kea. It is **not** a safe default
for SpatiumDDI, because our lease pipeline is driven by exactly those writes:

```
kea-dhcp4 → memfile CSV write → agent tails the file → POST /dhcp/agents/lease-events
                                                          ↓
                                              DDNS record + IPAM lease mirror
```

Suppress the write and the lease event never happens — so a chatty client's DDNS
record and its IPAM "last seen" timestamp quietly go stale, with nothing in the
UI to indicate why.

So SpatiumDDI **renders the value explicitly rather than inheriting Kea's
default**, and ships it as an operator setting that defaults to **`0.0`
(disabled)** — i.e. every renewal writes through, exactly as on Kea 2.6. An
install upgrading across the Kea major keeps its existing behaviour with no
action required; operators who want the reduced database churn opt in.

| Setting | Where | Default | Meaning |
|---|---|---|---|
| `lease_cache_threshold` | `DHCPServerGroup` | `0.0` | Fraction of the lease lifetime (0–1). `0.0` disables caching. |
| `lease_cache_max_age` | `DHCPServerGroup` | `NULL` | Cap on how long a cached lease may be reused. `NULL` = uncapped (Kea's own default). |
| `lease_cache_threshold` | `DHCPScope` | `NULL` | Per-scope override. `NULL` = inherit the group. |
| `lease_cache_max_age` | `DHCPScope` | `NULL` | Per-scope override. `NULL` = inherit the group. |

Rendered as Kea's `cache-threshold` / `cache-max-age` on the `Dhcp4` / `Dhcp6`
root (group-wide) and on the individual `subnet4` / `subnet6` entry (per-scope
override).

> **`0.0` is a value, not an absence.** A scope with `lease_cache_threshold = 0.0`
> means "caching explicitly off for this scope" and must survive even when the
> group has caching on; `NULL` means "inherit". Every layer therefore tests
> `is not None` rather than truthiness — a truthy check silently converts an
> explicit disable into an inherit (and `"0"` is falsy in JS too, which is why the
> scope modal compares the input string against `""`).

---

## 4c. Packets lost before Kea reads them (#980)

A Kea server that is short of CPU does not slow down — it loses packets, in
the kernel, before the server ever sees them. Everything Kea can tell you
about itself stays green: it answers **100 % of what it reads**, its own
`pkt4-receive-drop` stays at zero, its health check passes, it heartbeats
normally and its pools have free addresses. The only symptom is clients
taking several retransmit rounds (4 s apart, and up) to get an address,
which from the server looks like somebody else's problem.

Measured on a 4 vCPU appliance serving a relayed burst: at 1,200 devices /
20 DORA per second, 32-48 % of first DISCOVERs had to be resent, while Kea
reported having answered every packet it received.

### Where the loss actually is, and where it isn't

Three counters, and only one of them moves:

| Counter | What it means | Moves here? |
|---|---|---|
| per-socket `sk_drops` (`/proc/net/udp`) | the kernel found the receive buffer full and discarded the datagram | **yes** |
| `pkt4-receive-drop` / `pkt6-receive-drop` | Kea read the packet and discarded it (unparseable, `DROP` class, no subnet) | no |
| `pkt4-discover-received` vs `pkt4-offer-sent` | Kea answering what it read | always equal |

Verified against kea-dhcp4 3.0.3: a run that lost **9,700** datagrams to
buffer overflow reported `pkt4-receive-drop = 0` for its entire duration.
Both are reported per 60 s bucket on `dhcp_metric_sample` as `socket_drop`
and `receive_drop`, but only the first is treated as loss.

> **`receive_drop` is context, not a fault.** Kea counts a packet there when
> it reads one and throws it away — *including on purpose*. Verified against
> kea-dhcp4 3.0.3: a client matching a `DROP` client-class increments it once
> per packet, and a `DROP` class is exactly what the shipped
> [DHCP MAC blocklist](#4a-dhcp-mac-blocklist) renders; Kea's HA hook drops
> out-of-scope queries in `hot-standby` the same way. So the *DROPPED* line,
> the `N dropped` chip and the alert rule all read `socket_drop` **alone** —
> a rule that counted `receive_drop` would fire permanently, and never
> auto-resolve, on any install with a blocklisted MAC or an HA pair.
> `receive_drop` is still surfaced beside it, labelled as what it is.

The server detail modal's **Stats** tab draws a dashed *DROPPED* line and a
red `N dropped` chip from `socket_drop`, and the default-on
**`dhcp_packets_dropped`** alert rule fires on any confirmed kernel-side loss
over a 15-minute window (raise the rule's minimum-count threshold to alert
only past a number of packets).

> **`NULL` is not zero, anywhere in this chain.** An agent older than #980,
> or one whose runtime cannot read `/proc/net/udp`, reports no `socket_drop`
> and the column stays NULL. That renders as *loss not measured*, the alert
> skips the server rather than vouching for it, and nothing folds it to 0 —
> a wall of green zeros from an un-upgraded fleet is precisely the false
> reassurance this section exists to remove. Every "was this measured?" test
> keys on `socket_drop` **by itself**: `receive_drop` always arrives from a
> #980 agent, so testing the pair would report a server whose kernel-side
> loss is unmeasurable as measured-and-clean.
>
> A partial read counts as no read. If one of `/proc/net/udp` /
> `/proc/net/udp6` exists but cannot be read, the whole sample is discarded
> rather than returning the half that succeeded — otherwise the missing
> inodes drop out of the baseline, and when the next read succeeds they
> return as new sockets whose entire lifetime `sk_drops` is charged to that
> one bucket. On a socket up for days that is a fabricated spike, on a rule
> whose floor is one packet. (A file that is *absent* is different, and is
> a valid partial answer: no IPv6 stack means no v6 sockets to miss.)
>
> One real blind spot: the AF_PACKET socket Kea opens for
> `dhcp-socket-type: raw` is not covered. `/proc/net/packet` carries no drop
> column and its statistics can only be read by the process that owns the
> socket. Relayed traffic is unicast and therefore arrives on the UDP
> fallback socket, which is fully covered; directly-attached broadcast
> traffic is not.

### What actually helps

Two things do not, and it is worth knowing why before reaching for them:

* **A bigger socket receive buffer** removes the drops and replaces them with
  latency. Measured under #952: with 8 MiB of buffer the drops vanish and a
  DORA takes **34 s instead of 1.5 s**, because Kea then works through a
  backlog answering requests whole retransmit rounds late.
* **A bigger `packet-queue-size`** does nothing at all. 64 → 2048 (32x)
  changed neither throughput nor drops; that queue sits *behind* the receive
  thread, and the bottleneck is the receive thread not being scheduled.

What helps is giving the receive thread the CPU. The chart already ships a
500m CPU request on the Kea pod (#953 / #967 — see
[`APPLIANCE.md`](../deployment/APPLIANCE.md)), whose `node_pressure` alert
reads the kernel's PSI stall time and names the *cause* where `socket_drop`
names the *effect*; a node stalling with no DHCP loss still has headroom.
Two group settings tune the packet path itself:

| Setting | Where | Default | Meaning |
|---|---|---|---|
| `kea_thread_pool_size` | `DHCPServerGroup` | `1` | Kea's `multi-threading.thread-pool-size`. `0` = let Kea auto-size. |
| `kea_packet_logging` | `DHCPServerGroup` | `true` | Log every packet received and sent. |

**`kea_thread_pool_size` is the important one, and its default changed.**
Left to Kea, `thread-pool-size` is `0` — one worker per CPU that
`hardware_concurrency()` reports, which is the *machine's* CPU count and
knows nothing about the cgroup share the container is held to. Verified: a
container limited to 0.20 CPU starts **ten** workers, which then compete,
inside that one cgroup, with the single thread that has to drain the receive
socket. Packets served on kea-dhcp4 3.0.3 (memfile, relayed unicast, 12,000
pkt/s offered, median of 4 runs):

| cgroup CPU | pool = 1 | pool = 2 | pool = 4 (what "auto" gives on 4 vCPU) |
|---|---|---|---|
| 0.25 | **19,381** | 11,119 | 6,723 |
| 4.0 (no quota) | **93,717** | 73,089 | 55,957 |

Monotonic in both shapes, so the default is 1 and every existing group picks
it up on upgrade (one Kea config-reload, no restart). Note this is a *resize*
and not `enable-multi-threading: false` — with MT off one thread must both
receive and process, which measured **15,170** socket drops in a run where a
pool of one measured **none**, and it also changes host-reservation lookup
order.

Kea's HA hook does **not** keep independent HTTP pools by default —
`http-listener-threads` / `http-client-threads` default to `0`, which Kea
reads as *"same as `thread-pool-size`"*. Counting OS threads with the hook
loaded: pool=1 gave 8, pool=8 gave 29, a delta of 21 for a pool delta of 7,
i.e. three pools of N. Left alone, this change would have taken a failover
pair's peer HTTP concurrency to 1 as an unmeasured side effect, so the agent
pins both to 4 and the setting moves only the packet-worker pool.

**`kea_packet_logging` defaults to on, which is exactly today's behaviour.**
At INFO, Kea writes four lines per transaction to two appenders, one of them
flushed. Turning this off raises only the `kea-dhcpN.packets` child logger to
WARN — silencing `DHCP4_PACKET_RECEIVED` and `DHCP4_PACKET_SEND`, which carry
the source address and receiving interface — for 1.30x more packets served
(24,997-26,077 against 19,026-20,403 on the same rig). The lines naming the
client and the address handed out come from other loggers and stay, so the
Logs tab keeps one entry per transaction. It is an opt-in because it removes
something an operator can see; the `socket_drop` counter above is what tells
you whether you are at the knee where it is worth it.

> `kea-dhcpN.dhcpN` is *not* touched, though it looks like the same kind of
> noise. At INFO it also carries `DHCP4_OPEN_SOCKETS_FAILED` — a real failure
> Kea logs at INFO — plus `DHCP4_CONFIG_COMPLETE`, `DHCP4_STARTED` and
> `DHCP4_MULTI_THREADING_INFO`, the last being the line that reports whether
> the pool size above took effect.

---

## 5. DHCP Lease Tracking

Leases are **read-only** in SpatiumDDI — they are pulled from the DHCP server, not managed directly.

```
DHCPLease (not persisted long-term — cached in Redis, written to DB for history)
  ip_address, mac_address, hostname
  duid, iaid            -- DHCPv6 identity (#1141); mac_address is NULL on most v6 leases
  scope_id, server_id   -- per-server (each Kea owns its own memfile)
  starts_at, ends_at, expires_at
  state: enum(active, expired, released, abandoned)
  client_id, user_class
  last_seen_at
```

### Lease Sync Strategy

- **Real-time (preferred)**: Kea `lease_cmds` hook + webhook to SpatiumDDI on lease events
- **Polling fallback**: Celery task pulls lease dump every N minutes via DHCP driver API
- Leases are used to update `IPAddress.status`, `IPAddress.last_seen`, and trigger DDNS

### Lease History (forensic trail)

Landed in `2026.04.26-1` via migration
`f4e1d2a09b75_lease_history_and_nat`. The `dhcp_lease_history`
table records every lease that ever expired, was reassigned to a
different MAC, or got swept on absence-delete — gives operators a
"who had this IP last week" audit trail when the live
`dhcp_lease` row is gone.

- Written from three sites: the `dhcp_lease_cleanup` expiry sweep,
  the agent lease-event ingest path on MAC change, and
  `pull_leases` on absence-delete.
- Surfaced on the DHCP server detail as a new **Lease History**
  tab with filtering by MAC / IP / time window.
- Daily prune task (`app.tasks.dhcp_lease_history_prune`) honours
  `PlatformSettings.dhcp_lease_history_retention_days` (default
  90; set to 0 to keep forever).

---

## 6. Local Config Caching on DHCP Agents

**Critical resilience requirement**: DHCP servers must continue operating even when SpatiumDDI control plane is unreachable.

### Caching Architecture

Each DHCP server is managed by an **SpatiumDDI Agent** — a lightweight sidecar process running on or near the DHCP server.

<p align="center">
  <img src="../assets/diagrams/dhcp-host-internals.svg" alt="DHCP agent host internals" width="900"/>
</p>

### Agent Behavior

**When control plane is reachable:**
1. Agent polls SpatiumDDI API for config changes every N seconds (configurable, default 30s)
2. On config change: agent validates new config, writes to local cache, applies to DHCP daemon
3. Agent reports lease events back to SpatiumDDI API in real time
4. Agent writes a "last successful sync" timestamp to local disk

**When control plane is unreachable:**
1. Agent detects connectivity failure after 3 consecutive failed polls
2. Agent logs: `"Control plane unreachable — operating from cached config"`
3. Agent continues serving from cached config — **DHCP service is NOT interrupted**
4. Agent retries connectivity every 60 seconds
5. On reconnect: agent replays every push it spooled during the gap — lease
   events, activity log, metrics — in order, then reconciles leases from a
   full Kea snapshot (see *Push spool* below, #1077)

### Cache Format

Cached config is stored in a structured JSON file:
```json
{
  "version": "1.4.2",
  "generated_at": "2024-01-15T14:30:00Z",
  "checksum": "sha256:...",
  "scopes": [...],
  "pools": [...],
  "static_assignments": [...],
  "client_classes": [...]
}
```

The Kea daemon config file (JSON) is generated from this cache. On startup, the agent always checks if the cache is newer than the running daemon config and applies if so.

### Cache Invalidation

- Cache is **never automatically deleted**
- A manual "force resync" is available from the admin UI (`POST /api/v1/dhcp/servers/{id}/sync`)
- Cache version is tracked; SpatiumDDI will reject applying a cache version older than the current DB version

### Last-known-good revert (issue #882)

The section above covers a control plane that is *unreachable*. It does not
cover one that is *wrong* — a bundle that renders to a Kea config the daemon
refuses.

Two files back the fallback, under `config/` in the agent state dir:
`previous.json` is the last bundle Kea **accepted** (not, as it used to be,
whichever bundle came before this one — that rotation destroyed the fallback
after two poll cycles), and `quarantine.json` records an etag whose apply
failed so it is not re-rendered on every poll.

Kea's `config-test` is what makes the distinction usable: a rejection is a
verdict about the config, whereas an unreachable control socket says nothing
about it — Kea may simply be restarting. Only a rejection reverts; reverting
on an unreachable socket would discard a good bundle because of a timing
accident.

The revert rewrites the on-disk `kea-dhcp4.conf` / `kea-dhcp6.conf`, not just
the agent's bookkeeping. `config-test` rejects *without* disturbing the
running daemon, so Kea itself is fine either way — but the refused document
has already been written to those paths, and that file is what Kea reads on
its next start. Leaving it turns a rejected apply into a crash loop the next
time the container restarts.

Before #882 a refused config was reported as a **success**: the loop advanced
its etag, called `_record_success()`, logged `dhcp_config_applied` and stamped
the Kubernetes readiness marker. The agent now reports the verdict on its
heartbeat (`config` field → `dhcp_server.config_apply_*`), which drives the
server-row chip, the `agent_config_rejected` alert rule and the
`find_agents_with_config_failures` Copilot tool.

The heartbeat's `daemon` field — `{"status": "ok"}` after a good reload,
`{"status": "degraded", "reason": ...}` when a control socket is
unreachable or a config was rejected — lands on `dhcp_server.daemon_status`
/ `daemon_reason` / `daemon_status_since` since #1067 (it was declared and
read by nothing before), is exposed on the server row, drives a chip and a
detail banner, and feeds the `agent_daemon_degraded` alert rule once a
daemon that is not serving has stayed that way past a five-minute grace. A
rejected config is not that: `config-test` refuses without disturbing the
running Kea, so a `degraded` whose reason is `config_apply_reverted: …` or
Kea's own `dhcp4_config_rejected: …` / `dhcp6_…` is the verdict above,
reported by `agent_config_rejected`. The server response's
`daemon_not_serving` is `false` for it, and that one field is what the
chip, the banner and the alert read.

### Push spool + lease snapshot (issue #1077)

Kea lease events are the **only** way the control plane learns about
agent-managed leases — `KeaDriver.get_leases()` is a stub and the scheduled
lease pull deliberately skips agent-based drivers. So before #1077 an outage
long enough to overflow the agent's 5,000-event memory buffer, or any agent
restart during one, left leases with no `dhcp_lease` row, no IPAM mirror and
no DDNS record until the client happened to renew.

Two mechanisms close that, push-plus-pull like the Windows path:

* **Durable spool.** Every push the control plane does not accept is written
  under `<state dir>/spool/<stream>/` (`/var/lib/spatium-dhcp-agent/spool/`)
  and replayed in order on reconnect, surviving agent restarts. Streams:
  `lease_events`, `dhcp_log`, `metrics`, `mac_sightings`, `fingerprints`,
  `ra_observations`. The rogue-DHCP probe and HA status are deliberately
  **not** spooled — they are current-state readings with no observation
  time, and replaying a stale one would be wrong rather than late. Same
  settings as the DNS agent: `AGENT_SPOOL_ENABLED` (default `true`),
  `AGENT_SPOOL_MAX_BYTES` (default 256 MiB, split across streams; oldest
  batches trimmed at the cap — keep it well under the agent state volume,
  1 Gi `storage.agentState` in the Helm chart), `AGENT_SPOOL_LOG_MAX_AGE_HOURS`
  (default 24; applies to the activity log only). See
  [`DNS_AGENT.md` §3](../deployment/DNS_AGENT.md) for ordering and replay
  semantics.
* **Lease snapshot backstop.** After each agent start and each recovery from
  an outage (at most once per 5 minutes) the agent pages Kea's full lease
  table over the control socket (`lease4-get-page`, 100 leases per POST) and
  posts it to the existing `POST /dhcp/agents/lease-events` endpoint. That
  ingest is an upsert, so the snapshot reconciles whatever the spool missed —
  including leases trimmed at the cap. DHCPv4 only.

Every spooled batch carries a `batch_id`; the control plane records it in
`agent_ingest_receipt` in the same transaction as the rows, so a batch whose
response was lost is acknowledged `{"duplicate": true}` on replay and inserts
nothing. That is load-bearing for metrics, which **accumulate** per bucket
since #980 — an undeduplicated replay would double a minute of packet counts
and packet loss. The activity-log endpoint also skips lines older than its
24 h retention (`expired` in the response). The agent reports lease state
`released` (Kea 3.0 CSV state 3) as such; the ingest treats it like any other
non-active state and tears down the auto IPAM mirror + DDNS.

The spool's state rides the heartbeat as `spool` → `dhcp_server.spool_status`
(NULL = never reported), shown as an amber *Replaying … backlog* or red
*Spool trimmed* chip on the server row. The default-on `agent_spool_trimmed`
alert fires for 24 h after a trim, **critical** when `lease_events` were among
the batches dropped; `find_agents_with_spool_backlog` is the Copilot tool.

---

## 7. DHCP ↔ IPAM Synchronization

### Push (IPAM → DHCP Server)
Triggered by:
- Scope/pool/static assignment create/update/delete
- Manual "Force Sync" from UI
- Scheduled full sync (default: every 5 minutes)

The push is **diff-based** — only changed objects are sent, not a full config replacement. This prevents unnecessary DHCP server disruption.

### Pull (DHCP Server → IPAM)
Triggered by:
- Lease events (real-time via webhook or Kea hook)
- Scheduled lease dump pull (fallback)
- Manual "Import Leases" from UI

### Reconciliation Report
Available from the admin UI: compares IPAM DB state vs. live DHCP server state and flags:
- IPs in DHCP scope but not in IPAM
- Static assignments in DHCP not in IPAM
- Scopes in DHCP not known to IPAM

---

## 8. Import / Export

### Export (IPAM → file)
- Export all DHCP scopes + pools + static assignments for a server or subnet
- Formats: JSON (native), Kea config JSON

### Import (file → IPAM)
- Import from Kea JSON config
- Import from CSV (static assignments: IP, MAC, hostname columns)
- Dry-run mode: shows what would be created before committing
- Conflict resolution: skip / overwrite / error on duplicates

### Migrating from an existing DHCP server (issue #129)

The **DHCP configuration importer** is the one-shot path for loading a
real DHCP estate into SpatiumDDI without retyping every scope, pool,
reservation, and option-set. It lives under **DHCP Import** in the
sidebar (gated by the `dhcp.import` feature module, default-on) and
covers three sources:

- **Kea** — upload a `kea-dhcp4.conf` / `kea-dhcp6.conf` from a
  non-managed daemon.
- **Windows DHCP** — live-pull every IPv4 scope from a registered
  `windows_dhcp` server over WinRM (reuses the Path A read driver).
- **ISC DHCP** — upload a `dhcpd.conf` (the importer ships its own
  tokeniser; ISC is supported as an *import source* only — SpatiumDDI
  does not run ISC daemons).

The flow is preview → commit: the preview parses the source and shows
the would-create scopes (with pool / reservation counts, conflicts,
IPAM linkage, and a "didn't import" panel) before any DB write; commit
writes each scope in its own savepoint. Every imported row is stamped
with `import_source` + `imported_at` provenance. Each scope either
links to an existing IPAM subnet on its CIDR or auto-creates one under
an operator-chosen IP space + block. **Live leases are never imported**
— they repopulate from the running daemon once a Kea server is attached
to the target group.

Full reference: [Migration](MIGRATION.md). Parser internals:
[DHCP Drivers § Importing existing daemon configs](../drivers/DHCP_DRIVERS.md).

---

## 9. DHCP Permissions

| Role | Capability |
|---|---|
| **superadmin** | Full server, scope, pool, static assignment management |
| **admin** (subnet scope) | Manage scopes and static assignments within their subnets |
| **operator** (subnet scope) | Add/modify/delete static assignments; cannot change pool ranges |
| **viewer** | View scopes and leases; no modifications |

---

## 10. Environment Variables for DHCP

```bash
DHCP_SYNC_INTERVAL_SECONDS=30       # How often agents poll for config
DHCP_LEASE_SYNC_INTERVAL_MINUTES=5  # Fallback polling for leases
DHCP_CONFIG_CACHE_PATH=/var/cache/spatiumddi/dhcp-config.json
DHCP_AGENT_RECONNECT_INTERVAL=60    # Seconds between reconnect attempts
DHCP_AGENT_MAX_CACHE_AGE_HOURS=72   # Alert if cache older than this
```

---

## 11. DHCP Options Reference

The following standard DHCP options can be configured at the scope, pool, or host level. All options are configurable in the UI and via API. Parent scope options are inherited by child pools unless overridden.

| Option Code | Name | Description |
|---|---|---|
| 1 | Subnet Mask | Auto-computed from subnet prefix |
| 3 | Router | Default gateway IP(s) |
| 6 | Domain Name Server | DNS server IPs. Canonical option name is `dns-servers`; the IANA name `domain-name-servers` is accepted as a legacy alias on write and still maps to code 6 on read |
| 12 | Host Name | Override hostname sent to client |
| 15 | Domain Name | DNS search domain (e.g., corp.example.com) |
| 28 | Broadcast Address | Auto-computed |
| 43 | Vendor Specific | Raw hex or vendor-specific encapsulated options |
| 51 | IP Address Lease Time | Seconds; default lease time |
| 58 | Renewal Time | T1 (default: 50% of lease time) |
| 59 | Rebinding Time | T2 (default: 87.5% of lease time) |
| 66 | TFTP Server Name | Boot server hostname (PXE) |
| 67 | Bootfile Name | PXE bootfile path |
| 119 | Domain Search | Multiple search domains |
| 150 | TFTP Server Address | Cisco VoIP boot server IP |

**Min/Max lease times**: Configured as `min_lease_time` / `max_lease_time` on the DHCPScope. Clients requesting shorter/longer leases are clamped to this range.

---

## 12. Parent/Child Setting Inheritance

DHCP options follow the same inheritance model as IPAM:

```
IPSpace → IPBlock → Subnet → DHCPScope → DHCPPool → DHCPStaticAssignment
```

At each level, options can be:
- **Inherited** (not set → use parent's value)
- **Overridden** (set → use this level's value, ignoring parent)
- **Extended** (for list-type options like domain-search: append to parent list)

Example:
```
IPSpace: Corporate
  domain-name: corp.example.com

  Subnet: 10.1.2.0/24 (HR VLAN)
    domain-name: hr.corp.example.com   ← overrides parent

    DHCPPool: Guest
      domain-name: guest.corp.example.com  ← overrides subnet
      lease-time: 7200                      ← 2-hour lease for guest
```

---

## 13. Hostname → IPAM Sync (Configurable)

When a DHCP client receives a lease, the hostname provided by the client can be automatically written back into the IPAM module (setting `IPAddress.hostname`).

```
DHCPScope.hostname_to_ipam_sync: enum(disabled, on_lease, on_static_only)
```

| Mode | Behavior |
|---|---|
| `disabled` | No hostname sync — IPAM hostname is managed manually |
| `on_lease` | Hostname from every new DHCP lease is written to IPAM |
| `on_static_only` | Only static DHCP assignments sync hostname to IPAM |

**Recommendation**: Set to `disabled` or `on_static_only` for large dynamic subnets (e.g., WiFi /16) where lease hostname data is noisy. Set to `on_lease` for server subnets where every IP should have a known hostname.

---

## 14. DHCP Pool Coordination — Kea HA on a Server Group

When two DHCP server containers serve the same pool, they must not hand the same IP to different MACs. SpatiumDDI solves this by treating a **`DHCPServerGroup` with two Kea members as an implicit HA pair** — HA tuning lives on the group, per-peer URL lives on each server, and Kea's `libdhcp_ha.so` hook is rendered on every member's config. There is no separate "failover channel" row any more (that was removed in 2026.04.22-1 when scopes moved to the group).

### Data model

- HA config fields live on `DHCPServerGroup`: `mode`, `heartbeat_delay_ms`, `max_response_delay_ms`, `max_ack_delay_ms`, `max_unacked_clients`, `auto_failover`.
- Each `DHCPServer` has its own `ha_peer_url` — the listener endpoint the partner calls for heartbeats + lease updates. Empty string for standalone servers.
- A group with **one Kea member** is standalone; HA fields are ignored. A group with **two Kea members + non-empty `ha_peer_url` on both** renders HA into their configs. A third or later Kea member renders as a `backup` peer (#332): it takes no part in the heartbeat but receives lease updates.
- Mixed groups (Kea + Windows DHCP) are **refused** (#1110): creating or moving a server into a group that already has the other kind is a `422`. Kea serves every active scope of its group and cannot coordinate with Windows failover, so a scope both serve would be two uncoordinated DHCP servers. A mixed group that predates the refusal is flagged on the group's Windows failover panel, and each shared scope is reported uncoordinated. Two or more *Windows* members are handled by §15.8.

### Modes

- **`hot-standby`** — one active peer + one passive standby. The primary serves all clients; the standby takes over on `partner-down`. Secondary peer's role is rendered as `standby` in the HA hook.
- **`load-balancing`** — both peers active; Kea splits traffic by hash of client identifier. Secondary peer's role is rendered as `secondary`.

### What the agent ships

On each `ConfigBundle` long-poll, the control plane emits a `failover` block alongside scopes / client-classes when the server's group is an HA pair. The agent's `render_kea.py` injects two hook entries in `Dhcp4.hooks-libraries`:

```json
{ "library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so" }
{ "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
  "parameters": {
    "high-availability": [{
      "this-server-name": "<local server name>",
      "mode": "hot-standby|load-balancing",
      "heartbeat-delay": 10000,
      "max-response-delay": 60000,
      "max-ack-delay": 10000,
      "max-unacked-clients": 5,
      "peers": [
        {"name": "dhcp1", "url": "http://10.0.0.5:8000/", "role": "primary",   "auto-failover": true},
        {"name": "dhcp2", "url": "http://10.0.0.6:8000/", "role": "standby",   "auto-failover": true}
      ]
    }]
  }
}
```

The `libdhcp_lease_cmds.so` hook is a hard prerequisite for HA and is loaded unconditionally — leaving it out will cause the HA hook to refuse to load.

### Live state reporting

A fourth thread in the agent (`HAStatusPoller`, `agent/dhcp/spatium_dhcp_agent/ha_status.py`) calls `status-get` against the local Kea control socket every ~15 s with small jitter and POSTs the result to `POST /api/v1/dhcp/agents/ha-status`. Kea 2.6 folded HA state into the generic `status-get` response under `arguments.high-availability[0].ha-servers.local.state`; the extractor also accepts pre-2.6 `ha-status-get` shapes for forward-compat. The control plane stores the state on `DHCPServer.ha_state` + `ha_last_heartbeat_at`. The poller self-disables when the most recent bundle carried no `failover` block, so standalone servers don't spam Kea with commands that return an error.

Kea state names pass through verbatim (`normal` / `hot-standby` / `load-balancing` / `ready` / `waiting` / `syncing` / `communications-interrupted` / `partner-down` / `backup` / `passive-backup` / `terminated`). The DHCP server detail header renders a colored `HA: <state>` pill. The dashboard's DHCP column lists one row per HA-paired group with a state dot per peer. The group detail view shows the same pill inline per-server so you can see HA state without drilling into each server page; use the Refresh button there after changing HA mode to repaint without waiting for the 30 s React Query poll.

### Peer IP drift self-healing

Kea's HA hook parses peer URLs with Boost asio, which only accepts IP literals — hostnames aren't looked up by Kea itself. The agent resolves hostnames at render time via `_resolve_peer_url`, but the IP can change afterwards (compose `--force-recreate`, k8s pod restart, bridge-IP reshuffle), leaving Kea pointing at a stale peer. A fifth thread (`PeerResolveWatcher`, `agent/dhcp/spatium_dhcp_agent/peer_resolve.py`) re-resolves peer hostnames every 30 s and, if any have drifted, triggers a render + config-reload with the fresh URL. Resolution failures are treated as transient (keep the cached IP, try again next tick), so a brief DNS outage doesn't thrash reloads.

### Not yet shipped (follow-up)

- **State-transition actions** — `ha-maintenance-start`, `ha-continue`, force-sync. The state machine is observable today but operators can't drive it from the UI; `kubectl exec` + manual `kea-shell` is the workaround.
- **Peer compatibility validation** — the control plane doesn't yet refuse groups with ≥ 3 Kea members (Kea HA only supports pairs).
- **Per-pool HA scope tuning** — the Kea HA hook supports per-subnet scope overrides; we render the relationship globally only.
- **Kea version skew guard** — `status-get` HA shape shifted between Kea 2.4 and 2.6. The extractor handles both, but the control plane still accepts pairing peers on mismatched Kea versions.
- **DDNS double-write under HA** — agent-side `apply_ddns_for_lease` doesn't gate on HA state. If the standby ever serves a lease (pre-sync window, partner-down), both peers could try to write the same RR.
- **HA DHCP e2e test** — the kind-based workflow stands up a single DNS agent; an HA DHCP variant would have caught all the bootstrap / port-split / `status-get` / wire-shape regressions shaken out in 2026.04.21-2.

### Managing HA

HA is configured on the server group, not a separate page. Edit the group under the DHCP tab, pick mode (`hot-standby` / `load-balancing`), tune the heartbeat / max-response / max-ack / max-unacked fields if the defaults don't fit your network, and make sure each Kea member has its **HA Peer URL** filled in (the server-level field) — typically `http://<host>:8000/` on the SpatiumDDI-shipped image. The HA hook renders automatically once the group has two Kea peers with non-empty URLs. Removing a server from the group or clearing its URL drops the hook on the next config push.

**On appliances, the firewall opens the HA listener to the pair (#1167).** The host `input` chain is `policy drop`, and nothing used to open the HA port, so two appliances in one HA group could not reach each other. The control plane now works out, for each appliance in a rendered HA group, the port in its own member's `ha_peer_url` (80 / 443 when the URL names none) and the addresses of the group's other Kea members. A partner's address is the IP literal in its URL, else the node IPs of the appliance running it, else the address its agent last connected from. The rule is scoped to those addresses and never opened to `any`: Kea's HA API is unauthenticated unless you configure TLS or basic auth, and it accepts lease updates. It follows the same readiness rule as the HA hook, so the port is open exactly while Kea listens on it. A change reaches the firewall on the appliance's next heartbeat, within about 30 s. The Fleet → Firewall effective view shows the rule as `role:dhcp-ha`.

---

## 15. Windows DHCP — Path A (read-only)

SpatiumDDI supports Windows Server DHCP as an **agentless** backend, driven over WinRM. It polls each Windows server for its leases and scopes and reflects them into IPAM, and writes scope / pool / reservation edits through to the server per object (it does not push config bundles — Windows has no whole-config entry point). A group with more than one Windows member is covered in §15.8.

### 15.1 What's implemented

| Capability | Status | Mechanism |
|---|---|---|
| Read leases | ✅ | `Get-DhcpServerv4Scope` + `Get-DhcpServerv4Lease` per scope, JSON-serialised back. |
| Read scopes | ✅ | `Get-DhcpServerv4Scope` + options + exclusions + reservations in one PowerShell call. |
| Per-object scope CRUD | ✅ | `Add-DhcpServerv4Scope` / `Remove-DhcpServerv4Scope`. |
| Per-object reservation CRUD | ✅ | `Add-DhcpServerv4Reservation` / `Remove-DhcpServerv4Reservation`. |
| Per-object exclusion CRUD | ✅ | `Add-DhcpServerv4ExclusionRange` / `Remove-DhcpServerv4ExclusionRange`. |
| Read failover relationships | ✅ | `Get-DhcpServerv4Failover`, on the lease-sync poll (#1110). |
| Manage failover relationships | ✅ | `Add-` / `Set-` / `Remove-DhcpServerv4Failover`, `Add-` / `Remove-DhcpServerv4FailoverScope`, `Invoke-DhcpServerv4FailoverReplication` (#1110). Needs the CredSSP WinRM transport. |
| Bundle push (`/sync`) | ❌ | `READ_ONLY_DRIVERS` — rejected by the API. Windows DHCP is cmdlet-driven, not config-file-driven. |
| `reload` / `restart` / `validate_config` | ❌ | Not applicable to Windows; raise `NotImplementedError`. |

The driver lives at [`app/drivers/dhcp/windows.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/windows.py) (class `WindowsDHCPReadOnlyDriver`). See [DHCP_DRIVERS.md](../drivers/DHCP_DRIVERS.md#4-windows-dhcp-driver-agentless--read-only-path-a) for internals.

### 15.2 Credentials

Stored on `DHCPServer.credentials_encrypted` as a Fernet-encrypted JSON dict:

```json
{
  "username": "CORP\\spatium-dhcp",
  "password": "…",
  "winrm_port": 5985,
  "transport": "ntlm",
  "use_tls": false,
  "verify_tls": false
}
```

Service account requirements:
- **Read-only lease mirroring**: member of the Windows `DHCP Users` local group.
- **Per-object scope/reservation/exclusion CRUD**: member of `DHCP Administrators`.
- **Managing failover relationships**: `DHCP Administrators` on **both** partners, and `"transport": "credssp"` — each cmdlet runs on one server and acts on its partner from there (see §15.8).

See [WINDOWS.md](../deployment/WINDOWS.md) for the WinRM + account setup.

### 15.3 Scheduled lease pull

Scheduled Celery beat task: [`app.tasks.dhcp_pull_leases.auto_pull_dhcp_leases`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/tasks/dhcp_pull_leases.py). Beat fires every **10 seconds**; the task gates on platform settings so the UI can change cadence without restarting beat. A 10-second beat tick means operators can configure near-real-time IPAM population from Windows DHCP — the interval is the only knob that limits poll frequency now.

| Setting | Default | Description |
|---|---|---|
| `dhcp_pull_leases_enabled` | off | Master toggle. |
| `dhcp_pull_leases_interval_seconds` | 15 | How often to poll each agentless server, in seconds. Floor is 10 (matching the beat tick). Operators who don't need sub-minute freshness can raise it to 60 / 300 / etc to reduce WinRM load. |
| `dhcp_pull_leases_last_run_at` | — | Populated after each pass; visible in Settings. |

> **Windows DHCP has no streaming primitive.** The lease audit log (`DhcpSrvLog-<Day>.log`) and `Get-DhcpServerv4Lease` are the only real windows into the running service, and both are pull-based. WinRM itself is request/response — `Get-Content -Wait` does exist in PowerShell but it holds the HTTPS connection open indefinitely and can't flush partial output back through `pywinrm.run_ps`, so true push-style streaming would require an agent process on the DC that POSTs events back to SpatiumDDI. Short-interval polling is the practical upper bound without adding that complexity.

Per poll:

1. Enumerate agentless DHCP servers (`DHCPServer.driver in AGENTLESS_DRIVERS`).
2. For each, call `driver.get_leases(server)` over WinRM.
3. Upsert the lease into `DHCPLease` by `(server_id, ip_address)`.
4. If the lease's IP falls inside a known subnet, mirror it into `IPAddress` with `status="dhcp"` and `auto_from_lease=True`.
5. **Absence-delete** — any active `DHCPLease` row for this server whose IP didn't appear in the wire response is deleted, along with its mirrored `auto_from_lease=True` IPAM row. The Windows DHCP driver only returns *currently-active* leases, so absence from the response is the server's way of saying "that lease is gone" (admin purged it, client released it, etc.). Before this fix, deleted-on-server leases persisted in our DB indefinitely because `pull_leases` was upsert-only and the time-based cleanup sweep only looked at `expires_at`. The response adds two counters — `removed` (lease rows dropped) and `ipam_revoked` (IPAM mirrors cleaned up alongside) — both surface in the scheduled-task audit row and the manual sync modal.
6. The existing time-based `dhcp_lease_cleanup` sweep still handles leases that drift past `expires_at` between polls (e.g. when lease pull is disabled). The two mechanisms overlap harmlessly.

**Scope absence** — not yet deleted. If an operator removes a scope on the Windows server, the `DHCPScope` row stays in SpatiumDDI's DB until deleted via the UI. Scope-absence cleanup is tracked separately.

### 15.4 Manual "Sync Leases" button

Agentless DHCP servers have a **Sync Leases** button on the server detail header that runs the same lease pull immediately without waiting for the scheduled task. Useful after adding a new server, or when debugging a new lease. From the **subnet detail**, a `[Sync ▾]` dropdown with a **DHCP** entry fans out `POST /dhcp/servers/{id}/sync-leases` across every unique server backing a scope in that subnet and opens a result modal with per-server counters (active / refreshed / new / removed / IPAM revoked + any errors).

`sync-leases` is an agentless-only operation — agent-based Kea streams lease events continuously and converges scope/config via the ConfigBundle long-poll, so there is nothing to pull. As of `2026.06.25-1` (#453) calling it against an agent-based server is **no longer a 400**: the endpoint returns a no-op `SyncLeasesResponse` with an explanatory `note` (and nudges the agent to re-poll its config so the scope definition converges immediately), rendered as an info line in both the subnet sync modal and the server-detail banner.

### 15.5 Scope auto-import

The first lease pull against a Windows DHCP server also imports its scopes — scopes found on the server but not in SpatiumDDI are created with their options, exclusions, and reservations. This mirrors the auto-import pattern from the DNS "Sync with Servers" flow.

### 15.6 Not yet (Path B full CRUD)

Full config-push to Windows DHCP (analogous to Windows DNS Path B) would unlock:

- Scope options pushed from SpatiumDDI instead of being managed in the Windows DHCP MMC.
- Client class / policy rendering.

The per-object writes (`apply_scope`, `apply_reservation`, `apply_exclusion`) are wired: the scope / pool / static endpoints write through before committing (`services.dhcp.windows_writethrough`). What remains is the list above.

### 15.7 Migrating off Windows DHCP entirely (issue #756)

Everything above treats Windows as a supported *backend*. When the goal is to stop using it, the guided **Windows cutover** surface (feature module `migration.cutover`, ships **disabled**, `/api/v1/migration/cutover`, superadmin) drives the switch per scope: parity against the live server (lease time, pools, reservations, options), the lease handover, the switch itself, and a decommission checklist.

Two things matter here. The **lease handover** exists because the DHCP importer (§8) deliberately skips live leases — so a naive switch hands clients to a Kea with an empty lease database, and the first renewal offers a fresh pool address to a client still using the one Windows gave it. The handover promotes each live Windows lease to a reservation (stamped `import_source="windows_cutover"`) so a renewing client keeps the address it already holds. And the **switch is ordered**: the Windows scope is deactivated *before* the managed scope is activated, so the two never answer the same subnet at once; if the managed side then fails to come up, the Windows scope is re-activated. Rollback reverses it, with the recovery-time expectation stated as the scope's lease time. See [MIGRATION.md](MIGRATION.md#windows--spatiumddi-cutover-756).

### 15.8 Two or more Windows servers in one group (issue #1110)

Two Windows DHCP servers only share a scope safely inside a **failover relationship** that covers it; without one they hand out the same addresses. So on a group with two or more Windows members:

- Writes go only to the members that already **hold** the scope, and never create it anywhere else. A covered scope is written to **both** partners — Windows failover syncs leases between partners, not configuration.
- A **new** scope goes to one member, by its **Windows placement**: into a failover relationship (created on one side and added to it, so Windows copies it to the partner) or on one server only. Without a placement, the one relationship the members share is used; otherwise the create is **refused (422)** with the choices. Activating a scope several members hold with no relationship covering it is **refused (422)**.
- **Deleting** a scope a failover pair in the group covers takes it out of the relationship and then deletes it; a scope whose partner is outside the group is **refused (409)**.
- A **split scope** (no relationship, the servers' parts kept apart) is left alone unless a change would make the parts overlap — then it is **refused (422)**.
- **Relationships are managed from the group's panel** — create, edit, delete, add or remove scopes, replicate one partner's configuration over the other's — over the CredSSP WinRM transport, which is the only one that can reach the partner from the server a cmdlet runs on.
- The lease-sync poll records each server's relationships and the scopes it holds; one member imports each shared scope and the others are compared against it for drift.
- A lease's shared IPAM mirror and DDNS records are not torn down while another server in the group still holds the lease.
- The default-on **DHCP scope served uncoordinated** alert rule (`dhcp_scope_uncoordinated`, critical) fires per scope two servers serve without coordinating.

The group page shows it all under **Windows DHCP failover**; the scopes table and the IPAM subnet's scope card carry a **Windows** badge. REST: `GET /dhcp/server-groups/{id}/failover`, `GET /dhcp/scopes/{id}/failover`, and the management routes under `/dhcp/server-groups/{id}/failover/relationships` (superadmin, audited — never the shared secret); MCP: `find_dhcp_failover_relationships` (read-only — deliberately no `propose_*` for relationship changes). Setup and every refusal: [WINDOWS.md](../deployment/WINDOWS.md#more-than-one-windows-dhcp-server-in-a-group). Internals: [DHCP_DRIVERS.md](../drivers/DHCP_DRIVERS.md#failover-relationships-and-multi-member-groups-1110).

## 16. Rules & constraints

Server-side validations that reject requests with a human-readable
error. Clients should render the `detail` string into their UI — every
rule here has been surfaced to an operator, not just silently logged.

### Scopes

- **Scope already exists for this group + subnet.** A subnet may host
  at most one scope per server group. `409` at
  `backend/app/api/v1/dhcp/scopes.py`.
- **Overlapping CIDR from another IP space (#844).** IPAM allows the
  same CIDR in different IP spaces (VRF semantics), but one Kea server
  renders one `subnet4`/`subnet6` entry per scope and rejects the whole
  config at load on a duplicate prefix — an outage for every scope on
  the group. Creating or *activating* a scope whose subnet overlaps
  another active scope's subnet in the same group is refused. `409` at
  `backend/app/api/v1/dhcp/scopes.py`; the bundle build additionally
  drops any raced-in duplicate (oldest scope wins, logged as
  `dhcp_bundle_duplicate_prefix_dropped`) so a bad combination can never
  reach an agent. **Overlapping IP spaces need a separate DHCP server
  group per space.**
- **`group_id` required when multiple groups are registered.** If
  more than one DHCP server group is defined, scope-create must name
  one explicitly; single-group deployments can omit the field.
  `422` at `backend/app/api/v1/dhcp/scopes.py`.
- **Hostname sync mode must be one of the configured values.** Mode
  picker is validated against `VALID_SYNC_MODES`; reserved / internal
  modes are not selectable from the API. `422`.
- **DDNS hostname policy enum.** `ddns_hostname_policy` must match one
  of the documented values (see §13). Pydantic validator.
- **A field must not be set twice, under both its names, to different
  values.** Two scope fields are accepted under two names: `enabled`
  (what the response emits) is the same column as `is_active` (what
  the model, the services layer and this document call it), and
  `hostname_sync_mode` is the same as `hostname_to_ipam_sync`. Sending
  both names of a pair with values that disagree is a `422`; sending
  either name alone works as it always has. This closes a silent
  no-op: a read-modify-write — `GET`, edit `is_active`, `PUT` the whole
  representation back — used to resolve in favour of the `enabled` the
  `GET` supplied and answer `200` while the scope kept handing out
  addresses. A `null` or empty string on either name counts as "not
  supplied", not as a disagreement.  `422`, [#774](https://github.com/spatiumnorth/spatiumddi/issues/774).

### Pools

- **Pools in the same scope cannot overlap.** Start/end ranges are
  checked against every other pool on the scope before insert. `409`
  at `backend/app/api/v1/dhcp/pools.py:143`.
- **Pool type enum.** `pool_type` must be in `VALID_POOL_TYPES`
  (`dynamic`, `reserved`, `excluded`). Validator at
  `backend/app/api/v1/dhcp/pools.py:40`.

### Static reservations

- **Duplicate MAC in the same group.** A MAC can only be reserved
  once per server group, regardless of which scope it's attached to
  — under the group-centric model every peer in the group serves
  the same reservation so duplicates across scopes in the same
  group are rejected. `409` at `backend/app/api/v1/dhcp/statics.py`.
- **Static IP inside a dynamic pool is allowed (#631).** Pinning a
  reservation whose IP falls inside a `dynamic` pool is the standard
  idiom on every driver we ship — Kea honours it (default
  `reservations-out-of-pool: false` won't hand the reserved address to
  another client), FortiGate renders `reserved-address` independently
  of `ip-range`, and Windows *requires* the reservation to fall inside
  the scope's range. No conflict check refuses it. Pool occupancy
  counts in-pool reservations as assigned so exhaustion isn't
  under-reported even while the reserved device is offline.
- **Reservation IP outside the scope's subnet.** `422` at
  `backend/app/api/v1/dhcp/statics.py:177` (issue #619). Kea renders a
  reservation **nested inside** its subnet's `subnet4` stanza and Windows
  binds it to the scope's network address, so an out-of-CIDR reservation
  ships structurally invalid config to the agent — Kea refuses the whole
  config at load, taking every *other* reservation on that server down with
  it. Caught here as a legible 422 instead of a downstream agent failure.
- **A body `scope_id` on create / update.** `422` at
  `backend/app/api/v1/dhcp/statics.py:41` (issue #619). A reservation belongs
  to its scope (uniqueness is keyed on it, and there is no renderable form of
  a relocated row), so on create the scope comes from the path and on update
  it cannot change at all. It used to be **silently dropped with a `200`**
  (Pydantic's default `extra="ignore"`), so a caller re-pointing a reservation
  got no error and no effect. Rejected as a *declared* field rather than via a
  blanket `extra="forbid"` — that would also `422` an ordinary
  GET → edit → PUT round-trip, since `StaticResponse` carries the server-owned
  `id` / `created_at` / `modified_at`.
- **Malformed IP.** Non-parseable IP strings return `422` at
  `backend/app/api/v1/dhcp/statics.py:162`.
- **Malformed hostname.** The reservation hostname is operator-entered, so a
  bad value is rejected (`422`), not sanitized — RFC 1123 host rule, via
  `app.core.dns_names.validate_hostname` at
  `backend/app/api/v1/dhcp/statics.py:30`. (A *client-supplied* hostname
  arriving off the DHCP lease wire is sanitized instead — see `DNS.md` §18.)
- **Malformed `domain-name` / `domain-search` scope option.** `422` — validated
  as an FQDN at `backend/app/api/v1/dhcp/scopes.py:90`.

### Servers & server groups

- **Duplicate server name.** Each `DHCPServer.name` is globally unique.
  `409` at `backend/app/api/v1/dhcp/servers.py:228`.
- **Driver enum.** `driver` must be one of `kea`, `windows_dhcp`.
  `422` at `backend/app/api/v1/dhcp/servers.py:73`.
- **Read-only drivers refuse config push.** Attempting to push a
  config bundle to an agentless read-only driver (e.g.
  `windows_dhcp`) returns `400` with a message directing the operator
  to `/sync-leases` instead. `backend/app/api/v1/dhcp/servers.py:378`.
- **Windows credentials must be complete on first set.** Setting
  credentials on a `windows_dhcp` server requires both `username` and
  `password` — you can't partial-update an empty credential blob.
  Later edits may include either field alone. `400` at
  `backend/app/api/v1/dhcp/servers.py:310`.
- **Duplicate server-group name.** `409` at
  `backend/app/api/v1/dhcp/server_groups.py:73`.
- **Server-group mode enum.** `VALID_MODES` only; enforced at
  `backend/app/api/v1/dhcp/server_groups.py:35`.

### Kea HA (on a server group)

- **At most 2 Kea members in a group.** `libdhcp_ha.so` only supports
  pairs; adding a third Kea member makes the config ambiguous.
  Validation is a deferred follow-up (see `CLAUDE.md`), not enforced
  at the CRUD layer today.
- **Group mode enum.** `mode` must be `standalone`, `hot-standby`, or
  `load-balancing`. Enforced at `backend/app/api/v1/dhcp/server_groups.py`.
- **HA rendering requires both peers' URLs.** If either Kea member in
  a 2-member group has an empty `ha_peer_url`, the config bundle
  drops the `failover` block and neither peer loads the HA hook —
  silent fall-through to "not-yet-configured" state.
- **Mixed driver groups are OK.** A group can contain Windows DHCP
  servers alongside Kea; only Kea members participate in the HA
  rendering path.

### Client classes

- **Duplicate client-class name per group.** Class names are scoped
  to the server group — every member renders the same classes. `409` at
  `backend/app/api/v1/dhcp/client_classes.py`.

## 17. Passive DHCP Fingerprinting (Phase 2 device profiling)

Auto-populate "what is this thing?" for every DHCP-leasing client by
sniffing each DISCOVER / REQUEST and looking the resulting
option-55 / option-60 signature up against fingerbank's device
taxonomy. Pairs with the active layer (auto-nmap on lease) — both
write into the same `IPAddress.device_type` / `device_class` /
`device_manufacturer` columns, so the IP detail modal shows one
consolidated answer regardless of which layer enriched the row.

### How it flows

1. The DHCP agent's `DhcpFingerprintShipper` thread runs scapy's
   `AsyncSniffer` against the BPF filter `udp and (port 67 or port 68)`
   and extracts option-55 (parameter request list), option-60
   (vendor class), option-77 (user class) and option-61 (client id)
   from each DISCOVER / REQUEST.
2. Observations are buffered + deduped at the agent layer (one
   batch per MAC per minute) and POSTed to
   `/api/v1/dhcp/agents/dhcp-fingerprints` every 10 s in batches of
   up to 50.
3. The control plane upserts the fingerprint into the
   `dhcp_fingerprint` table (keyed by MAC) and enqueues a Celery
   task per fresh / changed signature.
4. The task hits fingerbank's `/api/v2/combinations/interrogate`
   endpoint, caches the result on the row for 7 days, and stamps
   matching `IPAddress` rows (joined on MAC) with the resolved
   `device_type` / `device_class` / `device_manufacturer`. Rows
   with `user_modified_at` set are left alone — the operator's
   edits win.

### Enabling it

The feature is **default off** for two reasons: it requires
`CAP_NET_RAW` to bind a BPF socket, and sniffing every DHCP
transaction is privacy-sensitive on guest / BYOD subnets.

**On the agent** — add the env var **and** the Linux capability to
your compose override:

```yaml
services:
  dhcp-kea:
    cap_add:
      - NET_RAW
    environment:
      DHCP_FINGERPRINT_ENABLED: "1"
      # Optional — defaults to "any" which works for host-networked
      # containers. Bridge-networked containers should pick a real
      # interface name (eth0, etc).
      DHCP_FINGERPRINT_IFACE: "any"
```

The shipped `docker-compose.yml` does **not** add `NET_RAW`
unconditionally — operators who don't need fingerprinting shouldn't
have to grant the capability. Same reasoning for not enabling it via
default env.

**On the control plane** — set the fingerbank API key in
**Settings → IPAM → Device Profiling**. The form is a password-style
input with a "Configured ✓ Replace… Clear" view once a key is on file
(the encrypted value is never echoed back). Without a key, the agent
still ships raw signatures (visible as the option-55 / option-60
strings under the "Raw signature" disclosure on the IP detail
modal), but no enrichment runs. Get a key at https://fingerbank.org
(free tier: 30 lookups / hour / account is plenty for small-to-medium
fleets).

### Privacy + data shape

The fingerprint table is **MAC-keyed, not lease-keyed**. We don't
record per-transaction history; one row per device, refreshed
in-place on every observation. That means:

- A device that comes and goes still produces a single row with
  `last_seen_at` bumped on every observation.
- The raw option-55 / option-60 strings persist in the DB for
  operator triage. There's no separate retention sweep — the table
  is bounded by the number of unique MACs the agent has ever seen,
  which scales with the size of your physical fleet.
- We don't capture client IPs in fingerprints — the linkage to a
  specific IP comes from `IPAddress.mac_address` and is updated on
  every lease event (the existing path).

### Operator-facing UI

The IP detail modal surfaces both the enriched device line and (in
a "Raw signature" disclosure) the option-55 / option-60 strings.
The same surface lets operators force a re-lookup if they think the
fingerbank result is wrong (the dispatched task ignores the cache
window for that one MAC).

## 17a. Fingerprint-driven device policies (issue #700)

Section 17 tells you what a device *is*. Section 4 lets you treat
classes of device differently. This joins them: the operator picks
fingerbank device classes and an outcome — an option set, a lease
time, and optionally a pool — and SpatiumDDI compiles it into a real
Kea client-class `test` expression.

### Device classes are fingerbank's strings, not tidy categories

Worth setting expectations before the first policy: `device_class` is
fingerbank's own taxonomy (the first parent of the matched device), and
it sits at mixed granularity. Verified against a live key, real values
look like:

| `device_class` | `device_name` | score |
|---|---|---|
| `HP Print Server` | HP JetDirect Print Server | 89 |
| `Operating System` | Windows OS | 78 |
| `Generic Android` | Samsung Android | 60 |
| `Hardware Manufacturer` | Apple, Inc. | 29 |
| `Generic IoT` | Raspberry Pi | 15 |

There is no plain `Printer` or `IoT` class to select. Always pick from
`GET …/device-observations` rather than typing a string — one that does
not appear there compiles to an empty expression and renders nothing,
which looks configured and does nothing.

**The score is part of the safety story, not decoration.** A low
fingerbank score means it could not identify the device and fell back to
the MAC vendor — which is exactly what `Hardware Manufacturer` at 29
above is. A class like that groups unrelated hardware, so building a
quarantine on it targets an arbitrary set of unidentified devices. The
class picker shows the score per class and flags anything under 30, and
the compiler adds a warning when the best score among matched devices is
below that.

That produces NAC-lite outcomes with no 802.1X and no switch
configuration: unknown and IoT devices get a short lease, a restricted
resolver and a quarantine pool; corporate laptops get the normal
treatment.

### What the expression actually matches

Fingerbank classifies by querying their corpus with the signature a
device emitted. Kea cannot do that mid-packet, and there is no
`device-class == IoT` predicate to render. So the compiler matches
**the signatures we have observed and had classified into the
selected classes** — not the abstract category.

Two consequences, repeated in the UI rather than hidden:

1. A device whose signature we have never seen matches nothing,
   however obviously it belongs to the category. It is classified on
   its first lease and the policy applies from the **next renewal**.
   Nothing here is instant enforcement.
2. The policy tracks observation. As new signatures land in a selected
   class the expression grows on its own — which is the feature, but
   it also means the rendered config changes with no operator edit,
   and the bundle ETag legitimately shifts. It is bounded by *distinct
   signatures*, not device count, so it settles once the estate has
   been seen: a fleet of 500 identical handsets adds one term, not 500.

### Ambiguous signatures are excluded by default

DHCP signatures are not unique to a device class. A minimal parameter
request list like `1,3,6,15` is emitted by embedded Linux in a
doorbell and by a rack server alike. If a signature appears on devices
both inside **and** outside the selected classes, matching it applies
the policy to devices the operator did not choose — which for a
feature whose headline use is "put unknown devices in a quarantine
pool" is how the CEO's laptop ends up quarantined.

Such signatures are excluded, counted, and listed in the preview.
`include_ambiguous` is the explicit, audited opt-in.

Devices fingerbank has **not** classified are treated differently:
they are not evidence of a different class (excluding an otherwise
clean signature because of one would make the feature unusable before
an API key is set), so they do not trigger ambiguity. They *will*
receive the policy, so the count is reported instead — and only for
signatures that survived filtering and the term cap, so the number
reflects devices the rendered expression actually reaches.

### Nothing device-controlled becomes syntax

Option 60 is a value the *device* chooses, and it lands inside a
config file with quoting. Both halves of every term are emitted as hex
literals:

```
(option[55].hex == 0x0103060F and option[60].hex == 0x4D53465420352E30)
```

so a vendor class of `' or 1--` becomes inert bytes rather than
expression syntax. Verified against kea-dhcp4 3.0.3.

A device that sent no option 60 compiles to `not option[60].exists`
rather than omitting the test — ignoring the absence would widen the
match to every device sharing the request list, including ones that
*do* send a vendor class.

### The compiled expression is visible and overridable

`GET /dhcp/device-policies/{id}/preview` returns the expression, the
signatures behind it, the excluded ones, and the MACs currently
matched. `match_override` replaces the generated expression entirely,
and the preview still shows what the compiler produced so the two can
be compared. Nobody should end up debugging a black box against
`kea-dhcp4.log`.

An override is structurally checked at the API (balanced parentheses
and quotes, length). This is deliberately not a Kea expression parser
— operators need the real language for the escape hatch to be usable —
but Kea rejects a malformed config **whole**, so an unbalanced paren
would stop every other class, scope and reservation in the group
converging, not just this policy. Same blast radius `named.conf`
validation exists for in #876 / #899. The agent still runs Kea's own
`config-test` before applying, and #882's quarantine means a rejected
bundle is reverted rather than re-applied in a loop.

### Rendering

| Property | Value |
|---|---|
| Table | `dhcp_device_policy` (migration `f3b8d21c74ae`) |
| Kea class name | `spatium-device-<slug>`, stored not derived |
| Per-class lease | Kea `valid-lifetime` on the class |
| Address family | **DHCPv4 only** — options 55/60 are v4 option codes |
| Order | After operator, PXE and phone classes |

`class_name` is a stored column rather than derived from `name` at
render time. Pools bind to a class **by name** via
`DHCPPool.class_restriction`, so regenerating it on rename would leave
every pool restricted to a class that no longer exists — which Kea
accepts, and which silently stops the pool serving anyone.

A policy that compiles to nothing is **dropped**, never rendered with
an empty `test`: a Kea client class with no test matches every packet,
which would hand a quarantine's option set and lease time to the whole
network. The agent renderer fails closed the same way.

The maximum number of signature terms in one expression is 128. Kea's
parser is not the constraint (a 1024-term / 32 KB expression loads
fine); per-packet evaluation cost and operator legibility are. Hitting
the cap is **reported**, never silent.

### Endpoints

| Method | Path |
|---|---|
| GET/POST | `/dhcp/server-groups/{gid}/device-policies` |
| GET/PUT/DELETE | `/dhcp/device-policies/{id}` |
| GET | `/dhcp/device-policies/{id}/preview` |
| GET | `/dhcp/server-groups/{gid}/device-observations` |

Permissions ride on `dhcp_client_class` — a device policy *is* a
client class, generated rather than hand-written — so the builtin DHCP
Editor role gains **read** with no role migration. **Writes are
superadmin**, matching the hand-authored client-class surface rather
than quietly widening it: the two produce the same Kea object, and a
policy that can move devices into a quarantine pool is not a smaller
privilege than typing that class by hand.

The preview is genuinely read-only — it commits nothing, so it cannot
become an unaudited write on a path authorised by `read` and not gated
by maintenance mode.

A vendor class that was stored after a lossy decode (option 60 arrived
as non-UTF-8 and `DHCPFingerprint` decodes with `errors="replace"`) is
**refused**, not re-encoded: `EF BF BD` is not what the device puts on
the wire, so the term could never match while the preview claimed the
device was caught. It falls back to matching option 55 alone.

MCP: `find_dhcp_device_policies` and `preview_dhcp_device_policy`,
both read-only and default-enabled.

**Deferred:** auto-creating the quarantine pool alongside the policy
(today the operator points a pool's class restriction at the generated
class name); DHCPv6, which needs the option 16 / ORO equivalents and a
different fingerbank input; and rules that key on fingerbank
*device name* rather than class.

---

## 18. PXE / iPXE provisioning profiles (issue #51)

Operator-curated `pxe_profile` rows wrap the per-architecture TFTP
boot story so the same scope can serve legacy PXE BIOS, EFI x86_64,
EFI ARM64, and EFI x86 clients without hand-written client classes.

**Data model.** New `pxe_profile` table — name + description +
`next_server` (TFTP host) + four nullable `boot_filename_*` columns
keyed on architecture (`bios_x86` / `efi_x86_64` / `efi_arm64` /
`efi_x86`) + an optional `ipxe_script` body. Profiles live at the
DHCP server-group level so the same profile serves every Kea
server in the group.

**Per-scope binding.** `DHCPScope.pxe_profile_id` is a SET-NULL FK
to `pxe_profile`. The scope create / edit modal surfaces a "PXE
profile" picker; null = no PXE on this scope.

**Kea render.** When a scope has a PXE profile attached, the agent
renders one `client-class` per arch-match (matching DHCP option 93
via `option dhcp.client-arch`) plus one `iPXE` class guarded by a
substring match on `option dhcp.user-class` so legacy PXE clients
see the BIOS bootfile and iPXE clients (which loop back with the
`iPXE` user-class set) jump straight to the chained iPXE script.

**Admin UI.** New `/dhcp/groups/{id}/pxe` page lists profiles for a
group with create / edit / delete + an in-line preview of the
rendered Kea client-class block.

## 19. IPv6 Router Advertisements + rogue-RA detection (issue #524)

SpatiumDDI ships DHCPv6 via Kea, but Kea does not emit ICMPv6 Router
Advertisements. This feature lets the DHCP agent run **radvd** from
config rendered by the control plane, and passively watches the segment
for **rogue RAs**. Both live behind the `ipv6.router_advertisements` feature module, which
ships **disabled** (Settings → Features): it is the one DHCP-adjacent surface
that ends in something transmitted onto the wire, and a v4-only install has no
use for it ([#1069](https://github.com/spatiumnorth/spatiumddi/issues/1069)).

### 19.1 RA management (radvd)

RA config is per-IPv6-scope, opt-in via `DHCPScope.ra_enabled`. When on,
the control plane renders a full `radvd.conf` stanza for the subnet and
ships it in the **DHCP ConfigBundle** (`radvd_conf`, folded into the
bundle ETag so a change wakes the agent long-poll — same path as the Kea
config). The agent writes it to `RADVD_CONFIG_PATH` and reloads radvd
(SIGHUP via pidfile); the last-known-good config rides the on-disk bundle
cache, so radvd keeps advertising if the control plane is unreachable
(non-negotiable #5).

Per-scope RA columns (v6 scopes only; edited in the scope modal's IPv6
section):

| Column | Meaning |
|---|---|
| `ra_enabled` | Opt-in — emit RAs for this subnet |
| `ra_mo_override` | Use `ra_managed_flag`/`ra_other_flag` verbatim instead of deriving M/O from the mode |
| `ra_router_lifetime` | `AdvDefaultLifetime` (s); 0 = not a default route |
| `ra_max_interval` | `AdvMaxInterval` (s) between unsolicited RAs |
| `ra_prefix_valid_lifetime` / `ra_prefix_preferred_lifetime` | Advertised prefix lifetimes (s) |
| `ra_prefix_on_link` / `ra_prefix_autonomous` | Per-prefix `AdvOnLink` / `AdvAutonomous` (SLAAC) |
| `ra_interface` | Host NIC radvd advertises on (blank = agent `RADVD_DEFAULT_IFACE`) |

**M/O derivation.** By default the advertised M (Managed) / O (Other)
flags derive from the scope's `v6_address_mode`: `stateful` → (1,1),
`stateless` → (0,1), `slaac` → (0,0). Set `ra_mo_override` to advertise
the literal `ra_managed_flag`/`ra_other_flag` instead.

**RDNSS / DNSSL.** The RA advertises RDNSS (RFC 8106 IPv6 resolvers) from
the scope's `dns-servers` option (IPv6 only), falling back to the
subnet's `dns_servers`; DNSSL search domains come from `domain-search` /
`domain-name` / the subnet's `domain_name`.

**Running radvd.** radvd is baked into the Kea agent image but started
only when `RADVD_MANAGED=1` (needs `CAP_NET_RAW` + `CAP_NET_ADMIN` and
host `net.ipv6.conf.all.forwarding=1`). The entrypoint waits for the
agent to render a config before launching radvd. The `/dhcp/groups/{id}`
→ **Router Adverts** tab previews the rendered `radvd.conf` + resolved
per-subnet M/O.

### 19.2 Rogue-RA detection

The IPv6 twin of the rogue-DHCP probe. An opt-in passive sniffer on the
DHCP agent (`DHCP_RA_SNIFFER_ENABLED=1`, same `CAP_NET_RAW` posture as
the fingerprint sniffer, default OFF) uses a scapy `AsyncSniffer` for
ICMPv6 type-134 RAs and ships each observed router (source IP + MAC,
advertised prefixes, M/O flags, router lifetime) to
`POST /dhcp/agents/ra-observations`.

The control plane classifies each source against the group's
**expected-router allowlist** (`ra_router_allowlist`, matched on source
IP or MAC): on the list → `expected`, otherwise → `rogue`, upserting a
`ra_observed_router` row per (group, source IP). The **`rogue_ra` alert
rule** (seeded disabled, enable once the sniffer is on) fires on rows
classified `rogue` within its recency window and rides the standard
AlertEvent fan-out (syslog / webhook / SMTP / chat). Acknowledging a
router from the Router Adverts tab allowlists it and reclassifies it so
the alert auto-resolves.

### 19.3 API + MCP

REST (gated by the module): `GET /dhcp/ra/groups/{id}/ra-config`
(rendered preview), `GET|POST /dhcp/ra/groups/{id}/observed-routers`
(+`/{id}/acknowledge`), and `GET|POST|DELETE
/dhcp/ra/groups/{id}/ra-allowlist`. Operator-Copilot tools:
`find_ra_subnets`, `find_observed_ra_routers`, `count_rogue_ra_routers`
(reads, default on) + `propose_allowlist_ra_router` (write proposal).
