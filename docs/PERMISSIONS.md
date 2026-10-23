# Permissions Model

SpatiumDDI uses a **group-based RBAC** model. Users are members of one or more
**Groups**, groups carry one or more **Roles**, and roles carry a list of
**Permission entries**. Every API mutation is checked server-side (see
non-negotiable #3 in `CLAUDE.md`).

## The Permission Entry

Each entry in `Role.permissions` (JSONB) is an object with this shape:

```json
{
  "action": "write",
  "resource_type": "subnet",
  "resource_id": "c3f1e7b9-2a5d-…"
}
```

| Field           | Required | Meaning                                                                |
| --------------- | -------- | ---------------------------------------------------------------------- |
| `action`        | yes      | What the user may do. See **Actions** below.                           |
| `resource_type` | yes      | Which resource kind. See **Resource types** below.                     |
| `resource_id`   | no       | Scope to a specific UUID. Omit / `null` for "any instance of the type". |

### Actions

| Action   | Meaning                                                    |
| -------- | ---------------------------------------------------------- |
| `read`   | GET / list / export                                        |
| `write`  | POST / PUT / PATCH (create, update)                        |
| `delete` | DELETE                                                     |
| `admin`  | All of `read`, `write`, `delete` for the given resource    |
| `approve` | The second-person decision on a queued change request — only meaningful on `change_request`. Does not imply `read`, and `admin` does not imply it |
| `*`      | Wildcard — match any action                                |

### Resource types

| `resource_type`   | Covers                                                |
| ----------------- | ----------------------------------------------------- |
| `ip_space`        | IPAM spaces                                           |
| `ip_block`        | Top-level CIDR blocks                                 |
| `subnet`          | Subnets under a block                                 |
| `ip_address`      | Individual IPs, aliases, bulk address ops             |
| `vlan`            | VLANs and routers                                     |
| `vrf`             | VRFs (Virtual Routing and Forwarding) — `manage_vrfs` |
| `asn`             | Autonomous Systems + RPKI ROAs + BGP peering / communities — `manage_asns` |
| `domain`          | Domain registration tracking (registrar / expiry / NS drift) — `manage_domains` |
| `dns_zone`        | DNS zones (forward and reverse)                       |
| `dns_record`      | DNS records within a zone                             |
| `dns_group`       | DNS server groups, servers, views, ACLs, trust anchors |
| `dns_blocklist`   | Response Policy Zones / blocking lists                |
| `dhcp_server`     | Kea + Windows DHCP server objects and server groups   |
| `dhcp_scope`      | DHCP scopes / shared networks                         |
| `dhcp_pool`       | Address pools within a scope                          |
| `dhcp_static`     | Static / reserved leases                              |
| `dhcp_client_class` | DHCP client classes                                 |
| `audit_log`       | Audit log read                                        |
| `user`            | Users — **superadmin only** in practice               |
| `group`           | Groups — admin required                               |
| `role`            | Roles — admin required                                |
| `auth_provider`   | LDAP/OIDC/SAML providers — superadmin only            |
| `custom_field`    | Custom field definitions                              |
| `manage_ipam_templates` | IPAM template classes (#26)                     |
| `settings`        | Platform settings                                     |
| `api_token`       | API tokens                                            |
| `acme_account`    | ACME DNS-01 provider credentials (`/api/v1/acme/`)    |
| `customer`        | Customer logical-ownership entity (#91)               |
| `site`            | Site logical-ownership entity (#91)                   |
| `provider`        | Provider logical-ownership entity (#91)               |
| `circuit`         | WAN circuit (#93)                                     |
| `network_service` | Service-catalog row (#94) — bundles VRF/Subnet/IPBlock/DNSZone/DHCPScope/Circuit/Site/OverlayNetwork into a customer deliverable |
| `overlay_network` | SD-WAN overlay topology + sites (#95)                 |
| `routing_policy`  | Per-overlay declarative routing policies (#95)        |
| `application_category` | SaaS application catalog used by `match_kind=application` (#95) |
| `looking_glass_collector` | BGP Looking Glass receive-only GoBGP collectors — register / CRUD + learned-route reads (#566) |
| `bgp_lg_peer`     | BGP Looking Glass configured peer sessions within a collector (#566) |
| `conformity`      | Conformity policies + results + auditor PDF export (#106) |
| `manage_packet_capture` | On-demand packet capture (tcpdump) — start / read / download / delete captures (#59). High-sensitivity (captured bytes can contain plaintext creds/PII); granted to `Network Editor`, not `Viewer`. Download is audited. |
| `manage_block_sync` | Active block sync / write-back enforcement (#601) — create/lift SpatiumDDI-owned IP/MAC blocks, arm per-target OPNsense/UniFi enforcement + write-scoped creds, reveal + reconcile. High blast-radius (pushes a real firewall/gateway block that can lock devices out); granted to `Network Editor`, not `Viewer`. Every push is audited and eligible for two-person approval (`admin:manage_block_sync`). |
| `manage_firewall_enforcement` | Arming the *off-prem / broad-blast-radius* firewall write-back targets (#605 / #606) — Palo Alto Dynamic Address Group tag register (User-ID API) and Meraki per-client `Blocked` device policy (cloud Dashboard API). Required **in addition to** `manage_block_sync`. Unlike an OPNsense alias or a UniFi L2 quarantine, these push through a vendor cloud / User-ID surface with a separate write-scoped credential, so it is deliberately granted to **no built-in role** — Superadmin bypasses, and any other grant must be made on purpose. |
| `address_set`     | Named IP range within a subnet carrying its own RBAC scope — delegates edit of a slice without subnet-wide write (#103). Creating a set / resizing its range additionally requires write on the parent subnet. |
| `change_request`  | Queued two-person-approval change requests (#62) — `approve` + `read` for the second-person decision (the underlying operation's permission is *also* required server-side). |
| `provisioning_request` | Self-service request portal (#696) — `write` submits a request for an IP / subnet / DNS record / DHCP reservation, `read` sees your own. Deliberately confers **no** provisioning ability: submitting skips the underlying operation's permission (that inversion is the feature), and the request only becomes a change when a *different* operator who **does** hold that permission approves it. Deciding a portal request reuses `approve,change_request`. |
| `wol_schedule`    | Scheduled Wake-on-LAN jobs + run history (#586) — recurring, tag-targeted, calendar-gated fleet wake |
| `wol_calendar`    | Subscribed iCal / CalDAV calendars whose all-day spans gate scheduled wakes (#586) |
| `av_flow`         | AV-over-IP flow descriptors + operator-declared reserved multicast ranges (#540) — the Dante / AES67 / SMPTE 2110 layer over the multicast registry |
| `bacnet_device`   | BACnet/IP device registry (#541) — internetwork-unique device instance numbers, vendor/model metadata, BBMD flag + BDT/FDT snapshots |
| `dicom_ae`        | DICOM Application Entity registry (#723) — institution-wide-unique AE Titles, their host/port bindings, and the configured AE→AE association map. Network identity only; this permission never grants access to imaging data, which SpatiumDDI does not store |
| `ot_device`       | Industrial / OT device inventory + Purdue zoning (#542) — read-only identification; this permission never grants control-protocol access, which is out of scope entirely |
| `*`               | Wildcard — match any resource type                    |

## Evaluation rules

1. **Superadmin short-circuits everything.** If `User.is_superadmin=True`
   the check always passes (no audit denial written).
2. **Inactive users are denied** regardless of permissions.

### "Effective superadmin" — legacy flag + RBAC wildcard

Two paths grant superadmin-level access (#190):

- **Legacy column** — `User.is_superadmin=True` set directly on the
  row (seeded `admin`, anyone explicitly flagged in the user-admin
  form).
- **RBAC wildcard** — the user is a member of a group whose role
  carries a `{action: "*", resource_type: "*"}` permission (the
  built-in `Superadmin` role or any clone of it).

Both pass `require_permission` gates identically. For endpoints with
`Depends(require_superadmin)` (or an inline `is_effective_superadmin`
check), both also admit — without this unification, users provisioned
via LDAP / OIDC / SAML and mapped into a Superadmin-role group passed
every `require_permission` check but 403'd on hand-rolled superadmin
helpers (the canonical pre-#190 bug).

Carve-out: the legacy-flag path keeps admitting **inactive**
superadmins so a disabled bootstrap admin can still reach diagnostic
surfaces during incident triage. The wildcard-permission path still
requires `is_active=True` because `user_has_permission` short-circuits
on inactive.
3. **Match algorithm** for a given check (`action`, `resource_type`, `resource_id`):
   - Walk every role in every group the user is a member of.
   - A permission entry matches when:
     - `entry.action == "*"` or `entry.action == action` or
       (`entry.action == "admin"` and `action ∈ {read, write, delete, admin}`), AND
     - `entry.resource_type == "*"` or `entry.resource_type == resource_type`, AND
     - `entry.resource_id` is missing/empty/`"*"`, OR `entry.resource_id == resource_id`.
   - Any single matching entry grants the permission.
4. **Unscoped vs scoped checks.** A permission with `resource_id` set cannot
   satisfy an unscoped check (one passed without `resource_id`). This prevents
   "I have write on *this one* subnet" from accidentally granting "write on
   subnets in general".
   **IPAM subnets (#2438).** A `read` / `write` grant scoped to one subnet
   reaches that subnet and its addresses and nothing else. The routes it
   opens are an allow-list, so a route added later stays closed to it until
   it is listed: the subnet's own reads (detail, addresses, aliases, domains,
   effective DNS / DHCP / fields, network context, next-IP preview, probe
   policy, reconciliation, utilization history), `PUT /ipam/subnets/{id}`,
   `POST /ipam/subnets/{id}/addresses`, and the subnet list, which is
   narrowed to the granted subnets. Through the scoped grant the holder may
   not point the subnet at another resource (block, customer, site, VLAN,
   DHCP server group, DNS server groups, DDNS domain), nor name a DNS zone,
   on the subnet or on an address, that the subnet does not already publish
   into unless they hold `write` on that `dns_zone`. A collision warning
   on an address create says that a hostname or MAC is in use but not
   where, when the row is in a subnet the holder cannot read. Spaces,
   blocks, other subnets, the DNS drift report, NAT mappings, delete /
   resize / split / merge / next-IP / bulk / DNS-sync, and editing or
   deleting an existing address stay refused unless a type-level grant
   covers them.
   **IPAM address sets (#103).** A `write` / `admin` grant on an address set
   (the Address Set Editor role, scoped to one set) reaches an allow-list of
   address routes and nothing else in IPAM: create, next-IP, bulk-allocate
   (preview and commit), edit and delete an address, add and remove its
   aliases, bulk-edit and bulk-delete addresses, deprecate stale IPs, and the
   address import (preview and commit). Each of those checks every address it
   touches against the set's range, so the holder changes only addresses
   inside the sets it holds. Every other mutating IPAM route, including one
   added later, refuses such a holder with 403 until it is listed
   (`_ADDRESS_SET_ROUTES` in `backend/app/api/v1/ipam/router.py`). Reads
   still need a normal read grant.
5. **Privilege ceiling on role / group edits (#400 C4).** When a non-superadmin
   creates or edits a role's permission set (or assigns roles to a group), every
   permission they add must be one they *themselves* effectively hold —
   `user_has_permission(editor, entry)` must pass for each entry in the new set,
   and no entry may carry a wildcard (`*`). The editor must hold each entry
   through a static role: a permission held only through a live time-bound
   grant is not one they can grant onward, or a grant meant to lapse could be
   turned into a role, a membership or a longer grant that does not. This
   stops, say, an IPAM editor from
   minting a `{*, *}` role and assigning it to their own group to escalate.
   Superadmins (either path in the section above) are exempt by rule 1.

   A group's roles, plus its live time-bound grants, are what its members hold,
   so the same ceiling bounds every change to who holds them:

   - **adding or removing a member** — against every role the group carries
     (the ones it keeps and the ones the same edit attaches) and its live
     time-bound grants. Resending the unchanged member list is not a change;
   - **detaching a role** from a group, **deleting a group**, **changing or
     deleting a role** (its current permissions as well as the new ones), and
     **revoking a wildcard time-bound grant** (revoking any other grant only
     narrows access, so a group admin may do it).

   So only a superadmin can change the membership of a group that carries a
   wildcard permission. A refusal is a 403 with a `denied` audit row.
   Group membership synced from an identity provider at sign-in is not bounded
   by this: it follows the provider group mappings, which only a superadmin
   configures.
6. **At least one active superadmin.** Any change that would leave no active
   superadmin — through the `is_superadmin` flag or a `{*, *}` role — is refused
   with 409 and a `denied` audit row: disabling, un-flagging or deleting a user;
   removing a member from, detaching a role from, or deleting a group; changing
   or deleting a role. A superadmin who holds `{*, *}` only through a time-bound
   grant does not count, since the grant lapses on its own; so revoking such a
   grant is never refused by this rule. The check and the change it guards run
   under one advisory lock, so two concurrent changes cannot each remove one of
   the last two superadmins.

### Bulk deletes need `delete`

Router-level gates derive the action from the HTTP method (GET `read`,
POST/PUT/PATCH `write`, DELETE `delete`). A POST that removes many rows at
once — every `POST .../bulk-delete`, and `POST /ipam/subnets/{id}/orphans/purge`
— removes them exactly as `DELETE` does, so it requires `delete` on the same
resource type as the single-row route, not `write`. A role holding `write`
without `delete` is refused on both. The list lives in
`MULTI_ROW_DELETE_SUFFIXES` in `app/core/permissions.py`. Routes with their own
gate (domains, nmap, pcap) require `delete` explicitly.
`tests/test_bulk_delete_requires_delete_action.py` walks the route table: it
checks every listed route against a write-only role, and fails on a POST route
named like a multi-row delete (`purge`, `prune`, `clear`, `remove`, …) that is
neither on the list nor reviewed as something else.

## Built-in roles (seeded on first start)

| Role           | Permissions                                                  |
| -------------- | ------------------------------------------------------------ |
| `Superadmin`   | `[{"action": "*", "resource_type": "*"}]`                    |
| `Viewer`       | `[{"action": "read", "resource_type": "*"}]`                 |
| `IPAM Editor`  | `admin` on `ip_space`, `ip_block`, `subnet`, `ip_address`, `address_set`, `vlan`, `nat_mapping`, `custom_field`, `manage_ipam_templates`, `customer`, `site`, `provider`, `network_service` |
| `DNS Editor`   | `admin` on `dns_zone`, `dns_record`, `dns_group`, `dns_blocklist`; `read` on `manage_dns_pools` — create, edit and delete zones, records, views and ACLs, and the entries and exceptions of existing blocklists. Infrastructure stays superadmin-only (see below) |
| `DHCP Editor`  | `admin` on `dhcp_server`, `dhcp_scope`, `dhcp_pool`, `dhcp_static`, `dhcp_client_class`, `dhcp_option_template`, `dhcp_mac_block` — create, edit and delete scopes, pools, static assignments, client classes and device policies, option templates, phone and PXE profiles, and MAC blocks; acknowledge rogue-responder and router-advertisement findings. Infrastructure stays superadmin-only (see below) |
| `Network Editor` | `admin` on `manage_network_devices`, `manage_nmap_scans` (nmap `extra_args` are allowlisted, #1223), `manage_packet_capture`, `manage_block_sync`, `use_network_tools`, `manage_asns`, `vrf`, `circuit`, `multicast`, `av_flow`, `bacnet_device`, `dicom_ae`, `ot_device`, `network_service`, `overlay_network`, `routing_policy`, `application_category`, `customer`, `site`, `provider`, `tls_cert` |
| `Auditor`        | `read` on `conformity`, `audit_log`, `subnet`, `ip_address`, `dns_zone`, `dhcp_scope`, `tls_cert` — external auditor account, can view conformity dashboard + pull the auditor PDF + verify supporting evidence without making changes |
| `Compliance Editor` | `admin` on `conformity`, `read` on `audit_log`, `subnet`, `ip_address`, `dns_zone`, `dhcp_scope` — for the team that authors / tunes conformity policies without touching operational config |
| `Address Set Editor` | `admin` on `address_set` (#103) — delegated edit of a named IP slice within a subnet without subnet-wide write. Grant on a specific address-set id to scope a department admin to just their slice. Creating / resizing a set still requires write on the parent subnet. |
| `Change Approver`  | `approve` + `read` on `change_request` (#62) — the second-person decision capability in the two-person approval workflow. Reading the queue needs no grant for your own rows (#1863): any signed-in user sees, and may cancel, the requests they made themselves; `read` widens nothing, and seeing every row takes `approve`. Approving a specific request *also* requires the underlying operation's permission (e.g. `delete,subnet`), enforced server-side. |
| `Requester`        | `write` + `read` on `provisioning_request` (#696) — the low-privilege half of the request workflow, meant to be granted broadly (a whole department, not just the network team). Holders can ask for an IP / subnet / DNS record / DHCP reservation and see their own requests; they cannot provision anything, cannot see anyone else's requests, and cannot approve. |
| `Appliance Operator` | `admin` on `appliance` (#134) — full control of the SpatiumDDI OS appliance management surface (TLS cert upload, release manager, container start/stop/restart + live logs, host network + firewall config, maintenance mode, diagnostic bundle download) for ops staff who manage the appliance lifecycle without full superadmin over the DDI data plane. |

Built-in roles (`is_builtin=True`) can be cloned but not deleted.

### DNS and DHCP: data writes vs infrastructure (#1861)

Until #1861 the DNS Editor and DHCP Editor descriptions promised "Full CRUD"
while almost every DNS and DHCP write route also took `SuperAdmin`, so the
roles could read everything and write DNS records and little else. The
everyday data routes now check the role's own resource permission, with the
HTTP method's action (`write` for POST / PUT, `delete` for DELETE), so the
Editor roles grant the writes they always claimed to:

| Surface | Gate |
|---|---|
| DNS zones (create, from template, edit, delete) | `write` / `delete` on `dns_zone` |
| DNS records, bulk create, zone-file import | `write` / `delete` on `dns_record` (a `replace` import that would remove records also takes `delete`; the import preview and commit, which answer with the zone's existing records, also take `read` on `dns_group`, `dns_zone` or `dns_record`, as the export does) |
| DNS views and named ACLs | `write` / `delete` on `dns_group` |
| Blocklist entries and exceptions | `write` / `delete` on `dns_blocklist` |
| DHCP scopes, phone profiles, PXE profiles | `write` / `delete` on `dhcp_scope` |
| DHCP pools / static assignments | `write` / `delete` on `dhcp_pool` / `dhcp_static` |
| DHCP client classes and device policies | `write` / `delete` on `dhcp_client_class` |
| DHCP option templates (applying one to a scope also takes `write` on `dhcp_scope`) | `write` / `delete` on `dhcp_option_template` |
| DHCP MAC blocks | `write` / `delete` on `dhcp_mac_block` |

**Infrastructure stays superadmin-only**: DNS and DHCP server groups and
servers (create, edit, delete, move, credentials, pause / resume, approve,
sync), DNS server options and trust anchors, TSIG keys, DNSSEC signing, key
rollover and policies, dynamic-update ACLs, zone moves between groups,
blocklist lists themselves (subscriptions, feeds, profiles, assignments,
refresh), DNS GSLB pools (their health checks probe the network), Windows
DHCP failover relationships, DHCP lease deletion, every importer and the
cutover, and agent registration. Inside an opened route, three things stay
superadmin-only as well: `?permanent=true` on a zone or scope delete (as on
the IPAM deletes), and changing a zone's `dnssec_enabled` /
`dnssec_policy_id`, `dynamic_update_enabled` or `auto_tls_probe` (sending
the current value back is not a change, so an edit dialog still saves).

`backend/tests/test_builtin_roles_match_routes.py` holds the built-in roles
to the routes: each role's promised routes must be reachable on its grants,
every write grant must back one of them, and every other DNS / DHCP write
route must take `SuperAdmin`. `backend/tests/test_dns_dhcp_editor_roles.py`
drives the same promises through the API.

> **Feature-module gating.** The `Change Approver` role only matters when
> the default-off `governance.approvals` feature module is enabled, and
> `Address Set Editor` when `ipam.address_sets` is enabled.

## Using the helpers

```python
from app.core.permissions import require_resource_permission, user_has_permission

# Router-level: GET=read, POST/PUT=write, DELETE=delete
router = APIRouter(dependencies=[Depends(require_resource_permission("subnet"))])

# Fine-grained inside a handler:
subnet = await db.get(Subnet, subnet_id)
if not user_has_permission(current_user, "write", "subnet", subnet.id):
    raise HTTPException(403, "Permission denied on this subnet")
```

See `backend/app/core/permissions.py` for the full API.

### Every read route declares its permission

A `GET` route that takes only `CurrentUser` answers every signed-in account,
whatever its role grants. So every `GET` route carries a permission
dependency — a `require_*permission` factory or `SuperAdmin` — unless it is
listed in `NO_PERMISSION_DEPENDENCY` in
`backend/tests/test_get_routes_declare_permission.py` with the reason: it is
reachable before sign-in, it is authenticated by something other than a user
session (an agent JWT, a signed download URL, a feed token), it returns only
the caller's own rows, it serves static reference data or settings the UI
shell needs, or the handler checks the permission itself. That test walks the
served route table and fails for a new unlisted route, and for a listed route
that has since gained a dependency.

A rollup over several resource types (the Network and Integrations dashboard
tabs, the DNS / DHCP traffic series) needs `read` on at least one of the types
it summarises, and fills only the panels whose type the caller can read, so it
never shows more than the resources' own routes would. The tag autocomplete
(`GET /tags/keys`, `/tags/values`) follows the same rule per table: it offers
tags only from the tables whose rows the caller can read, and an empty list
when there are none.

## Refusals are audited

Every 403 the permission gates produce leaves a `denied` audit row, including a
refusal from a route that takes `SuperAdmin` (recorded as `access` on
`superadmin`, #2304). A handler that is superadmin-only must take the `SuperAdmin`
dependency rather than check `is_effective_superadmin` and raise by hand, or its
refusal is invisible to the audit log and the security dashboard.

## The console mirrors the server, it does not enforce

The API is the enforcement point (non-negotiable #3). The console reads the
caller's grants from `GET /api/v1/auth/me/permissions` through
`usePermissions()` (`frontend/src/hooks/usePermissions.ts`) only so it does not
offer a write the server would refuse: a control the user may not use stays in
place, disabled, with the reason as its tooltip (`permissionGate()`, #1155), or
is hidden where a whole surface is superadmin-only. Each gate asks exactly what
its route asks — `can(action, resource_type)` for a router or handler permission
check, `isSuperadmin` (reason `NEEDS_SUPERADMIN`) for a handler that takes
`SuperAdmin` whatever the grants. One deliberate exception: a bulk delete is
gated on `delete`, although most `POST …/bulk-delete` routes are admitted by the
router's method gate as `write` (only Domains checks `delete` inline); the
console asks what the action does rather than widen a delete to every writer. Appliance actions use
`useApplianceAdminGate()` (`admin` on `appliance`). When you add a write control,
gate it the same way, and give its mutation an error display so a refusal the
console could not predict still says why (#1338–#1342).
