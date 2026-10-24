# Data Model

A navigable reference to the SpatiumDDI database schema. This is a
*map*, not a column-by-column dump — it groups the SQLAlchemy models by
domain, names the anchor tables and their key relationships, and
documents the shared conventions every model follows. For the exact
column list of any table, read the model source under
[`backend/app/models/`](https://github.com/spatiumnorth/spatiumddi/tree/main/backend/app/models); each file is the
authoritative definition.

All models are SQLAlchemy 2.x async (`Mapped[...]` /
`mapped_column(...)`) and live in PostgreSQL 16. The Alembic migrations
under [`backend/alembic/`](https://github.com/spatiumnorth/spatiumddi/tree/main/backend/alembic) are the source of truth
for the deployed schema; the model classes are the source of truth for
what the application reads and writes.

Feature-level behaviour lives in the matching specs —
[IPAM](features/IPAM.md), [DNS](features/DNS.md),
[DHCP](features/DHCP.md), [Permissions](PERMISSIONS.md),
[Observability](OBSERVABILITY.md).

---

## 1. Shared conventions

These mixins and patterns are defined in
[`backend/app/models/base.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/base.py) and
reused across the schema.

### Primary keys

Almost every table uses a UUID primary key via `UUIDPrimaryKeyMixin`:

```python
id: Mapped[uuid.UUID] = mapped_column(
    UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
)
```

The UUID default is generated application-side (`uuid.uuid4`), not by
the database. A handful of tables deviate deliberately:

- `feature_module` uses a stable dotted-string PK (e.g. `ai.copilot`,
  `network.customer`) instead of a UUID.
- `dns_metric_sample` / `dhcp_metric_sample` use a composite PK
  `(server_id, bucket_at)` — they are time-series buckets, not entities.
- `audit_log` keeps its UUID `id` but also carries a monotonic
  `BigInteger seq` for chain ordering (see §11).

### Timestamps

`TimestampMixin` adds `created_at` and `modified_at`, both
`DateTime(timezone=True)` with `server_default=now()` and `modified_at`
carrying `onupdate=now()`. Append-only tables (audit, metric samples,
conformity results, lease history, log entries) intentionally omit the
mixin — they never mutate, so a `modified_at` would be meaningless.

### Soft delete

`SoftDeleteMixin` implements a 30-day soft-delete + recovery window for
high-blast-radius rows. It adds `deleted_at`, `deleted_by_user_id`
(FK → `user`, `ON DELETE SET NULL`), and `deletion_batch_id`. A cascade
soft-delete stamps a parent and all its descendants with the same
`deletion_batch_id` so a single restore brings them all back
atomically.

The query filter lives in
[`backend/app/db._filter_soft_deleted`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/db.py): a
SQLAlchemy `do_orm_execute` listener injects `deleted_at IS NULL` into
every SELECT touching a soft-delete model, unless the caller opts in
with `execution_options(include_deleted=True)`.

Models carrying `SoftDeleteMixin`:

| Model | Table |
|---|---|
| `IPSpace`, `IPBlock`, `Subnet` | `ip_space`, `ip_block`, `subnet` |
| `DNSZone`, `DNSRecord` | `dns_zone`, `dns_record` |
| `DHCPScope`, `DHCPPool`, `DHCPStaticAssignment` | `dhcp_scope`, `dhcp_pool`, `dhcp_static_assignment` |
| `Customer` | `customer` |
| `Circuit` | `circuit` |
| `NetworkService` | `network_service` |
| `OverlayNetwork` | `overlay_network` |

`IPAddress` is **not** soft-deletable — it has its own `orphan` status
in the lifecycle instead.

### Fernet-encrypted secrets

Credentials at rest (bind passwords, API keys, client secrets, agent
keys, TSIG secrets, driver admin creds, integration tokens) are
Fernet-encrypted via
[`backend/app/core/crypto.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/core/crypto.py)
(`encrypt_str` / `decrypt_str`, AES-128-CBC + HMAC-SHA256 keyed from
`CREDENTIAL_ENCRYPTION_KEY`). The convention is a `LargeBinary` column
named `*_encrypted` (or `secrets_encrypted` for a JSONB blob of
secrets). API responses never return the plaintext — they expose a
boolean such as `eab_hmac_set` / `fingerbank_api_key_set` instead, and a
password-gated reveal endpoint handles the rare "show me the value
once" case.

Models with encrypted columns include `AuthProvider`
(`secrets_encrypted`), `DNSServerGroup` (TSIG), `DNSServer`
(`api_key_encrypted`, `credentials_encrypted`), the integration mirror
tables (`KubernetesCluster`, `DockerHost`, `ProxmoxNode`,
`TailscaleTenant`, `UnifiController`, `CloudEndpoint`, `OPNsenseRouter`),
`AIProvider`, `BackupTarget`, `AuditForwardTarget`, `EventSubscription`,
`PlatformSettings`, `TLSCertTarget`, and the ACME client account. Public
certs (e.g. a Kubernetes CA bundle) are stored cleartext — they're not
secrets.

### Multi-source provenance

Rows that can be created by an importer or a read-only integration
reconciler carry provenance columns so re-runs are idempotent and
operators can tell hand-authored rows from mirrored ones. Common shapes:
`import_source` + `imported_at` (NetBox / DNS / DHCP importers), and the
integration FKs described in §5. `IPAddress.status` distinguishes
operator-settable lifecycle values
(`IP_STATUSES_OPERATOR_SETTABLE`) from integration-owned ones
(`IP_STATUSES_INTEGRATION_OWNED`); an operator override stamps
`user_modified_at` and locks the row from future reconciler overwrites.

---

## 2. IPAM — the address-space tree

Files: [`ipam.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/ipam.py),
[`vlans.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/vlans.py),
[`vrf.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/vrf.py),
[`multicast.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/multicast.py). Feature spec:
[IPAM.md](features/IPAM.md).

The core hierarchy is a strict containment tree:

<p align="center">
  <img src="assets/diagrams/data-model-ipam.svg" alt="IPAM data model — the address-space containment tree" width="900"/>
</p>

| Model | Table | Key FKs |
|---|---|---|
| `IPSpace` | `ip_space` | optional `vrf_id`, `asn_id`, `customer_id`, `dhcp_server_group_id` (all `SET NULL`) |
| `IPBlock` | `ip_block` | `space_id` (`CASCADE`), `parent_block_id` → self (`CASCADE`), optional `vrf_id` / `asn_id` / `customer_id` / `site_id` / `ipam_template_id` |
| `Subnet` | `subnet` | `space_id` (`RESTRICT`), `block_id` (`RESTRICT`), `router_zone_id` / `vlan_ref_id` (`SET NULL`) |
| `IPAddress` | `ip_address` | `subnet_id` (`CASCADE`); optional `dns_zone_id` / `dns_record_id` (`SET NULL`), `nmap_scan_id` |

Notes:

- `IPSpace.is_default` flags a single "simplified deployment" space.
- Block ↔ subnet overlap is enforced at the application layer using the
  PostgreSQL `cidr &&` operator (see IPAM.md); `IPAddress` is unique per
  `(subnet_id, address)`.
- `Subnet.kind` is a discriminator: `unicast` (default) vs `multicast`.
  IP-allocation endpoints refuse on `multicast` subnets — multicast
  stream identities are tracked by `MulticastGroup`, not per-endpoint
  `IPAddress` rows.
- The `RESTRICT` on `Subnet.space_id` / `block_id` is intentional: you
  can't delete a space or block out from under live subnets.

Supporting IPAM tables:

| Model | Table | Purpose |
|---|---|---|
| `RouterZone` | `router_zone` | named L3 zone a subnet can sit in |
| `SubnetDomain` | `subnet_domain` | many-to-many subnet ↔ DNS zone (`subnet_id`, `dns_zone_id`, both `CASCADE`) |
| `CustomFieldDefinition` | `custom_field_definition` | per-resource-type custom field schema |
| `NATMapping` | `nat_mapping` | inside ↔ outside IP/subnet mapping |
| `SubnetPlan` | `subnet_plan` | saved multi-level CIDR design (planner workspace) |
| `IPAMTemplate` | `ipam_template` | reusable stamp template with optional child layout |
| `SubnetUtilizationHistory` | `subnet_utilization_history` | append-only per-subnet utilization samples |
| `IpMacHistory` | `ip_mac_history` | observed IP ↔ MAC sightings (arpwatch-style) |
| `MACAllowlist` | `mac_allowlist` | known-MAC allowlist for new-device detection |

### VLAN / VXLAN

VLANs live under a `Router` (the L3 device that owns them), distinct
from the `VLANMapping` VLAN→VXLAN reference table:

| Model | Table | Key FKs / constraints |
|---|---|---|
| `Router` | `router` | unique `name`; optional `local_asn_id` (`SET NULL`) |
| `VLAN` | `vlan` | `router_id` (`CASCADE`); unique `(router_id, vlan_id)` and `(router_id, name)` |
| `VLANMapping` | `vlan_mapping` | `space_id` (`CASCADE`); unique `(space_id, vlan_id)`; optional `vxlan_id` |

`Subnet.vlan_ref_id` → `VLAN` ties a subnet to a defined VLAN.

### Multicast

`multicast.py` adds `MulticastDomain` (PIM domain registry with
scope-boundary CIDRs + RP set), `MulticastGroup` (a group address /
stream identity), `MulticastGroupPort`, and `MulticastMembership`
(observed IGMP listeners).

---

## 3. DNS

File: [`dns.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/dns.py). Feature spec:
[DNS.md](features/DNS.md). Drivers:
[DNS_DRIVERS.md](drivers/DNS_DRIVERS.md).

The DNS hierarchy is group-centric — configuration lives on the group,
servers are members, zones and records hang off the group:

<p align="center">
  <img src="assets/diagrams/data-model-dns.svg" alt="DNS data model — the group-centric hierarchy" width="900"/>
</p>

| Model | Table | Key FKs |
|---|---|---|
| `DNSServerGroup` | `dns_server_group` | — (unique `name`); TSIG secret encrypted |
| `DNSServer` | `dns_server` | `group_id` (`CASCADE`), optional `appliance_id` (`CASCADE`); `api_key_encrypted`, `credentials_encrypted` |
| `DNSView` | `dns_view` | `group_id` (`CASCADE`); unique `(group_id, name)` |
| `DNSZone` | `dns_zone` | `group_id` (`CASCADE`), optional `view_id` (`SET NULL`), `subnet_id` / `domain_id` / `customer_id` (`SET NULL`); unique `(group_id, view_id, name)` |
| `DNSRecord` | `dns_record` | `zone_id` (`CASCADE`), optional `view_id` (`SET NULL`), `ip_address_id` (`SET NULL`), `pool_member_id` |
| `DNSPool` | `dns_pool` | `group_id` + `zone_id` (`CASCADE`); unique `(zone_id, record_name)` |
| `DNSPoolMember` | `dns_pool_member` | `pool_id` (`CASCADE`) |

`DNSPool` members render as ordinary `DNSRecord` rows with
`pool_member_id` set (one per healthy + enabled member), so the
underlying driver renders unchanged; a health-check task flips members in
and out of the rendered set.

Supporting / config tables:

| Model | Table | Notes |
|---|---|---|
| `DNSServerOptions` | `dns_server_options` | group/server-level resolver + RRL tuning |
| `DNSServerZoneState` | `dns_server_zone_state` | per-(server, zone) reported SOA serial → drift pill |
| `DNSServerRuntimeState` | `dns_server_runtime_state` | latest agent-reported runtime status |
| `DNSRecordOp` | `dns_record_op` | queued per-server record op (the propagation chokepoint) |
| `DNSAcl` / `DNSAclEntry` | `dns_acl` / `dns_acl_entry` | named address-match lists |
| `DNSTSIGKey` | `dns_tsig_key` | named operator-managed TSIG key (Fernet secret) |
| `DNSTrustAnchor` | `dns_trust_anchor` | DNSSEC trust anchors |
| `DNSSECPolicy` / `DNSKey` | `dnssec_policy` / `dnssec_key` | inline-signing policy + key material |
| `DNSBlockList` | `dns_blocklist` | backend-neutral RPZ blocklist |
| `DNSBlockListEntry` | `dns_blocklist_entry` | one blocked domain (`blocklist_id` `CASCADE`) |
| `DNSBlockListException` | `dns_blocklist_exception` | passthru exception |

---

## 4. DHCP

File: [`dhcp.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/dhcp.py). Feature spec:
[DHCP.md](features/DHCP.md). Drivers:
[DHCP_DRIVERS.md](drivers/DHCP_DRIVERS.md).

Like DNS, DHCP is group-centric: scopes / pools / statics / classes live
on the **group**, not on individual servers (a 2-member Kea group is an
HA pair). Leases are per-server because each Kea instance owns its own
memfile.

<p align="center">
  <img src="assets/diagrams/data-model-dhcp.svg" alt="DHCP data model — the group-centric hierarchy" width="900"/>
</p>

| Model | Table | Key FKs / constraints |
|---|---|---|
| `DHCPServerGroup` | `dhcp_server_group` | unique `name` |
| `DHCPServer` | `dhcp_server` | `group_id` (`SET NULL`), optional `appliance_id` (`CASCADE`); unique `name`; unique `agent_id` |
| `DHCPScope` | `dhcp_scope` | `group_id` + `subnet_id` (`CASCADE`); unique `(group_id, subnet_id)`; optional `pxe_profile_id` (`SET NULL`) |
| `DHCPPool` | `dhcp_pool` | `scope_id` (`CASCADE`) |
| `DHCPStaticAssignment` | `dhcp_static_assignment` | `scope_id` (`CASCADE`); unique `(scope_id, mac_address)` and `(scope_id, ip_address)` |
| `DHCPClientClass` | `dhcp_client_class` | `group_id` (`CASCADE`); unique `(group_id, name)` |
| `DHCPLease` | `dhcp_lease` | `server_id` (`CASCADE`), `scope_id` (`SET NULL`) |

Supporting tables:

| Model | Table | Purpose |
|---|---|---|
| `DHCPOptionTemplate` | `dhcp_option_template` | named group-scoped reusable option set |
| `DHCPMACBlock` | `dhcp_mac_block` | MAC blocklist |
| `DHCPLeaseHistory` | `dhcp_lease_history` | append-only lease event history |
| `DHCPConfigOp` (alias `DHCPRecordOp`) | `dhcp_config_op` | queued agent config / record ops (`DHCPRecordOp` is a Python alias of the same class) |
| `DHCPPXEProfile` / `DHCPPXEArchMatch` | `dhcp_pxe_profile` / `dhcp_pxe_arch_match` | PXE / iPXE per-arch provisioning |
| `DHCPPhoneProfile` / `DHCPPhoneProfileScope` | `dhcp_phone_profile` / `dhcp_phone_profile_scope` | VoIP phone option profiles |
| `DHCPObservedResponder` / `DHCPResponderAllowlist` | `dhcp_observed_responder` / `dhcp_responder_allowlist` | rogue-DHCP detection |
| `DHCPFingerprint` | `dhcp_fingerprint` | passive fingerprint records (`dhcp_fingerprint.py`) |

---

## 5. Network modeling

Logical ownership + WAN/service modeling overlaid on the IPAM/DNS/DHCP
core. Files:
[`asn.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/asn.py),
[`vrf.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/vrf.py),
[`domain.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/domain.py),
[`ownership.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/ownership.py),
[`circuit.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/circuit.py),
[`network_service.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/network_service.py),
[`overlay.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/overlay.py),
[`network.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/network.py),
[`bgp_looking_glass.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/bgp_looking_glass.py).

| Model | Table | Notes |
|---|---|---|
| `ASN` | `asn` | `BigInteger number` (full 32-bit range); derived `kind` + `registry` |
| `ASNRpkiRoa` | `asn_rpki_roa` | RPKI ROAs pulled per-ASN |
| `BGPPeering` | `bgp_peering` | peer / customer / provider / sibling relationships |
| `BGPCommunity` | `bgp_community` | well-known + per-AS community catalog |
| `LookingGlassCollector` | `looking_glass_collector` | BGP Looking Glass — receive-only GoBGP collector daemon (#566); agent-registered like `DNSServer`; `appliance_id` (`CASCADE`) |
| `BGPLGPeer` | `bgp_lg_peer` | configured receive-only BGP session; `collector_id` (`CASCADE`); Fernet TCP-MD5 (`md5_password_encrypted`); `max_prefixes` cap + collector-reported runtime state (`session_state` / `down_since`) |
| `BGPLGRoute` | `bgp_lg_route` | learned Adj-RIB-In route; absence-reconcile sets `withdrawn_at` (never hard-delete); identity `(peer, prefix, next_hop, route_distinguisher)`; `matched_*_id` IPAM/ASN/VRF links (`SET NULL`); `rpki_status` |
| `VRF` | `vrf` | routing/forwarding domain; optional `asn_id` (`SET NULL`) |
| `Domain` | `domain` | registered domain (registrar / expiry / NS / DNSSEC) — distinct from `DNSZone` |
| `Customer` | `customer` | logical owner; soft-deletable |
| `Site` | `site` | physical location; hierarchical via `parent_site_id` (`SET NULL`) |
| `Provider` | `provider` | upstream/carrier org; optional `default_asn_id` (`SET NULL`) |
| `Circuit` | `circuit` | carrier WAN circuit; soft-deletable (`status='decom'`) |
| `NetworkService` | `network_service` | per-customer deliverable; soft-deletable |
| `NetworkServiceResource` | `network_service_resource` | polymorphic join `service → (VRF/Subnet/IPBlock/DNSZone/DHCPScope/Circuit/Site/OverlayNetwork)` |
| `OverlayNetwork` | `overlay_network` | SD-WAN/IPsec/WireGuard/VXLAN overlay; soft-deletable |
| `OverlaySite` | `overlay_site` | overlay ↔ site membership with role + preferred-circuit chain |
| `RoutingPolicy` | `routing_policy` | overlay traffic policy |
| `ApplicationCategory` | `application_category` | curated SaaS app catalog |

Cross-reference pattern: the ownership entities (`Customer`, `Site`,
`Provider`) and the modeling entities (`VRF`, `ASN`) are linked into the
IPAM/DNS/DHCP tables via nullable FKs with `ON DELETE SET NULL` (e.g.
`IPSpace.customer_id`, `IPBlock.site_id`, `DNSZone.customer_id`,
`Subnet.site_id`). Deleting an owner therefore detaches resources rather
than cascading their deletion.

`NetworkServiceResource.resource_id` is **not** a real FK — it's a
polymorphic pointer (`resource_kind` + `resource_id`) validated at attach
time, with a `service_resource_orphaned` alert sweeping for stale rows
when a target is later deleted. The triple
`(service_id, resource_kind, resource_id)` is unique.

The `network.py` file holds discovery-side tables: `NetworkDevice`,
`NetworkInterface`, `NetworkArpEntry`, `NetworkFdbEntry`,
`NetworkNeighbour` (SNMP/ARP/FDB/LLDP poll results).

---

## 6. Auth + RBAC

File: [`auth.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/auth.py),
[`auth_provider.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/auth_provider.py),
[`time_bound_grant.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/time_bound_grant.py).
Permission grammar: [PERMISSIONS.md](PERMISSIONS.md).

<p align="center">
  <img src="assets/diagrams/data-model-rbac.svg" alt="Auth and RBAC — the permission chain" width="900"/>
</p>

| Model | Table | Notes |
|---|---|---|
| `User` | `user` | unique `username` / `email`; nullable `hashed_password` (external-auth users) |
| `Group` | `group` | membership container |
| `Role` | `role` | `is_builtin` flag; `permissions` JSONB (`{action, resource_type, resource_id?}`) |
| `APIToken` | `api_token` | hashed token; `scope`, `allowed_paths`, coarse `scopes`; `user_id` (`CASCADE`), `created_by_user_id` (`RESTRICT`) |
| `UserSession` | `user_session` | active session rows |
| `AuthProvider` | `auth_provider` | LDAP / OIDC / SAML / RADIUS / TACACS+ config; `secrets_encrypted` |
| `AuthGroupMapping` | `auth_group_mapping` | external-group → SpatiumDDI-group mapping |
| `TimeBoundGrant` | `time_bound_grant` | temporary permission grant (issue #65) |

Association tables `user_group` and `group_role` are plain
`Table(...)` many-to-many links with composite PKs and `CASCADE` on both
sides. Permissions are stored as a JSONB list on `Role` rather than a
relational join — wildcard `*` for action and resource_type is
supported, and `resource_id` scopes a permission to one resource.
`Role.is_builtin` marks the seeded roles (Superadmin, Viewer, IPAM/DNS/
DHCP Editor, Auditor, Compliance Editor, Change Approver) that the
startup path keeps in sync.

---

## 7. Integration mirrors

Read-only pull reconcilers, each one a `*` endpoint/target row with
connection config + `enabled` + `last_synced_at` / `last_sync_error`,
and Fernet-encrypted credentials. The reconcilers stamp `IPAddress` (and
some `IPBlock` / `Subnet`) rows tagged with an integration-owned status
and an FK back to the source endpoint (`ON DELETE CASCADE`, so deleting
an endpoint cleans up its mirrored rows).

| Model | Table | Mirrors |
|---|---|---|
| `KubernetesCluster` | `kubernetes_cluster` | nodes / services / LB IPs |
| `DockerHost` | `docker_host` | container network IPs |
| `ProxmoxNode` | `proxmox_node` | bridges / SDN VNets / guest IPs |
| `TailscaleTenant` | `tailscale_tenant` | tailnet device IPs |
| `UnifiController` | `unifi_controller` | UniFi networks + clients |
| `CloudEndpoint` | `cloud_endpoint` | AWS / Azure / GCP instance / public / LB IPs |
| `OPNsenseRouter` | `opnsense_router` | interface + DHCP + ARP-table state |

The reconciler FKs live on the IPAM rows: e.g.
`IPAddress.kubernetes_cluster_id`, `docker_host_id`, `proxmox_node_id`,
`tailscale_tenant_id`, `unifi_controller_id`, `cloud_endpoint_id`,
`opnsense_router_id` (all `CASCADE`), with parallel columns on `IPBlock`
and `Subnet` where the mirror creates structure.

The NetBox importer (`models` provenance columns, not a continuous
mirror) and the cloud DNS drivers are documented in
[MIGRATION.md](features/MIGRATION.md) and
[INTEGRATIONS.md](features/INTEGRATIONS.md).

---

## 8. Appliance + fleet

File: [`appliance.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/appliance.py). Deployment:
[DNS_AGENT.md](deployment/DNS_AGENT.md).

| Model | Table | Notes |
|---|---|---|
| `Appliance` | `appliance` | one row per supervisor; `public_key_fingerprint` unique; `pending_approval` → `approved` / `rejected`; `role_health` JSONB; `firewall_state` JSONB (`{}` = healthy; set when the supervisor refuses a firewall drop-in that would partition a live etcd member — #593); `cluster_join_state_at` timestamp gating the `clear-cluster-state` escape hatch (#590) |
| `ApplianceCA` | `appliance_ca` | internal CA (RSA root) for signing supervisor certs |
| `ApplianceCertificate` | `appliance_certificate` | Web UI TLS cert storage + deploy state |
| `ApplianceUpgradeImage` | `appliance_upgrade_image` | uploaded A/B slot image metadata |
| `PairingCode` | `pairing_code` | single-use or persistent join code; stored sha256, cleartext shown once |
| `PairingClaim` | `pairing_claim` | one row per (code, supervisor) successful claim |

`DNSServer.appliance_id` and `DHCPServer.appliance_id` (`ON DELETE
CASCADE`) tie managed service rows back to the supervisor that runs
them, so deleting an appliance cascades to the servers it hosted. The
pairing-code FK on `Appliance` is `SET NULL` so the code reaper can sweep
terminal codes without taking down the appliances they provisioned.

System-upgrade state lives in
[`system_upgrade.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/system_upgrade.py)
(`SystemUpgradeRun`, table `system_upgrade_run`).

---

## 9. Compliance + governance

Files: [`conformity.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/conformity.py),
[`alerts.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/alerts.py),
[`change_request.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/change_request.py).

| Model | Table | Notes |
|---|---|---|
| `ConformityPolicy` | `conformity_policy` | declarative check + `target_filter` JSONB predicate |
| `ConformityResult` | `conformity_result` | append-only; one row per (policy, resource) per pass; no `modified_at` |
| `AlertRule` | `alert_rule` | operator-authored alert definition |
| `AlertEvent` | `alert_event` | one firing per subject; open while condition matches, closed on a later clear |
| `ChangeRequest` | `change_request` | risky operation queued for second-person approval (#62) **and** self-service provisioning requests (#696), discriminated by `origin` |
| `ApprovalPolicy` | `approval_policy` | rule deciding whether an operation needs approval |

A `ConformityPolicy` pass→fail transition can emit an `AlertEvent`
against the policy's wired `AlertRule`. The two-person-rule governance
flow (default-off `governance.approvals` module) gates the six delete
handlers through `ChangeRequest` + `ApprovalPolicy`.

`change_request` carries **both** governance flows, split by `origin`:

| `origin` | Surface | Direction | Approving… |
|---|---|---|---|
| `gate` (default) | `/change-requests` — #62 | a permitted operator's risky action is intercepted | *unblocks* the delete |
| `portal` | `/requests` — #696 | a low-privilege user asks for something they cannot do | *provisions* the resource |

One table and one state machine on purpose: the lifecycle, the approver
checks (approver ≠ requester, approver holds the operation's own
permission), the re-preview stale guard, the execution under the
approver's identity, the audit rows and the expiry sweep are identical
for both. Only the direction of privilege differs. Every query on either
surface filters by `origin`, so neither queue ever renders the other's
rows. `justification` is the requester's free-text "why" and is NULL on
gate rows, which carry the policy-derived `risk_reason` instead.

---

## 10. Observability + audit

Files: [`audit.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/audit.py),
[`logs.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/logs.py),
[`metrics.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/metrics.py),
[`event_subscription.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/event_subscription.py),
[`audit_forward.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/audit_forward.py),
[`diagnostics.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/models/diagnostics.py). Spec:
[OBSERVABILITY.md](OBSERVABILITY.md).

### Audit log (append-only + hash chain)

`AuditLog` (table `audit_log`) is the append-only record of every
mutation. It is **never** updated or deleted application-side, and
DB-level row triggers refuse both as a second guard: `audit_log_no_delete`
(`BEFORE DELETE`, issue #73) and `audit_log_no_update` (`BEFORE UPDATE`,
issue #2315). `TRUNCATE` is not guarded, since the selective restore of
the `audit` section truncates the table before reloading it.

This makes the table **tamper-evident, not tamper-proof**: the database
owner can disable or drop a trigger. The built-in conformity policy
"Audit log is reachable and append-only" (check `audit_log_immutable`)
reads `pg_trigger` and fails, naming the trigger, when either guard is
missing, disabled, or altered. A migration that ever has to rewrite rows
must disable `audit_log_no_update` for its duration.

Tamper-evidence is a hash chain: each row carries a monotonic
`BigInteger seq` (assigned from `audit_log_seq_seq`), a `row_hash`, and a
`prev_hash` pointing at the previous row's hash. The hash is computed in
[`app.services.audit_chain`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/audit_chain.py) via
a SQLAlchemy `before_flush` listener that takes a Postgres advisory lock
to serialize "look up previous row → hash → append", so concurrent
inserts can't interleave and break the chain. `prev_hash` is NULL only on
the first row. A nightly `verify_chain` task re-walks and validates it.

Each row records *who* (`user_id`, `user_display_name`, `auth_source`,
`source_ip`, `user_agent`), *what* (`action`, `resource_type`,
`resource_id`, `resource_display`), the *state change*
(`old_value` / `new_value` / `changed_fields` JSONB), correlation
(`request_id`), and the `result` (`success` / `denied` / `error`).

### Log entries, metrics, events

| Model | Table | Notes |
|---|---|---|
| `DNSQueryLogEntry` | `dns_query_log_entry` | parsed BIND9 query log lines (24h retention) |
| `DHCPLogEntry` | `dhcp_log_entry` | parsed Kea `kea-dhcp4.log` lines |
| `DNSMetricSample` | `dns_metric_sample` | composite PK `(server_id, bucket_at)`; query/response counters |
| `DHCPMetricSample` | `dhcp_metric_sample` | composite PK `(server_id, bucket_at)`; DHCP message counters |
| `EventSubscription` | `event_subscription` | one downstream webhook receiver (HMAC-signed) |
| `EventOutbox` | `event_outbox` | one delivery attempt: pending / in-flight / delivered / failed / dead; `subscription_id` (`CASCADE`) |
| `AuditForwardTarget` | `audit_forward_target` | SIEM / syslog forward destination |
| `InternalError` | `internal_error` | captured unhandled exceptions for the diagnostics surface |

The log-entry and metric-sample tables are append-only operator-triage
data (short retention) — longer history belongs in Loki / Prometheus per
OBSERVABILITY.md, not these tables.

---

## 11. Platform + miscellaneous

| Model | Table | File | Purpose |
|---|---|---|---|
| `PlatformSettings` | `platform_settings` | `settings.py` | singleton global config (DNS auto-sync, SNMP, NTP, timezone, device profiling, …) |
| `FeatureModule` | `feature_module` | `feature_module.py` | togglable feature catalog; dotted-string PK |
| `BackupTarget` | `backup_target` | `backup.py` | remote backup destination config |
| `SavedView` | `saved_view` | `saved_view.py` | per-user saved list view |
| `AIProvider` / `AIChatSession` / `AIChatMessage` | `ai.py` | Operator Copilot LLM provider + chat history |
| `OUIVendor` | `oui_vendor` | `oui.py` | MAC OUI → vendor lookup table |
| `NmapScan` / `PacketCapture` | `nmap.py` / `pcap.py` | on-demand scan / capture job rows |
| `WolSchedule` / `WolRun` / `WolRunTarget` | `wol_schedule` / `wol_run` / `wol_run_target` | `wol_schedule.py` | Scheduled Wake-on-LAN (#586) — recurring cron/tag-targeted job + per-fire run history + per-host outcome. `wol_schedule.verify_method` picks the liveness source (`ping` / `tcp` / `seen` / `auto`, #596). `wol_run.verify_params` (JSONB, nullable) is the per-run verify+re-wake config snapshot for ad-hoc runs (`schedule_id IS NULL`, `trigger='adhoc'`), which have no parent schedule row to read it from; NULL on scheduled runs. `wol_schedule.verify_alert_enabled` mutes the `wol_wake_failed` alert per schedule; `wol_run_target.verify_evidence` (JSONB, nullable) is the ordered trail of every liveness source consulted on the final pass |
| `WolCalendar` / `WolCalendarEvent` | `wol_calendar` / `wol_calendar_event` | `wol_schedule.py` | subscribed iCal/CalDAV calendar (Fernet password) whose flattened all-day spans gate scheduled wakes |
| `TLSCertTarget` / `TLSCertProbe` | `tls_cert.py` | cert-expiry monitoring targets + probe results |
| `FirewallPolicy` / `FirewallRule` / `FirewallAlias` / `FirewallApplyState` | `firewall.py` | per-appliance host firewall config |
| `ACMEAccount` | `acme.py` | ACME DNS-01 *provider* account |
| `ACMEClientAccount` / `ACMEOrder` / `ACMEHTTPChallenge` | `acme_client.py` | embedded ACME *client* (Let's Encrypt Web UI cert) |
| `AddressSet` | `address_set.py` | named range within a subnet with its own RBAC scope (`subnet_id` `CASCADE`) |

A `feature_module` row defaults to `enabled=true` (server default) and is
seeded by Alembic alongside its feature's model migration; the router
include and MCP tools gate on it.

---

## See also

- [IPAM.md](features/IPAM.md) — address-space management behaviour
- [DNS.md](features/DNS.md) — zones, records, views, pools, blocklists
- [DHCP.md](features/DHCP.md) — scopes, pools, statics, leases, HA
- [PERMISSIONS.md](PERMISSIONS.md) — the `{action, resource_type, resource_id?}` grammar
- [OBSERVABILITY.md](OBSERVABILITY.md) — audit chain, logging, metrics, alerting
- [`backend/alembic/`](https://github.com/spatiumnorth/spatiumddi/tree/main/backend/alembic) — the deployed schema, migration by migration
