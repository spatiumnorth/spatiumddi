---
layout: default
title: Integrations
nav_order: 8
---

# Integrations

SpatiumDDI mirrors network state from external systems into IPAM (and optionally DNS) so operators don't have to double-enter inventory. Every integration is **read-only** — SpatiumDDI never writes back to the source system. This doc covers the shared pattern and the specific integrations available today.

---

## The shared shape

Every integration follows the same reconciler pattern:

1. **Per-integration enable toggle** on Settings → Integrations. Turning the toggle on:
   - Lights up a sidebar nav item.
   - Starts a 30 s Celery beat sweep that iterates every registered target.
2. **Per-target rows** (one `KubernetesCluster` / `DockerHost` / future `*Target` per external system) bound to:
   - Exactly one **IPAM space** (required — mirrored CIDRs and addresses land here).
   - Optionally one **DNS server group** (for any DNS records the integration emits).
3. **Per-target `sync_interval_seconds`** gates the actual reconcile pass (minimum 30 s). A target configured for 5 minutes sees 10 beat ticks between passes.
4. **Sync Now** button per target fires the reconciler on demand, bypassing the interval gate.
5. **Provenance FK** on every mirrored row (`kubernetes_cluster_id`, `docker_host_id`, …) with `ON DELETE CASCADE` so removing a target sweeps every row it created.
6. **Status surfacing** — each target row carries `last_synced_at` + `last_sync_error`. Dashboard folds these into a green / amber / red dot on the Integrations panel.
7. **Legal host names** (#1459) — an address's hostname is copied from an upstream name (a UniFi client alias, a VM name, a Meraki client description). A name that is already a legal host name is kept as written. Anything else is folded before it reaches IPAM, so the record IPAM's DNS sync publishes is one the DNS servers accept: umlauts spelled out, accents and apostrophes dropped, other characters outside letters / digits / hyphens turned into `-`, lower-cased (`Sonos Büro` → `sonos-buero`). The upstream name is kept at the end of the address's description (`… — name: Sonos Büro`). Two devices with the same upstream name still get the same hostname.
8. **Smart parent-block detection** — when a mirrored CIDR is an RFC 1918 or CGNAT range (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`) and no enclosing operator block exists in the target space, the reconciler auto-creates the canonical private supernet as an **unowned** top-level block. Unowned = no integration FK, so it survives removal of the integration and can be shared with manual allocations.

---

## Kubernetes

**Phase status**: 1a + 1b shipped. Phase 2 (external-dns webhook) deferred.

Per-cluster config (`KubernetesCluster` rows):

| Field | Notes |
|---|---|
| `api_server_url` | e.g. `https://1.2.3.4:6443` |
| `ca_bundle_pem` | Optional — system CA store used when empty (cloud-managed clusters) |
| `token` | Bearer token, Fernet-encrypted at rest |
| `pod_cidr` + `service_cidr` | Auto-detected from cluster state if omitted; operator-entered otherwise |
| `ipam_space_id` | Required |
| `dns_group_id` | Optional — zone matching for Ingress → DNS is disabled when null |
| `mirror_pods` | Default off — pod IPs churn, CIDR-as-IPBlock is the value |

### Mirror semantics

- **Pod CIDR + Service CIDR** → one `IPBlock` each under the bound space.
- **Nodes** → `IPAddress` with `status="kubernetes-node"`, hostname = node name, IP = `InternalIP`.
- **Services** of type `LoadBalancer` with a populated VIP → `IPAddress` with `status="kubernetes-lb"`, hostname = `<svc>.<ns>`.
- **Service ClusterIPs** → `IPAddress` with `status="kubernetes-service"`, hostname = `<svc>.<ns>.svc.cluster.local`.
- **Ingresses** with `status.loadBalancer.ingress[0].ip` → A record per `rules[].host` in the longest-suffix-matching zone in the bound DNS group. `ingress[0].hostname` (cloud LBs) → CNAME. `auto_generated=True` + fixed 300 s TTL.
- **Pods** (opt-in) → `IPAddress` per pod with `status="kubernetes-pod"`.

**Delete semantics**: removed cluster objects immediately drop their mirror rows (not orphaned). Deleting the cluster itself cascades every mirror via the FK.

### Setup

Admin page at `/kubernetes` ships a complete setup guide (expand the **Setup Guide** dropdown when creating or editing a cluster) with copy-paste YAML for:

- Namespace
- ServiceAccount
- ClusterRole (read-only — `nodes`, `services`, `ingresses`, `pods`, `endpoints`, `namespaces`)
- ClusterRoleBinding
- Secret (token-typed ServiceAccount token)

Plus the exact `kubectl` commands to extract the bearer token + CA bundle. **Test Connection** probes `/version` + `/api/v1/nodes` and distinguishes 401 / 403 / TLS / network errors with human-readable messages.

---

## Docker

**Phase status**: 1a + 1b shipped. Phase 2 (rich per-host management surface — container actions, logs, shell, compose up/down) placeholder.

Per-host config (`DockerHost` rows):

| Field | Notes |
|---|---|
| `connection_type` | `unix` or `tcp` (SSH deferred) |
| `endpoint` | `/var/run/docker.sock` (unix) or `tcp://host:2376` (tcp+TLS) |
| `ca_bundle_pem` + `client_cert_pem` + `client_key_pem` | TCP+TLS only. Client key Fernet-encrypted at rest |
| `ipam_space_id` | Required |
| `dns_group_id` | Optional |
| `mirror_containers` | Default off |
| `include_default_networks` | Default false — skip `bridge` / `host` / `none` / `docker_gwbridge` / `ingress` |
| `include_stopped_containers` | Default false |

Swarm overlay networks are **always skipped** regardless of the toggle — they're cluster-wide and mirroring them from every node would duplicate rows.

### Mirror semantics

- **Networks** with a CIDR → `Subnet` (nested under the enclosing block, or the auto-created RFC 1918 supernet if none exists).
- **Network gateway** → one `reserved`-status `IPAddress` per subnet, so the subnet looks like a normal LAN.
- **Containers** (opt-in) → `IPAddress` per `(container × connected network)` with `status="docker-container"`. Hostname comes from either:
  - `com.docker.compose.project` + `com.docker.compose.service` labels → `<project>.<service>`, or
  - Container name (when Compose labels are absent).

### Unix socket permissions

When using `connection_type=unix`, the api + worker containers need read access to the host's `/var/run/docker.sock`. Both `docker-compose.yml` and `docker-compose.dev.yml` ship commented-out `volumes` + `group_add` blocks on the api and worker services — uncomment them and set `DOCKER_GID` in your `.env` to match the host socket's group (`stat -c '%g' /var/run/docker.sock`).

---

## Proxmox VE

**Phase status**: 1a + 1b shipped. Phase 2 (per-VM management actions — start / stop / console / snapshot / migrate) deferred.

Per-endpoint config (`ProxmoxNode` rows):

| Field | Notes |
|---|---|
| `host` | Hostname or IP of **any** node in the cluster. PVE's REST API is homogeneous across members, so a single row covers a cluster. |
| `port` | Default `8006`. |
| `verify_tls` | Default `true`. Disable for self-signed labs, or paste the PVE CA bundle in the field below. |
| `ca_bundle_pem` | Optional. Trusted in addition to the system store when `verify_tls=true`. |
| `token_id` | Format `user@realm!tokenid` (e.g. `spatiumddi@pve!spatiumddi`). |
| `token_secret` | UUID printed by `pveum user token add`. Fernet-encrypted at rest. |
| `ipam_space_id` | Required. |
| `dns_group_id` | Optional. |
| `mirror_vms` | Default `true`. Turn off to mirror bridges only. |
| `mirror_lxc` | Default `true`. |
| `include_stopped` | Default `false`. |
| `infer_vnet_subnets` | Default `false`. When on, infer SDN VNet CIDRs from guest NICs for VNets that have no declared subnet — exact from `static_cidr`, speculative /24 from runtime IPs. |

### Mirror semantics

- **SDN VNets** (`/cluster/sdn/vnets/{vnet}/subnets`) → `Subnet` named `vnet:<vnet>`, gateway from the VNet subnet declaration. Operator-declared intent, authoritative over bridges that happen to carry the same CIDR. PVE without SDN installed returns 404 — the reconciler treats that as "no SDN" and keeps going; no error on the endpoint row.
- **VNet subnet inference** (opt-in via `infer_vnet_subnets`) — for VNets that exist but have no declared subnet, derive the CIDR from guests attached to the VNet. Priority: (1) exact `static_cidr` from `ipconfigN` / LXC `ip=`, gateway from `gw=`; (2) /24 guess around guest-agent runtime IPs, no gateway. The /24 path is speculative and logs a `proxmox_vnet_cidr_guessed` warning — declare subnets properly with `pvesh create /cluster/sdn/vnets/<vnet>/subnets --subnet <cidr> --gateway <ip> --type subnet` to replace guesses with exact values.
- **Bridges + VLAN interfaces with a CIDR** → `Subnet` under the enclosing operator block (or the auto-created RFC 1918 / CGNAT supernet). Bridges without a CIDR (common L2-only VM bridges, *and* every VLAN the PVE host doesn't terminate) are skipped to avoid empty-subnet noise — use SDN for those, or add the subnet in IPAM manually.
- **Bridge gateway IP** → one `reserved` `IPAddress` per subnet.
- **VM NICs** → `IPAddress` with `status="proxmox-vm"`, MAC from `netN` config. Runtime IP from the QEMU guest-agent (`/nodes/{n}/qemu/{vmid}/agent/network-get-interfaces`) when the agent is enabled + running; falls back to `ipconfigN`; NIC dropped when nothing resolves. Link-local + loopback filtered.
- **LXC NICs** → `IPAddress` with `status="proxmox-lxc"`, hostname = container hostname, MAC from `netN`. Runtime IP from `/nodes/{n}/lxc/{vmid}/interfaces`; falls back to the inline `ip=` on `netN`.

### Setup — minimum-privilege token

The admin page ships a copy-paste guide. TL;DR on any PVE node:

```sh
pveum useradd spatiumddi@pve --comment "SpatiumDDI read-only"
pveum aclmod / -user spatiumddi@pve -role PVEAuditor
pveum user token add spatiumddi@pve spatiumddi --privsep=0
```

The last command prints the `full-tokenid` (`spatiumddi@pve!spatiumddi`) + `value` (UUID). Paste those into the admin form's **Token ID** and **Token Secret** fields; hit **Test Connection** to verify.

`PVEAuditor` grants read-only ACLs across datacentre + SDN resources — enough for the endpoints this integration calls (`/version`, `/cluster/status`, `/cluster/sdn/vnets*`, `/nodes/*/{qemu,lxc,network}`) plus the per-guest agent / interfaces calls.

### Discovery modal

The reconciler writes a `last_discovery` JSONB snapshot on every successful sync containing category counters and a per-guest diagnostic list. The admin page exposes a magnifier-icon button on each endpoint row that opens the **Discovery** modal:

- **Counter pills** at the top: VM totals vs. agent reporting / not responding / off, LXC reporting / no IP, SDN VNets resolved vs. unresolved, subnets mirrored, addresses skipped because no subnet encloses the IP.
- **Filter tabs** — `Issues (N)` (default), `All (N)`, and one tab per issue code (`Agent not responding`, `Agent off`, `No IP`, `No NIC`, `Static only`).
- **Search box** — name / vmid / node / bridge substring match.
- **Per-row table** with agent-state pills, mirrored IP count split (`Na/Ms` = `N` from agent, `M` from static), and an inline operator-facing **hint** like "install qemu-guest-agent inside the VM: `apt install qemu-guest-agent && systemctl enable --now qemu-guest-agent`" or "Enable the QEMU agent on this VM in Options → QEMU Guest Agent".

The button is disabled until the endpoint has been synced at least once (nothing to show). Snapshot freshness matches `last_synced_at`; click **Sync Now** on the row to refresh.

---

## Tailscale

**Phase status**: 1 shipped (read-only device mirror). Phase 2 (synthetic `<tailnet>.ts.net` DNS surface backed by the same poll, optionally rendering a BIND9 forwarder zone for `100.100.100.100`) is on the roadmap.

Per-tenant config (`TailscaleTenant` rows):

| Field | Notes |
|---|---|
| `tailnet` | Tailnet slug from <https://login.tailscale.com/admin/settings/general>, or `-` for the API key's default tailnet (works for solo accounts and any PAT issued without an explicit tailnet override). |
| `api_key` | Personal-access token (`tskey-api-…`). Generate at <https://login.tailscale.com/admin/settings/keys>. Fernet-encrypted at rest; tokens carry the issuing user's permissions but SpatiumDDI only ever reads. |
| `ipam_space_id` | Required. The CGNAT IPv4 + IPv6 ULA blocks land here. |
| `dns_group_id` | Optional. Held for Phase 2 — unused today. |
| `cgnat_cidr` | Default `100.64.0.0/10` (Tailscale's standard CGNAT slice). Override only if your tailnet was provisioned with a custom slice. |
| `ipv6_cidr` | Default `fd7a:115c:a1e0::/48` (Tailscale's standard ULA prefix). |
| `skip_expired` | Default `true`. Skip devices whose Tailscale node-key has expired. The `0001-01-01T00:00:00Z` "never expires" sentinel is correctly treated as not-expired. |
| `sync_interval_seconds` | Default `60`. Floor `30`. Tailscale's documented rate limit is 100 req/min — 60 s default leaves plenty of headroom. |

### Mirror semantics

- **CGNAT IPv4 block + IPv6 ULA block** are auto-created under the bound space on first sync (one tenant-owned `IPBlock` each), with a single `Subnet` per block covering the whole slice. The tailnet is a flat overlay — no subdivision.
- **Devices** (`GET /api/v2/tailnet/{tn}/devices?fields=all`) → one `IPAddress` per `(device, address)` tuple under the matching subnet, with:
  - `status="tailscale-node"`, `hostname` = device FQDN (`<host>.<tailnet>.ts.net`).
  - `description` = `<os> <client_version> — <user>`.
  - `custom_fields` carry: `tailscale_id`, `tailscale_node_id`, `os`, `client_version`, `user`, `tags`, `authorized`, `last_seen`, `expires`, `key_expiry_disabled`, `update_available`, `advertised_routes`, `enabled_routes`. Empty / falsy fields are dropped to keep the JSON column compact.
- **MAC** is always null — Tailscale is an L3 overlay, no L2 addresses.
- **Tailnet domain** (`tailnet_domain` on the row) is auto-derived from the first device FQDN — no separate config field.

### Lock semantics

Same shape as Proxmox / Docker / Kubernetes:

- **Claim-on-existing**: pre-existing operator rows in the CGNAT block at desired Tailscale addresses get adopted (FK stamped) with `user_modified_at` set, locking the operator's hostname / description / status / mac from reconciler overwrites.
- **Skip-on-locked**: rows the operator has edited (`user_modified_at IS NOT NULL`) preserve their soft fields on every subsequent reconcile. The reconciler still updates `subnet_id` and the `custom_fields` JSON (since tailnet metadata like `last_seen` is most useful when fresh).
- **Un-claim-on-disappear**: locked rows whose upstream device is gone keep the operator's edits — the FK is released so the row appears as "manually managed", rather than being silently deleted.
- **Cross-integration safety**: rows already owned by Proxmox / Docker / Kubernetes are skipped with a warning rather than claimed.

### Setup

The admin page ships a copy-paste guide:

1. Open <https://login.tailscale.com/admin/settings/keys>, click **Generate API key…**.
2. Pick an expiry window (90 days minimum). Tailscale doesn't support non-expiring API keys.
3. Copy the printed value (`tskey-api-…`).
4. Open <https://login.tailscale.com/admin/settings/general> for the **Organization** slug — paste it into **Tailnet**, or leave the default `-` for solo / single-tailnet accounts.
5. Hit **Test Connection** to verify before save.

### Phase 2 — synthetic tailnet DNS surface

Shipped as Option 2 from the original plan (synthetic `DNSZone` materialised by the reconciler, not a `TailscaleDNSReadOnlyDriver`). Activates automatically when the tenant has `dns_group_id` bound; skipped silently otherwise.

**What it does.** Every reconcile pass:

1. Derives the tailnet domain from the first device FQDN (already cached on `TailscaleTenant.tailnet_domain`).
2. Upserts a `DNSZone` named `<tailnet>.ts.net.` in the bound DNS group, FK-stamped with `tailscale_tenant_id` + `is_auto_generated=True`.
3. Diffs the desired record set (one A or AAAA per device address) against the existing synthesised records — keyed on `(label, record_type, value)`. Adds new, deletes orphaned. No-ops when the device list is unchanged.
4. Stamps each record with `auto_generated=True` + `tailscale_tenant_id`. TTL = 300 s.

**Read-only enforcement.** API write paths (`PUT /zones/{id}`, `DELETE /zones/{id}`, record CRUD) return **422** with an explanatory message when `tailscale_tenant_id IS NOT NULL` on the target row. UI shows a cyan **Tailscale (read-only)** badge near the zone title and disables the Edit / Delete / Add Record buttons. The per-record lock badge differentiates `Tailscale` vs `IPAM` based on which integration owns the row.

**Conflict with operator zones.** If an operator has manually created `<tailnet>.ts.net` in the same group, the reconciler refuses to claim it (which would silently overwrite operator records every sync). The conflict is recorded as a `summary.warnings` entry visible in the audit log; the operator-managed zone is left untouched, and the IPAM mirror still runs to completion. To unblock Phase 2, the operator deletes their manual zone (or rebinds the tenant to a different DNS group).

**Filtering.** Devices skipped by the IPAM mirror (expired keys, no FQDN, foreign-tailnet FQDN) are also skipped here, so the DNS view stays consistent with the IPAM view.

**Bonus.** Records land in real `DNSRecord` rows — the existing BIND9 render path picks them up automatically. Non-Tailscale LAN clients can resolve `<host>.<tailnet>.ts.net` through SpatiumDDI's BIND9 with no forwarder plumbing.

### What's not done

- **Per-tenant zone-name override.** Auto-derived from the device FQDN today. Adding a `synthetic_zone_name` column would cover operators with custom split-DNS arrangements (e.g. publishing under `tailnet.internal`).
- **Subnet-router routes (`enabled_routes`) as first-class IPBlock rows** — currently surface only in `custom_fields`. Promoting them is straightforward but waits for an operator request.
- **Per-device management surface** (rename / expire / authorize / delete via the admin API write side) — outside scope of the read-only mirror; Phase 3 territory if it ever lands.

---

## NetBird (#603)

**Phase status**: 1 shipped (read-only peer mirror) + 2 shipped (synthetic mesh-domain DNS surface). Gated behind the `integrations.netbird` feature module (**default off** — Settings → Features).

NetBird is the Tailscale-shaped sibling — a managed WireGuard mesh overlay with a real REST management API, but self-hostable. One `NetbirdInstance` row per NetBird deployment (a management server + a personal-access token). Unlike Tailscale's fixed `api.tailscale.com` host, the management URL is operator-supplied, and NetBird peers carry a **single IPv4 overlay address** (no IPv6 ULA), so there is one overlay CIDR — not the CGNAT + ULA pair Tailscale mirrors.

Per-instance config (`NetbirdInstance` rows):

| Field | Notes |
|---|---|
| `api_url` | Management-server base URL. Cloud is `https://api.netbird.io`; a self-hosted install is the dashboard / management host (the API is served under `/api` on the same host — a trailing `/api` is stripped so either form works). Operator-supplied, so the **Test Connection** probe runs it through the advisory SSRF guard (`app.core.ssrf`) at the API boundary, as every operator-URL integration does. |
| `verify_tls` | Default `true`. Turn off for a self-hosted install behind a private-CA / self-signed cert. |
| `api_key` | Personal-access token (`nbp_…`), minted under **Settings → Users** in the NetBird dashboard. Fernet-encrypted at rest and **never returned** by the API — responses only carry an `api_key_present` boolean. Auth header is `Authorization: Token <key>` (NetBird's scheme — `Token`, not `Bearer`). SpatiumDDI only ever reads. |
| `ipam_space_id` | Required. The overlay block + subnet land here. |
| `dns_group_id` | Optional. Binding a group activates the Phase 2 synthetic zone; leave unset to run the IPAM mirror only. |
| `network_cidr` | Default `100.64.0.0/10` (NetBird allocates peer addresses from CGNAT space). Override if your management server is configured with a custom slice. Mirrored as **one flat subnet** — the mesh is a routed overlay, not a subdivided LAN. |
| `skip_expired` | Default `true`. Skips a peer only when the instance opts in **and** the peer actually has login-expiration enabled **and** it has expired — long-lived setup-key / service peers commonly disable expiration entirely. |
| `sync_interval_seconds` | Default `60`, floor `30`. Swept by `sweep_netbird_instances` on the shared 30 s beat tick, with per-instance interval gating. |

### Mirror semantics

- **Overlay block + subnet** are auto-created under the bound space on first sync (one instance-owned `IPBlock` + one `Subnet` covering the whole `network_cidr`). Routed-overlay semantics — no broadcast, every host address usable.
- **Peers** (`GET /api/peers` — one round-trip, no pagination) → one `IPAddress` per peer overlay `ip`, with:
  - `status="netbird-peer"`, `hostname` = the peer's FQDN from `dns_label` (falling back to the short `hostname` / `name` while a peer is still onboarding).
  - `description` = `<os> <version>`.
  - `custom_fields` carry: `netbird_id`, `os`, `version`, `hostname`, `dns_label`, `groups`, `connected`, `last_seen`, `login_expired`, `ssh_enabled`, `approval_required`, `user_id`. Empty / falsy fields are dropped to keep the JSON column compact.
- **MAC** is always null — NetBird is an L3 overlay, no L2 addresses.
- **Mesh DNS domain** (`dns_domain` on the row) is auto-derived from the first peer's `dns_label` FQDN (e.g. `server-1.netbird.cloud` → `netbird.cloud`) — no separate config field.

### Lock semantics

Same ownership shape as Proxmox / Tailscale / UniFi:

- **Claim-on-existing**: pre-existing operator rows at desired peer addresses are adopted (FK stamped) with `user_modified_at` set, locking the operator's hostname / description / status from reconciler overwrites.
- **Skip-on-locked**: locked rows keep their soft fields on every subsequent pass. The reconciler still corrects the factual `subnet_id`.
- **Un-claim-on-disappear**: a locked row whose upstream peer is gone keeps the operator's edits — the FK is **released**, not the row deleted, so it appears as "manually managed". Unlocked rows are deleted.
- **Cross-integration safety**: rows already owned by any sibling integration are skipped with a warning rather than claimed.

**⚠️ NetBird and Tailscale share the same default CGNAT range** (`100.64.0.0/10`), so a peer and a tailnet device can legitimately land on the same address. Each reconciler therefore refuses to claim rows owned by the other (the guard was added symmetrically to the Tailscale reconciler in the same change). If you run both mirrors, bind them to **different IPAM spaces** — or expect one to win the address and the other to log an `owned by another integration; not claiming` warning.

### Setup

1. In the NetBird dashboard open **Settings → Users**, pick an account admin (or a service user with read access), and create a **personal-access token**. Copy the printed value (`nbp_…`).
2. Paste the management URL into **API URL** — `https://api.netbird.io` for NetBird Cloud, or your self-hosted management host.
3. Bind an **IPAM space** (required) and, optionally, a **DNS server group** to light up Phase 2.
4. Hit **Test Connection** (`POST /netbird/instances/test`) — it verifies reachability + auth and reports the derived mesh domain + peer count before save.

A `401` means the token is invalid or revoked; a `403` means the token's user can't list peers; a `404` usually means the management URL isn't the API base.

### Phase 2 — synthetic mesh DNS surface

Same shape as Tailscale's Phase 2: a synthetic `DNSZone` materialised by the reconciler (not a driver). Activates automatically when the instance has `dns_group_id` bound; **skipped silently otherwise**.

**What it does.** Every reconcile pass:

1. Derives the mesh domain from the first peer's `dns_label` FQDN (cached on `NetbirdInstance.dns_domain`).
2. Upserts a `DNSZone` named `<domain>.` in the bound DNS group, FK-stamped with `netbird_instance_id` + `is_auto_generated=True`.
3. Diffs the desired record set — one **A** record per peer (NetBird peers are IPv4-only, so no AAAA) — against the existing synthesised records, keyed on `(label, record_type, value)`. Adds new, deletes orphaned.
4. Stamps each record with `auto_generated=True` + `netbird_instance_id`. TTL = 300 s.

**Read-only enforcement.** DNS API write paths return **422** when `netbird_instance_id IS NOT NULL` on the target zone or record, with a message pointing the operator at unbinding the DNS group (or deleting the instance) to release the zone.

**Conflict with operator zones.** A pre-existing **operator-managed** zone of the same name in the bound group is **not** claimed — claiming it would silently overwrite operator records every sync. The collision is reported as a `summary.warnings` entry (visible in the `netbird.reconcile` audit row), the operator's zone is left untouched, and the IPAM mirror still runs to completion. Delete / rename the manual zone (or rebind the instance to a different group) to unblock Phase 2.

**Filtering.** Peers skipped by the IPAM mirror (expired logins, no FQDN, an FQDN outside the derived domain) are skipped here too, so the DNS view stays consistent with the IPAM view.

### Operator Copilot

`list_netbird_targets` (module-gated on `integrations.netbird`) lists configured instances — name, description, enabled flag, bound IPAM space, sync interval, `last_synced_at`. API tokens never appear in the response.

---

## UniFi Network Application

**Phase status**: read-only mirror shipped. Gated behind the `integrations.unifi` feature module (**default off** — Settings → Features).

One `UnifiController` row per UniFi Network controller. A controller can be a **local** console (direct HTTPS to `https://<host>:<port>/proxy/network/...`) or a **cloud-hosted** console reached through `api.ui.com` and the cloud-connector path. The reconciler picks the transport from `mode` and constructs the same logical paths underneath.

Per-controller config (`UnifiController` rows):

| Field | Notes |
|---|---|
| `mode` | `local` or `cloud`. Local talks directly to the controller; cloud wraps every call in the `api.ui.com` connector path. |
| `host` + `port` | Controller hostname / IP + port (default `443`). Used for `mode=local`. |
| `cloud_host_id` | Console host id from the Site Manager URL (`unifi.ui.com/consoles/<host_id>/…`). Used for `mode=cloud`. |
| `verify_tls` | Default `true`. Disable for self-signed local consoles, or paste the controller CA in the field below. |
| `ca_bundle_pem` | Optional. Trusted in addition to the system store when `verify_tls=true`. |
| `auth_kind` | `api_key` (modern UniFi OS ≥ 4.x; `X-API-Key` header — required for `mode=cloud`) or `user_password` (legacy local controllers; cookie + CSRF login). |
| `api_key` | Fernet-encrypted at rest. |
| `username` + `password` | Fernet-encrypted at rest. Only used for `auth_kind=user_password`, `mode=local`. |
| `ipam_space_id` | Required. |
| `dns_group_id` | Optional. |
| `mirror_networks` | Default `true`. Off mirrors nothing useful — a controller without subnets is the whole point. |
| `mirror_clients` | Default `true`. Active (connected) clients → IPAM addresses. |
| `mirror_fixed_ips` | Default `true`. DHCP fixed-IP reservations → `reserved` rows. |
| `site_allowlist` | `[]` = mirror every site. A non-empty list narrows by site short-name or human description. |
| `network_allowlist` | Per-site VLAN allowlist `{"<site>": [10, 20]}` — keeps guest SSIDs out of IPAM without disabling whole sites. A site missing from the map mirrors all its networks. |
| `include_wired` / `include_wireless` | Default `true` each. Gate which connected clients mirror. |
| `include_vpn` | Default `false` — VPN clients (L2TP / OpenVPN / WireGuard / Teleport) are usually managed elsewhere and would churn as stale rows. |
| `sync_interval_seconds` | Default `60`. The reconciler clamps `mode=cloud` to a 60 s floor so it doesn't hammer the rate-limited `api.ui.com`. |

> SpatiumDDI reads UniFi's **legacy controller API** (`/proxy/network/api/...`) as the rich-data source — the public Integration API deliberately omits MAC, hostname, `network_id`, OUI, fixed IP, DHCP scope, etc., none of which can be synthesised. Both APIs ride the same TLS connection, so this is a per-call routing choice, not a separate auth/transport.

### Mirror semantics

- **Networks** (`rest/networkconf`) with an IPAM-relevant `purpose` (`corporate` / `guest` / `remote-user-vpn`) and a parseable `ip_subnet` → one `Subnet` per network, gateway from the network's declared subnet. `wan`, `vpn`, and `site-vpn` networks are skipped (no L3 LAN to mirror). The same CIDR seen on two sites keeps the first one — narrow `site_allowlist` if you run overlapping IP plans across sites.
- **VLAN tags** → the reconciler creates one `Router` per controller (`vendor="Ubiquiti"`, `model="UniFi Network Controller"`) plus one `VLAN` row per 802.1Q tag, and stamps each tagged subnet's `vlan_ref_id` + `vlan_id` so the IPAM page's VLAN column lights up automatically. Untagged networks mirror as subnets with no VLAN linkage.
- **Active clients** (`stat/sta`) → `IPAddress` with `status="unifi-client"`, hostname from the client name / hostname, MAC carried through, description noting wired / wireless / guest / OUI.
- **DHCP fixed-IP reservations** (`rest/user`) → `IPAddress` with `status="reserved"`.
- **Smart parent block**: a mirrored CIDR with no enclosing operator block gets the canonical RFC 1918 / CGNAT supernet auto-created as an unowned top-level block (shared by all integrations).

### Lock semantics

Same ownership shape as Proxmox / Tailscale / Cloud: pre-existing operator rows at a desired address are adopted (FK stamped, `user_modified_at` set so soft fields lock); rows owned by another integration — or another UniFi controller — are skipped with a warning rather than claimed; locked rows whose upstream client disappears release the FK (appear as "manually managed") instead of being deleted. The reconciler always corrects the factual `subnet_id` and VLAN linkage (a network property, not an operator preference). A per-site fetch failure (e.g. a `429` from the rate-limited `stat/sta` call) aborts the whole pass rather than mass-deleting that site's rows.

### Setup

The admin page at `/unifi` ships a copy-paste guide (expand **Setup guide** when creating a controller). On a local UniFi OS console, generate the key under the controller's **Settings → Integrations → Create API Key** (the key displays once). For cloud-hosted consoles (UniFi Site Manager), generate the key at `unifi.ui.com → Settings → API` and capture the console host id from the URL bar into **Cloud host id**. **Test Connection** (`POST /controllers/test`) probes `self/sites` + the integration `info` endpoint, reports the controller version + site count, and distinguishes 401 / 403 / 404 / TLS / network errors with human-readable messages.

### Discovery modal

The reconciler writes a `last_discovery` JSONB snapshot on every successful sync — a per-site rollup (`site_total`, `network_total` / `network_mirrored`, `client_total` / `client_mirrored`, `addresses_skipped_no_subnet`) plus a per-site row list (networks / mirrored / clients per site). Same magnifier-icon-button shape as the Proxmox / Cloud Discovery modals; disabled until the controller has synced at least once.

---

## Cloud (AWS / Azure / GCP)

**Phase status**: Part A shipped (read-only infrastructure mirror). Cloud DNS — the agentless authoritative-DNS driver family for Cloudflare / Route 53 / Azure DNS / Google Cloud DNS — is **Part B** and is *not* part of this integration; it ships through the Add DNS server flow instead (see [DNS.md](DNS.md) and [DNS_DRIVERS.md](../drivers/DNS_DRIVERS.md)).

Gated behind the `integrations.cloud` feature module (**default off** — Settings → Features). One `CloudEndpoint` row per cloud account / subscription set / project set. AWS, Azure, and GCP are wired today; the model reserves the token-only providers (Hetzner / DigitalOcean / Linode / Vultr) for a future phase without a schema change.

Per-endpoint config (`CloudEndpoint` rows):

| Field | Notes |
|---|---|
| `provider` | `aws` \| `azure` \| `gcp`. Immutable after create (re-create to switch). |
| `credentials` | Provider-specific secret dict, Fernet-encrypted at rest. AWS: `{access_key_id, secret_access_key}`. Azure: `{tenant_id, client_id, client_secret}`. GCP: `{service_account_json}` (the whole key file as a string). |
| `provider_config` | Non-secret routing scope, shown in the UI without a decrypt. Azure: `{subscription_ids: [...]}` (required). GCP: `{project_ids: [...]}` (required). AWS: `{}` — AWS scopes by `regions`. |
| `regions` | Region / location allow-list. Empty = all regions the account can see. AWS fans out one client per region (empty → `ec2:DescribeRegions` discovers every opted-in region); Azure / GCP filter the flat resource list. |
| `ipam_space_id` | **Required.** Private VPC/VNet networks + their subnets + instance NICs land under this space (one `IPBlock` per VPC CIDR, `Subnet` rows beneath). |
| `public_space_id` | Optional. A separate space for `cloud-public` / `cloud-lb` IPs. NULL keeps them in `ipam_space_id`. |
| `dns_group_id` | Optional. Held for future cloud-DNS surfacing; unused by the infra mirror today. |
| `mirror_load_balancers` | Default `true`. Mirror load-balancer frontend IPs as `cloud-lb` rows. |
| `mirror_stopped_instances` | Default `false` — only running instances land in IPAM. On keeps stopped / deallocated instances too (capacity-planning views). |
| `sync_interval_seconds` | Default `300`. Floor `60`. Cloud APIs are slower + rate-limited, so the cadence is deliberately longer than the 30 s shared default. Swept by `sweep_cloud_endpoints` on a 30 s beat tick. |

### Mirror semantics

- **VPCs / VNets** → one `IPBlock` per address-space CIDR under the bound space, named `<provider>:<network>` (the CIDR suffix is appended only when a network declares more than one CIDR). When an operator (or other-integration) block already encloses the CIDR, the reconciler nests beneath it rather than creating a same-CIDR duplicate.
- **GCP networks carry no CIDR of their own** — a GCP VPC is a global CIDR-less container and the addressing lives entirely on its (regional) subnetworks. For those the reconciler creates one block per distinct subnet CIDR, and the subnet nests directly inside its same-CIDR block. No supernet is speculatively invented.
- **Subnets** → one `Subnet` each, enclosed by the network's block. Cloud subnets are routed overlays: they are created with `kubernetes_semantics=True` so the IPAM tree suppresses the LAN-specific network / broadcast / gateway placeholder rows (same as Kubernetes pod-CIDR / Tailnet subnets). The gateway defaults to the first usable host (`x.x.x.1`) unless the provider reports one.
- **Instance NICs** → `IPAddress` with `status="cloud-instance"`, hostname = instance name, MAC from the NIC when the provider exposes it (AWS / Azure do; GCP does not). A NIC's public IP, if present, also yields a `cloud-public` row.
- **Standalone public / Elastic / external IPs** → `IPAddress` with `status="cloud-public"`.
- **Load-balancer frontends** (when `mirror_load_balancers`) → `IPAddress` with `status="cloud-lb"`. AWS NLBs expose static frontend IPs; AWS ALBs + classic ELBs are DNS-name-only (their public IPs float) so they are skipped with a warning.
- **Public + LB IPs are usually out-of-band /32s.** A `cloud-public` / `cloud-lb` row only materialises when an enclosing **mirrored** subnet exists (in `public_space_id` when set, else `ipam_space_id`). IPs that fall outside every mirrored subnet are counted under `skipped_no_subnet` — a documented limitation, not an error.

### Lock semantics

Same ownership shape as Proxmox / Tailscale: pre-existing operator rows at a desired address are claimed (FK stamped, `user_modified_at` set so the operator's soft fields lock); rows owned by another integration are skipped with a warning; locked rows whose upstream resource disappears release the FK (appear as "manually managed") instead of being deleted; an operator subnet at an exact-CIDR match is reused untouched (`subnets_matched`). The reconciler always corrects the factual `subnet_id`.

### Setup — least-privilege credentials

The admin page at `/cloud` ships a per-provider copy-paste guide. **Test Connection** (`POST /endpoints/test`) does a cheap auth + reachability probe — AWS resolves the account via `sts:GetCallerIdentity` + counts VPCs in one region; Azure lists VNets in the first subscription; GCP lists networks in the first project — and surfaces a clean message on failure rather than a raw SDK traceback.

**AWS** — create an IAM user with programmatic access and attach the three AWS-managed read-only policies:

```
AmazonVPCReadOnlyAccess
AmazonEC2ReadOnlyAccess
ElasticLoadBalancingReadOnly
```

Paste the access key id + secret access key into the form. Leave **Regions** blank to walk every opted-in region, or pin a subset.

**Azure** — create a read-only service principal scoped to the subscription(s):

```sh
az ad sp create-for-rbac --name spatiumddi-readonly --role Reader \
  --scopes /subscriptions/<subscription-id>
```

Paste the printed `tenant` / `appId` / `password` into **Tenant ID** / **Client ID** / **Client secret**, and the subscription id(s) into **Subscription IDs** (required — Azure scopes by subscription).

**GCP** — create a service account, grant it `roles/compute.viewer`, and download a JSON key:

```sh
gcloud iam service-accounts create spatiumddi-readonly
gcloud projects add-iam-policy-binding <project-id> \
  --member="serviceAccount:spatiumddi-readonly@<project-id>.iam.gserviceaccount.com" \
  --role="roles/compute.viewer"
gcloud iam service-accounts keys create key.json \
  --iam-account=spatiumddi-readonly@<project-id>.iam.gserviceaccount.com
```

Paste the whole `key.json` contents into **Service account JSON** and the project id(s) into **Project IDs** (required).

### Discovery modal

The reconciler writes a `last_discovery` JSONB snapshot on every successful sync — category counters (networks / subnets / public IPs / load balancers totals, instances running / mirrored / no-subnet / no-NIC) plus a per-instance diagnostic list categorising each instance as `mirrored`, `no_subnet` (its private IP isn't enclosed by any mirrored subnet — check the VPC subnet was discovered in this region), or `no_nic`. Same shape + magnifier-icon button as the Proxmox Discovery modal. Disabled until the endpoint has synced at least once.

### Delete semantics

Mirror rows provenance via the `cloud_endpoint_id` FK on `IPBlock` / `Subnet` / `IPAddress` with `ON DELETE CASCADE`, so deleting the endpoint sweeps every materialised row atomically. Endpoint-owned blocks that no longer back any subnet are dropped on each reconcile.

### Non-goals

- **Read-only.** SpatiumDDI never writes back to the cloud — no instance / network / DNS mutation, no tagging.
- **Cloudflare is not a Part A provider.** It has no VPC / instance concept; it appears only as a Part B cloud-DNS driver.
- **No per-resource management surface** (start / stop / console) — outside the read-only-mirror scope.

---

## OPNsense

**Phase status**: read-only mirror shipped. Gated behind the `integrations.opnsense` feature module (**default off** — Settings → Features).

One `OPNsenseRouter` row points SpatiumDDI at a single OPNsense firewall's REST API. The reconciler mirrors the firewall's interface CIDRs (LAN / OPT* / VLANs) as IPAM subnets and its DHCPv4 leases + static reservations (optionally the ARP table) as IP addresses.

Per-firewall config (`OPNsenseRouter` rows):

| Field | Notes |
|---|---|
| `host` + `port` | Firewall hostname / IP (no scheme) + port (default `443`). The client builds `https://{host}:{port}/api/...`. |
| `verify_tls` | Default `true`. Disable for self-signed lab boxes, or paste the CA below. |
| `ca_bundle_pem` | Optional. Trusted in addition to the system store when `verify_tls=true`. |
| `api_key` | The HTTP Basic-auth **username**. Stored in plaintext (like Proxmox's `token_id` — it's not the secret). |
| `api_secret` | The HTTP Basic-auth **password**. Fernet-encrypted at rest. |
| `ipam_space_id` | Required. |
| `dns_group_id` | Optional. |
| `mirror_dhcp_leases` | Default `true`. DHCPv4 leases → `dhcp` rows. |
| `mirror_static_mappings` | Default `true`. Static DHCP reservations → `reserved` rows. |
| `mirror_arp` | Default `false` — the ARP table is noisier (every device the firewall has seen on the wire). |
| `sync_interval_seconds` | Default `60`, floor `30`. Swept by `sweep_opnsense_routers` on a 30 s beat tick. |

OPNsense API keys are minted per-user under **System → Access → Users → API keys**; auth is always HTTP Basic with the key as username and the secret as password.

### Mirror semantics

- **Interfaces are real LANs.** Unlike Kubernetes pod CIDRs (routed overlays with no broadcast), OPNsense LAN / OPT* / VLAN interfaces are genuine subnets: the firewall's interface IP is the gateway and the broadcast is real. So subnets are created with normal LAN semantics (gateway reserved, network + broadcast excluded from usable hosts). Interface config comes from `interfaces/overview/export`, which carries the logical identifier, the operator's description and the VLAN tag in one payload; `diagnostics/interface/getInterfaceConfig` is the fallback on firmware that lacks it, and `interfaces/vlan_settings/get` still supplies VLAN labels on that path. Interfaces that are administratively disabled, or whose address is DHCP-assigned, are skipped — they don't describe a subnet this IPAM should own. Only the primary address per family is mirrored; secondaries and VIPs are ignored.
- **Interface gateway IP** → one `reserved` `IPAddress` per subnet under the firewall's identity.
- **DHCPv4 leases** → `IPAddress` with `status="dhcp"` + `auto_from_lease=True` (Kea-shape parity), description noting the lease state. Sourced from every DHCP backend present (see below).
- **Static reservations** → `IPAddress` with `status="reserved"`. Added before leases so an IP that has both prefers the richer reservation description.
- **ARP table** (`diagnostics/interface/getArp`, opt-in) → `IPAddress` with `status="opnsense-arp"`, lowest priority.
- **Smart parent block**: a mirrored CIDR with no enclosing operator block gets the canonical RFC 1918 / CGNAT supernet auto-created as an unowned top-level block (shared by all integrations).

### DHCP backends

OPNsense has shipped three DHCPv4 servers across the supported firmware range, and which one answers depends on both the version and what the operator configured. ISC `dhcpd` was deprecated through 24.x / 25.1 and **moved out of core to a plugin in 25.7** ([opnsense/core#9155](https://github.com/opnsense/core/issues/9155)), with Dnsmasq becoming the wizard default and Kea the advanced option.

| Backend | Leases | Reservations | Present on |
|---|---|---|---|
| **Kea** | `kea/leases4/search` | `kea/dhcpv4/searchReservation` | 24.x+ when enabled |
| **Dnsmasq** | `dnsmasq/leases/search` | `dnsmasq/settings/searchHost` (rows with a MAC) | 25.7+ default |
| **ISC** (legacy) | `dhcpv4/leases/searchLease` | `dhcpv4/settings/getReservation` | core ≤25.1; 25.7+ only with the plugin |

SpatiumDDI queries **all three every pass and unions the results** rather than making the operator pick — 25.7+ can genuinely run Kea and Dnsmasq side by side on different interfaces. A backend that 404s is simply absent and contributes nothing; a 5xx or timeout still aborts the pass, so a transient failure can never be mistaken for an empty lease table.

A Dnsmasq "host" doubles as a static DNS entry, so only rows carrying a MAC are mirrored as reservations. Kea reports lease state numerically (`0` = active); it is normalised to the same vocabulary the ISC path produces.

> **Why this is called out at such length.** Until [#797](https://github.com/spatiumnorth/spatiumddi/issues/797) this integration queried the ISC endpoints *only*. On any 25.7+ firewall they 404, the client treated that as an empty table, and the sync reported success with zero leases on every pass — indefinitely, and with nothing in the UI to suggest anything was wrong.

### When a sync succeeds but mirrors nothing

`last_sync_warning` records non-fatal findings from the last pass and surfaces as an amber line beside the sync time (red `last_sync_error` still means the pass failed outright). It fires when:

- **No DHCP backend responded** — Kea, Dnsmasq and ISC are all absent, disabled, or not permitted. Nothing can mirror while this is true.
- **A backend refused the API user (403)** — the backend exists but the credentials lack its privilege. Different remedy: grant the privilege rather than change firmware.
- **No addressed interfaces were found** — every mirrored address needs an enclosing subnet, so zero interfaces zeroes the whole mirror downstream.
- **A subnet or address is owned by another integration** and was therefore not claimed.

A backend that answered and had nothing to report is a genuine zero and does **not** warn — otherwise the signal would fire on every quiet firewall and be trained away as noise.

Separately, a non-empty interface payload that parses to zero interfaces is treated as a **degraded read** and fails the pass rather than reporting an empty mirror. That combination means the response shape isn't the one this client parses, which is exactly how #797 stayed invisible.

### Lock semantics

Same ownership shape as the other integrations: pre-existing operator rows at a desired address are adopted (FK stamped, `user_modified_at` set so soft fields lock); rows owned by another OPNsense firewall or another integration are skipped with a warning; locked rows whose upstream entry disappears release the FK (appear as "manually managed") instead of being deleted. An operator subnet at an exact-CIDR match is reused untouched (`subnets_matched`); a router-owned subnet that still has non-OPNsense addresses living in it is un-claimed rather than cascade-deleted. The reconciler always corrects the factual `subnet_id`.

### Setup — read-only API key

The admin page at `/opnsense` ships a copy-paste guide (expand **Setup guide**). In the OPNsense web UI:

1. Create a dedicated read-only user (**System → Access → Users → +**), e.g. `spatiumddi` with no shell access.
2. Grant it read access — the built-in **GUI – All pages (read only)** privilege is simplest, or scope it for least privilege (table below).
3. Edit the user → **API keys → +** to generate a key / secret pair. OPNsense downloads an `apikey.txt` with `key=` and `secret=` lines.

**Least-privilege scoping.** Grant the pages matching what you're mirroring:

| Mirrors | Privileges needed |
|---|---|
| Interfaces → subnets | Interfaces: Overview, Interfaces: VLAN, Diagnostics: Interface |
| DHCP leases + reservations (Kea) | Services: Kea DHCP, **plus Kea's own lease privileges** |
| DHCP leases + reservations (Dnsmasq) | Services: Dnsmasq DNS/DHCP |
| DHCP leases + reservations (ISC, legacy) | Services: DHCPv4 |
| ARP table (opt-in) | Diagnostics: ARP Table |

The Kea lease and service endpoints carry **separate ACL entries** from the Kea settings pages ([opnsense/core#7770](https://github.com/opnsense/core/issues/7770)), so a user granted only the Kea page still gets 403 on the leases. SpatiumDDI does not fail the pass for this — the interface mirror keeps working — but it raises a `last_sync_warning` naming the backend, because the alternative is leases that silently never appear.

Paste `key` into **API Key** and `secret` into **API Secret**. **Test Connection** (`POST /routers/test`) verifies HTTPS reachability + auth + firmware version before save.

---

## Palo Alto PAN-OS / Panorama (#605)

One `PANOSFirewall` row points SpatiumDDI at a single managed **scope**: a standalone NGFW (one `vsys`, default `vsys1`) or a Panorama **device-group** (`is_panorama=True` + `device_group`). Feature module `integrations.paloalto`, default-OFF. Two integration shapes ride the one row — a read-only mirror (this section) and opt-in Dynamic Address Group enforcement (folded into [Active block sync](#active-block-sync--write-back-enforcement-601) below).

Palo Alto is the reference vendor for the enterprise-firewall family because its API is the best of the family and its **Dynamic Address Group** model is a near-perfect fit for SpatiumDDI's desired-state enforcement design.

Per-scope config (`PANOSFirewall` rows): connection (`host` / `port` / `verify_tls` / optional `ca_bundle_pem` / REST `api_version`, default `10.1`), a Fernet-encrypted read-scoped `api_key`, the Panorama/vsys scoping, the bound `ipam_space_id` (+ optional `dns_group_id`), four mirror toggles, and `sync_interval_seconds` (default 60, 30 s floor, swept on the 30 s beat tick). The client speaks the **REST API** (`/restapi/v{ver}/Objects/Addresses`, `/AddressGroups`, `/Policies/NatRules`, header `X-PAN-KEY`) for objects/NAT and the legacy **XML API** (`type=keygen` / `type=op` / `type=user-id`) for key minting, op-commands (system info, interface IPs, DHCP leases), and DAG tag registration.

### Mirror semantics

- **Address objects + groups → `firewall_endpoint_object` mirror rows** (the "shadow IPAM" store). Named to *not* collide with the appliance's own fleet-nftables `FirewallPolicy` / `FirewallRule` / `FirewallAlias` (#285). Each row carries provenance (`panos_firewall_id`, `ON DELETE CASCADE`), the object `kind` (host / network / range / fqdn / group), its verbatim `value`, tags, and — where the value resolves to a known IPAM CIDR/IP — an optional link to the live `ip_address` / `subnet` row. **Drift report** (`GET /paloalto/firewalls/{id}/drift`): objects that resolve to a CIDR/IP but link no IPAM row, and in-space subnets that no firewall object covers.
- **NAT rules → `nat_mapping` rows** stamped with `panos_firewall_id` provenance (making the previously manual-entry-only NAT table a live data source). DNAT / port-forward → `internal_ip` = translated dst, `external_ip` = original dst; source-NAT → `internal_ip` = original source, `external_ip` = translated source. Mirror-owned rows sweep on target delete and never collide with operator-entered rows.
- **Zones + interfaces → IPAM subnets** (opt-in, `mirror_interfaces`): interface CIDRs from `show interface all` become PAN-owned subnets under an auto-created wrapper block, gateway = the interface IP, zone in the description.
- **DHCP leases → IPAM addresses** (opt-in, `mirror_dhcp_leases`, when the firewall is a DHCP server): `status="dhcp"` + `auto_from_lease=True`, Kea-shape parity.

### Lock semantics

Same ownership shape as the other integrations: pre-existing operator rows at a desired address are adopted (FK stamped, `user_modified_at` set); rows owned by another integration are skipped with a warning (`panos_firewall_id` is threaded through every reconciler's sibling-ownership guard); operator subnets at an exact-CIDR match are reused untouched; a PAN-owned subnet that still has non-PAN addresses in it is un-claimed rather than cascade-deleted.

### Setup

The admin page at `/paloalto` collects the connection + scope. Provide either a pre-minted API key (**Device → Setup → Management → API key**, or a custom admin role scoped to XML/REST read) **or** admin username + password — **Test Connection** (`POST /paloalto/firewalls/test`) then mints the key via `type=keygen` and returns it for the create form to store. Least privilege: an admin role with read on Objects + Policies + Operational commands is enough for the mirror; DAG enforcement needs a separate User-ID-capable key (below).

---

## The shared firewall-mirror engine (#606)

The address-object / NAT / interface-subnet / DHCP-lease mirror is identical across every firewall vendor — only the *owner* (which provenance FK carries the vendor id) differs. `backend/app/services/firewall_mirror.py` holds that logic once, parameterized by a `FirewallOwner` (`paloalto` / `fortinet` / `meraki`). Each vendor reconciler fetches from its own client, maps the wire shapes into neutral `MirrorObject` / `MirrorNat` / `MirrorSubnet` / `MirrorAddress` dataclasses, and calls `apply_objects` / `apply_nat` / `apply_subnets` / `apply_addresses`. The #605 PAN-OS reconciler was migrated onto this engine (its test suite pins the behaviour). The `firewall_endpoint_object` store carries all three vendors via mutually-exclusive owner FKs with a `num_nonnulls(...) = 1` CHECK, and `INTEGRATION_OWNERSHIP_FKS` centralises the sibling-ownership guard set so no mirror claims another vendor's rows.

---

## Fortinet FortiGate (#606)

One `FortinetFirewall` row points SpatiumDDI at a single FortiGate **VDOM** (default `root`), driven over the **FortiOS REST API** (`/api/v2/cmdb/...` + `/api/v2/monitor/...`, `Authorization: Bearer <token>`, every request carrying `?vdom=`). Feature module `integrations.fortinet`, default-OFF. This vendor is **read-only mirror only** on this row — FortiGate enforcement is the credential-free threat-feed path (see [Firewall block-list feeds](#firewall-block-list-feeds-606) below), not a write-back.

Per-firewall config: connection (`host` / `port` / `verify_tls` / optional `ca_bundle_pem` / `vdom`), a Fernet-encrypted read-scoped `api_token` (a FortiGate REST-API-admin bearer token), the bound `ipam_space_id` (+ optional `dns_group_id`), four mirror toggles, and `sync_interval_seconds` (default 60, 30 s floor). Reads share the [shared firewall-mirror engine](#the-shared-firewall-mirror-engine-606).

### Mirror semantics

- **Address objects + groups → `firewall_endpoint_object`** (`/api/v2/cmdb/firewall/address` + `/addrgrp`). `ipmask` → host or network, `iprange` → range, `fqdn` → fqdn, group → member-name list; `tagging` flattened into the object's tags. Same "shadow IPAM" store + two-way **drift report** (`GET /fortinet/firewalls/{id}/drift`) as Palo Alto.
- **VIPs (destination NAT) → `nat_mapping`** (`/api/v2/cmdb/firewall/vip`): `external_ip` = the VIP `extip`, `internal_ip` = the mapped IP.
- **Interface CIDRs → IPAM subnets** (opt-in, `mirror_interfaces`) and **DHCP leases → IPAM addresses** (opt-in, `mirror_dhcp_leases`), same ownership/lock semantics as the other mirrors.

### Setup

Create a REST API admin on the FortiGate (**System → Administrators → Create New → REST API Admin**) with a read-only profile scoped to the relevant VDOM, copy its API token, and paste it on the `/fortinet` admin page. **Test Connection** (`POST /fortinet/firewalls/test`) probes `/api/v2/monitor/system/status`.

---

## Cisco Meraki MX (#606)

One `MerakiOrg` row points SpatiumDDI at a single Meraki **organization**, driven over the cloud **Dashboard API** (`https://api.meraki.com/api/v1`, `Authorization: Bearer <key>`) — nothing on-prem to reach. Feature module `integrations.meraki`, default-OFF. Two shapes ride the one row — a read-only mirror (this section) and opt-in per-client Blocked enforcement (folded into [Active block sync](#active-block-sync--write-back-enforcement-601)).

Per-org config: `base_url` (regional shard override), the `org_id`, a Fernet-encrypted read-scoped `api_key`, an optional `network_ids` allow-list (empty = every appliance network), the bound `ipam_space_id` (+ optional `dns_group_id`), five mirror toggles, and `sync_interval_seconds` (default **300** — the Dashboard API is rate-limited; the client honours `429` + `Retry-After`). The reconciler accumulates every network's desired state before converging the [shared engine](#the-shared-firewall-mirror-engine-606) once per kind (a per-network apply would delete the other networks' rows).

### Mirror semantics

- **Appliance VLANs → IPAM subnets** (`/networks/{id}/appliance/vlans`): each VLAN `subnet` → an owned subnet under an auto-created wrapper block, gateway = the MX applianceIp. Networks with VLANs disabled fall back gracefully (the `400` "VLANs are not enabled" is treated as an empty list).
- **DHCP fixed-IP reservations → IPAM addresses** (the high-value signal): each VLAN's `fixedIpAssignments` → a `reserved` IP row keyed by MAC.
- **Org policy objects / groups → `firewall_endpoint_object`** (`/organizations/{id}/policyObjects` + `/groups`): `cidr`/`ip`/`fqdn` mapped to the shared kinds; category carried as a tag. Same drift report (`GET /meraki/orgs/{id}/drift`).
- **MX 1:1 NAT + port-forward → `nat_mapping`** (`oneToOneNatRules` + `portForwardingRules`).
- **Network clients → IPAM addresses** (opt-in, `mirror_clients`, noisy): `status="dhcp"`.

### Setup

Generate a Dashboard API key (**Organization → Settings → Dashboard API access**, or a per-user key), find the organization id (`getOrganizations`), and paste both on the `/meraki` admin page. **Test Connection** (`POST /meraki/orgs/test`) confirms the org + counts its appliance networks. Enforcement needs a *separate* write-scoped key (below).

---

> **This is the deliberate exception to the read-only-mirror rule above.** Every other integration in this doc is a one-way `source → IPAM` pull. Active block sync is the opposite direction — `decision → source`, a push reconciler. It exists to close the half-open detect→block loop: rogue-DHCP detection (#370) and new-device watch (#459) can *see* a hostile device, and the DHCP MAC blocklist can starve it of a lease, but a device that **self-assigns a static IP walks right past a DHCP block**. Active block sync pushes a real block at the natural enforcement point instead.

It is off by default and layered behind several independent gates so it can never fire by accident:

1. **Feature module `security.block_sync`** (default-OFF) gates the entire surface (REST router, MCP tools, sidebar entry). Enabling it exposes the UI but **arms nothing**.
2. **Per-target enforcement master switch** (`block_sync_enabled`, default-OFF) on each OPNsense router / UniFi controller / Palo Alto firewall — independent of both the mirror's `enabled` flag and the `integrations.opnsense` / `integrations.unifi` / `integrations.paloalto` modules. The read-only mirror is never touched; enforcement is a separate armed capability on the same row.
3. **Distinct write-scoped credentials.** The read mirror uses a read-only API user; enforcement needs a Firewall-privileged OPNsense user / a UniFi admin key / a PAN-OS User-ID-capable key. Stored Fernet-encrypted, never returned (password-confirm reveal, audited — mirrors the agent-bootstrap-key reveal).
4. **RBAC `manage_block_sync`** on every endpoint (Network Editor builtin role; superadmin bypasses). Palo Alto DAG enforcement additionally requires **`manage_firewall_enforcement`** to arm.
5. **Preview + confirm + full audit** on every push — `POST /block-sync/blocks/preview` (and `?preview` on reconcile) returns the exact per-target add/remove diff without writing.
6. **Two-person approval** — creating/arming a block routes through the approval workflow (#62) as `admin:manage_block_sync` when a policy matches.

### Desired-state model

`network_block` is the SpatiumDDI-owned block set: one row per blocked value (`kind` = `ip` | `mac`), with `reason`, `source` (`manual` / `new_device` / `rogue_dhcp`), `enabled`, and an optional `expires_at` for auto-lift. `network_block_push` tracks per-(block, target) convergence (`push_status` = pending / pushed / removing / error + `last_error`). The reconciler is **target-driven and idempotent** (NN#9): for each armed target it ensures every applicable enabled block is present on the device and lifts every push whose block was disabled / expired / deleted. Convergence is **non-destructive** — SpatiumDDI only removes values it added (tracked via push rows); it never touches alias members / blocked clients it doesn't own. A 60 s beat sweep plus an immediate on-create/lift enqueue keep the device converged.

### OPNsense — firewall table-alias membership

IP-kind blocks push to an operator-**pre-created** OPNsense table alias (e.g. `spatiumddi_blocked`) that the operator references from one block rule. SpatiumDDI only ever mutates alias membership: `POST /api/firewall/alias_util/add|delete/{alias}` then `POST /api/firewall/alias/reconfigure`. No rule CRUD, no rule-ordering state. **Setup:** create a user with Firewall-alias privileges, mint an API key/secret, create the block rule + alias by hand, then arm the target with the alias name + write creds.

### UniFi — L2 client quarantine

MAC-kind blocks push a device quarantine via the legacy controller command `POST /proxy/network/api/s/{site}/cmd/stamgr` `{"cmd": "block-sta", "mac": …}` / `unblock-sta` — the same call the UniFi UI issues (the public Integration v1 API does not expose client-block, so the legacy path + captured `X-CSRF-Token` / `X-API-Key` is mandatory). This is an L2 quarantine at the AP/switch, great for "quarantine this device"; subnet/CIDR firewall rules (`rest/firewallrule`) are out of scope for v1.

### Palo Alto PAN-OS — Dynamic Address Group tag register (#605)

The enterprise-grade, **commit-free** tier of the same enforcement theme. IP-kind blocks push an `IP → tag` registration via the PAN-OS **User-ID API** (`type=user-id`, `<uid-message><payload><register>…`), with `timeout='0'` for a persistent registration and **no policy commit**. The operator pre-creates a **Dynamic Address Group** whose match is `'<block_tag_name>'` (default `spatiumddi-quarantine`); the DAG picks up the registered IP near-instantly and any security rule referencing the DAG enforces it. Convergence reads current on-device state (`show object registered-ip tag <t>`) so SpatiumDDI adds only what's missing and unregisters only what it owns (never diffing against a bad-empty set, NN#5). SpatiumDDI's classification flags (`pci_scope` / `internet_facing`) and free-form tags map naturally onto DAG tags.

Extra guardrails on top of the shared block-sync gates: enforcement targets a **standalone firewall vsys** (User-ID registration is not a Panorama operation — arming a Panorama target 422s); it needs a **distinct User-ID-capable write key** (Fernet-encrypted, never returned, password-confirm reveal); and arming it requires the dedicated **`manage_firewall_enforcement`** permission *in addition to* `manage_block_sync` (an off-prem, broad-blast-radius write). **Setup:** create an admin role / API key with User-ID write on the target vsys, pre-create the DAG referencing the tag, then arm the target from **Block sync → Targets** with the tag name + write key.

### Cisco Meraki — per-client Blocked device policy (#606)

A `meraki` block-sync target consumes **`mac`**-kind blocks (alongside UniFi). The reconciler resolves a blocked MAC to its `(network, client)` across the org's appliance networks and moves the client to the built-in **`Blocked`** device policy via the Dashboard API (`updateNetworkClientPolicy`) — the cloud applies it immediately, **no on-prem deploy**. Lifting a block restores the client to `Normal`. Like UniFi there's no cheap "list blocked" read, so convergence is push-row driven with a periodic re-assert; a MAC not currently seen in any network records a soft error and retries next sweep. Needs a **distinct write-scoped Dashboard key** + the `manage_firewall_enforcement` permission (same guardrails as PAN-OS). Phase 1 wires the built-in `Blocked` policy; a custom named group policy (which needs `groupPolicyId` resolution) is a follow-up.

### One-click from detection

The New Devices review-queue **Block** action grows an "also quarantine upstream" option: when the module is on, the caller holds `manage_block_sync`, and a UniFi target is armed, blocking a MAC there *also* creates a `network_block` (source=`new_device`) — routed through the same approval gate. Rogue-DHCP responders can be blocked by IP the same way through the dedicated surface (source=`rogue_dhcp`) — an armed OPNsense alias or Palo Alto DAG enforces it at the firewall.

### Non-goals (v1)

Full firewall rule authoring / reordering (OPNsense alias membership + PAN-OS DAG tags only, never security-rule CRUD or any commit); UniFi subnet/CIDR firewall rules (L2 MAC quarantine only); any write-back other than block/unblock/tag-register; pfSense enforcement (folds in once the pfSense mirror #32 lands, same shape).

---

## Firewall block-list feeds (#606)

The **feed inversion** — the credential-free enforcement path. Instead of SpatiumDDI holding write credentials and pushing to the device (the #601 model above), the device polls a SpatiumDDI-hosted URL and applies whatever it returns. Feature module `security.firewall_feeds`, which ships **disabled** ([#1069](https://github.com/spatiumnorth/spatiumddi/issues/1069)) — it is an enforcement surface, and it pairs with Active block sync, which has always been off. Even enabled, no feed serves anything until an operator creates one.

A `FirewallFeed` row exposes `GET /api/v1/firewall-feeds/feeds/{id}/blocklist.txt` — an **unauthenticated** (session-less) endpoint authed purely by a per-feed token (`?token=` or `Authorization: Bearer`). It renders the active `NetworkBlock` set of the feed's kind (`ip` today) as plain text, one IP/CIDR per line — the same desired-state intent the #601 push reconcilers converge, fed by rogue-DHCP (#370), new-device watch (#459), and manual entries. The token is Fernet-encrypted at rest, shown once on create, revealed again through a password-confirmed endpoint, and rotatable (invalidating the old URL). Each poll stamps `last_polled_at` / `last_polled_ip` / `poll_count` so operators can confirm a firewall is actually consuming the feed.

**Subscribers:** a **Fortinet FortiGate** *External Threat Feed* (Security Fabric → External Connectors → Threat Feeds → IP Address) points at the feed URL — no write creds on the FortiGate at all. **Cisco FTD/FMC** *Security Intelligence* network feeds and **Check Point** IOC feeds follow the same shape (Phase 2). Managed from the **Security → Firewall Feeds** page; three superadmin-safe MCP reads and `list_firewall_feeds`.

---

## Dashboard surface

When **any** integration toggle is on, the dashboard renders an **Integrations panel** below the service health strip with:

- One column per enabled integration (Kubernetes / Docker / Proxmox / Tailscale / NetBird / UniFi / Cloud / OPNsense / Palo Alto / Fortinet / Meraki), header linking to the full admin page.
- Per-row: status dot (green = synced recently, amber = stalled > 3× sync interval, red = `last_sync_error`, gray = disabled or never synced), name, endpoint, node / container count, humanized last-synced age.
- `last_sync_error` is exposed as the row tooltip so operators can triage without leaving the dashboard.

---

## Roadmap — additional integrations

Tier 1 status (tracked in [CLAUDE.md §Integration roadmap](https://github.com/spatiumnorth/spatiumddi/blob/main/CLAUDE.md)): **UniFi Network Application**, **OPNsense** and **NetBird** have shipped as read-only mirrors (gated by the `integrations.unifi` / `integrations.opnsense` / `integrations.netbird` feature modules); **pfSense** remains. All target the same homelab / SMB audience and fit the Kubernetes/Docker/Proxmox/Tailscale reconciler shape. See CLAUDE.md for per-integration scope notes.

The **enterprise-firewall family** has since shipped on the same reconciler shape — **Palo Alto PAN-OS / Panorama** (#605) plus **Fortinet FortiGate** and **Cisco Meraki MX** (#606, Phase 1), each with its own section above. Check Point and Cisco FTD / FMC are the remaining Phase 2 vendors.

Tier 2 (narrower): MikroTik RouterOS 7, Incus / LXD, HashiCorp Nomad, NetBox one-shot import.

Tier 3 (cloud VPC family): AWS / Azure / GCP **shipped** (see [Cloud](#cloud-aws--azure--gcp) above). The token-only providers (Hetzner / DigitalOcean / Linode / Vultr) are reserved in the `CloudEndpoint` provider enum for a future phase.

**Explicit non-goals**: VMware vCenter / ESXi (SOAP-heavy, enterprise effort), SNMP polling (tracked as a separate IPAM discovery line item), WireGuard raw config (no API).
