---
layout: default
title: DHCP Drivers
---

# DHCP Driver Specification

DHCP drivers are the backend-specific layer that turns SpatiumDDI's internal DHCP model into operations on real DHCP servers. The service layer only ever speaks to [`DHCPDriver`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/base.py) (CLAUDE.md non-negotiable #10) — no Kea / PowerShell specifics leak above this line.

The driver registry ([`registry.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/registry.py)) classifies drivers along two axes:

| Axis | Values | What it means |
|---|---|---|
| `AGENTLESS_DRIVERS` | `windows_dhcp`, `fortigate` | Driver runs from the control plane. No co-located agent, no `ConfigBundle` long-poll. |
| `READ_ONLY_DRIVERS` | `windows_dhcp` | Driver implements lease reads only. Config push / reload / restart raise `NotImplementedError`. |
| `CLOUD_DHCP_DRIVERS` | `fortigate` | Agentless **and** write-capable: pushes whole-scope config to a provider REST API. `is_cloud()` gates the write-through + port defaults. |

All other drivers (currently just `kea`) are agented: the control plane renders a `ConfigBundle`, hash-keyed by SHA-256 ETag, and the co-located `spatium-dhcp-agent` long-polls `/config` to pick up changes.

---

## 1. Driver shapes

Today's drivers split into three shapes:

<p align="center">
  <img src="../assets/diagrams/dhcp-driver-shapes.svg" alt="DHCP driver shapes — agented vs agentless, read-only vs write" width="900"/>
</p>

The abstract base (`DHCPDriver`) has methods for both halves. Read-only agentless drivers (Windows) implement only the read methods + a stub `apply_config` / `reload` / `restart` / `validate_config` that raises; the API layer consults `READ_ONLY_DRIVERS` before offering write endpoints. Cloud agentless drivers (FortiGate) are write-capable but push the **whole scope object** synchronously over a REST API instead of rendering a daemon config bundle — see §5.

---

## 2. Abstract base class

Key methods on [`DHCPDriver`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/base.py):

```python
class DHCPDriver(ABC):
    name: str = "abstract"

    # Rendering (agented drivers).
    @abstractmethod
    def render_config(self, bundle: ConfigBundle) -> str: ...

    # Applying on the server host (agent-side).
    @abstractmethod
    async def apply_config(self, server: Any, bundle: ConfigBundle) -> None: ...
    @abstractmethod
    async def reload(self, server: Any) -> None: ...
    @abstractmethod
    async def restart(self, server: Any) -> None: ...
    @abstractmethod
    def validate_config(self, bundle: ConfigBundle) -> tuple[bool, list[str]]: ...

    # Reads.
    @abstractmethod
    async def get_leases(self, server: Any) -> list[dict[str, Any]]: ...
    @abstractmethod
    async def health_check(self, server: Any) -> tuple[bool, str]: ...
    @abstractmethod
    def capabilities(self) -> dict[str, Any]: ...

    # Optional per-object write APIs (Windows DHCP today). The default
    # batch impls below loop over the singular methods, which only the
    # Windows driver overrides; non-Windows drivers raise NotImplementedError.
    async def apply_reservations(self, server: Any, *,
                                 items: Sequence[ReservationItem]
                                 ) -> list[ReservationResult]: ...
    async def remove_reservations(self, server: Any, *,
                                  items: Sequence[RemoveReservationItem]
                                  ) -> list[ReservationResult]: ...
    async def apply_exclusions(self, server: Any, *,
                               items: Sequence[ExclusionItem]
                               ) -> list[ExclusionResult]: ...
```

Neutral data classes (`ScopeDef`, `PoolDef`, `StaticAssignmentDef`, `ClientClassDef`, `ConfigBundle`) are frozen dataclasses — hashing them gives the ETag that drives long-poll.

---

## 3. Kea driver (agented + write)

Located at [`app/drivers/dhcp/kea.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/kea.py). Agent image: [`agent/dhcp/`](https://github.com/spatiumnorth/spatiumddi/tree/main/agent/dhcp).

### Update strategy

| Operation | Mechanism | Notes |
|---|---|---|
| Full scope/pool/reservation push | `ConfigBundle` → agent fetches via long-poll → agent renders + writes `/etc/kea/kea-dhcp4.conf` → `config-test` → `config-reload` over the Kea **unix control socket** | Incremental config — no daemon restart. |
| Validate | `config-test` on the unix socket (with the full config doc as `arguments`) | Preflight — a config Kea rejects is never reloaded. |
| Read leases | Agent tails the **memfile lease CSV** (`/var/lib/kea/kea-leases4.csv`) | Not the `lease_cmds` HTTP API. The hook is still loaded (HA depends on it), but leases reach the control plane by CSV tail → `POST /dhcp/agents/lease-events`. |
| HA state | `status-get` on the unix socket, every ~15 s | Drives the live HA pill in the UI. |
| Metrics | `statistic-get-all` on the unix socket, every ~60 s | Deltas of the `pkt4-*` counters. |

**There is no HTTP Control Agent.** `kea-ctrl-agent` was removed in #637: Kea 3.0 deprecates it, and SpatiumDDI never spoke to it. Everything above rides the **unix control sockets** (`/run/kea/kea4-ctrl-socket`, `/run/kea/kea6-ctrl-socket`) via `agent/dhcp/spatium_dhcp_agent/kea_ctrl.py`. `:8000` is the HA hook's peer-to-peer listener and is now the only TCP port the image exposes.

Note also that the backend's `KeaDriver.apply_config()` / `reload()` / `get_leases()` are **no-ops** — the backend renders config only for the ETag / audit / shape-validation path. The renderer that actually feeds the daemon is the agent's `render_kea.py`. Two renderers exist; the agent one is the load-bearing one.

The agent drives Kea by:

1. Rendering the config bundle into Kea JSON (`Dhcp4` for IPv4, `Dhcp6` for IPv6 — address-family split on `DHCPScope.address_family`).
2. Sending `config-test` with the rendered doc to catch validation errors *before* touching the live config (a daemon too old to know the command answers `result=2`, which is treated as a soft pass).
3. Calling `config-reload`, which re-reads the file without dropping in-flight leases.

### Kea 3.0 path restrictions

Kea 3.0 (CVE-2025-32801/2/3) refuses to start if hook libraries, unix control sockets, lease files or log files sit outside its **compiled-in default directories**. Enforcement is a literal string compare of the config path's parent — there is no `realpath()`, so even `/var/run/kea` vs `/run/kea` fails. Alpine builds Kea with `-Dprefix=/usr -Dlocalstatedir=/var -Drunstatedir=/run`, so the enforced defaults are `/usr/lib/kea/hooks`, `/run/kea`, `/var/lib/kea`, `/var/log/kea` — **exactly** SpatiumDDI's existing layout, which is why the 2.6 → 3.0 jump needed no config changes. Do not relocate any of them. Verify with `kea-dhcp4 -W` ("Hooks directory") and `kea-dhcp4 -T <conf>`.

The IPv6 path renders a `Dhcp6` tree in parallel to `Dhcp4`. Dhcp6 option-name translation lands via `_KEA_OPTION_NAMES_V6` in both `backend/app/drivers/dhcp/kea.py` and the agent's `render_kea._options_from_mapping_v6`; v4-only options (`routers`, `broadcast-address`, `mtu`, `time-offset`, tftp-*) are dropped from v6 scopes with a warning.

### Wire shape from control plane → renderer

The HTTP envelope returned by `GET /api/v1/dhcp/agents/config` is:

```json
{
  "server_id": "<uuid>",
  "etag": "sha256:…",
  "bundle": {
    "server_name": "…",
    "driver": "kea",
    "roles": [...],
    "server": { "interfaces": ["*"], "dhcp_socket_type": "raw",
                "kea_thread_pool_size": 1, "kea_packet_logging": true },
    "scopes": [
      {
        "subnet_cidr": "10.0.0.0/24",
        "lease_time": 3600,
        "options": {…},
        "pools": [{"start_ip": "...", "end_ip": "...", "pool_type": "dynamic"}, …],
        "statics": [{"ip_address": "...", "mac_address": "...", "hostname": "..."}, …],
        "ddns_enabled": false
      }, …
    ],
    "client_classes": [{"name": "...", "match_expression": "...", "options": {…}}, …],
    "failover": { ... } | null
  },
  "pending_ops": [...]
}
```

Shipped 2026.04.21-2: `render_kea.py:_scope_to_subnet` maps each wire scope to a Kea `subnet4` entry — `subnet_cidr` → `subnet`, `pools[start_ip,end_ip,pool_type]` → `{"pool": "start - end"}` (only `dynamic` pools are emitted; `excluded` / `reserved` are IPAM bookkeeping and must **not** become Kea lease pools), `statics[ip_address,mac_address,hostname]` → `reservations[ip-address,hw-address,hostname]`. Client-class `match_expression` → Kea `test`. Subnet `id` is derived deterministically from the CIDR via truncated SHA-256, so a config reload never orphans active leases by renumbering subnets.

**Socket type (issue #365).** The `server.dhcp_socket_type` field drives `Dhcp4.interfaces-config.dhcp-socket-type`. It is derived from the server group's `dhcp_socket_mode` in `services/dhcp/config_bundle.py` (`direct` → `raw`, `relay` → `udp`) and is part of `ConfigBundle.compute_etag()`, so flipping the mode shifts the ETag and the agent re-renders on its next long-poll. The default is `raw` (AF_PACKET) so Kea hears broadcast `DHCPDISCOVER`s from directly-attached clients; the agent's `render_kea.py` also falls back to `raw` when an older control plane omits the `server` block. `raw` needs `CAP_NET_RAW` (appliance DaemonSet + shipped compose Kea services grant it). DHCPv6 has no socket-type concept — the field applies to `Dhcp4` only.

**Packet path (issue #980).** Two more `server` fields, both rendered
explicitly rather than left to Kea's defaults, both folded into the ETag.

`kea_thread_pool_size` → `Dhcp4`/`Dhcp6` `multi-threading.thread-pool-size`.
Kea's own default is `0`, meaning one worker per CPU `hardware_concurrency()`
reports — the *machine's* count, with no regard for the container's cgroup
share. Verified against kea-dhcp4 3.0.3: a container limited to 0.20 CPU
starts ten workers, which then compete inside that cgroup with the single
thread draining the receive socket, and packets are lost in the kernel before
Kea reads them. The default is `1`; `0` restores Kea's auto-sizing. Note that
`enable-multi-threading` stays **true** — this is a resize, not a mode change,
because MT-off makes one thread both receive and process (measured 15,170
socket drops where a pool of one had none) and also flips host-reservation
lookup order.

Kea's HA hook does **not** keep independent HTTP pools by default:
`http-listener-threads` / `http-client-threads` default to `0`, which Kea
reads as *"same as `thread-pool-size`"*, not as an independent auto-size.
Measured by counting OS threads with the hook loaded — pool=1 gave 8 threads
and pool=8 gave 29, a delta of 21 for a pool delta of 7, i.e. three pools of
N. Left alone, the packet-path fix would have taken HA's peer HTTP
concurrency to 1 as a side effect, so `_ha_hook` now renders an explicit
`multi-threading` block pinning both to 4 (a decoupling constant, not a
tuned one — the HA threads do short LAN POSTs and never contend for the
receive thread). With it, the same measurement gives 14 threads at pool=1 and
21 at pool=8: a delta of exactly the core pool.

`kea_packet_logging` → when false, appends a `kea-dhcpN.packets` logger at
`WARN`, silencing `DHCP4_PACKET_RECEIVED` / `DHCP4_PACKET_SEND`. Default
true (today's behaviour); off is worth ~1.30x more packets served. The child
declares **no `output_options`** and inherits the parent's — verified against
kea-dhcp4 3.0.3: at DEBUG with no outputs of its own every packet line still
reached both stdout and the shipped file, and at WARN none did while the
parent's INFO lines kept flowing. Copying the parent's appenders also works
but puts a second `RollingFileAppender` on one path with its own rotation
state, so at 50 MB one renames the file while the other holds the old
descriptor. `kea-dhcpN.dhcpN` is deliberately never silenced: at INFO it
carries `DHCP4_OPEN_SOCKETS_FAILED`, `DHCP4_CONFIG_COMPLETE`,
`DHCP4_STARTED` and `DHCP4_MULTI_THREADING_INFO`, the last being the line
that confirms the pool size took effect.

Both also appear in the control-plane-side `KeaDriver.render_config`, which
backs the **Rendered config** tab. That render is a *preview*, not a copy of
the file the agent writes — it omits the control socket, hooks, timers,
expired-lease processing and the full logger block, and does not parse as a
Kea config on its own. What it does carry is the group tunables an operator
just set, which is the same rule `dhcp_socket_type` (#365) and
`cache-threshold` (#637) already follow: `thread-pool-size` renders in full,
and `kea_packet_logging` renders as the `kea-dhcpN.packets` severity
override alone (nothing when it is on). Full measurements:
[`DHCP.md` §4c](../features/DHCP.md).

### HA coordination

Kea's built-in `libdhcp_ha.so` hook handles pool coordination between paired servers. Under the group-centric data model (shipped 2026.04.21-2), SpatiumDDI treats a `DHCPServerGroup` with exactly two Kea members as an implicit HA pair — HA tuning lives on the group, per-peer URLs live on each `DHCPServer.ha_peer_url`. There is no separate "failover channel" object any more.

- `_resolve_failover` in `backend/app/services/dhcp/config_bundle.py` walks the server's group. If the group has ≥ 2 Kea members and each has a non-empty `ha_peer_url`, it emits a `FailoverConfig` carrying the group's mode / heartbeat / max-response / max-ack / max-unacked tuning and both peers' URLs. Members are sorted by `id` so both peers render an identical `peers` array.
- The agent's `render_kea.py:_ha_hook()` injects `libdhcp_ha.so` alongside the always-loaded `libdhcp_lease_cmds.so` (the HA hook depends on it).
- **Peer URL hostname resolution** — Kea's HA hook parses peer URLs with Boost asio directly and only accepts IP literals. Hostnames like `http://dhcp-kea-2:8000/` fail with `bad url ...: Failed to convert string to address`. `render_kea._resolve_peer_url` resolves the hostname agent-side (via the container's resolver — Docker DNS on compose, k8s DNS on Kubernetes) before emitting the URL into Kea config. IPv4/v6 literals pass through unchanged.
- **Peer IP drift self-healing** — `PeerResolveWatcher` (`agent/dhcp/spatium_dhcp_agent/peer_resolve.py`) runs as a 30 s background thread, re-resolves every peer hostname from the last-applied bundle's failover block, and if any resolution has changed, triggers the renderer + reload via the agent's existing apply pipeline. Resolution failures are treated as transient (cached IP kept, retried next tick) so a brief DNS outage doesn't thrash reloads. Matters most on k8s where pod IPs churn; on compose bridges IPs are mostly stable across `restart`, but `docker compose --force-recreate` WILL reshuffle bridge allocations.
- **Port topology** — Kea 2.6's HA hook spins up its own `CmdHttpListener` bound to the `this-server` peer URL to receive peer-to-peer traffic. That **must not** collide with `kea-ctrl-agent`. SpatiumDDI's Kea image dedicates:
  - `:8000` — HA hook peer-to-peer HTTP (the URL advertised to the partner).
  - `:8544` — `kea-ctrl-agent` operator-facing REST (deliberately off 8000).
- Each peer's `this-server-name` is derived from its `DHCPServer.name`; the `peers` array carries both entries with roles `primary` + (`standby` in hot-standby / `secondary` in load-balancing).
- Agent-side `HAStatusPoller` (`agent/dhcp/spatium_dhcp_agent/ha_status.py`) calls `status-get` on the Kea unix socket every ~15 s and POSTs the state to the control plane — drives the live HA pill in the UI. Kea 2.6 moved HA state into the generic `status-get` response under `arguments.high-availability[]`; the poller also accepts pre-2.6 `ha-status-get` shapes for forward-compat.
- **Bootstrap reload** — on agent startup the entrypoint launches `kea-dhcp4` in the background with the Dockerfile-baked config, then the agent re-renders the cached bundle and issues `config-reload` with up to 15 s of retry so Kea picks up HA even on cold starts where the control socket isn't live yet.
- **Daemon supervision** — both `kea-dhcp4` and `kea-ctrl-agent` run under per-daemon supervise loops in the container entrypoint. Each loop scrubs stale `/run/kea/*.pid` files before every launch (Kea only removes its own PID on GRACEFUL shutdown, so SIGKILL / hard crash / mid-init SIGTERM leaves the file behind and `createPIDFile` refuses to start with `DHCP4_ALREADY_RUNNING`), restarts the daemon on transient crashes (e.g. the Docker bridge-attach race that intermittently fails HA-hook bind with "Address not available" right after a container restart), and trips a 5-in-30s crash-loop guard so a truly broken config surfaces instead of looping forever. SIGTERM handlers inside each loop forward to the live daemon AND flip a stopping flag so we don't restart during container shutdown.
- The driver does **not** replicate leases itself — Kea's hook talks directly to the peer's HA listener. SpatiumDDI just renders the config.
- **Scope mirroring** is automatic under the group-centric model: scopes / pools / statics / client classes live on the group, and every member of the group renders the same Kea config. Operators configure scopes once, both peers serve them.

### Agent bootstrap

Identical pattern to the DNS agent ([`DNS_AGENT.md`](../deployment/DNS_AGENT.md)):

1. Agent starts with `SPATIUM_AGENT_KEY` (PSK) in its environment; the control plane validates it against its own `DHCP_AGENT_KEY`.
2. Calls `POST /api/v1/dhcp/agents/register` with the PSK in the `X-DHCP-Agent-Key` header → receives a per-server rotating JWT (`agent_token`).
3. Long-polls `GET /api/v1/dhcp/agents/config` with the JWT and an `If-None-Match` ETag.
4. On 401 or 404, re-bootstraps from the PSK.
5. Caches the last-good bundle under `/var/lib/spatium-dhcp-agent/`.

---

## 4. Windows DHCP driver (agentless + read-only, Path A)

Located at [`app/drivers/dhcp/windows.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/windows.py). Class: `WindowsDHCPReadOnlyDriver`.

### Capabilities

| Operation | Status | How |
|---|---|---|
| `get_leases` | ✅ | `Get-DhcpServerv4Scope` → `Get-DhcpServerv4Lease` per scope via WinRM. |
| `get_scopes` | ✅ | `Get-DhcpServerv4Scope` + options + exclusions + reservations in one PowerShell call, JSON-serialised back. |
| `apply_scope` / `remove_scope` | ✅ | `Add-DhcpServerv4Scope` / `Remove-DhcpServerv4Scope`. Called per-object from the API — not via a bundle push. |
| `apply_reservation` / `remove_reservation` | ✅ | `Add-DhcpServerv4Reservation` / `Remove-DhcpServerv4Reservation`. |
| `apply_exclusion` / `remove_exclusion` | ✅ | `Add-DhcpServerv4ExclusionRange` / `Remove-DhcpServerv4ExclusionRange`. |
| `get_failover_relationships` | ✅ | `Get-DhcpServerv4Failover` — read-only (#1110). `ok` false means the read failed, not "no relationships". |
| `probe_scopes` | ✅ | Live presence / state / range of given scopes + the server's relationships, in one round trip — what the write-through plans from (#1110). |
| Failover relationship management | ❌ | `Add-/Set-/Remove-DhcpServerv4Failover` and `Add-DhcpServerv4FailoverScope` are #1110 Phase 2. |
| `render_config` | ❌ | Raises `NotImplementedError`. Windows DHCP is cmdlet-driven, not config-file-driven. |
| `apply_config` / `reload` / `restart` / `validate_config` | ❌ | Raise `NotImplementedError`. |

The `/sync` endpoint (bundle push) rejects read-only drivers; the `/{server_id}/sync-leases` endpoint and per-object CRUD drive all writes instead.

### Credentials

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

The service account needs to be in the Windows `DHCP Users` local group (read-only) or `DHCP Administrators` (for per-object writes). See [WINDOWS.md](../deployment/WINDOWS.md) for the account setup and WinRM configuration.

### PowerShell calls

The driver shells out to pre-built PowerShell strings with `$ErrorActionPreference = 'Stop'` and `ConvertTo-Json -Compress -Depth 3` for machine-readable output. An example — the lease pull:

```powershell
$scopes = Get-DhcpServerv4Scope | Where-Object { $_.State -eq 'Active' }
$all = @()
foreach ($s in $scopes) {
    $leases = Get-DhcpServerv4Lease -ScopeId $s.ScopeId -AllLeases
    foreach ($l in $leases) {
        $all += [PSCustomObject]@{
            ScopeId       = $s.ScopeId.ToString()
            IPAddress     = $l.IPAddress.ToString()
            ClientId      = $l.ClientId
            HostName      = $l.HostName
            AddressState  = $l.AddressState
            LeaseExpiryTime = if ($l.LeaseExpiryTime) { $l.LeaseExpiryTime.ToString('o') } else { $null }
        }
    }
}
$all | ConvertTo-Json -Compress -Depth 3
```

WinRM transport is `pywinrm` (`winrm.Session`), wrapped in `asyncio.to_thread` because `pywinrm` is synchronous. Transport, port, and TLS options come from the credential dict.

### Lease → IPAM mirror

Leases drive a scheduled Celery beat task ([`app.tasks.dhcp_pull_leases.auto_pull_dhcp_leases`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/tasks/dhcp_pull_leases.py)). Beat fires every 60s; the task gates on `PlatformSettings.dhcp_pull_leases_enabled` / `dhcp_pull_leases_interval_seconds`, so the UI can change cadence without restarting beat.

Per poll cycle:

1. Enumerate agentless DHCP servers.
2. For each, call `driver.get_leases(server)`.
3. Upsert into `DHCPLease` by `(server_id, ip_address)`.
4. If the lease's IP falls inside a known subnet, mirror it into `IPAddress` with `status="dhcp"` and `auto_from_lease=True`.
5. **Absence-delete** — any active `DHCPLease` row for this server whose IP didn't come back in the wire response is deleted along with its `auto_from_lease=True` IPAM mirror. The driver's `get_leases()` returns only currently-active leases, so absence means the server deleted it (admin purged / client released / etc.). `PullLeasesResult` gains `removed` + `ipam_revoked` counters; both flow into the scheduled-task audit row and the manual sync response. See [features/DHCP.md §15.3](../features/DHCP.md) for the rationale.
6. The time-based `dhcp_lease_cleanup` sweep still handles leases that drift past `expires_at` between polls. The two mechanisms overlap harmlessly.

### Scope reconcile (topology)

The same beat task runs a **topology** phase ahead of the lease phase, for any driver that implements `get_scopes` — which today means Windows DHCP alone. For each wire scope whose CIDR exactly matches an IPAM `Subnet.network` (no auto-create), the scope row is upserted and its pools + reservations are **diff-merged** against the wire. Reservations are keyed on MAC, pools on `(start, end)`; a MAC / range that is already tracked is updated in place, so **a reservation keeps its row id across polls**.

That id stability is load-bearing (#620). A reservation owns an `ip_address` mirror that back-links to it by id, so anything that re-creates the row (the pre-#620 reconciler Core-DELETEd and re-inserted every reservation, every poll) leaves the mirror pointing at a row Postgres has dropped — an address that is neither allocated nor free, and that deleting the reservation in the UI never frees, because the lookup keys on the *current* id. Merging also means an unchanged reservation is not written at all, which is what keeps the reconciler from re-publishing its DNS records on every tick.

Reservations found on the server are mirrored into IPAM exactly like UI-created ones (`status="static_dhcp"`), via the same `upsert_ipam_for_static` helper — a reservation is an allocation whoever made it, and an IPAM that doesn't show it is an IPAM that will hand the address out twice. The mirror upsert (and therefore the DNS re-sync it performs) fires only when the reservation's address or hostname actually moved, or when its mirror is missing or stale.

Three things the merge deliberately refuses to do:

* **Absence-delete against a wire it can't trust.** Absence normally means "deleted on the server" — the reservation is dropped, its mirror deleted and its DNS torn down. But `_PS_LIST_TOPOLOGY` enumerates options / exclusions / reservations inside per-list `try/catch` blocks, so a failure hands back an *empty array*, not an error. The driver therefore reports `pools_ok` / `statics_ok` alongside each list, and the reconciler also declines to delete when a wholly-empty list arrives while it tracks rows (the same call the lease path's zero-wire floor guard makes, #482). Both cases record a soft error on the sync result. The trade is deliberate: a stale reservation an operator can delete beats a reservation and its A record torn down on a blip.
* **Act on rows newer than its own information.** The wire is a snapshot taken before a multi-second WinRM round-trip. A reservation created or edited *after* that snapshot is judged against stale data, so it is skipped — otherwise a reservation created in the UI mid-poll is "absent from the wire" and gets deleted out from under the operator.
* **Write an address change row-by-row.** Renumbering reservations on the server (`A` takes `B`'s address) produces a wire whose end state is legal but whose intermediate states violate `uq_dhcp_static_scope_ip` — which would abort the poll, and keep aborting it, since the wire keeps reporting the same state. Movers are lifted out of that partial index (it is `WHERE deleted_at IS NULL`) inside the transaction, re-addressed, and put back.

`PullLeasesResult` reports `scopes_imported` / `scopes_refreshed` / `scopes_skipped_no_subnet` plus `pools_synced` / `statics_synced` (created **or changed**) and `pools_removed` / `statics_removed`. Because the merge is a diff, a steady-state poll reports zeros.

### Failover relationships and multi-member groups (#1110)

The group model — every member serves every scope — is what Kea HA makes true and what a pair of Windows servers makes true **only** where a failover relationship covers the scope. A relationship is a first-class named object with an explicit per-scope membership list; two servers being partners says nothing about whether a *given* scope is in their relationship, so it cannot be inferred from scope enumeration. Two Windows servers holding one scope without one hand out the same addresses, and nothing on either reports a problem.

**What is read.** The topology phase of the lease pull (`pull_leases._observe_topology`) runs `get_failover_relationships` alongside `get_scopes` and stores both, per server: `dhcp_failover_relationship` (one row per observing server and relationship name — both partners report it, each from its own side) and `dhcp_server_scope_state` (which scopes the server holds, keyed by CIDR, with range, exclusions and a configuration hash). Freshness is per server (`DHCPServer.scopes_observed_at` / `failover_observed_at`), so a poll that finds nothing changed writes one timestamp, not every row. A failed failover read keeps the last-known relationships and records `failover_error`; the read is skipped when `get_scopes` itself failed, since a third WinRM call to an unreachable server only adds another timeout.

**The classifier.** [`services/dhcp/windows_failover.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/dhcp/windows_failover.py) `classify_serving` is pure: given, per member, whether it holds the scope, its state and range, and the relationship covering the scope there, it returns a verdict — `single_server`, `failover`, `failover_one_sided` (partner outside the group), `split_scope` (disjoint effective ranges, no relationship), `uncoordinated` (overlapping ranges, no relationship: the outage), `unknown` (a holder's relationships could not be read) or `not_on_windows`. Two holders are a pair when both report a relationship of the same name covering the scope — the name is the evidence, so it needs no matching of `PartnerServer` against the host SpatiumDDI dials; a side whose partner positively names a *third* member rules the pairing out. The write-through feeds it a live probe; the poll, the REST views and the MCP tool feed it the stored rows.

**The write-through** ([`windows_writethrough.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/dhcp/windows_writethrough.py)), on a group with two or more Windows members:

- *Scope upsert* probes every member concurrently (a member that cannot be probed fails the write — its silence might mean it holds the scope), writes to the holders only with `apply_scope(create_if_missing=False)`, and refuses (422) activating a scope held by several members no relationship covers. The create guard is in the PowerShell, next to the write, so a plan made from a probe seconds old still cannot create what it did not intend.
- *A new scope* — one no member holds — goes to ONE member (`WindowsPlacement`, the scope-create body's `windows_placement`): created on one side of a failover relationship and then `add_failover_scopes`'d into it, so Windows copies it to the partner; or created on one named server alone. With no placement a group whose members share exactly one drivable relationship uses it; otherwise 422 listing the choices. A failed join removes the half-created scope before the 502 rolls the row back.
- *Scope delete* of a scope a failover pair in the group covers runs `remove_failover_scopes` on one side (deleting the partner's copy) and then `remove_scope` there — when that side can make the second hop. Otherwise, and whenever the partner is outside the group, 409 with the Windows step; other scopes are removed from their holders only.
- *Split scopes* — several holders, no relationship, disjoint effective ranges — are simulated before any write that could widen a holder's range (`_split_collapses`): a new range, or removing / moving an exclusion, is refused (422) when the holders' parts would then overlap. Adding an exclusion only narrows, so it needs no probe.
- *Reservations and exclusions* need no probe: `apply_reservation` / `apply_exclusion` check, in the same script, that the server holds the scope, and return `False` without writing when it does not. Only "no member holds it" is refused (409).
- **A covered scope is written to both partners**, because Windows failover syncs leases between partners but not configuration — option values, exclusions and reservations move only on `Invoke-DhcpServerv4FailoverReplication`. Writing one partner would leave the other stale at failover. Replication is an explicit operator action instead (below), for drift made in the DHCP console.

**Managing relationships (Phase 2).** [`windows_failover_manage.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/dhcp/windows_failover_manage.py) drives `create_` / `update_` / `delete_failover_relationship`, `add_` / `remove_failover_scopes` and `replicate_failover` on the driver — `Add-` / `Set-` / `Remove-DhcpServerv4Failover`, `Add-` / `Remove-DhcpServerv4FailoverScope`, `Invoke-DhcpServerv4FailoverReplication`. Imperative, not desired-state: each action runs one cmdlet, records what the server reports back into the observation rows and re-reads the partner best-effort; nothing reconciles Windows towards a stored copy.

- **The second hop.** Every one of these cmdlets acts on both partners from the one server it runs on, so the WinRM logon there must authenticate onward. Only `credssp` can (`SECOND_HOP_TRANSPORTS`); NTLM / Basic are network logons with nothing to delegate, and the image has no GSSAPI stack for Kerberos. `failover_management_blocker` decides from the stored credentials and the action is refused (422) before anything is sent. `requests-credssp` ships in the image for this — before #1110 the server form offered CredSSP while the library was missing, so choosing it failed every call.
- **Where it runs.** Create and add-scopes run on the member that HOLDS the scopes (Windows copies them to the partner, and refuses when the partner already has one — checked live first). Delete and remove-scope run on the member that KEEPS them (Windows deletes the partner's copy; the caller picks, default hot-standby Active else lowest-named). Replicate runs on the named source. An update carrying a load-balance share or a hot-standby role must name its side — Windows applies both to the server the cmdlet runs on.
- **Size.** Each op is its own short script, with the relationships read back in a second call. A first cut that held every op plus the read in one script encoded to ~12,700 characters against the 7,800 command-line budget, so every call would have been refused before it was sent; a long scope list is sent in chunks of `_FAILOVER_SCOPE_CHUNK` (a create sends the first chunk and adds the rest). A test pins every op, with maximal inputs, under the budget.
- **The shared secret** travels in the base64 payload, is never interpolated, never stored or logged, and is not in the audit row (`shared_secret_set` only). Errors are re-thrown as their message alone, so an error record cannot carry the script.

**Kea + Windows in one group.** Refused at server create / move (422): Kea renders every active scope of its group and cannot coordinate with Windows failover. An existing mixed group lists `kea_members` in the report, and every active scope a Windows member also holds is reported `uncoordinated`.

Every existence check enumerates `Get-DhcpServerv4Scope` under `-ErrorAction Stop` rather than querying one id under `SilentlyContinue`, because the latter returns `$null` for a lookup that failed as well as for one that found nothing — and "failed" would then read as "not here, skip it".

**The reconcile owner.** Each member's topology pass used to merge its own view of the group's scopes, so two partners that disagreed (ordinary, since they do not sync configuration) undid each other on every poll — creating and absence-deleting reservations, their IPAM mirrors and DNS records. One member now imports each shared scope: the lowest-named holder whose view is fresher than `OBSERVATION_FRESH_FOR` (15 min), decided the same way from either side, so both passes agree without coordinating and an unreachable member drops out. The others are compared against it by configuration hash and a difference is reported as drift (`PullLeasesResult.warnings`), never merged.

**Lease teardown** (`lease_cleanup.peer_holds_active_lease`) — a failover pair reports each lease once per partner, but the IPAM mirror and its DDNS records are shared. `purge_lease`, the expiry sweep and the Kea release/expire path leave them in place while another server in the same group holds an active, unexpired lease on the address.

**Views.** `GET /dhcp/server-groups/{id}/failover`, `GET /dhcp/scopes/{id}/failover`, the `find_dhcp_failover_relationships` MCP tool and the default-on `dhcp_scope_uncoordinated` alert rule all build from the stored rows through one report builder ([`windows_failover_report.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/dhcp/windows_failover_report.py)) — never a live read — so a badge, a copilot answer and an alarm cannot disagree. There is deliberately no `propose_*` tool for the management routes: they create and delete scopes on the partner and carry the shared secret.

### The orphaned-mirror backstop

A reservation owns its `ip_address` mirror by id, and every path that destroys a reservation is responsible for releasing that mirror first. When one doesn't, the result is nasty out of proportion to the mistake: the address sits at `status="static_dhcp"` pointing at a row Postgres has dropped, so it is neither allocated nor free, nothing hands it out, and *no amount of clicking in the UI frees it* — every release path looks the mirror up by the reservation's current id and matches nothing. It took a one-shot repair migration (`d7b3f2a9c15e`) to clear the last batch.

So there is a recurring backstop: `app.tasks.dhcp_mirror_sweep.sweep_orphaned_mirrors`, hourly, which is that migration's step 1 made permanent. It frees any `static_dhcp` row whose **non-NULL** back-link resolves to no live reservation, deleting the row (a freed-but-persisted row still renders in the subnet table and still counts toward utilization) after tearing down its DNS. If the reservation is merely soft-deleted, the operator-authored columns are snapshotted onto it first so a Trash restore stays lossless.

The predicate is deliberately narrow: a `static_dhcp` row with a **NULL** back-link is left alone, because an operator can set that status by hand and a sweep that deletes hand-made rows is worse than the bug it fixes. On a healthy install it matches nothing and writes nothing — so a non-zero `mirrors_freed` (logged at WARNING, and audited) is itself the signal that some path is still skipping its mirror release.

### Batched WinRM writes

Per-object writes against Windows DHCP used to round-trip WinRM **per reservation / exclusion** — a bulk delete of 200 reservations took minutes. The driver now groups writes into a single PowerShell script per `(server, scope)` chunk.

**Driver surface.** New plural methods on the ABC:

```python
class DHCPDriver(ABC):
    async def apply_reservations(
        self, server: Any, *, items: Sequence[ReservationItem]
    ) -> list[ReservationResult]: ...

    async def remove_reservations(
        self, server: Any, *, items: Sequence[RemoveReservationItem]
    ) -> list[ReservationResult]: ...

    async def apply_exclusions(
        self, server: Any, *, items: Sequence[ExclusionItem]
    ) -> list[ExclusionResult]: ...
```

Default ABC impls call the singular method in a loop — Kea inherits the plural interface without changes.

**Windows batch size — 30 ops per chunk.** `pywinrm.run_ps` ships the script as a single CMD.EXE command line (8191-char cap, see [DNS_DRIVERS.md §3.7](DNS_DRIVERS.md#37-batched-winrm-dispatch) for the full math). DHCP payloads are leaner than DNS — each reservation / exclusion op is ~60 raw chars of JSON vs. DNS's ~160 — so the cmdline limit is farther away, but capped at 30 to stay comfortably inside it. Documented in `_WINRM_BATCH_SIZE` in [`drivers/dhcp/windows.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/windows.py).

**Dispatcher.** `push_statics_bulk_delete` groups by `(server, scope)` so the IPAM purge-orphans path went from N×M WinRM calls to one per server. Unlike the DNS side there is no state-aware commit here: the dispatcher returns nothing and the caller deletes the `DHCPStaticAssignment` rows regardless — the push is best-effort, and the next lease poll / config bundle reconciles the server.

---

## 5. FortiGate driver (agentless + cloud push)

[`fortigate.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/fortigate.py) is the first **cloud** agentless DHCP driver: the control plane drives a FortiGate's per-interface DHCP server directly over the FortiOS REST API with an API-admin **Bearer token**, VDOM-scoped, no co-located agent. It subclasses [`AgentlessDHCPDriverBase`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dhcp/_cloud_base.py) (the shared cloud base) rather than rendering a daemon config.

### Model mapping

One SpatiumDDI `DHCPServer(driver="fortigate")` = one FortiGate device + VDOM. A `DHCPScope` (one subnet) maps to the `system.dhcp.server` object on the **interface whose primary IP+netmask CIDR equals the scope CIDR** — SpatiumDDI never creates interfaces or changes interface IPs; no match / multiple matches raise a clear error. Dynamic pools → `ip-range`; excluded/reserved pools → `exclude-range` (clipped to the dynamic range — FortiGate rejects an exclude outside the ip-range); statics → `reserved-address`; scope options → first-class fields (`default-gateway` / `dns-server1..4` / `domain` / `ntp-server1..3` / `filename` / `lease-time`) or the generic `options` subtable. Numeric options (`mtu`, `time-offset`) are emitted as `type: "hex"` big-endian — a `string` MTU would reach the client as ASCII, not a 16-bit integer.

### Write unit

The whole DHCP-server object per scope: any scope / pool / static / option edit rebuilds the full desired object from the DB and PUTs it (create-if-absent). The cloud write-through ([`services/dhcp/cloud_writethrough.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/dhcp/cloud_writethrough.py)) runs **synchronously, before commit**, so a REST failure raises `CloudPushError` (502) and rolls the transaction back — keeping the DB and the FortiGate in sync. `push_cloud_scope_upsert` fans a scope out to every cloud member of its group; cascade / group / restore paths reach it through the shared `windows_writethrough` seam.

**Child-table id stability.** FortiOS applies a parent PUT to child tables (`reserved-address` / `ip-range` / `exclude-range` / `options`) **per entry id**, not as an atomic replace. Positionally renumbered ids therefore break deletion: removing a non-last reservation shifts every later entry onto a different id, the per-id update transiently duplicates a MAC still present at the next id, and FortiOS aborts mid-apply — the wrong entries end up deleted and the push errors out. Before an update PUT, `_reconcile_child_ids` pins each desired entry to the id its logical match (by MAC / range / option code) already holds on the device, assigns new entries ids above every id in play, and removes stale device entries via explicit child-endpoint `DELETE`s (excludes before the ranges they depend on; a 404 counts as already-gone). Fresh POSTs keep the positional ids — there is no device state to pin to.

### Ownership + adopt-guard (#630)

So a push never silently overwrites or deletes a DHCP server an operator hand-managed on the FortiGate, the control plane records the FortiOS `mkey` of the object *SpatiumDDI created* on the scope (`DHCPScope.provider_refs`, keyed per cloud server) and passes it back as `provider_ref`:

* recorded mkey present → PUT that object;
* no mkey + interface empty → POST, then record the new mkey;
* no mkey + an object already exists → raise `CloudDHCPAdoptionError` → **409**, unless the operator opts in with `adopt_existing` (query param on `POST /{id}/sync`).

`_remove_scope` only deletes an object whose mkey we recorded. The `GET /{id}/fortigate-interfaces` preflight surfaces any pre-existing DHCP server (ip-range / reservation / option counts + a `managed` flag) so the clobber risk is visible before an adopt-and-sync.

### Credentials + TLS

Fernet-encrypted on `DHCPServer.credentials_encrypted`: `{"api_token", "vdom", "verify_tls", "ca_bundle_pem"}`. `verify_tls` **defaults to `True`** (the admin Bearer token is sensitive) with an optional `ca_bundle_pem` to pin a private-CA FortiGate; disabling verification logs a WARNING. The API echoes the non-secret `vdom` + `verify_tls` on the server response so the edit modal seeds the checkbox from the stored value instead of silently re-disabling it. API-created cloud servers default to **port 443** when the caller omits `port`.

### Endpoints

`POST /dhcp/servers/test-fortigate-credentials` (dry-run probe), `GET /dhcp/servers/{id}/fortigate-interfaces` (preflight), `POST /dhcp/servers/{id}/sync?adopt_existing=` (synchronous full reconcile). All three call `assert_safe_target` (advisory SSRF guard) before dialing the host.

---

## 6. Error handling

All driver methods:

- Raise `DriverConnectionError` for network / auth failures.
- Raise `DriverOperationError` for a successful connection but failed operation (e.g. PowerShell cmdlet failed, Kea validation rejected the bundle).
- Never swallow errors. Log full details at `ERROR` before raising.
- Are safe to retry — service layer handles retry via Celery task retries, drivers are not responsible for retry.

For WinRM drivers, `pywinrm` errors get caught and re-raised as `DriverConnectionError` with the PowerShell `std_err` in the message — the API surfaces this verbatim in the 502 response so the UI "Test Connection" button shows the real Windows error.

---

## 7. Adding a new driver

1. Subclass `DHCPDriver`. Implement all abstract methods. If read-only, raise `NotImplementedError` on writes.
2. Register in `app/drivers/dhcp/registry.py`:
   ```python
   _DRIVERS["my_driver"] = MyDriverClass
   ```
3. If agentless, add to `AGENTLESS_DRIVERS`. If read-only, add to `READ_ONLY_DRIVERS`.
4. Add the driver name to the enum in `DHCPServer.driver` (Alembic migration).
5. Update the UI's server create modal to render the right credential fields (see how `windows_dhcp` conditionally shows WinRM fields in `frontend/src/pages/dhcp/CreateServerModal.tsx`).
6. Add a "Test Connection" PowerShell / API probe (e.g. `POST /dhcp/servers/test-windows-credentials`) so operators can validate before saving.

---

## 8. Importing existing daemon configs (issue #129)

The **DHCP configuration importer** is separate from the driver
abstraction: drivers *render + push* config to managed servers; the
importer *reads* a foreign daemon's config one-shot and writes the
canonical SpatiumDDI rows. It never touches a live daemon's config
file. Code lives in `backend/app/services/dhcp_import/`.

**Canonical IR** (`canonical.py`) — every source parses into the same
neutral shapes: `ImportedScope` (CIDR, address family, lease times,
options, DDNS), `ImportedPool`, `ImportedReservation`,
`ImportedClientClass`, rolled into an `ImportPreview`. The shared
`commit.py` is the only module that touches the DB, so all three
sources share IPAM linkage, conflict handling, audit logging, and the
per-scope savepoint pattern.

**Parsers:**

- `kea_parser.py` — strips Kea's JSON-with-comments (`//`, `#`,
  `/* */`) string-aware, then walks `Dhcp4.subnet4` / `Dhcp6.subnet6`.
  Inverts the Kea driver's option-name map (`options.py` builds
  the inverse of `_KEA_OPTION_NAMES` / `_KEA_OPTION_NAMES_V6`). Pools
  parse both `"a - b"` and CIDR forms; `code:NN` option-data round-trips
  the same way the driver renders it. DUID-only v6 reservations are
  skipped (our reservations are MAC-keyed). Top-level `client-classes`
  import verbatim — Kea `test` expressions are SpatiumDDI's native class
  shape. `hooks-libraries` / `control-socket` / `lease-database` /
  `loggers` are listed unsupported.
- `windows_dhcp_pull.py` — reuses `WindowsDHCPReadOnlyDriver.get_scopes()`
  (the same Path A read path the Logs surface uses), reshaping its
  neutral dicts. IPv4 only; option names already arrive canonical.
- `isc_dhcp_parser.py` — a self-contained tokeniser (comment- +
  string-aware) → recursive-descent statement tree → walker.
  `subnet` / `subnet6` → scopes; `range` / `range6` / `pool {}` →
  pools (with `allow members of "class"` → `class_restriction`);
  `host` → reservations (global hosts attach to the subnet containing
  their `fixed-address`); `option` → canonical options;
  `shared-network` / `group` are flattened. ISC's runtime-expression
  classifier DSL doesn't map to our model, so `class` declarations are
  emitted `supported=false` (manual review, never auto-created);
  `failover` / `key` / `zone` / `include` are listed unsupported.

**IPAM linkage** — `DHCPScope.subnet_id` is mandatory, so each commit
resolves a `Subnet`: link to an existing one whose CIDR matches, or
auto-create under the operator-chosen IP space + block (containment +
non-overlap validated). Link-only mode (no space/block) reports an
actionable per-scope error for unmatched CIDRs rather than failing the
whole batch.

**Provenance** — `import_source` (`kea` / `windows_dhcp` / `isc_dhcp`)
+ `imported_at` are stamped on every `dhcp_scope` / `dhcp_pool` /
`dhcp_static_assignment` / `dhcp_client_class` row the importer creates
(migration `c7f1a3e58b94`). Endpoints under
`/api/v1/dhcp/import/{kea,windows,isc}/…` are gated by the `dhcp.import`
feature module + superadmin RBAC.

See [Migration](../features/MIGRATION.md) for the operator-facing flow
and the DNS-importer sibling.

---

## Related docs

- [DHCP Features](../features/DHCP.md) — user-facing: scopes, pools, leases, HA modes.
- [Getting Started](../GETTING_STARTED.md) — where DHCP fits in the setup order.
- [Windows Setup](../deployment/WINDOWS.md) — WinRM prerequisites, service accounts.
- [DNS Drivers](DNS_DRIVERS.md) — the parallel structure on the DNS side.

---

## Kea 3.0 — HA has no rolling-upgrade path (#637)

Kea 3.0's HA hook is **wire-incompatible with peers older than 2.7.0**. 3.0
introduced the "released" lease state (value `3`) into the lease updates that HA
partners exchange, and an older peer rejects them outright.

**There is therefore no rolling 2.6 → 3.0 upgrade for an HA pair — both members
must cross in the same window.** This is upstream's guidance, not a SpatiumDDI
limitation, and there is nothing the orchestrator can do about it.

That collides directly with the #296 rolling-upgrade orchestrator, whose whole
primitive is *one node at a time*: cordon → drain → swap slot → reboot →
uncordon → next. Midway through such a run, one Kea is on 3.0 and its partner is
still on 2.6, and the pair falls out of sync until the second node lands.

Two things make this visible rather than a surprise:

1. **`dhcp_server.kea_version`** — the agent reads the running daemon's version
   off the control socket (`version-get`) and reports it on every heartbeat. This
   is the Kea *daemon* version, distinct from `agent_version` (the Python agent).
   `NULL` means "not reported yet" and must be treated as **unknown**, never as
   "old".
2. **The `kea_ha_version_skew` preflight check** — runs as part of the
   rolling-upgrade preflight and classifies the fleet:

   | Condition | Level | Why |
   |---|---|---|
   | Members of one HA group already on different Kea majors | `warn` | HA lease sync is broken *now* — and finishing the upgrade is what converges them. |
   | An HA group is on pre-3.0 Kea | `warn` | This run will cross the boundary node-at-a-time; HA degrades until it completes. |
   | A member has never reported a version | `warn` | Unknown, so we can't rule out the crossing. |
   | Every member already on Kea ≥ 3 | `ok` | Nothing to do — and the check self-clears, so it isn't a permanent nag. |

Two pieces of scoping keep the check honest, and getting either wrong turns it
into something that blocks unrelated work:

* **Appliance nodes only.** The orchestrator never touches docker / k8s DHCP
  agents (they upgrade through the manual copy-paste path), so counting them
  would let two unrelated containers veto an appliance-cluster upgrade.
  `deployment_kind` is matched strictly against `appliance`.
* **Real HA pairs only.** HA is *not* "≥ 2 Kea members" — `_resolve_failover`
  renders the HA hook only when there are ≥ 2 Kea members **and every one has a
  non-empty `ha_peer_url`**. Without a URL there is no HA relationship and
  nothing for an upgrade to disrupt. The check uses the same predicate, or it
  would invent pairs the renderer never built.

**The check never returns `fail`.** A `fail` sets `can_start=False`, and blocking
would be exactly backwards: an already-mixed pair has broken HA *right now*, and
completing the rolling upgrade is what gets both members onto one version.
Refusing to start would strand the operator in the broken state. DHCP also keeps
serving throughout (each Kea answers from its own lease store) — only the HA
replication *between* peers is disrupted.
