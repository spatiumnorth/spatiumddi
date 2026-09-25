# DNS Agent / Container Architecture

> Design spec for how SpatiumDDI ships, enrolls, configures, and operates the
> managed DNS service containers (BIND9) that sit on the data plane.
>
> **Status:** Implemented — see post-#170 architecture note below.
>
> **Related:** `CLAUDE.md` (#5 config caching, #8 incremental DNS, #10 driver
> abstraction, #11 multi-arch), `docs/features/DNS.md`,
> `docs/drivers/DNS_DRIVERS.md`, `docs/OBSERVABILITY.md`.

---

## Post-#170 architecture (2026-05-14)

The Appliance role (was "Application" pre-#272) + `spatium-supervisor` from
[#170](https://github.com/spatiumnorth/spatiumddi/issues/170)
reshape this document's scope. Read this first; the historical
sections below describe the pre-#170 agent surface (still
functional for in-field installs — they keep registering against
`/dns/agents/register` with the long PSK).

**What stays in the DNS service container**: the agent sidecar
(`agent/dns/spatium_dns_agent/`) still owns every DNS-service-level
call: `POST /dns/agents/register` (the *service* identity, distinct
from the supervisor's appliance identity), the ConfigBundle long-poll
(`GET /dns/agents/config`), DDNS lease events, per-zone serial
reporting on `POST /dns/agents/zone-state`, BIND9 query-log shipping,
and metrics push. None of those changed in #170 wave C.

**What moved to the supervisor (#170 Wave C1)**: every
appliance-host concern. Slot telemetry, slot-upgrade trigger writes,
reboot trigger, SNMP / chrony reload triggers, deployment-kind
detection. The DNS service container drops the four host bind mounts
(`/etc/spatiumddi-host`, `/boot/efi-host`,
`/var/lib/spatiumddi-host/release-state`, `/run/udev`); the supervisor
mounts them instead and is the single producer of host-side state.

**Service heartbeats** (`POST /dns/agents/heartbeat`) no longer
carry the slot / deployment / upgrade-state block. The supervisor's
new `POST /api/v1/appliance/supervisor/heartbeat` is the single
producer of appliance-row telemetry now.

**Installer wizard** for fresh installs uses the **Appliance**
role (was "Application" pre-#272; one of Full stack / Frontend / core /
Appliance). Operators no longer pick `dns-agent-bind9` /
`dns-agent-powerdns` at the installer prompt; the control plane assigns
roles after admin approval in the Fleet tab. The legacy `dns-agent-*`
role names alias to the appliance role in firstboot so existing
in-field appliances keep booting through a slot upgrade.

The rest of this document — driver protocol, config layout, etc. —
is unchanged and still authoritative for the service-container half
of the split.

---

## 0. Terminology

| Term | Meaning |
|---|---|
| **Control plane** | The SpatiumDDI FastAPI + PostgreSQL + Celery stack. Source of truth. |
| **Data plane** | Running DNS daemons (BIND9) that actually answer queries. |
| **Agent** | The SpatiumDDI-shipped sidecar process that supervises a DNS daemon, renders configs, applies records, and talks to the control plane. |
| **DNS container** | A container image containing both the DNS daemon and the agent. |
| **Driver** | Server-side (control-plane) Python code implementing `DNSDriverBase` per daemon flavor (see `docs/drivers/DNS_DRIVERS.md`). |

---

## 1. Container Role & Topology

### Decision

**One image per DNS flavor, agent baked in as a second process, supervised by a lightweight init (`tini` + a small Python supervisor).**

The agent images that ship:

| Image | Processes | Purpose |
|---|---|---|
| `ghcr.io/spatiumnorth/dns-bind9` | `named` + `spatium-dns-agent` | Authoritative and/or recursive BIND9 |
| `ghcr.io/spatiumnorth/dns-powerdns` | `pdns_server` + `spatium-dns-agent` | Authoritative PowerDNS (LMDB backend) |
| `ghcr.io/spatiumnorth/dns-technitium` | `dotnet DnsServerApp.dll` + `spatium-dns-agent` | Authoritative Technitium DNS Server (v1: primary zones + standard records) |

The **agent is the same Python codebase** (`spatium_dns_agent`) in every image; the DNS daemon differs. The agent abstracts daemon specifics internally (symmetric to the control-plane driver, but on the container side).

### Rationale

- **Single image per flavor** keeps operational surface small and lets the agent run `rndc`, write `named.conf`, manage the  SQLite/pgsql backend, and own the daemon lifecycle locally — none of which a detached sidecar can do without shared volumes and ambient capabilities.
- **Not a standalone sidecar** because BIND9 config-file edits + `rndc reconfig` require filesystem and UNIX socket co-location. A sidecar model adds complexity (shared PID namespace, shared volumes) with no benefit at our scale.
- **Not a single universal image** because the daemons have different footprints and dependencies. Bundling every flavor into one image bloats it and widens the attack surface.

### Alternatives considered

- *Thin sidecar + upstream image* (e.g. `internetsystemsconsortium/bind9`): rejected — we lose control of base OS, healthchecks, multi-arch, and CVE response cadence.
- *Agent-less pure API management* (control plane SSHes into each server): rejected — violates non-negotiable #5 (local config cache) and is brittle across network partitions.

---

## 2. Auto-Registration Protocol

### Decision

**Pre-shared bootstrap key (`DNS_AGENT_KEY`) for first-contact registration, then per-server JWT (`agent_token`) issued by the control plane, rotated on each heartbeat.** The existing `/api/v1/dns/agents/register` + `/agents/{id}/heartbeat` endpoints are extended — the current shared-key model is kept as the *bootstrap* step and a token is issued on success.

#### Pairing-code path retired for standalone agents (#246)

The 8-digit pairing-code → PSK exchange originally landed in #169
shipped against a control-plane endpoint (``POST /api/v1/appliance
/pair``) that was retired under #170 Wave A3. Pairing-code flow now
lives entirely inside the **Appliance** supervisor —
the supervisor exchanges the code via ``POST /api/v1/appliance
/supervisor/register``, gets the per-role agent keys back as part
of the heartbeat-response ``SupervisorRoleAssignment`` block, and
writes them into ``role-compose.env`` so the DNS / DHCP service
containers pick them up on first boot with zero operator action.

For **standalone** docker-compose / K8s DNS agents, paste the long
``DNS_AGENT_KEY`` PSK directly into the agent's env. The agent's
``pairing.py`` module was deleted in 2026.05.18-1 (#246) because the
``/pair`` endpoint no longer exists — agents that had been bootstrapped
with ``BOOTSTRAP_PAIRING_CODE=<digits>`` were 404-looping forever
against the gone endpoint. The container entrypoint now requires
``DNS_AGENT_KEY`` non-empty.

See ``docs/deployment/APPLIANCE.md §9`` for the appliance
pairing-code workflow.

### Flow

<p align="center">
  <img src="../assets/diagrams/dns-agent-bootstrap.svg" alt="DNS agent bootstrap — PSK exchanged for a rotating JWT" width="900"/>
</p>

### Identity

- **AgentID** — UUID generated once on first boot, persisted in `/var/lib/spatium-dns-agent/agent-id`. Survives restarts; stable across re-registrations.
- **Fingerprint** — SHA-256 of a locally-generated ed25519 public key, sent with registration; pinned on the `DNSServer` row. A changed fingerprint on re-registration triggers `pending_approval=true` (anti-hijack).
- **Bootstrap key** rotation: admin rotates `DNS_AGENT_KEY`; existing agents already hold a valid JWT and are unaffected until re-bootstrap.

### Approval flow

A new platform setting `require_agent_approval: bool` (default **false** for homelab/single-tenant, recommended **true** for production) gates whether a freshly-registered agent is immediately active or sits in a `pending_approval` state visible in the DNS Server Group UI with an **Approve / Reject** action. Until approved:
- Agent receives `200` and a token but `config_version = null`.
- No config is served.
- Heartbeats still accepted (for telemetry).

The hold is cleared through the API with `POST /api/v1/dns/groups/{group_id}/servers/{server_id}/approve` (superadmin; the DNS twin of `POST /api/v1/dhcp/servers/{id}/approve`), which sets `pending_approval=false`, writes a `dns.server.approve` audit event and wakes the agent so its next config poll serves the bundle. The row keeps the fingerprint the agent re-registered with, so approving accepts that identity (spatiumddi#1121).

### Re-registration

On restart, the agent tries its cached token first. If the control plane returns `401`, it falls back to bootstrap with the PSK. If the PSK has rotated too, the agent logs and enters a retry loop with jittered backoff (cap 5 min).

### Alternatives considered

- **mTLS with internal CA** — more robust but requires a CA pipeline (cert-manager in K8s, something custom in Docker Compose). Deferred to Phase 4; the token model is a clean superset.
- **First-contact UI approval with no PSK** (Tailscale-style) — better UX but requires a pre-enrolled claim code in the container. Equivalent to our PSK with extra steps.

---

## 3. Config Sync Model

### Decision

**Hybrid: long-poll for config, push for urgent record changes, local disk cache as the source of truth for daemon operation.**

Three channels:

| Channel | Direction | Transport | Purpose |
|---|---|---|---|
| **Config long-poll** | Agent → CP | `GET /dns/agents/config` with `If-None-Match: <etag>` (long hold) | Full config bundle (views, ACLs, options, zone list). Returns `304` if unchanged, `200` with new bundle + new etag on change. The agent is identified by its JWT, not a path id. |
| **Heartbeat** | Agent → CP | `POST /dns/agents/heartbeat` (30 s interval) | Liveness, daemon status, version, queued-change ACK, token rotation. |

**Why not push / webhook from control plane to agent?**
- Requires agent to expose an HTTPS listener, open an inbound port, and obtain a valid TLS cert. Non-negotiable #6 and general operational cost.
- Breaks behind NAT (on-prem appliances reaching a central control plane).
- Long-poll gives ~1 s effective latency and keeps the agent **egress-only**.

**Why not pure polling (e.g. 30 s)?**
- Record changes in DDNS flow must feel instant. Long-poll early-return delivers in <1 s.

**Why not WebSocket / SSE?**
- We considered it. Long-poll is simpler, survives hostile proxies, does not need sticky-session affinity on a multi-replica API. We can upgrade to SSE in a later phase without changing the agent contract (long-poll remains a compatible fallback).

### Stored bundles — rendered once, served as bytes (#1111)

The bundle the long-poll hands out is **not assembled in the request**. It
is rendered once per `(server, watermark)` by the Celery worker
(`app.tasks.agent_bundles`, queue `bundles`) and stored in
`dns_agent_bundle` — `etag`, `structural_etag`, the compact JSON body
gzip-compressed — and the long-poll reads one small row per wake, compares
`If-None-Match` with the stored ETag, splices the per-server ops page in
front of the stored bytes and streams them. Whatever the group's record
count, the api never holds the group's record set as Python objects and
never serialises a multi-megabyte body on the request loop; the DB runs
the records query once per change, not once per agent per poll. The worker
has no HTTP liveness probe and its per-task engine carries no
`command_timeout`, so a render of a million-row group simply runs.

*What says a stored bundle is current.* `dns_server.bundle_dirty_seq` is
bumped **in the same transaction** as every change that feeds the bundle
(an `after_flush` listener, `services/dns/bundle_dirty.py`, maps every
contributor — records via their zone, zones, views, ACLs, options, TSIG
keys, update ACLs, sibling servers for the catalog producer pick, new
pending ops, blocklists, pools, and the platform singletons — to the
servers it feeds; each flush's servers are collected and bumped once, at
the outermost commit, in server-id order, so the bump's row locks live for
the COMMIT alone and two writers can never deadlock on them); `bundle_watermark` is the sequence the newest stored
bundle was rendered at. Current ⇔ `watermark ≥ seq` **and** the bundle came
from this process's renderer revision or a newer one
(`bundle_renderer_revision ≥ RENDERER_REVISION`, #1185): two integer
comparisons, no assembly, no content hash. The revision half is what makes
an upgrade that changes the renderer's output re-render every server once,
instead of serving the previous renderer's bytes until something unrelated
marks it. It replaced an equality check on the release string
(`bundle_app_version`, now diagnostic only), which re-rendered every server
on every release and let the old and new pods of a rolling upgrade replace
each other's renders every 30 s. Now a release that leaves the renderer
alone re-renders nothing, and an older process never replaces a newer
render: it serves it. `RENDERER_REVISION` lives in
`services/dns/agent_bundle_store.py`, and
`tests/test_dns_agent_bundle_revision.py` fails when the rendered output
changes without a bump. After commit the render is enqueued (the worker
coalesces duplicates: one render in flight per server, one more after it if
a change landed meanwhile — that is what turns a thousand-batch seed into a
handful of renders), and a 30 s beat sweep re-enqueues anything still
behind, so a lost broker message costs at most one tick. The per-server
lock and the fleet-wide render slot are a lease
(`dns_agent_bundle_render_lease_seconds`, 60 s) that the render renews
while it runs and releases only while it still holds it: a render the OOM
killer takes mid-flight frees the slot within one lease instead of holding
every server's render for the render ceiling. A render waiting for the slot
keeps its server's lock, so the duplicates the sweep and further marks
enqueue meanwhile coalesce into it.

*Every process that writes DNS rows must carry the listener.* It is
installed by importing `bundle_dirty`: `app.main` does so for the api,
`app.celery_app` for the worker and beat. A process without it commits its
changes unmarked — the bundle stays "current", and because the ops page is
gated to its snapshot (below) the new ops never ship either. That is not
hypothetical: pool health failover, ACME DNS-01, lease-expiry DDNS, IPAM
auto-sync and blocklist refresh all write from Celery tasks.
`test_the_worker_process_installs_the_listener` probes the worker's own
import graph in a fresh interpreter, because the test suite imports
`app.main` and so always has it. The listener sees only ORM unit-of-work
writes; a Core `insert()` / `update()` / `delete()` on a bundle input calls
`bundle_dirty.mark_bundles_dirty()` in the same transaction.

*A mark is not free, so writes the bundle never reads do not mark.* Every
mark costs a render, renders run one at a time fleet-wide, and a
million-row group renders in about half a minute, so a writer that marks on
bookkeeping keeps renders busy with nothing to deliver. A dirty contributor
therefore marks only when a column the bundle renders has a net change: the pool
health check's timestamps, the `dnssec_synced_at` stamp every agent posts
after a structural reload, blocklist sync bookkeeping, and every platform
setting outside the `snmp_` / `ntp_` columns the bundle renders (the beat
tasks' `*_last_run_at` stamps, the release check) mark nothing. New and
deleted rows always mark. Geo steering reads the Site a pool member is
scoped to and that Site's live subnets, so a subnet joining or leaving a
Site — or changing its prefix — marks the groups whose pools use it.

*The ops page carries what the body's render read, nothing newer.* Every
body an agent holds is a superset of every op it has applied. The inline
build had that by construction, because the body was built moments before
the page. A stored body ships only the ops whose transaction had committed
before its render read. The render takes `pg_current_snapshot()` (stored
as `dns_agent_bundle.visible_xacts`) in a statement of its own before its
records query, and each op carries the transaction that queued it
(`dns_record_op.xact_id`, `pg_current_xact_id()`). An op is covered when
that transaction is visible in the snapshot.

The op's `created_at` cannot decide this: it is the transaction's START.
A bulk write that began before a render and committed after its records
query would pass a time gate with records the body never read. Without the
gate, the full re-render (or a restart replaying `current.json`) would
drop a record the agent had already applied over RFC 2136. The same gate
decides which queued ops a split-horizon render retires as applied, so an
ACME DNS-01 wait never reads an op as applied that no body carries. An op
the snapshot does not cover rides with the next render, whose dirty mark
its own commit made.

Three cases keep the time gate (`created_at <= snapshot_at`):
- ops and bundles from before these columns;
- a transaction id this cluster has not reached yet;
- a snapshot this cluster has not reached yet.
The last two come from a backup restored onto a new appliance.

*What the agent sees.* Nothing changes in the protocol: weak `ETag` / 304 /
the body shape / the "200 while ops are pending" fast path /
`structural_etag` / the #882 quarantine. The one difference is that the
ETag is the stored body's and no longer folds the ops page in, so a page
does not rotate it — the fast path answers 200 with the same ETag and the
next page, and the poll after the last ack answers 304 instead of
re-sending the whole body. The agent never short-circuits on an unchanged
ETag (it saves, compares `structural_etag`, drains the ops).

*The newest render is served, current or not.* A long-poll serves the
newest bundle the running release stored, even when changes have been
committed since it was rendered. Its render is enqueued and the poll wakes
when one lands. Under a write storm marks arrive faster than renders
finish, so no render is current until the writes stop. Serving only a
current bundle held every agent on its last config for the whole storm: in
a 250k-record seed a pool failover stayed in `named` for 339 s while 74
renders landed unserved. Now each render that lands reaches the agents, at
most one render behind, and the gate above keeps that safe. A bundle from
an older renderer revision is never served; the sweep re-renders it. With
nothing current stored for this revision the poll holds on the wake the
render publishes, 304 at the deadline.

*Staleness is never silent.* A render
that raises lands on `dns_server.bundle_render_status / _error / _at` —
deliberately not `config_failed_etag`, which is the agent's #882 verdict
and is cleared by its next healthy heartbeat — and fires the
`agent_bundle_render_failed` alert (critical when the server has never had
a bundle, warning while a previous one is still served). The same rule
fires when changes have waited 10 minutes with no render landing
(`dns_server.bundle_dirty_at`, set by the first mark and cleared by a
render that catches up): an OOM-killed render, a render slot held by a dead
worker, or a worker that does not consume the `bundles` queue never records
a failure, and that is the case that most needs seeing. The migration
release keeps `dns_agent_bundle_inline_fallback` on: a deployment whose
worker is still one release behind builds a missing or stale bundle inline
exactly as before, once per version, because it stores what it built (the
inline render's page is gated like the worker's). The
fallback is bounded. The api builds a server's bundle only when the server
has never had one, or when its stale bundle has waited longer than
`dns_agent_bundle_inline_fallback_after_seconds` (120 s) for the worker;
every render that lands restarts that clock, so a change storm the worker
keeps up with costs the api nothing (unbounded, a 250k-record seed had the
api build the growing bundle 48 times beside the worker). One attempt per
server at a time across replicas, and none for
`dns_agent_bundle_inline_fallback_backoff_seconds` (600 s) after one fails.
A failed attempt (at a million records the records query outlives the
api's 30 s `command_timeout`) is logged and counted
(`spatiumddi_agent_bundle_inline_failures_total`) and the poll waits for
the worker's render; it is never recorded as the server's render failure.

### RFC 2136 `nsupdate` responsibility

**Agent-local.** The control-plane BIND9 driver does **not** connect to `named` directly. Instead:

1. Control plane computes the record delta and writes one `pending_record_ops` row **per enabled agent-based server in the zone's group** (per-server queue keyed on `server_id`). Pre-2026.05.14-1 the queue only went to the `is_primary=True` server, which silently broke multi-server (and supervised-appliance) groups — secondaries' on-disk zone files stayed frozen at the bundle they received on initial register. Under #170 every DNS agent renders the zone as `type master` (independent authoritative copy) so record CRUD has to land on every one.
2. Each agent pulls its own queued ops via config long-poll (the bundle ships `pending_record_ops` for any agent-based server regardless of `is_primary`; the `is_primary` flag now only matters for the agentless / Windows-DNS path where exactly one server writes).
3. The agent invokes `nsupdate` **against its own daemon over loopback**.
4. The agent ACKs success/failure per-op on the next heartbeat.

Rationale: loopback `nsupdate` is simpler, never traverses the network as a TSIG-sensitive payload, and makes the agent the single enforcer of the local daemon state. The TSIG key lives only on the container.

The control-plane `DNSDriverBase` implementations become **thin**: they translate the DB model into a canonical `AgentConfigBundle` + `RecordOp` list. They do not speak `nsupdate` via RFC 2136 directly.

### Local disk cache (non-negotiable #5)

Layout on `/var/lib/spatium-dns-agent/`:

```
agent-id                         # UUID, 0600
agent_token.jwt                  # current JWT, 0600
bootstrap.last                   # last-used PSK hash (for rotation detect)
config/
  current.json                   # last AgentConfigBundle FETCHED from the control plane
  current.etag
  previous.json                  # last bundle that APPLIED cleanly — the revert target
  previous.etag
  quarantine.json                # etag of a bundle that failed to apply, + its backoff
rendered/
  zones/
    example.com.db
    10.in-addr.arpa.db
  rpz/
    spatium-blocklist.rpz
tsig/
  ddns.key                       # 0600, owned by agent user; read by named via include
                                 #   ALL bundle keys, not just the group key: an
                                 #   operator DNSTSIGKey can be named in a zone's
                                 #   update ACL and in the allow-transfer grant,
                                 #   and BIND rejects a config naming a key it has
                                 #   no definition for
ops/
  inflight/                      # one file per unacked RecordOp
  failed/                        # ops that exhausted retries (surfaced in heartbeat)
```

> **Every path in the rendered `named.conf` is derived from the state dir**
> (`AGENT_STATE_DIR`, default `/var/lib/spatium-dns-agent`) — zone files,
> `rndc.key`, the DoT/DoH cert and the `include` for `tsig/ddns.key`. The key
> include was the one exception until #920: hardcoded to the default path, so
> under a non-default state dir the agent wrote the key file to one place and
> told `named` to read another. If nothing exists at the default path that is
> a loud `named-checkconf` failure; if something *does* — a leftover from an
> earlier layout — it is silent, because the config validates, the apply
> reports `ok`, and `named` simply holds a stale key set. Every TSIG-signed
> transfer then fails `BADKEY` with nothing anywhere reporting a problem.
> `agent/dns/tests/live_axfr_check.py` now asserts the include resolves to the
> render's own state dir, and covers the operator-key-only group shape.

**Offline operation**: if the control plane is unreachable on boot, the agent loads `config/current.json`, renders configs if not already rendered, starts the daemon, and continues serving DNS. It enters a retry loop and resumes sync when the control plane returns. No query path ever depends on control-plane reachability.

### Last-known-good revert (issue #882)

Offline operation covers a *missing* control plane. It does not cover a
*wrong* one: a bundle that parses fine but renders config `named` rejects.
Both agents wrote `previous.json` from the first release and **neither ever
read it**, so a bad-but-parseable bundle overwrote the cache and left the
agent with nothing to fall back to.

Two properties make the fallback real:

* **`previous` is the last bundle that APPLIED, not the last one fetched.**
  It used to be rotated on every fetch, which destroyed the fallback in two
  poll cycles: a failing bundle leaves the etag unadvanced, so the next poll
  re-fetches the *same* bundle and rotates it — now known-bad — into
  `previous`. It is now written by an explicit commit after the driver
  accepts the bundle, and that commit refuses to run if `current` is not the
  bundle that was applied.
* **A failed etag is quarantined.** The long-poll wakes on a 12 s tick with a
  2 s poll fallback, so without this a bad bundle is not one failure but a
  re-render loop. The agent parks on the failing etag (the long-poll then
  blocks on a 304, costing nothing) and retries on a 60 s → 5 min → 15 min
  ladder, so a *transient* failure — a full disk mid-render, a daemon still
  starting — still recovers on its own. Any bundle that applies clears the
  record, as does the control plane simply serving a different etag.

The apply is phased — render → validate → swap/reload — and the phase decides
the recovery. BIND renders and validates into `rendered.new`, so a
`named-checkconf` failure never reached `named`: the daemon is already in the
state a revert would produce, and re-rendering the previous bundle there would
bounce a healthy server for nothing. Only a swap/reload failure, where the
live config directory has already been replaced, re-renders the previous
bundle. Kea is the mirror image — `config-test` rejects without disturbing the
running server, but the refused document has already been written to
`kea_config_path`, and that file is what Kea reads on its next start, so a
rejection there always rewrites the files even though the daemon is fine.

On restart the agent checks the quarantine before re-applying `current.json`:
a container that crash-loops must not re-break itself with the bundle that
broke it.

**A revert is reported, never silent.** That matters more than it sounds: a
reverted agent keeps serving and keeps heartbeating, so `status`, the health
check and `last_seen_at` all read normal while the zone the operator saved is
live nowhere. The verdict rides the heartbeat's `config` field, lands on
`dns_server.config_apply_*`, and drives a chip on the server row, a banner on
the server detail, the `agent_config_rejected` alert rule and the
`find_agents_with_config_failures` Copilot tool.

**So is a daemon that is not serving (#1067).** The heartbeat's `daemon`
field is `{"status": "ok"}` once the daemon is confirmed up and
`{"status": "degraded", "reason": ...}` while it is not — from the moment a
start is deferred because no bundle has been rendered yet
(`"start deferred, no bundle yet"`, #1061) until the first bundle lands,
and after a failed apply. A registered agent in that state heartbeats
every 30 s, `named` never starts and the pod restarts on its liveness
probe every two minutes, while `status`, `last_seen_at` and the config
verdict all read normal. The field lands on `dns_server.daemon_status` /
`daemon_reason` / `daemon_status_since` (the stamp of the heartbeat that
began the current state, so "degraded for 12 min" is readable), is
exposed on the server row, drives a chip and a detail banner, and the
`agent_daemon_degraded` alert rule fires once a daemon that is not serving
has stayed that way past a five-minute grace. A failed apply is the
exception: the agent echoes it as `degraded` with a `config_apply_*`
reason, but that is the revert reported above — often a daemon that is up
on its last-known-good config — so the chip, the banner and the alert all
leave it to `agent_config_rejected`. They read one server-side
classification, `daemon_not_serving` on the server response, so they
cannot disagree. NULL means the agent has never reported one — a
pre-#1061 agent, or an agentless driver — and is unknown, never healthy.

### Push spool — the reporting half of an outage (issue #1077)

Non-negotiable #5 keeps the agent *serving* through a control-plane outage.
The spool keeps it *reporting*: a query-log batch or a per-minute metric the
control plane does not accept is written to disk and replayed, in order, when
it answers again — instead of being dropped, which is what every shipper did
before (and every in-memory buffer was lost on an agent restart besides).

| | |
|---|---|
| Location | `<state dir>/spool/<stream>/` — `/var/lib/spatium-dns-agent/spool/` by default. One file per batch, written tmp + fsync + rename, so a crash leaves a batch whole or absent. Survives agent restarts. |
| Streams | DNS: `query_log`, `metrics`. (DHCP: `dhcp_log`, `lease_events`, `metrics`, `mac_sightings`, `fingerprints`, `ra_observations` — see [`DHCP.md`](../features/DHCP.md).) |
| `AGENT_SPOOL_ENABLED` | Default `true`. `false` restores the pre-#1077 drop behaviour — kept for the negative control in tests, not as a tuning knob. |
| `AGENT_SPOOL_MAX_BYTES` | Default `268435456` (256 MiB), shared across the agent's streams by fixed weights. At the cap the **oldest** batches are trimmed and counted. Keep it well under the agent state volume (the Helm chart's `storage.agentState` defaults to 1 Gi, and PowerDNS also keeps `pdns.log` in that directory). |
| `AGENT_SPOOL_LOG_MAX_AGE_HOURS` | Default `24`, matching the control plane's query-log retention. Log batches spooled longer ago than this are dropped at drain time (counted as *expired*) rather than shipped into a table the nightly prune would empty. Metrics are not age-limited. |

**Ordering.** A live batch never overtakes the backlog: while anything is
spooled, new batches queue behind it. Drain stops at the first failure so a
still-unreachable control plane does not reorder the queue.

**Replay is idempotent on the server.** Every spooled batch carries a
`batch_id` (32 lowercase hex). The ingest endpoint records it in
`agent_ingest_receipt` in the **same transaction** as the rows it inserts, so
the batch in flight when the control plane went away — committed, but its
response lost — is answered `{"status": "ok", "duplicate": true}` on replay
and inserts nothing. This matters most for metrics, which accumulate per
bucket: an undeduplicated replay would double a minute of traffic. Receipts
are kept 35 days (pruned by the nightly log sweep). A body without `batch_id`
(a pre-#1077 agent) is ingested exactly as before. A 4xx that is not about
auth or rate-limiting is a verdict on the batch, so that one batch is dropped
rather than jamming everything queued behind it. A batch that keeps drawing a
plain **500** — a server bug meeting that particular body — is treated the
same way, but only after 5 consecutive attempts spanning at least 10 minutes
**and** once the control plane has accepted the batch queued behind it — a 500
for every body (schema skew mid-upgrade, an unhandled dependency error) is an
outage in all but status code and costs nothing. It is moved to
`spool/<stream>/poison/` (the last 20 are kept) rather than deleted, so it can
be inspected. **502 / 503 / 504 never count**, and reset the run: that is the
control plane or its proxy being down, which is exactly what the spool rides
out.

**Retention on the server too.** The query-log endpoint skips lines whose
own timestamp is older than the 24 h retention window and reports them as
`expired` — a belt to the agent's spool-age braces. A line with no parseable
timestamp is stamped with the arrival time and is never expired. RPZ hits
are exempt (they are kept 30 days).

**Surfaced, not silent.** The spool rides every heartbeat as `spool`
(bytes / entries queued, oldest entry, cumulative trim counters, per-stream
breakdown) and lands on `dns_server.spool_status` — NULL until an agent
reports one, which means *unknown*, never "empty". The server list shows an
amber **Replaying … backlog** chip while a backlog drains and a red **Spool
trimmed** chip for 24 h after the cap forced a drop; the default-on
`agent_spool_trimmed` alert fires on the same condition, and the
`find_agents_with_spool_backlog` Copilot tool answers "did we lose anything
during the maintenance window?".


---

## 4. Health & Telemetry

### What the agent reports (heartbeat body)

```json
{
  "agent_version": "2026.04.13-1",
  "daemon_version": "9.20.27",
  "daemon": {"status": "ok"},
  "config": {
    "status": "ok",
    "etag": "sha256:...",
    "failed_etag": null,
    "phase": null,
    "error": null
  },
  "spool": {
    "enabled": true,
    "cap_bytes": 268435456,
    "bytes": 3355443,
    "entries": 41,
    "oldest_at": "2026-09-22T09:14:00.000Z",
    "trimmed_entries_total": 0,
    "trimmed_bytes_total": 0,
    "last_trim_at": null,
    "expired_entries_total": 0,
    "streams": {"query_log": {"bytes": 3301000, "entries": 38, "...": "..."}, "metrics": {"...": "..."}}
  },
  "ops_ack": [
    {"op_id": "...", "result": "ok"},
    {"op_id": "...", "result": "error", "message": "NXRRSET"}
  ],
  "failed_ops_count": 0,
  "disk_free_bytes": 8123456789,
  "zone_serials": {"example.com.": 2026041407}
}
```

### Endpoints

| Endpoint | Direction | Cadence |
|---|---|---|
| `POST /dns/agents/heartbeat` | agent → CP | every 30 s (jittered ±3 s) |
| `GET  /dns/agents/config` | agent → CP | continuous long-poll |
| `POST /dns/agents/ops/{op_id}/ack` | agent → CP | piggybacked on heartbeat; separate endpoint reserved for out-of-band recovery |
| `POST /dns/agents/admin/rendered-config`, `POST /dns/agents/admin/rndc-status` | admin UI → CP → agent | pull-through for rendered config / `rndc status` |

### Stale / unhealthy surfacing

- Control plane marks `DNSServer.status = unreachable` if no heartbeat for **3 × heartbeat_interval** (90 s default).
- UI: the existing server-group view shows colored status dots; a new "Last seen" column uses `last_health_check_at`.
- A Celery beat job `dns_agent_stale_sweep` runs every 60 s, flips statuses, emits an audit entry, and triggers notifications (Phase 4).
- Metrics: Prometheus gauges `spatium_dns_agent_up`, `spatium_dns_agent_config_lag_seconds`, `spatium_dns_zone_serial`, `spatium_dns_failed_ops_total` — scraped from the control plane (agent does not expose a scrape endpoint; keeps it egress-only).

---

## 5. Incremental Updates (Non-Negotiable #8)

### Record lifecycle end-to-end

<p align="center">
  <img src="../assets/diagrams/dns-record-propagation.svg" alt="DNS record change — end-to-end propagation" width="900"/>
</p>

### Serial bump responsibility

- **Control plane bumps the logical serial** when constructing the op: `YYYYMMDDNN` format, monotonically increasing per zone, persisted on `DNSZone.last_serial`.
- The op carries the target serial. The agent's `nsupdate` script explicitly deletes + re-adds the SOA with the target serial in the same update transaction (atomic under RFC 2136).
- The API zone `PATCH` includes the `serial` field.
- Every enabled agent-based server in the zone's group receives the record op — see "Group coordination" below. No server is skipped on the assumption that another server will hand it the data via transfer.

### Group coordination (per-server-master fan-out — the default)

Under the post-#170 model (see §3), **every** enabled agent-based
server in a `DNSServerGroup` runs an **independent authoritative copy**
of each zone — the agent renders it as `type master` in `named.conf`
(`agent/dns/spatium_dns_agent/drivers/bind9.py`). There is no
primary→secondary push; SpatiumDDI is the source of truth and fans the
data out to every server directly.

- A record change enqueues **one `DNSRecordOp` row per enabled
  agent-based server in the group** (`enqueue_record_op` in
  [`backend/app/services/dns/record_ops.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/dns/record_ops.py)).
  Each agent pulls its own queued ops via the config long-poll and
  applies them through loopback `nsupdate` against its local daemon.
- `DNSServer.is_primary` does **not** mean "the only writer" for
  agent-based groups. It only orders the fan-out and identifies the
  server whose op the typed-event audit path reports back; every
  server still gets the write. (Pre-#170 the queue went to the
  `is_primary=True` server only, which silently left every other
  agent's on-disk zone files frozen at the bundle they received on
  initial register.)
- If one agent is unreachable, its ops sit in `DNSRecordOp(state="pending")`
  and drain when it returns; the other servers in the group apply
  immediately. The op state is per-server, so partial convergence is
  visible per `server_id`.

> **Optional native secondary path.** A zone may instead be declared a
> `secondary` / `slave` / `stub` zone (issue #336) with an explicit
> `masters` list, in which case the daemon AXFRs the zone from those
> masters and the agent emits no zone file. That is an opt-in per-zone
> setting — *not* the default coordination model — and is the standard
> way to back a non-SpatiumDDI master.

### Agentless / Windows DNS — the single-writer alternative

For **agentless** drivers (`windows_dns` plus the cloud-hosted DNS
drivers — see `AGENTLESS_DRIVERS` in
[`backend/app/drivers/dns/__init__.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/__init__.py))
there is no agent and no loopback `nsupdate`. Here the
`is_primary=True` server is the **single writer**: `enqueue_record_op`
detects the agentless driver and applies the op **immediately from the
control plane** via the driver (WinRM / PowerShell for Windows DNS,
provider REST for cloud DNS), landing the `DNSRecordOp` row directly as
`applied` or `failed` rather than queuing it for a long-poll. Any
native secondaries behind a Windows or cloud primary are coordinated by
that platform's own NOTIFY/AXFR — SpatiumDDI neither proxies records to
them nor manages that transfer.

---

## 6. Security

| Concern | Decision |
|---|---|
| **Bootstrap PSK** | `DNS_AGENT_KEY` env var on both control plane and agent. 32-byte random (`openssl rand -hex 32`). Rotatable. Compared with `hmac.compare_digest`. |
| **Agent token** | JWT (HS256) signed by control-plane `SECRET_KEY`, 24 h lifetime, rotated silently via heartbeat response if within 12 h of expiry. Claims: `sub=server_id`, `agent_id`, `fingerprint`, `exp`. |
| **TSIG keys** | Generated by control plane on zone bind, stored encrypted at rest (Fernet, `SECRET_KEY`-derived). Transmitted to agent inside the config bundle over TLS. Agent writes to `tsig/ddns.key` at 0600, referenced by `named.conf` via `include`. |
| **TLS** | Agent↔CP is HTTPS-only. CP cert verified against the system CA bundle (+ optional `CA_BUNDLE_PATH` env for private CAs). Self-signed dev certs only when `SPATIUM_INSECURE_SKIP_TLS_VERIFY=1` (dev only). |
| **RBAC between agents** | An agent's JWT is scoped to its `server_id`. Config endpoint rejects requests for any other server. Record ops are likewise `server_id`-scoped; an agent cannot fetch another server's TSIG keys. |
| **Audit** | Every config apply, op-apply, token rotation, and failed auth is audit-logged on the control plane. Agent-local audit is kept on disk for 7 days (rotated) and surfaced via `/agents/{id}/diagnostics`. |

---

## 7. Image Layout

### Base

**Alpine 3.23** for every agent image — *except* `dns-technitium`, which is **not Alpine at all** (see below). Multi-arch: `linux/amd64`, `linux/arm64/v8` via `docker buildx`.

> **`dns-powerdns` carries an LMDB schema guard.** Alpine 3.23 ships pdns 5.0.5 (3.22 shipped 4.9.5), and PowerDNS 5.0 performs an automatic, silent, **irreversible** LMDB schema upgrade (v5 → v6) the first time it opens the database — a read is enough, and there is no opt-out. Afterwards pdns 4.9 cannot open the database at all (`Somehow, we are not at schema version 5. Giving up`). Because the LMDB is persisted on `/var` in every deployment shape, and the appliance A/B slot rollback swaps only the *rootfs*, an upgrade-then-rollback would otherwise leave pdns crash-looping with DNS down and no automatic recovery. [#638](https://github.com/spatiumnorth/spatiumddi/issues/638) closed that: the entrypoint runs `spatium-pdns-lmdb-guard snapshot` before the agent spawns `pdns_server`, copying the database aside whenever the pdns major version changed and failing closed if it cannot. **Rolling a PowerDNS node back is therefore a two-step operation — redeploy the old image AND run `spatium-pdns-lmdb-guard restore latest`.** Full mechanics in [DNS_DRIVERS.md §4.9](../drivers/DNS_DRIVERS.md).

> **Why `dns-technitium` is glibc/Ubuntu-based, not Alpine.** Technitium ships no Alpine package and no binary release assets on GitHub at all (its releases carry notes only, zero attached artifacts — confirmed empirically). The only reproducible, versioned, multi-arch artifact it publishes is its own official Docker image (`technitium/dns-server`, Ubuntu 24.04 + .NET 10 aspnet runtime), so `agent/dns/images/technitium/Dockerfile` builds `FROM` that image and layers the `spatium_dns_agent` wheel on top rather than fetching a build artifact that doesn't exist. The builder stage matches (Debian `python:3.12-slim-bookworm`, not Alpine) since `spatium_dns_agent` depends on `cryptography`, which ships compiled wheels — a musllinux wheel built on Alpine wouldn't load on the Ubuntu-based runtime. The image also explicitly upgrades to the distro's patched `aspnetcore-runtime-10.0` package and deletes the vendored `/usr/share/dotnet` copy the upstream image ships, since Trivy's .NET scanner reads shared-framework directories directly (not `dotnet --list-runtimes`) and would otherwise keep flagging CVEs in files nothing loads.

### `dns-bind9` image

```
FROM alpine:3.23 AS runtime
RUN apk add --no-cache bind bind-tools tini python3 py3-pip libcap ca-certificates tzdata
# Agent
COPY --from=agent-build /install /usr/local
COPY entrypoint.sh /usr/local/bin/spatium-dns-entrypoint
RUN addgroup -S spatium && adduser -S -G spatium spatium \
 && mkdir -p /var/lib/spatium-dns-agent && chown spatium:spatium /var/lib/spatium-dns-agent
VOLUME ["/var/lib/spatium-dns-agent", "/var/cache/bind"]
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/spatium-dns-entrypoint"]
```

Entrypoint (`entrypoint.sh`) responsibilities:

1. Load/generate `agent-id`.
2. Bootstrap / token refresh against control plane.
3. Pull initial config bundle, render `named.conf`, zone files, RPZ files, TSIG keys.
4. Validate with `named-checkconf`.
5. `exec` a supervisor that runs two children: `named -g -u named` and the agent's sync loop. If either exits, kill the other and exit non-zero (let the orchestrator restart the container).

The `dns-powerdns` image follows the same shape — it swaps `bind`/`named`
for `pdns_server` (LMDB backend) but ships the same `spatium_dns_agent`
codebase and the same `spatium-dns-entrypoint`, and exposes the same
`53/udp 53/tcp`.

The `dns-technitium` image follows the same agent/entrypoint shape too,
but has no config file for the agent to render at all — Technitium is
configured entirely over its own HTTP API (`http://127.0.0.1:5380`), so
`render()`/`validate()`/`swap_and_reload()` collapse into "stash the
desired zone/record state as JSON, then reconcile it against the live
API." The agent provisions a permanent API bearer token on first-ever
boot (via `DNS_SERVER_ADMIN_PASSWORD` + `/api/user/createToken`) the same
way the PowerDNS driver provisions its local API key.


### Volumes

| Path | Purpose | Typical size |
|---|---|---|
| `/var/lib/spatium-dns-agent` | Agent state, config cache, TSIG, tokens, push spool (#1077) | <10 MB, plus up to `AGENT_SPOOL_MAX_BYTES` (256 MiB) of spool during an outage |
| `/var/cache/bind` (bind9 image) | Zone files, journals | grows with zone count |

Both must survive restarts → named volumes in Compose / PVCs in K8s.

---

## 8. Kubernetes Shape

### Decision

**One `StatefulSet` per `DNSServer` row** (umbrella chart,
`charts/spatiumddi/templates/dns-agent.yaml`), not per group. Headless
`Service` per StatefulSet (ClusterIP=None) plus an externally-exposed
`Service` of type `LoadBalancer` or `NodePort` for DNS traffic (UDP/TCP
53). On the appliance chart
(`charts/spatiumddi-appliance/templates/dns-bind9.yaml`) the same
service-container runs as a per-role-labelled `DaemonSet` instead.

### Rationale

- DNS servers have **stable identity** (own TSIG keys, own
  agent token, own persistent zone files + config cache). That matches
  StatefulSet semantics.
- **Each server is an independent authoritative copy.** Per the
  per-server-master fan-out model (§5), every agent in a group renders
  the zone as `type master` and receives its own `DNSRecordOp` queue
  from the control plane — there is no primary→secondary AXFR/NOTIFY
  between them, and the control plane is the single source of truth.
  The `role` value on a server is a cosmetic label
  (`spatiumddi.org/dns-role`, default `primary`; passed to the agent as
  `AGENT_ROLES`); it does **not** wire up DNS-level replication.
- **Not a Deployment**, because each server keeps per-replica
  persistent state (zone files, TSIG, agent identity) — replicas are
  not fungible.
- **Not a DaemonSet** in the umbrella chart, because placement is
  explicit (the appliance chart *does* use a DaemonSet, gated on a
  per-role node label).
- Shape:

```
DNSServerGroup "internal-resolvers"
 ├── StatefulSet/dns-internal-ns1  (replicas=1, type master, own record-op queue)
 │    └── Service/dns-internal-ns1 (LoadBalancer, 53/udp+tcp)
 └── StatefulSet/dns-internal-ns2  (replicas=1, type master, own record-op queue)
      └── Service/dns-internal-ns2 (LoadBalancer, 53/udp+tcp)
```

- Every record change fans out to **both** ns1 and ns2 as separate
  `DNSRecordOp` rows; each agent applies via loopback `nsupdate`
  against its own daemon. There is no in-cluster zone transfer between
  them to coordinate. (A zone explicitly declared `secondary` with a
  `masters` list — issue #336 — is the opt-in exception that AXFRs from
  a non-SpatiumDDI master.)
- Pod anti-affinity prefers landing ns1 and ns2 on different nodes.

### Helm chart structure (Phase 2 deliverable)

```
charts/spatiumddi/                 # umbrella chart — DNS agents are one optional
  Chart.yaml                       # component under .Values.dnsAgents
  values.yaml                      # .dnsAgents.servers[] defines name, role, group, storage
  templates/
    dns-agent.yaml                 # StatefulSet + LB/headless Service per server
    service-headless.yaml
    pdb.yaml
    configmap-bootstrap.yaml # non-secret bootstrap config
    secret-agent-key.yaml    # references existing secret created by user
    servicemonitor.yaml      # optional, Prometheus
```

The SpatiumDDI control-plane operator (Phase 3 stretch) can render this from the `DNSServerGroup` DB state, but Phase 2 ships only the static Helm chart driven by `values.yaml`.

### Docker Compose shape

One service per DNS server. Two servers in the same `AGENT_GROUP` are
independent `type master` copies that each get the group's record-op
fan-out — there is no primary/secondary distinction at the Compose
level. Example added to `docker-compose.yml`:

```yaml
dns-bind9-ns1:
  image: ghcr.io/spatiumnorth/dns-bind9:${SPATIUM_VERSION}
  environment:
    CONTROL_PLANE_URL: http://api:8000
    DNS_AGENT_KEY: ${DNS_AGENT_KEY}
    AGENT_HOSTNAME: dns-bind9-ns1
    AGENT_GROUP: default
    AGENT_ROLES: authoritative   # cosmetic label; does not wire up replication
  volumes:
    - dns-bind9-ns1-state:/var/lib/spatium-dns-agent
    - dns-bind9-ns1-cache:/var/cache/bind
  ports:
    - "53:53/udp"
    - "53:53/tcp"
```

> The agent reads `AGENT_ROLES` (default `authoritative`), `AGENT_GROUP`,
> and `AGENT_HOSTNAME` / `SERVER_NAME` from the environment
> (`agent/dns/spatium_dns_agent/config.py`). The role is a label only —
> the control plane fans record ops out to every enabled agent-based
> server in the group regardless of role.

> **`AGENT_GROUP` only decides where a BRAND-NEW agent lands.** On
> re-registration the control plane resolves the existing row by `agent_id`
> and never rewrites its `group_id`, so editing this variable does not move
> a server that has already registered — and leaving it stale does not drag
> a moved one back. To change a registered server's group, move it in the
> control plane (`group_id` on the server PUT, or the **Server group**
> picker in its edit modal — see
> [`DNS.md` §1](../features/DNS.md)). Naming a group that does not exist
> still auto-creates an empty one, so a stale value here is untidy rather
> than harmful.

---

## 9. Deliverables for Wave 2 Implementation

### Backend (control plane)

| File | Purpose |
|---|---|
| `backend/app/api/v1/dns/agents.py` | Split agent endpoints out of `router.py`: `register`, `heartbeat`, `config` (long-poll), `ops/ack`. |
| `backend/app/services/dns/agent_config.py` | Builds the `AgentConfigBundle` from DB state (zones, views, ACLs, options, TSIG keys, forwarders, blocklists). |
| `backend/app/services/dns/record_ops.py` | Enqueues `RecordOp` rows on record mutations; resolves primary server per zone. |
| `backend/app/services/dns/agent_token.py` | JWT mint/verify/rotate. |
| `backend/app/models/dns.py` | Extend with: `DNSServer.agent_id`, `fingerprint`, `pending_approval`, `is_primary`; new `RecordOp` model. |
| `backend/alembic/versions/<new>_dns_agent_ops.py` | Migration for the above. |
| `backend/app/tasks/dns.py` | Celery beat `dns_agent_stale_sweep`. |
| `backend/app/config.py` | Settings: `DNS_AGENT_TOKEN_TTL`, `DNS_AGENT_LONGPOLL_TIMEOUT`, `require_agent_approval`. |

### Agent (new codebase)

| File | Purpose |
|---|---|
| `agent/dns/pyproject.toml` | Package `spatium-dns-agent`. |
| `agent/dns/spatium_dns_agent/__main__.py` | CLI entry; loads env, delegates to supervisor. |
| `agent/dns/spatium_dns_agent/supervisor.py` | tini-child; runs daemon + sync loop. |
| `agent/dns/spatium_dns_agent/bootstrap.py` | PSK registration + token persistence. |
| `agent/dns/spatium_dns_agent/sync.py` | Long-poll loop, config apply, op execution. |
| `agent/dns/spatium_dns_agent/cache.py` | Disk-cache read/write, atomic swap, rollback. |
| `agent/dns/spatium_dns_agent/drivers/bind9.py` | Render `named.conf`, zone files, RPZ; `nsupdate` loopback; `rndc reconfig`. |
| `agent/dns/spatium_dns_agent/heartbeat.py` | Heartbeat body, token rotation. |

### Container images

| Path | Purpose |
|---|---|
| `agent/dns/images/bind9/Dockerfile` | Alpine + BIND9 + agent, multi-arch. |
| `agent/dns/images/bind9/entrypoint.sh` | Process-1 entrypoint. |
| `.github/workflows/build-dns-images.yml` | buildx, amd64+arm64, push to `ghcr.io/spatiumnorth/*`. |

### Kubernetes

| Path | Purpose |
|---|---|
| `k8s/dns/bind9-statefulset.yaml` | Reference StatefulSet. |
| `k8s/dns/service-dns.yaml` | Example LoadBalancer service (UDP+TCP 53). |
| `charts/spatiumddi/` | Umbrella Helm chart — DNS agents are the `dnsAgents` section. |
| `k8s/README.md` | Add "DNS server deployment" section. |

### Docker Compose

| File | Change |
|---|---|
| `docker-compose.yml` | Add optional `dns-bind9-ns1` (+ `dns-bind9-ns2`) services under a `dns` Compose profile — independent `type master` copies in one `AGENT_GROUP`, no primary/secondary roles. |
| `.env.example` | `DNS_AGENT_KEY=` (with `openssl rand -hex 32` hint). |

### Docs

| File | Change |
|---|---|
| `CLAUDE.md` | Add `docs/deployment/DNS_AGENT.md` to Document Map. |
| `docs/deployment/DNS_AGENT.md` | **This document.** |
| `docs/drivers/DNS_DRIVERS.md` | Update: clarify that drivers emit `AgentConfigBundle`/`RecordOp` rather than speaking to daemons directly. |
| `docs/features/DNS.md` | Cross-link to this doc from §6 and §7. |
| `docs/OBSERVABILITY.md` | Add agent metrics (`spatium_dns_agent_*`). |

### Acceptance criteria for Wave 2

1. `docker compose --profile dns up` starts a BIND9 container that auto-registers and appears in the DNS UI within 10 s.
2. Creating an A record via the UI results in the record being resolvable via `dig @<container-ip> ...` within 2 s.
3. Killing the control plane (`docker compose stop api worker`) does not interrupt DNS resolution; restarting it within 1 h resumes sync with no record loss.
4. The container image passes `trivy` with no high/critical CVEs at build time.
5. Helm chart deploys a 2-server group in `kind`; both servers render the zone as `type master` and a record created via the UI is resolvable against **each** server's `Service` (per-server record-op fan-out, no inter-server AXFR required).

---

## 10. Open Questions (Deferred)

- **mTLS vs JWT**: reconsider in Phase 4 once we have an internal CA story.
- **IPv6-only deployments**: agent must support AAAA-only control-plane URL; fine in theory, test in Phase 3.
- **Windows DNS integration**: explicitly out of scope for the agent model — Windows servers are managed via WinRM from the control plane (different driver branch, see roadmap).
- **DNSSEC signing (online vs bump-in-the-wire)**: BIND9 inline-signing is assumed; key storage and rotation design now lives alongside the driver docs (`docs/drivers/DNS_DRIVERS.md` §2.5).
