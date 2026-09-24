# Observability Specification

## Overview

SpatiumDDI's **shipped** observability consists of: structured NDJSON
logging to stdout (§ 1), a **built-in `/logs` viewer** over agent-pushed
DNS/DHCP logs and on-demand Windows reads (§ 3–4½), an append-only audit
log with external forwarding (§ 5), an API-request Prometheus family at
`/metrics` (§ 6), an agent-driven dashboard time-series path (§ 6), and
health endpoints (§ 7). All stdout output is compatible with standard
enterprise stacks (ELK, Loki, Datadog, Splunk) that you point at the
container streams.

> **What is *not* bundled.** Several pieces below are **design intent,
> not shipped code** and are flagged inline as planned: a centralized
> log store + collector (Loki / Grafana / Vector / Promtail — § 2), a
> generic control-plane log-explorer API (§ 3), the IPAM / DHCP / DNS /
> Celery / Database Prometheus metric families (§ 6), and the product
> Grafana dashboard bundle (§ 8). No Loki / Grafana / Vector / Promtail
> service ships in any `docker-compose*.yml` or in `charts/`.

### Native admin surfaces (since `2026.04.26-1`)

Two admin surfaces give operators platform visibility without
standing up Prometheus / Grafana:

- **Dashboard sub-tabs** (`/dashboard`) — Overview / IPAM / DNS /
  DHCP. The DNS and DHCP tabs show full-width Recharts
  time-series of query rate (BIND9 statistics-channels) and
  traffic (Kea `statistic-get-all`), driven by the per-server
  `dns_metric_sample` / `dhcp_metric_sample` tables.
- **Platform Insights** (`/admin/platform-insights`) — Postgres
  diagnostics (DB size, cache hit, WAL position, slow queries,
  table sizes, connection state, longest-running transaction),
  a **Redis** tab (since `#358`), and per-container CPU / memory /
  network / IO from the local Docker socket. See
  [SYSTEM_ADMIN § 0](features/SYSTEM_ADMIN.md#0-operator-surfaces-shipped-after-20260416-1).

  The **Redis** tab is superadmin-gated and reads Redis `INFO`
  (`/admin/redis/overview` — version / role / used + peak memory /
  fragmentation / connected clients / ops-per-sec / keyspace
  hit-ratio / connected replicas) plus `/admin/redis/keyspace`. Its
  headline panel is the **agent config-wake bus**
  (`/admin/redis/wake-bus`): the Redis pub/sub channels that wake
  parked agent `/config` long-polls the instant a change commits
  (#358), showing publishes-by-resource-class and the live
  subscriber count per channel (one subscriber per parked agent
  long-poll — so it doubles as a "how many agents are connected
  right now?" read). Every endpoint degrades to
  `available: false` + a hint on a Redis error rather than 500ing,
  so a Redis blip never takes the dashboard down. The Operator
  Copilot `get_redis_stats` tool (superadmin-gated, default-off)
  exposes the same rollup to chat.

  **Heartbeat-gated signals (#358 Phase 1).** The same bus also wakes
  the **supervisor heartbeat** long-poll: fleet OS/slot upgrade,
  reboot, role-assignment, and per-appliance host-config (firewall /
  the shared SNMP/NTP/LLDP/timezone broadcast) changes publish to a
  per-appliance channel (the `appliance` resource-class), so the
  supervisor acts in ~0 s instead of waiting up to one heartbeat
  interval. The supervisor stays HTTP-only — the wake is server-side,
  behind the heartbeat's opt-in `wait_seconds` long-poll — so remote /
  Application supervisors that can't reach `sentinel://` are
  unaffected and no Redis port is exposed to agent nodes. Redis-down
  degrades the hold to the bounded heartbeat interval (no storm), and
  a concrete pending command (upgrade / reboot) skips the hold so it
  is never delayed (non-negotiable #5).

  **Fleet-scale instrumentation + broker threshold (#358 Phase 2).**
  The wake-bus panel is the capacity signal for whether this
  Redis-only design still suffices: `total_subscribers` (open
  long-poll connections ≈ live agents + supervisors) and
  publishes-by-class (DNS / DHCP / hostconfig / appliance) are the
  inputs, with Redis `ops-per-sec` on the overview panel as the
  fan-out cost. The explicit threshold that would justify graduating
  to a dedicated broker — written down so the call is data-driven,
  not vibes — is **any of**: (a) sustained **> ~150** concurrent
  agent/supervisor long-poll subscribers (well past the "dozens" #171
  sized for); (b) the first **external / WAN-agent** topology (agents
  reaching the control plane across an untrusted network, where MQTT's
  retained-message / last-will / QoS / WSS-through-:443 wins start to
  matter); or (c) a sustained wake publish rate high enough that the
  per-replica pub/sub fan-out is visible in Redis `ops-per-sec`. Until
  one is crossed, Redis is the right answer and the work is done.

  **Transport abstraction + escalation path (#358 Phase 3 —
  deferred, not built).** `publish_wake()` / `wake_subscription()` in
  `backend/app/core/agent_wake.py` are the transport seam: callers
  only speak "publish a wake on this channel" / "wait for a wake", and
  the Redis pub/sub implementation is private to that module. Swapping
  in **Eclipse Mosquitto** (the escalation documented in #171:
  single-node StatefulSet behind the control-plane VIP, JWT-as-
  username auth + Dynamic-Security ACLs rendered from DB via the
  existing ConfigBundle → trigger-file → host-runner pattern, WSS on
  :443 for remote agents, MQTT kept a wake/notify channel only with
  HTTP config-pull + cache authoritative) would therefore be an
  implementation change inside that one module, not a protocol
  redesign. It is intentionally **not built** — no broker ships until
  a Phase-2 threshold is actually crossed.

The native surfaces are intentionally tactical — for long-term
metrics retention and cross-instance dashboards, fall back to
Prometheus scraping `/metrics` (see § 6).

---

## 1. Structured Logging

### Library and Format

All services use `structlog` configured to emit **newline-delimited JSON** (NDJSON):

```json
{
  "timestamp": "2024-01-15T14:30:00.123Z",
  "level": "info",
  "service": "api",
  "instance": "api-pod-3f8a",
  "request_id": "req-uuid-here",
  "user_id": "usr-abc123",
  "user_ip": "10.0.0.45",
  "method": "POST",
  "path": "/api/v1/ipam/subnets",
  "status": 201,
  "duration_ms": 42,
  "event": "subnet_created",
  "subnet_id": "sub-xyz789",
  "subnet_network": "10.1.5.0/24"
}
```

### Standard Fields (always present)

| Field | Description |
|---|---|
| `timestamp` | ISO 8601 UTC with milliseconds |
| `level` | `debug`, `info`, `warning`, `error`, `critical` |
| `service` | `api`, `worker`, `beat`, `agent`, `dhcp`, `dns` |
| `instance` | Hostname or pod name |
| `request_id` | UUID, passed through as `X-Request-ID` header |

### Sensitive Data Rules (enforced by linting)
- **Never log**: passwords, tokens, API keys, full credentials
- **Always mask**: MAC addresses in logs are shown as `aa:bb:cc:**:**:**`
- **Always mask**: Encryption keys, TSIG secrets
- Validator runs in CI (`grep -r 'password' app/ --include="*.py"` audit)

---

## 2. Centralized Log Management

> **Status: planned / not yet shipped.** No log collector, log store,
> or "log store query" API ships in the repo today. There is **no**
> Loki / Grafana / Vector / Promtail / Fluentd service in any
> `docker-compose*.yml` or in `charts/`, and nothing reads from a
> central store. What ships instead is described in sections 3–4½:
> every service logs **NDJSON to stdout** (section 1), and operators
> who want centralized retention point their own collector at those
> streams (Loki / Elasticsearch / Datadog / Splunk via standard
> Docker / Kubernetes log shipping). The pipeline below is the
> design target, not a bundled deliverable.

### Log Pipeline (planned)

```
Each service (API, Worker, Agents, DHCP, DNS)
        ↓ stdout (NDJSON)        ← shipped
Log Collector (Vector / Promtail / Fluentd)   ← operator-supplied, not bundled
        ↓
Central Log Store (operator's choice):
  - Grafana Loki
  - Elasticsearch (for existing ELK stacks)
  - External (Datadog, Splunk, Cloudwatch)
```

The shipped log surface (sections 3–4½) reads from PostgreSQL tables
the agents push into (BIND9 query log, Kea activity) and from Windows
servers over WinRM — **not** from a central log store. A store-backed
log-viewer API is not implemented.

### Bundled Log Store (planned)

If a bundled store lands, the intended shape is **Loki** (aggregation) +
**Grafana** (optional dashboards / log exploration) + **Vector** (collector
/ shipper). None of these ship today; treat this as a design note.

### Log Retention

For the **shipped** surfaces, retention is per-table and short — the
agent-pushed query/activity logs are pruned at 24 h (see § 4½.3) since
they're operator triage, not analytics. The audit log (§ 5) lives in
PostgreSQL and is not auto-pruned. Long-term log retention belongs in
an external store (Loki / a SIEM) fed from the stdout streams.

---

## 3. Built-in Log Viewer (shipped)

The shipped log viewer lives at **`/logs`**
(`frontend/src/pages/LogsPage.tsx`), backed by the router at
`backend/app/api/v1/logs/router.py`. It is **not** a generic
"control-plane application log explorer" — there is no `/admin/logs`
page and no generic `GET /api/v1/logs?service=&level=` query API. The
control-plane API / worker / beat processes log NDJSON to stdout
(section 1); to browse those, read the container streams
(`docker compose logs -f api worker`) or ship them to an external
store of your choice.

What the `/logs` page actually surfaces is four data-source tabs over
two transports — agent-pushed DNS/DHCP logs and on-demand Windows
server reads:

| Tab | Source | Transport | Detail |
|---|---|---|---|
| **DNS Queries** | BIND9 / PowerDNS query log (not Technitium — [#742](https://github.com/spatiumnorth/spatiumddi/issues/742)) | agent push → DB | § 4½.1 |
| **DHCP Activity** | Kea DHCPv4 activity | agent push → DB | § 4½.2 |
| **Event Log** | Windows DNS / DHCP Event Log | WinRM read-through | § 4.1 |
| **DHCP Audit** | Windows DHCP per-lease CSV trail | WinRM read-through | § 4.2 |

Each tab does its own server-side filtering, auto-fetches on mount and
on filter change, and has an explicit Refresh button (§ 4.3). The
agent tabs read from narrow PostgreSQL tables (§ 4½.3); the Windows
tabs are on-demand reads with no log-shipping. The endpoints are the
`POST /api/v1/logs/{query,dhcp-audit,dns-queries,dhcp-activity}` family
plus `GET /api/v1/logs/{sources,agent-sources}` — see sections 4 and
4½ for the full surface.

> **Planned (not shipped):** a unified explorer over the control-plane
> NDJSON streams (service / level / free-text filtering, live tail,
> NDJSON/CSV export) backed by a log-store query API. Today those
> streams are stdout-only.

---

## 4. Windows Server Log Viewer

Separate from the SpatiumDDI Log Explorer (section 3), there is a **Windows Server Log Viewer** at `/logs` that pulls logs directly off any Windows server SpatiumDDI has WinRM credentials for. Zero agent, no log-shipping — it's a read-through on demand, server-side filtered.

Two tabs today, plumbed through the driver abstraction so future sources (agent logs streamed over the bus, control-plane service logs) can plug in via `driver.available_log_names()` + `driver.get_events()` without touching the router.

### 4.1 Event Log tab

Filtered read of Windows Event Log via `Get-WinEvent -FilterHashtable`. Every filter runs server-side so the full log never crosses the wire.

**Inventory per driver:**

| Driver | Logs exposed |
|---|---|
| `WindowsDNSDriver` | `DNS Server` (classic) + `Microsoft-Windows-DNSServer/Audit` |
| `WindowsDHCPReadOnlyDriver` | `Microsoft-Windows-Dhcp-Server/Operational` + `Microsoft-Windows-Dhcp-Server/FilterNotifications` |

The DNS *Analytical* log is deliberately omitted — it's per-query, noisy, and better viewed in MMC's Event Viewer.

**Filters** (all optional, combined server-side):

- `log_name` — one of the entries above
- `level` — 1-5 per Windows severity codes (Critical / Error / Warning / Information / Verbose)
- `max_events` — 1-500 (truncation notice in the UI when the cap is hit)
- `since` — ISO datetime; frontend uses `<input type="datetime-local">` so we don't drag in a picker library
- `event_id` — filter to a single event code

**Endpoints:**

```
GET  /api/v1/logs/sources
  → [{server_id, name, driver, available_logs: [...]}, ...]

POST /api/v1/logs/query
  body: {server_id, log_name, level?, max_events?, since?, event_id?}
  → [{time_created, level, event_id, provider_name, message, ...}, ...]
```

**Error handling.** `Get-WinEvent` raises `System.Diagnostics.Eventing.Reader.EventLogException` when the log doesn't exist, zero events match, or a FilterHashtable key doesn't apply — it bypasses `-ErrorAction SilentlyContinue` because the exception is terminating at the .NET provider level. `fetch_events()` catches that explicitly and falls through to a generic "no data" matcher so those cases return `[]` cleanly instead of surfacing `"The parameter is incorrect"` to the UI as a 502.

### 4.2 DHCP Audit tab

Windows DHCP writes its **per-lease trail** to CSV-style files at `C:\Windows\System32\dhcp\DhcpSrvLog-<Day>.log` — one file per weekday (`Mon` / `Tue` / … / `Sun`), rotating, on by default on every DHCP role. These are the grants / renewals / releases / NACKs the Event Log itself does not cover.

**Helper** — `backend/app/drivers/windows_dhcp_audit.py`. Reads the day's file over WinRM via `Get-Content -Raw`, skips past the header block, feeds the remainder to `ConvertFrom-Csv`, returns the last N rows. Handles both UTF-16 (Unicode BOM) and ASCII — some Windows builds write one, some the other. Event-code → human label map covers the documented codes; unknown codes come through as `Code <n>` so new Windows releases don't drop silently. Access denied / missing file / locked-by-rotation all return `[]` instead of 500.

**Driver surface** — `WindowsDHCPReadOnlyDriver.get_dhcp_audit_events(day, max_events)` — thin wrapper routed through the standard `_load_credentials` + `_run_ps` path.

**Endpoint:**

```
POST /api/v1/logs/dhcp-audit
  body: {server_id, day?, max_events?}   # day: Mon..Sun, null = today
  → [{time, event_id, event_label, ip, hostname, mac, description}, ...]
```

**UI columns** — Time / Event (code + label) / IP / Hostname / MAC / Description. Event-dot colour mirrors Windows severity families:

| Colour | Event family |
|---|---|
| green | Grant / renew / successful ack |
| red | Failure / conflict / NACK |
| muted | Release / expire / scavenge |
| blue | Auth lifecycle (server started, authorised, etc.) |

The **event-code picker** shows distribution for the current day (e.g. `10 — Lease granted (238)`) so an operator can filter down to a specific outcome without knowing codes by heart.

### 4.3 Dispatch & auto-fetch

The frontend uses `useQuery` keyed on every filter (server / log / level / max / since), so:

1. Entering the page fires the first query immediately against the first available server + log.
2. Changing any filter (including the Since datetime picker) fires a re-fetch automatically.
3. `staleTime: Infinity` means switching tabs + back doesn't hit the DC unless the user actually changes something.
4. The explicit **Refresh** button calls `refetch()` to bypass the cache on demand.

Shared helpers (`ServerPicker` / `MaxEventsPicker` / `FilterSearch` / `RefreshButton` / `QueryErrorBanner` / `QueryingIndicator` / `TruncatedNotice`) are reused across both tabs.

---

## 4½. SpatiumDDI Agent Log Viewer (BIND9 + Kea)

Two additional tabs on the same Logs page, sourced from in-container agents instead of WinRM.

### 4½.1 DNS Queries tab

**Source.** BIND9's `query-log` channel. The control-plane template (`backend/app/drivers/dns/templates/bind9/named.conf.j2`) renders a `logging { channel queries_channel { file "/var/log/named/queries.log" versions 5 size 50m; ... }; category queries { queries_channel; }; };` block when `DNSServerOptions.query_log_enabled` is on. PowerDNS feeds the same pipeline, but from a **different file**: the agent's `start_daemon` redirects `pdns_server`'s stderr into `<state_dir>/pdns.log` (inside the agent's own state dir, so the unprivileged `spatium` user can write it) and passes that explicit path to `QueryLogShipper`, gated on `log-dns-queries=yes` + `loglevel` ≥ 6. That is the file to inspect, mount or override with `DNS_QUERY_LOG_PATH` on a PowerDNS agent — not `/var/log/named/queries.log`. The control plane dispatches parsing by `server.driver`, so the one ingest endpoint accepts either format.

> **Not Technitium.** Technitium's query logging is API/DB-backed
> (`/api/logs/query*`) rather than a tailable text file, so the
> file-tailing `QueryLogShipper` cannot reach it — it needs a
> poll-and-diff shipper instead. Tracked in
> [#742](https://github.com/spatiumnorth/spatiumddi/issues/742); until it
> lands, a Technitium group's queries are visible in Technitium's own
> console but not on this tab.

**Pipeline.**

1. BIND9 writes lines to `/var/log/named/queries.log` (path is templated; agents respect `DNS_QUERY_LOG_PATH` env override).
2. The DNS agent's `QueryLogShipper` thread (`agent/dns/spatium_dns_agent/query_log_shipper.py`) tails the file like `tail -F`, batches up to 200 lines or 5 s of activity (whichever first), and POSTs to `POST /api/v1/dns/agents/query-log-entries`.
3. The control plane parses each line into `DNSQueryLogEntry` rows (`backend/app/services/logs/bind9_parser.py`) — timestamp, client IP+port, qname, qclass, qtype, flags, view. The original raw line is preserved alongside.
4. UI calls `POST /logs/dns-queries` with filters (`q` substring, `qtype`, `client_ip`, `since`, `max_events`); newest first.

**Filters.** Server picker, qtype (A / AAAA / MX / …), client IP, datetime-`since`, max events, raw-substring search.

**Resilience.** File-not-yet-present (operator hasn't enabled `query_log_enabled`) is silent — the shipper sleeps + re-checks. Inode-change rotation is detected and the file re-opened. Control-plane errors drop the batch (logs are triage data, not durable). Buffer is capped at 5000 lines; older half is trimmed if the control plane stays unreachable.

### 4½.2 DHCP Activity tab

**Source.** Kea's `kea-dhcp4` logger. The agent's `render_kea` adds two `output_options` to the rendered config — `stdout` (existing `docker logs` workflow stays intact) **and** `/var/log/kea/kea-dhcp4.log` with in-process rotation (`maxsize: 50_000_000`, `maxver: 5`, `flush: true`).

**Pipeline.** Same shape as the DNS path — `LogShipper` thread (`agent/dhcp/spatium_dhcp_agent/log_shipper.py`) → `POST /api/v1/dhcp/agents/log-entries` → `kea_parser.py` → `DHCPLogEntry` rows.

**Parser fields.** Severity (`DEBUG` / `INFO` / `WARN` / `ERROR` / `FATAL`), Kea log code (`DHCP4_LEASE_ALLOC`, `DHCP4_LEASE_DECLINE`, `DHCP4_PACKET_PROCESS_STARTED`, etc), MAC address (after `hwtype=N`), lease IP, transaction id. Lines that don't match the regex still get stored with the raw text — Kea has hundreds of log codes and we only structure-parse the most common shape.

**Filters.** Server picker, severity, log code (free-form text — operators paste e.g. `DHCP4_LEASE_ALLOC`), MAC, IP, datetime-since, max events, raw substring.

### 4½.3 Storage + retention

Two narrow tables (`dns_query_log_entry`, `dhcp_log_entry`) with composite indexes on `(server_id, ts)`. Migration `d8c5f12a47b9_query_log_entries`. FK cascade drops a server's rows when the server is removed.

Retention is a nightly Celery task (`app.tasks.prune_logs.prune_log_entries`) that deletes rows older than 24 h. This is *operator triage*, not analytics — for longer history, ship to Loki / a SIEM.

**Outage backlog (#1077).** Agents spool the batches the control plane could not accept and replay them on reconnect, with the lines' original timestamps — so a maintenance window fills in rather than leaving a hole. The ingest endpoints skip lines already older than the 24 h window (reported as `expired` in the response) instead of inserting rows the next prune deletes, and the agents drop spooled log batches older than `AGENT_SPOOL_LOG_MAX_AGE_HOURS` themselves. Replays are deduplicated per batch (`batch_id` → `agent_ingest_receipt`, 35-day retention, pruned by the same nightly task). While an agent is draining a backlog the DNS / DHCP server row shows an amber **Replaying … backlog** chip; if its spool hit the cap, a red **Spool trimmed** chip and the `agent_spool_trimmed` alert (§9.1). See [`DNS_AGENT.md` §3](deployment/DNS_AGENT.md).

**Why so short?** Query logs are a firehose. A busy resolver doing 100 qps writes 8.6M rows per day; even 24 h of that is significant. Anyone needing days of history should run Loki alongside and the agent push can coexist with stdout shipping.

---

## 5. Audit Log

The audit log is a separate, append-only, structured log of all **data mutations** in SpatiumDDI. It is stored in the **PostgreSQL database** (not the log store) for queryability, immutability guarantees, and compliance.

```
AuditLog
  id (uuid)
  timestamp (timestamptz, indexed)
  user_id (FK → User)
  user_display_name: str    -- denormalized for historical record
  auth_source: str          -- local / ldap / oidc
  source_ip: inet
  user_agent: str
  action: enum(create, update, delete, login, logout, sync, permission_change, ...)
  resource_type: str        -- e.g., "subnet", "ip_address", "dhcp_scope"
  resource_id: str
  resource_display: str     -- human-readable, e.g., "10.1.2.0/24 (Corp LAN)"
  old_value: JSONB          -- full previous state (null for create)
  new_value: JSONB          -- full new state (null for delete)
  changed_fields: str[]     -- list of field names that changed (for updates)
  request_id: str           -- correlates to application log
  result: enum(success, denied, error)
  error_detail: str (nullable)
```

### Audit Log UI

Available at `/admin/audit`:
- Same filtering and live-tail as the log viewer
- Additional filters: `action`, `resource_type`, `result`
- Diff view for updates: shows old vs. new value side-by-side
- Non-deletable — no delete button, enforced at DB level (trigger prevents DELETE)

### 5.1 External forwarding

Every committed `AuditLog` row fans out to every enabled
`AuditForwardTarget`. Each target picks its own transport, wire
format, and optional severity / resource-type filter, so a single
SpatiumDDI instance can feed (for example) a Splunk HTTP collector,
a QRadar LEEF syslog relay, and a compliance-only JSON-lines sink at
the same time. Configure under **Settings → Audit Event Forwarding**.

**Delivery guarantee.** Best-effort. A dedicated `asyncio` task
runs outside the commit path, so the audit write always succeeds
before forwarding is attempted. A failing collector never rolls back
a DDI mutation. Each target's failure is isolated — one dead SIEM
doesn't affect the others. Operators who need at-least-once replay
should point a webhook at a queue (NATS / Kafka / Redis) and let
that be the durable layer.

**Implementation.** SQLAlchemy `after_commit` listener in
`app/services/audit_forward.py`. Snapshots new `AuditLog` rows
inside `after_flush`, then in `after_commit` schedules one
`asyncio.create_task` per (row, target) pair so slow collectors
don't serialize the queue.

**Transports.**
- **Syslog UDP** — `socket.sendto`, fire-and-forget, one syscall.
- **Syslog TCP** — `asyncio.open_connection`, 5 s connect timeout.
- **Syslog TLS** — same as TCP plus `ssl.create_default_context()`;
  an optional PEM-encoded CA bundle per target lets operators pin
  a private CA without touching the system store.
- **HTTP webhook** — `httpx.AsyncClient`, 5 s timeout,
  `Content-Type: application/json`, optional `Authorization`
  header sent verbatim. The `webhook_flavor` column picks between
  generic JSON, **Slack** (`mrkdwn` block), **Teams**
  (`MessageCard`), and **Discord** (`embed`) so chat-channel
  delivery doesn't need a separate adapter.
- **SMTP email** — stdlib `smtplib` driven through
  `asyncio.to_thread` (no extra dep). Supports `starttls` / `ssl` /
  plaintext, optional auth (Fernet-encrypted password at rest).
  Subject + body rendered from the audit row.

**Syslog output formats** (per-target). Webhook targets always
deliver JSON and ignore this setting.

| Format | Use case |
|---|---|
| `rfc5424_json` | Default. Modern SIEMs (Splunk, Elastic, Graylog) auto-parse the JSON body after the RFC 5424 header. |
| `rfc5424_cef` | ArcSight + many commercial SIEMs. `CEF:0\|SpatiumDDI\|SpatiumDDI\|1.0\|<rtype:action>\|<display>\|<sev>` header + `act=`/`suser=`/`cs1=…` extensions. CEF severity mapped as info=3, error=6, denied=9. |
| `rfc5424_leef` | IBM QRadar native format. LEEF 2.0 with `^` field delimiter (safer over UDP than the default tab). |
| `rfc3164` | Legacy BSD syslog: `<PRI>Mmm dd HH:MM:SS host tag: <JSON>`. For collectors that don't speak RFC 5424. |
| `json_lines` | Bare JSON per line — no syslog framing. For raw Logstash / Fluentd / Vector inputs. |

**Severity mapping** (RFC 5424): `result="success"` → 6 info,
`result="denied"` → 4 warn, `result="failed"` / `"error"` → 3 err.
Facility is per-target and configurable 0–23 (default 16 = local0).

**Three payload shapes go through one delivery path**, and until #1031
only the audit one was handled. Audit rows carry `result` + `timestamp`;
**alert events and the AI digest carry `severity` + `fired_at`**. Every
renderer and the filter gate now resolve both — see
`audit_forward._payload_severity` / `_payload_timestamp`, the single
place the shapes are reconciled.

Alert severities map onto the same RFC 5424 scale: `critical` → 2 crit,
`warning` → 4 warn, `info` → 6 info. The audit mappings above are
byte-identical to what they always were, because moving them would move
every line an existing collector already indexes.

CEF and LEEF carry the same severity on their own **numeric** scales
(3 / 6 / 9), from one shared map so the two renderers cannot disagree
about how severe the same event was. LEEF's `sev` is new — LEEF 2.0
defines it as an integer 1–10, and a word there is not something QRadar
can map, so it would have left every alert at default severity.

**Per-target filters.**
- `min_severity` — drop events below this bucket (info / warn /
  error / denied). Null = forward everything. Alert severities rank on
  the same scale, with **`critical` at the top, level with `denied`**:
  `denied` is the strictest threshold selectable, and a threshold that
  silently opts you out of the most severe alerts is exactly the defect
  #1031 was filed for.
- `resource_types` — optional allowlist of `AuditLog.resource_type`.
  Null / empty = forward everything. Useful for compliance-scoped
  targets that should only see, say, auth + IPAM events. An alert names
  its subject as `subject_type`, drawn from the same vocabulary, and is
  matched against that — without it a target carrying an allowlist
  dropped every alert for want of a key. One rule **namespaces** its
  subject: `compliance_change` fires against an audit row and reports
  `audit:<resource_type>`, so both the raw and the suffix form are
  accepted. Matching only the raw string would have left exactly those
  alerts failing every allowlist — the same bug, surviving in the one
  rule whose subject genuinely is an audited resource.

> **Behaviour change in this release (#1031).** Before it, a target with
> a non-null `min_severity` dropped **every** alert including criticals,
> because alerts were bucketed against a key they do not carry — and a
> syslog target on the default `rfc5424_json` format received no alert at
> all, since rendering raised `KeyError: 'timestamp'` and the per-target
> exception guard logged `alert_deliver_failed` and moved on. Both are
> fixed, so an operator who set that field long ago and forgot will start
> receiving alerts they were never getting. That is the intended
> behaviour; if the volume is unwanted, raise the threshold rather than
> clearing it. The "Test target" button never showed this, because it
> sends an audit-shaped payload with the filter forced off.

**JSON payload shape** (the body used by `rfc5424_json`, `json_lines`,
and the webhook):
  ```json
  {
    "id": "…", "timestamp": "2026-04-21T10:00:00+00:00",
    "action": "create", "resource_type": "dns_zone",
    "resource_id": "…", "resource_display": "example.com.",
    "result": "success", "user_id": "…",
    "user_display_name": "admin", "auth_source": "local",
    "changed_fields": [], "old_value": null, "new_value": {…}
  }
  ```

**Backward compatibility.** The pre-multi-target flat columns on
`platform_settings` (`audit_forward_syslog_*`, `audit_forward_webhook_*`)
are preserved and migrated into one `audit_forward_target` row apiece
on upgrade. When the targets table is empty the service falls back to
those flat columns so existing installs keep forwarding without
operator intervention. They are slated for removal in a future release.

**Known gap.** Celery-scheduled audits (e.g. the lease-pull
housekeeping row) may not forward — Celery wraps the task body in
`asyncio.run`, which closes its loop before the scheduled dispatch
task runs. Operator-triggered audit events (the 99% case) forward
reliably from the API worker's long-running loop. If scheduled-task
forwarding turns out to matter, the fix is an awaitable drain in
each task wrapper.

---

## 5b. Typed-event webhooks

Distinct from audit-forward: this is a curated **typed-event
surface** for downstream automation, not raw audit rows. Operators
configure subscriptions at `Admin → Webhooks` (`/admin/webhooks`).

**Vocabulary.** A curated set of typed events generated from a
resource × verb cross-product (plus a handful of special-cased
names) — e.g. `space.created`, `subnet.bulk_allocate`,
`dns.zone.updated`, `dhcp.scope.deleted`, `auth.user.created`,
`integration.kubernetes.created`. The live list is served by
`GET /api/v1/webhooks/event-types`. Subscriptions with no event-type
filter match everything.

**Pipeline.** Audit-row commit triggers an `EventOutbox` write per
matching `EventSubscription`. Celery beat (`event-outbox-drain`,
every 10 s) claims rows with `SELECT … FOR UPDATE SKIP LOCKED`,
signs each POST with `hmac(secret, ts + "." + body, sha256)`, and
delivers. Failures retry with exponential backoff
(2 / 4 / 8 … 600 s capped) up to `max_attempts` (default 8 ≈
8.5 min cumulative). Permanent failures flip to `state="dead"` for
operator review.

**Wire format.**
- Body: full audit-row JSON snapshot.
- Headers: `Content-Type: application/json`,
  `User-Agent: SpatiumDDI/<ver>`,
  `X-SpatiumDDI-Event: <event_type>`,
  `X-SpatiumDDI-Delivery: <outbox_id>`,
  `X-SpatiumDDI-Timestamp: <unix-seconds>`,
  `X-SpatiumDDI-Signature: sha256=<hex>`.
- Receivers verify by recomputing the HMAC over `<ts>.<body>` and
  rejecting requests whose timestamp is outside their tolerance
  window (default 5 minutes is sensible).
- Operator-supplied custom headers are applied last, but the
  `X-SpatiumDDI-*` namespace is reserved and can't be overridden.

**Delivery semantics.** At-least-once modulo the audit-row commit
window. The outbox write happens after the audit row commits, so a
process crash between the two drops the event. Receivers should
de-duplicate on `event_id` (= `AuditLog.id`).

**Operator controls.**
- One-time secret reveal on subscription create (also rotatable on
  edit). Stored Fernet-encrypted; the response only reveals
  `secret_set: bool` afterwards.
- Test button synthesizes a `test.ping` through the same pipeline
  with an inline pass/fail flash.
- Per-subscription deliveries panel with live state + manual
  **Retry now** on failed/dead rows.

---

## 6. Prometheus Metrics

The API service exposes a Prometheus scrape endpoint at `/metrics` on
the main API port (gated by the `prometheus_metrics_enabled` setting,
default on; registered in `backend/app/main.py`).

> **Implemented today:** only the **API-request family** below, defined
> and emitted in `backend/app/metrics.py` via a Starlette middleware on
> every request. The IPAM / DHCP / DNS / Celery / Database families that
> follow are **planned, not emitted** — no collector or exporter
> populates them, and scraping `/metrics` returns the request family
> (plus the default `prometheus_client` process / GC metrics) only. The
> two `spatiumddi_auth_*` counters are *declared* in `metrics.py` but
> not yet incremented by any call site, so they read zero. For the
> shipped, agent-driven dashboard metrics path, see
> **Built-in Dashboard Time-Series** below — that one is real.

### API Service Metrics (implemented)

```
spatiumddi_api_requests_total{method, path_template, status_code}
spatiumddi_api_request_duration_seconds{method, path_template} (histogram)
spatiumddi_api_active_requests (gauge)
```

Plus two counters declared but not yet wired to a call site (read zero):

```
spatiumddi_auth_login_total{method, result}   # planned — method=local/ldap/oidc
spatiumddi_auth_token_usage_total{scope}       # planned
```

### IPAM Metrics (planned — not emitted)

```
spatiumddi_subnet_utilization_percent{subnet_id, subnet_network, space_id}
spatiumddi_ip_addresses_total{subnet_id, status}
spatiumddi_subnets_total{space_id, status}
```

### DHCP Metrics (planned — not emitted)

```
spatiumddi_dhcp_leases_active{server_id, scope_id}
spatiumddi_dhcp_pool_utilization_percent{server_id, scope_id, pool_id}
spatiumddi_dhcp_sync_last_success_timestamp{server_id}
spatiumddi_dhcp_sync_duration_seconds{server_id}
spatiumddi_dhcp_server_status{server_id}   # 1=online, 0=offline
```

### DNS Metrics (planned — not emitted)

```
spatiumddi_dns_sync_last_success_timestamp{server_id}
spatiumddi_dns_records_total{server_id, zone_id, record_type}
spatiumddi_dns_zones_total{server_id, view_id}
spatiumddi_dns_blocklist_entries_total{list_id}
spatiumddi_dns_server_status{server_id}
```

### Built-in Dashboard Time-Series (agent-driven) — shipped

For operators who don't run Prometheus, SpatiumDDI ships a minimal
self-contained time-series path used by the built-in dashboard
charts. Agents poll their local daemons every 60 s and POST
per-bucket counter *deltas* to the control plane:

| Surface | Source | Endpoint |
|---|---|---|
| **BIND9** | `statistics-channels` XMLv3 (`/xml/v3/server`, bound to `127.0.0.1:8053`, injected at render time) | `POST /api/v1/dns/agents/metrics` |
| **Kea** | `statistic-get-all` over the existing control socket | `POST /api/v1/dhcp/agents/metrics` |

The control plane stores deltas in two small tables —
`dns_metric_sample(server_id, bucket_at, queries_total, noerror,
nxdomain, servfail, recursion)` and `dhcp_metric_sample(server_id,
bucket_at, discover, offer, request, ack, nak, decline, release,
inform, receive_drop, socket_drop)`. Retention is enforced by the
`prune_metric_samples` Celery task (daily, default 7 days).

Two of those DHCP columns are about packets *not* handled, and they do not
come from the same place or mean the same thing (issue #980).
`socket_drop` is the kernel's per-socket `sk_drops` from `/proc/net/udp`,
read by the agent directly: packets discarded because Kea's receive buffer
was full, so Kea never saw them and no counter it keeps can report them.
On a node short of CPU only this one moves, and it is the one the alert
and the dashboard treat as loss.

`receive_drop` is Kea's own `pkt4/6-receive-drop` — packets it read and then
discarded — and is **context, not a fault**: it counts deliberate drops too.
Verified against kea-dhcp4 3.0.3, a client matching a `DROP` client-class
increments it once per packet, and a `DROP` class is exactly what the shipped
DHCP MAC blocklist renders. See [`DHCP.md` §4c](features/DHCP.md).

**Both are nullable, and NULL means UNMEASURED.** An agent older than #980,
or one whose runtime cannot read `/proc/net/udp`, reports no `socket_drop`.
Readers must render that as unknown — a 0 would say "this server has dropped
nothing", which is exactly the false reassurance #980 was filed about. The
ingest endpoint therefore stores an omitted field as NULL rather than
clamping it, the `dhcp_packets_dropped` alert skips such a server rather than
vouching for it, and every "was this measured?" test keys on `socket_drop`
alone (`receive_drop` always arrives from a #980 agent, so testing the pair
would read an unmeasurable server as measured-and-clean). The InfluxDB
exporter omits the field entirely rather than writing 0, since line protocol
has no null.

One more thing worth knowing about both endpoints: a second report for a
bucket that already exists is **added** to it, not substituted. The agent
floors `bucket_at` to the minute while its own interval is 60 s ± 3 s of
jitter, so a tick early in a minute followed by a 57-59 s gap puts two
genuinely different deltas in the same bucket — about one bucket in forty.
Substituting (the pre-#980 behaviour, and the DNS endpoint's until #1077)
silently discarded a poll, which for a loss counter discards the minute
somebody is looking for.

Accumulating is only safe because a *retry* is not a second delta. Since
#1077 agents spool a metric POST that failed and replay it on reconnect, so
the backlog of an outage lands on the minutes it happened and the chart
fills in. Each replay carries the batch's `batch_id`, and a batch already
committed is acknowledged as a duplicate without being added again — the
batch in flight when the control plane stopped would otherwise be counted
twice.

The dashboard queries two read endpoints:

```
GET /api/v1/metrics/dns/timeseries?window={1h|6h|24h|7d}&server_id={uuid?}
GET /api/v1/metrics/dhcp/timeseries?window={1h|6h|24h|7d}&server_id={uuid?}
```

Server-side `date_bin` downsamples transparently — 60 s buckets for
windows ≤ 24 h, 5 min buckets for 7 d. That keeps the response under
~2 k points regardless of retention.

Windows DNS / DHCP drivers don't report through this path yet (they'd
need `Get-DnsServerStatistics` / `Get-DhcpServerv4Statistics` calls
over WinRM). The dashboard card shows "no data yet" rather than an
error in that case.

### InfluxDB Push Export (issue #889) — shipped

The same two tables feed an outbound push. `InfluxDBTarget` rows are
configured under **Settings → Metrics → InfluxDB Export**; a Celery
beat task (`app.tasks.influxdb_push.push_influxdb_metrics`, 30 s tick,
per-target interval gating) renders line protocol and POSTs it.

This is a *push*, so it works where the Prometheus scrape does not —
a control plane behind NAT, or an operator who already runs InfluxDB
and does not want a second TSDB. The two are independent; running both
is fine.

Measurements, versions (v1 / v2 / v3), idempotency and the high-water
marks (a strictly-forward drain plus a separately-budgeted replay
window) are documented in
[`features/SYSTEM_ADMIN.md` § 8](features/SYSTEM_ADMIN.md#influxdb-export-issue-889).
The short version:

* Counter deltas (`<prefix>dns_queries`, `<prefix>dhcp_messages`) carry
  the **agent bucket's own timestamp** — 60 s is the resolution floor
  no matter what push interval you pick.
* Gauges (`<prefix>subnet_utilization`, `<prefix>dhcp_scope_leases`)
  are sampled at push time and have no backfill.
* v3 reuses the v2 write endpoint with bearer auth and
  bucket=database naming, so InfluxDB 3 Core / Enterprise / Cloud all
  work through the same path.

#### Grafana with an InfluxDB datasource

Add the datasource (**Connections → Add new connection → InfluxDB**),
pick **Flux** as the query language, and point it at the same URL,
org, bucket and token you gave the target. Then, for the two panels
operators want first:

DNS query rate per server, as queries/second:

```flux
from(bucket: "ddi")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "spatiumddi_dns_queries")
  |> filter(fn: (r) => r._field == "queries_total")
  |> map(fn: (r) => ({r with _value: float(v: r._value) / 60.0}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group(columns: ["server"])
```

The `/ 60.0` is the load-bearing part: the stored value is a *delta
per 60 s bucket*, not a rate and not a running counter, so neither
`derivative()` nor a bare plot gives you queries/second.

Subnet utilization, latest sample per subnet, for a table or gauge:

```flux
from(bucket: "ddi")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "spatiumddi_subnet_utilization")
  |> filter(fn: (r) => r._field == "percent")
  |> last()
  |> group()
  |> keep(columns: ["subnet", "space", "_value"])
```

On a **v1** datasource the same series are reachable through InfluxQL,
where the deltas are plain values (`SELECT sum("queries_total") FROM
"spatiumddi_dns_queries" WHERE $timeFilter GROUP BY time($__interval),
"server"`) — again a per-bucket sum, not `derivative()`.

### Celery / Worker Metrics (planned — not emitted)

```
spatiumddi_celery_tasks_total{task_name, state}   # state=success/failure/retry
spatiumddi_celery_task_duration_seconds{task_name} (histogram)
spatiumddi_celery_queue_length{queue_name}
spatiumddi_celery_workers_active (gauge)
```

> Worker / beat health is currently surfaced through the
> `GET /health/platform` rollup (§ 7) and the Platform Insights admin
> surface, not through Prometheus metrics.

### Database Metrics (planned — not emitted)

```
spatiumddi_db_pool_connections{state}   # state=checked_out/idle/overflow
spatiumddi_db_query_duration_seconds{operation} (histogram)
spatiumddi_db_replication_lag_seconds{replica}
```

> Postgres diagnostics (DB size, cache hit, WAL position, slow
> queries, connection state) ship today through the **Platform
> Insights** admin surface (`/admin/platform-insights`, described in
> the Overview), which queries Postgres `pg_stat_*` views directly
> rather than exporting Prometheus metrics.

---

## 7. Health Endpoints

All services expose:

**`GET /health/live`** — Liveness probe
- Returns `200 {"status": "ok"}` if the process is running
- Returns `503` only if the process should be restarted

**`GET /health/ready`** — Readiness probe
- Checks: DB connectivity, Redis connectivity, required config present
- Returns `200 {"status": "ok", "checks": {...}}` if ready to serve traffic
- Returns `503` with failed check details if not ready

**`GET /health/startup`** — Startup probe (for Kubernetes slow-start containers)
- Same as readiness but used only during initial startup

**`GET /health/platform`** — Per-component rollup for the dashboard
- Unlike `/health/ready` (which returns a single binary verdict for
  orchestrator probes), this endpoint enumerates each control-plane
  piece so the UI can show a per-component status dot.
- Response: `200 {"status": "ok"|"degraded", "components": [...]}`.
  Individual component failures **never** make the endpoint itself
  fail — the caller always gets a 200 with the rollup so a single
  flaky component doesn't blank the dashboard card.
- Components checked:
  - `api` — always `ok` when the endpoint responds
  - `postgres` — `SELECT 1` with round-trip latency in the detail
  - `redis` — `PING` with round-trip latency
  - `celery-workers` — `celery_app.control.inspect(timeout=2).ping()`
    run in a threadpool with a 3 s overall timeout (so a dead broker
    can't hang the endpoint). Detail carries the worker count; full
    list surfaces on UI hover.

    > **Known limit (#925).** Ping is answered by the worker's
    > MainProcess pidbox consumer, which is independent of the prefork
    > pool. A worker whose every pool slot is blocked still answers
    > `pong` and reports `ok` here, while nothing it is handed can run.
    > Verified directly against a 2-slot worker holding two
    > forever-tasks. Detecting pool saturation would need an
    > `inspect.active()` round trip, and this endpoint is
    > unauthenticated — every extra broadcast RPC is amplification an
    > anonymous caller controls — so the `celery-beat` component below
    > is the signal that surfaces a wedged pool instead.

  - `celery-beat` — reads the `spatium:beat:heartbeat` key from
    Redis (written by `app.tasks.heartbeat.beat_tick` every 30 s with
    a 5-min TTL). Age folded into `ok` (≤ 90 s), `warn` (> 90 s — two
    beat intervals missed, or a stamp more than 90 s in the *future*,
    which is clock skew between the node that ran the tick and this
    one), or `error` (missing — no tick has landed for > 5 min).

    **`error` here does not mean beat is broken.** Beat *schedules*
    this task; a **worker** executes it, so the key is a round trip and
    its absence indicts either end. The detail says so. It used to read
    "beat is stopped", and that cost real investigation time on #925 —
    the appliance's beat was running perfectly and the fault was every
    worker pool slot wedged on an unbounded Redis connect, which per the
    note above is a state `celery-workers` reports as healthy.
- Consumed by the Dashboard → Platform Health card. Authenticated
  dashboard users only — the endpoint itself is unauthenticated for
  parity with the other `/health/*` probes, and exposes nothing a
  normal monitoring probe doesn't already see.

---

## 8. Bundled Grafana Dashboards

> **Status: planned / not shipped as a product bundle.** No
> operator-facing Grafana dashboard set ships with the product, and
> the dashboards below depend on the planned (un-emitted) metric
> families in § 6. What *does* exist is a single **perf-testing**
> "war room" dashboard at
> [`perf/dashboards/grafana/dashboards/warroom.json`](https://github.com/spatiumnorth/spatiumddi/blob/main/perf/dashboards/grafana/dashboards/warroom.json)
> (with provisioning under `perf/dashboards/grafana/provisioning/` and
> a matching scrape config at `perf/dashboards/prometheus/prometheus.yml`).
> That stack is for the load/soak test harness under `perf/`, not for
> production observability, and it scrapes the perf exporters rather
> than the product `/metrics` endpoint's request family.

The intended product dashboard bundle, once the § 6 metric families
are emitted, would be:

| Dashboard | Contents |
|---|---|
| **SpatiumDDI Overview** | API request rate, error rate, p95 latency, active users |
| **IP Utilization** | Top subnets by utilization, space-wide heatmap, trending |
| **DHCP Health** | Server status, lease counts, pool utilization, sync lag |
| **DNS Health** | Server status, zone counts, sync lag, blocklist hit rate |
| **System Health** | DB connections, replication lag, Redis memory, Celery queues |
| **Audit Activity** | Actions per hour, top users, failed auth attempts |

Until then, the **shipped** in-product equivalents are the Dashboard
sub-tabs and Platform Insights surfaces described in the Overview.

---

## 9. Alerting

SpatiumDDI exposes two parallel paths for alerts. Both can run at
once — they serve different audiences.

### 9.1 In-app alerts framework (native)

Operator-authored rules stored in the `alert_rule` table. The
evaluator (`backend/app/services/alerts.py:evaluate_all`) runs on a
60 s Celery beat tick; `POST /api/v1/alerts/evaluate` forces an
immediate pass. Each match opens an `alert_event` row (partial
index on `(rule_id, subject_type, subject_id) WHERE resolved_at IS
NULL` keeps dedup O(1)); events resolve automatically when the
subject clears. Delivery reuses the **Audit Event Forwarding**
syslog + webhook targets — one SIEM destination for both audit and
alerts.

Rule types shipped today:

| Type | Fires when |
|---|---|
| `subnet_utilization` | `Subnet.utilization_percent ≥ threshold`; honours `PlatformSettings.utilization_max_prefix_{ipv4,ipv6}` so PTP / loopback subnets can't trip the alarm. |
| `server_unreachable` | Any DNS / DHCP server whose status is `unreachable` or `error`. `server_type` filters the family. |
| `asn_holder_drift` / `asn_whois_unreachable` / `rpki_roa_expiring` / `rpki_roa_expired` | ASN / RPKI signals from the WHOIS + ROA refresh tasks (#85). |
| `bgp_prefix_hijack` / `bgp_more_specific_announced` | BGP prefix-hijack signals (#527) — an unexpected origin AS announcing a tracked prefix (exact) or a more-specific sub-prefix of it. Backed by the `bgp_hijack_detection` latch table (see §9.1a). Per-detection severity: `critical` when RPKI says the announcement is **invalid**, `warning` when RPKI coverage is **unknown**. Seeded disabled (external-signal rules are noisy). |
| `bgp_lg_session_down` / `bgp_lg_rpki_invalid_route` / `bgp_lg_unexpected_origin` / `bgp_lg_more_specific` / `bgp_lg_route_flap` / `bgp_lg_missing_advertisement` | BGP Looking Glass internal-RIB signals (#566) — the companion to `bgp_prefix_hijack` above that reads the operator's OWN live table via the receive-only collector (`bgp_lg_peer` / `bgp_lg_route`) instead of the public table. `session_down` fires on an enabled peer that stays out of `established` past a 2 min grace window anchored on `BGPLGPeer.down_since` (watermark set on first non-established observation, cleared on re-establish), auto-resolving the moment the session recovers. `rpki_invalid_route` fires on any active learned route whose ingest-computed `rpki_status` is `invalid`, always at `critical` severity. `unexpected_origin` / `more_specific` reuse the same `bgp_tracked_prefix` owned-prefix list #527 curates, matching an owned prefix exactly (`==`) or strictly more-specific (`<<`) against a learned route whose origin ASN is outside the expected set. `route_flap` fires when a route's lifetime `flap_count` crosses `threshold_percent` (reused as a raw flap-count floor, default 5) AND its `last_flap_at` is within the trailing 10 min window, so it flags currently-unstable paths rather than permanent scars. `missing_advertisement` fires on a `Subnet` flagged `bgp_should_advertise` with no active learned route covering it (`>>=`) across any peer. Gated on the `network.looking_glass` module; all six seeded **disabled** (need an operator-configured peer, and the tracked-prefix rules need at least one enabled `bgp_tracked_prefix`). |
| `rogue_ra` | Unexpected IPv6 Router Advertisement on a monitored segment (#524) — the passive RA sniffer observed an RA whose `(group, source_ip, source_mac)` identity isn't an allowlisted router. Seeded **disabled** (needs `DHCP_RA_SNIFFER_ENABLED` + the `ipv6.router_advertisements` module). |
| `ip_blocklisted` | An IP in scope for DNSBL monitoring appears on a curated RBL (#528) — a **latch** rule that auto-resolves when the IP is delisted or de-scoped. Gated on the `security.dnsbl` module + the `dnsbl_monitoring_enabled` sweep switch. |
| `wol_wake_failed` | A Wake-on-LAN schedule's latest **finalised** run (`verify_state='done'`, started within `threshold_days`, default 1) left SENT hosts unconfirmed, **and** a fresh passive re-check still can't see them (#596). Subject is the **schedule**, not the run — a 15-minute schedule would otherwise open ~96 events a day; the one event carries the blast-radius rollup. The re-check is what makes it recovery-aware: as stragglers boot and any subsystem stamps `IPAddress.last_seen_at`, the matcher stops matching and the shared loop auto-resolves — no bespoke resolve path. A clean next run, or the failing run ageing out of the window, resolves it too. Ad-hoc single-host wakes (`wol_run.schedule_id IS NULL`) never match: they have no schedule subject, and surface through History + the `find_wol_wake_failures` copilot tool instead. Per-schedule mute via `wol_schedule.verify_alert_enabled`. Seeded **disabled** (needs post-wake verify armed on a schedule). |
| `domain_expiring` / `domain_nameserver_drift` / `domain_registrar_changed` / `domain_dnssec_status_changed` | Registry-side domain signals (#87). The two transition-once rules latch their value into `last_observed_value` JSONB so a single flip fires exactly one event auto-resolved after 7 d. |
| `circuit_term_expiring` / `circuit_status_changed` | WAN circuit alerts (#93). Status-changed only fires on `suspended` / `decom` transitions and auto-resolves after 7 d. |
| `service_term_expiring` / `service_resource_orphaned` | Service-catalog alerts (#94). Orphan-sweep walks `network_service_resource` join rows whose target was deleted. |
| `compliance_change` | Audit-log scanner rule type (#105). One event per mutation against a classification-flagged subnet (or descendant IP / DHCP scope). Params: `classification` (one of `pci_scope` / `hipaa_scope` / `internet_facing`) and `change_scope` (one of `any_change` / `create` / `delete`). Watermark column on the rule baselines to `now()` on first run so historical audit history doesn't retro-page operators. Resource resolution falls back to `audit_log.old_value.subnet_id` for delete actions where the live row no longer exists. Three disabled seed rules ship at first boot (PCI / HIPAA / internet-facing). Auto-resolves after 24 h. |
| `node_pressure` | A cluster node reports sustained resource stalling through **PSI** (Pressure Stall Information, Kubernetes 1.36+, #983 Phase 2). Subject is the node NAME — cluster nodes have no row in this database. Reads `avg300` out of the kubelet Summary API the Cluster screen already fetches, so there is no new collector. Note that alert evaluation runs in the **Celery worker**, so this needs `worker.serviceAccount.enabled` (a narrow `nodes` + `nodes/stats` grant) or the rule evaluates to nothing while appearing enabled. A cluster the worker cannot read is treated as UNKNOWN and holds open events rather than resolving them — returning "no matches" on a kubeapi blip would close the alarm and re-open it a minute later, flapping notifications through exactly the incident it reports. The kernel's own 5-minute rolling average is what makes "sustained" need no state on our side. **Warning** when CPU or memory `some` stalling holds at or above `threshold_percent` (default 50); **critical** when memory `full` stalling — every runnable task blocked — holds at or above a fixed 1%. The two do not share a knob on purpose: `some` at 20% is a busy node, `full` at 20% is a node that did no work for a fifth of five minutes. CPU `full` is not evaluated at all (the kernel reports it as 0 at node level by definition). A node whose kubelet reports NO PSI never matches — null is UNRECORDED, not zero — so the rule is silent on a pre-1.36 fleet and is seeded **enabled** because of it. This is the alarm #980 needed: the appliance dropped relayed DHCP under CPU pressure with every dashboard green, because utilisation cannot tell a node at 70% CPU with a run queue from one without. |
| `cluster_dns_degraded` | The k3s cluster's DNS (CoreDNS) is down, thinner than the appliance targets, co-located on one node, or not answering (#985). Subject is the **cluster** — CoreDNS is cluster-scoped, and which node a replica sits on is already in the message. Every pod resolves `*.svc.cluster.local` through it (the api reaches Postgres and Redis that way), so a failure here surfaces later as unrelated components failing to start. Reads the same cluster-health snapshot the Cluster → Overview card renders, so there is no new collector and no new RBAC. **Warning** when fewer replicas are ready than `ensure_coredns_ha` targets (`min(nodes, 2)`), or when the ready replicas share a node — two replicas on one node is not HA, and Kubernetes never rebalances running pods (#633). **Critical** when no replica is ready, or when the live resolve probe fails. The probe is the load-bearing half: replica counts say the pods exist, the probe says the path works, and `ready 2 / spread ok / probe failed` is a real and distinct state pointing at kube-proxy or the CNI rather than at CoreDNS. It needs no RBAC (it is a DNS query from the pod) and therefore runs even in the **worker**, whose ServiceAccount deliberately cannot list pods cluster-wide — so the rule still fires there on a probe failure, and the worker is a genuine second vantage rather than a claimed one. A replica view that cannot be read is UNKNOWN and holds open events rather than resolving them; null is never treated as zero. Seeded **enabled**, and inert off the appliance. |
| `appliance_storage_degraded` | An appliance's software RAID (md) array or multipath map has lost redundancy (#999 Part A). Subject is the **appliance**. The supervisor reads `/proc/mdstat` + `/sys/block` out of the host through its privileged / `hostPID` window and folds the reading into the same `cluster_health` JSONB the #402 host partitions ride, so there is no new heartbeat field, no column and no migration. **Severity keys off redundancy remaining, never off the state string** — `2 of 3` in a three-way mirror and `1 of 2` in a pair both report `degraded`, and only the second has nothing left to lose. **Critical** when an array is down to the members it needs to serve at all, when it has failed outright, or when a multipath map has no paths at all. A map with exactly ONE path is deliberately **not** alarmed on: nothing knows whether it ever had more, and the installer explicitly permits installing to a single-path LUN — so a count-based alarm there would be critical forever, turn the console verdict red forever, and be clearable by no action, which is how an alarm gets muted before the night it matters. The count is on every screen for an operator who knows what it should be. **Warning** when redundancy is reduced but a further loss is survivable, or when some SCSI paths report a fault while others remain. A **scrub or resync on an intact array is deliberately not an event** — it is shown on all three screens with its progress, and nothing more. #999 asked for it as "informational, auto-clears", which would be right if `info` were quiet BY DEFAULT; it is not, because `min_severity` is nullable and NULL forwards everything — so on a stock install an `info` event notifies exactly like a critical one. (#999 originally gave a second reason that no longer holds: delivery filtered `min_severity` against `payload["result"]`, a key alert payloads never carry, so a target with a threshold received *nothing* and `info` could not be muted at all. #1031 fixed that. What has not changed is the default, and a finding that is quiet only for operators who went and configured it is not quiet.) Debian runs `checkarray` monthly by cron, so that row would mail every operator with an array, every month, about their array working correctly, which is how an alarm gets muted before the night it matters. The rebuild that DOES matter never reaches that branch anyway: an array with a member out of sync reports `degraded` and is classified on redundancy like any other. An assembled array that will not report its member count is a **warning**, one that failed to *assemble* (`array_state=inactive`) is **critical** whatever its member count says, and an IMSM/DDF metadata `container` is skipped entirely — it is permanently inactive on a healthy box and would raise an alert nothing could clear. A reading that **disappears** is not a recovery either: an appliance with an open event and no current reading is re-matched at its existing severity, so an A/B rollback to a pre-#999 supervisor holds the alarm instead of resolving it. **Multipath is under-sensitive by construction and says so**: the only per-path signal available without the device-mapper ioctl is the path's SCSI `device/state`, which stays `running` when multipathd's checker fails a path, so a map that has quietly lost half its paths produces no finding — which is why every surface renders a finding-less multipath map in a NEUTRAL style rather than the green an md array earns. Revoked appliances are skipped; so are supervisors too old to report storage, because no `storage` key is UNKNOWN and not a clean bill of health. Classified by one function (`services/appliance/storage_health.evaluate_storage`) shared with the `find_appliance_storage` copilot tool and both dashboard surfaces, so a chip cannot read "clean" while the alert reads "degraded". Seeded **enabled** — it is silent on an appliance with no arrays, which is every appliance until somebody builds one. |
| `agent_spool_trimmed` | A DNS or DHCP agent's durable push spool (#1077) hit its size cap (`AGENT_SPOOL_MAX_BYTES`, default 256 MiB) during a control-plane outage and discarded its **oldest** queued batches — part of the outage's logs, metrics or lease events will never arrive. Subject is `agent` with a `dns_server:<id>` / `dhcp_server:<id>` subject id, the same shape as `agent_config_rejected`. Reads the `spool_status` the heartbeat stored; no probing. Fires while the reported `last_trim_at` is within the last 24 h and auto-resolves after that (trim counters are cumulative, so there is no "recovered" report to key off). **Critical** when `lease_events` were among the streams trimmed — Kea lease events are the only way the control plane learns about agent-managed leases, so a trimmed one is a lease with no IPAM mirror and no DDNS record until the client renews or the agent's lease snapshot reconciles it; **warning** otherwise. NULL (an agent too old to report a spool, or an agentless driver) never matches. Seeded **enabled**. |

Admin UI lives at `/admin/alerts` — rules CRUD + live events viewer
(15 s refetch) + per-event `Resolve` to manually silence a known-
noisy event.

Conformity evaluations (#106) also feed this surface: a
`ConformityPolicy` can pin `fail_alert_rule_id`, and a `pass→fail`
transition on a (policy, resource) pair opens an `AlertEvent` row
against the named alert rule with `subject_type="conformity"` so
operators see drift in the same dashboard. Configure the wiring in
the policy edit modal at `/admin/conformity`.

### 9.1a BGP prefix-hijack monitoring (#527)

Extends the ASN subsystem with route-origin monitoring: **is someone
else announcing your prefix?** Two tables + a beat task + the two
alert rules above.

**What's tracked.** `bgp_tracked_prefix` holds the prefixes SpatiumDDI
watches on the public routing table (one row per `(asn, prefix)`). The
poll auto-populates them from each public ASN's **RPKI ROAs** + the
**RIPEstat `announced-prefixes`** feed; operators can also add
`source="manual"` rows (never auto-pruned). `expected_origin_asn` is
denormalised from the AS number for a fast mismatch compare, and
`allowed_origins` is the operator allowlist of *additional* legitimate
origins (intentional multi-origin / anycast / DDoS-scrubbing).

**Detection.** `bgp_hijack_detection` is the latch/dedup state — one
row per observed hijack, `resolved_at` NULL while active. On every
tracked prefix the poll compares the currently-observed origin ASes
(RIPEstat `prefix-overview` for the exact prefix, `related-prefixes`
for more-specifics) against the expected + allowlisted set. An
unexpected origin that is **not** covered by a valid ROA for that
origin opens a detection (`prefix_hijack` for the exact CIDR,
`more_specific` for a sub-prefix that wins BGP longest-match).

**RPKI severity ladder** (reuses the ROA data from
`app.tasks.rpki_roa_refresh`):

* **invalid** → `critical` — a ROA covers the observed prefix but does
  not authorise the observed origin (wrong AS, or announced length
  exceeds `max_length`).
* **unknown** → `warning` — no ROA covers the prefix; still a mismatch
  against the expected origin, but RPKI can't confirm.
* **valid** — a ROA authorises the observed origin → legitimate
  multi-origin, never persisted as a detection.

**Latch / auto-resolve.** An ongoing announcement bumps `last_seen_at`
on the same row (one stable `AlertEvent` subject); the poll resolves
detections whose announcement has been absent for the delist window
(default 12 h), which auto-resolves the mirrored `AlertEvent` — the
same latch-and-auto-resolve shape as the `domain_*` / `circuit_*`
rules. Operators can `acknowledge` a detection (mutes the alert now)
or `allowlist-origin` (appends the origin to the tracked prefix's
allowlist so it never fires again).

**Worker model — two delivery paths.** The **periodic RIPEstat poll**
(`app.tasks.bgp_hijack_poll.poll_bgp_hijacks`, beat-fired hourly) is
the reliable source of truth and the alert-latch owner — it runs on
any standard Celery deployment, gated on
`PlatformSettings.bgp_monitoring_enabled` (default OFF) with per-prefix
`next_check_at` pacing (`bgp_monitoring_interval_hours`, default 6 h).
An **optional RIS Live WebSocket consumer**
(`python -m app.services.bgp.ris_live`, gated by the
`BGP_RIS_LIVE_ENABLED` env flag, default OFF) is the real-time upgrade
— it subscribes to [RIPE RIS Live](https://ris-live.ripe.net/) for the
tracked prefixes and writes into the **same** detection table via the
**same** `app.services.bgp.hijack_monitor` helpers, so it never
becomes load-bearing. The feature works fully without it.

**Surfaces.** Per-ASN **BGP Monitoring** tab on the ASN detail page
(tracked prefixes + detections + `Check BGP now` + acknowledge /
allowlist); the two alert rules appear in `/admin/alerts`
automatically. MCP: `find_bgp_hijacks` / `count_bgp_hijacks` /
`find_tracked_prefixes` (read, default-on) + `propose_allowlist_bgp_origin`
(write, default-off). Feature-module: folds into the existing
`network.asn` module (no new module).

### 9.2 Prometheus alerting rules (external)

Reference Prometheus alerting rules for the `spatiumddi_*` metrics
(a perf-testing Prometheus config already lives under
`perf/dashboards/prometheus/`):

| Alert | Condition | Severity |
|---|---|---|
| `DHCPServerOffline` | `dhcp_server_status == 0` for 2m | critical |
| `DHCPSyncStale` | `time() - dhcp_sync_last_success > 900` | warning |
| `DHCPPoolNearExhaustion` | `pool_utilization > 90` | warning |
| `DNSServerOffline` | `dns_server_status == 0` for 2m | critical |
| `SubnetNearExhaustion` | `subnet_utilization > 90` | warning |
| `SubnetExhausted` | `subnet_utilization > 99` | critical |
| `APIHighErrorRate` | `rate(requests[5m]{status=~"5.."})/rate(requests[5m]) > 0.05` | warning |
| `DBReplicationLag` | `replication_lag > 30` | warning |
| `CeleryQueueBacklog` | `queue_length > 100` for 5m | warning |
| `BackupFailed` | Checked via Celery task failure metric | critical |


## DNS Agent Telemetry

See [`docs/deployment/DNS_AGENT.md`](deployment/DNS_AGENT.md) §4 for the full protocol.

### Metrics (scraped from the control plane)

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `spatium_dns_agent_up` | gauge | `server_id`, `flavor` | 1 if last heartbeat within 90s |
| `spatium_dns_agent_config_lag_seconds` | gauge | `server_id` | Age of the applied config etag |
| `spatium_dns_zone_serial` | gauge | `server_id`, `zone` | Last reported SOA serial |
| `spatium_dns_failed_ops_total` | counter | `server_id` | RecordOps that exhausted retries |
| `spatium_dns_agent_token_rotations_total` | counter | `server_id` | JWT rotations per server |

Agents are egress-only and do **not** expose a scrape endpoint — all metrics
are derived from the heartbeat body on the control plane.

### Logs

Agent logs are structured JSON (non-negotiable #7) and include the canonical
`service=spatium-dns-agent` binding. Notable events:

- `dns_agent_registered` — bootstrap complete
- `dns_agent_token_rotated` — JWT rotation
- `dns_agent_config_applied` — new config etag applied
- `dns_agent_op_failed` — RecordOp failed (attempt <= 5)
- `dns_agent_stale_sweep` — control-plane Celery task marked servers unreachable
