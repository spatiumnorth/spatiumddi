# spatium-lg-agent

Sidecar agent baked into the SpatiumDDI managed GoBGP Looking Glass
collector container image (`ghcr.io/spatiumnorth/looking-glass`).

The BGP Looking Glass collector is a **receive-only** BGP speaker: it
peers passively with the operator's edge/core routers, accepts their
routing table, and never advertises a route back. See
[`docs/features/LOOKING_GLASS.md`](../../docs/features/LOOKING_GLASS.md)
and `spatium_lg_agent/gobgp.py`'s module docstring for the full
receive-only enforcement writeup — that file is the single review gate
for anything that touches how gobgpd's config is rendered.

## Environment

| Variable | Purpose |
|---|---|
| `CONTROL_PLANE_URL` | e.g. `https://api.spatiumddi.example` (required) |
| `LG_AGENT_KEY` | Bootstrap pre-shared key (required) |
| `SERVER_NAME` / `AGENT_HOSTNAME` | Hostname reported to the control plane |
| `AGENT_STATE_DIR` | State directory (default `/var/lib/spatium-lg-agent`) |
| `GOBGPD_CONFIG_PATH` | Rendered gobgpd config path (default `/etc/gobgp/gobgpd.json`) |
| `GOBGPD_BIN` | Path to the `gobgpd` daemon binary (default `/usr/local/bin/gobgpd`) |
| `GOBGP_BIN` | Path to the `gobgp` CLI binary (default `/usr/local/bin/gobgp`) |
| `GOBGP_GRPC_HOST` / `GOBGP_GRPC_PORT` | gobgpd's local gRPC listener (default `127.0.0.1` / `50051`) |
| `RIB_POLL_INTERVAL` | Seconds between RIB + neighbor-state polls (default `30`) |
| `HEARTBEAT_INTERVAL` | Seconds between heartbeats (default `30`) |
| `LONGPOLL_TIMEOUT` | Seconds the control plane holds the config long-poll (default `30`) |
| `TLS_CA_PATH` | CA bundle to verify the control plane against (private CA or self-signed). Wins over the skip flag |
| `SPATIUM_INSECURE_SKIP_TLS_VERIFY=1` | Turns verification off. Lab only: the agent key is readable on the network path. Logged as a warning on every start |

## Cache layout

State directory (must be a persistent volume — see non-negotiable #5,
"config caching on agents"):

```
/var/lib/spatium-lg-agent/
├── agent-id                     # stable UUID, 0600
├── agent_token.jwt              # current JWT, 0600
├── config/
│   ├── current.json             # last-known-good peer-config bundle
│   ├── current.etag
│   └── previous.json
├── rendered/
│   └── gobgpd.json              # last rendered gobgpd config (for audit)
└── .ready                       # stamped after the first successful RIB poll+push
```

On startup the agent preloads and re-applies the cached bundle to gobgpd
**before** its first successful poll of the control plane — already
configured BGP sessions stay up even if the control plane is unreachable.

## Control-plane contract

Matches `backend/app/api/v1/looking_glass/agents.py` exactly (both
`AgentHeartbeatRequest`/`PeerStateReport` and `RoutesPushRequest`/
`RouteEntry` are `extra="forbid"` — an unrecognised field 422s the whole
call, not just that field):

- `POST /api/v1/looking-glass/agents/register` — PSK bootstrap
  (`X-LG-Agent-Key` header), body `{hostname, version, fingerprint,
  agent_id}`, mints a rotating JWT. No server-group concept (unlike
  DNS/DHCP) and no approval flow.
- `GET /api/v1/looking-glass/agents/config` — ConfigBundle long-poll
  (`If-None-Match`), returns `{collector_id, etag, bundle: {collector_name,
  peers: [...]}}` — peers keyed on `peer_id`, each carrying its own
  required `local_asn` (there is no daemon-wide "global AS" field; see
  `gobgp.py::render_config`'s docstring for how the agent picks one).
- `POST /api/v1/looking-glass/agents/heartbeat` — body `{agent_version,
  peers: [{peer_id, session_state, uptime_started_at, prefixes_received,
  prefixes_accepted, last_state_change, last_flap_at}]}` + JWT rotation
  (`rotated_token` in the response).
- `POST /api/v1/looking-glass/agents/routes` — **one call per peer**:
  `{peer_id, snapshot: true, routes: [{prefix, next_hop, origin_asn,
  as_path, local_pref, med, communities, large_communities,
  ext_communities, is_best}]}`. Absence-reconciled server-side (mirrors
  `pull_leases.py`'s upsert + absence-delete shape), with a zero-wire
  floor guard evaluated per peer against that peer's last-heartbeated
  `prefixes_received` — the agent always pushes a snapshot for every
  configured peer every cycle (even an empty one) so the backend gets a
  chance to apply that guard.

## Receive-only guarantee

Enforced in `spatium_lg_agent/gobgp.py::render_config` via a **global**
`apply-policy.config.default-export-policy = "reject-route"` (verified
against a live gobgpd — a per-neighbor `apply-policy` block alone does
NOT block export for a normal, non-route-server peer) plus a hard runtime
assertion (`_assert_receive_only`) that refuses to write or apply any
config that doesn't satisfy the invariant. Per-peer `max-prefixes` is
rendered into `afi-safis[].prefix-limit.config.max-prefixes` so a
misbehaving/full-table peer can't blow up the daemon's memory.
