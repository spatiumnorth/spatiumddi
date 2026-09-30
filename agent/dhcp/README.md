# spatium-dhcp-agent

Sidecar agent baked into the SpatiumDDI managed Kea DHCP container image
(`ghcr.io/spatiumnorth/dhcp-kea`).

See [`docs/features/DHCP.md`](../../docs/features/DHCP.md) §6 for the caching
and offline-resilience spec.

## Environment

| Variable | Purpose |
|---|---|
| `SPATIUM_API_URL` | e.g. `https://api.spatiumddi.example` (required) |
| `SPATIUM_AGENT_KEY` | Bootstrap pre-shared key (required) |
| `SPATIUM_SERVER_NAME` | Hostname reported to the control plane |
| `CACHE_DIR` | State directory (default `/var/lib/spatium-dhcp-agent`) |
| `KEA_CONFIG_PATH` | Kea dhcp4 config path (default `/etc/kea/kea-dhcp4.conf`) |
| `KEA_CONTROL_SOCKET` | Kea control unix socket (default `/run/kea/kea4-ctrl-socket`) |
| `KEA_LEASE_FILE` | Kea memfile leases path (default `/var/lib/kea/kea-leases4.csv`) |
| `LONGPOLL_TIMEOUT` | Seconds the control plane holds a long-poll (default `30`) |
| `HEARTBEAT_INTERVAL` | Seconds between heartbeats (default `30`) |
| `AGENT_GROUP` | Optional DHCP server group to join |
| `AGENT_ROLES` | Comma-separated: `primary,secondary,failover` (default `primary`) |
| `TLS_CA_PATH` | CA bundle to verify the control plane against (private CA or self-signed). Wins over the skip flag |
| `SPATIUM_INSECURE_SKIP_TLS_VERIFY=1` | Turns verification off. Lab only: the agent key is readable on the network path. Logged as a warning on every start |

## Cache layout

State directory (must be a persistent volume):

```
/var/lib/spatium-dhcp-agent/
├── agent-id                     # stable UUID, 0600
├── agent_token.jwt              # current JWT, 0600
├── config/
│   ├── current.json             # last-known-good ConfigBundle (source of truth when offline)
│   ├── current.etag
│   └── previous.json            # one-back for rollback/debug
├── rendered/
│   └── kea-dhcp4.json           # last rendered Kea config (for audit)
└── leases/
    └── pending.jsonl            # lease events not yet acked (future use)
```

## Offline resilience (DHCP.md §6)

The agent detects control-plane unreachability after 3 consecutive failed
polls. On the third failure it logs `control_plane_unreachable` once,
switches to 60 s retry interval, and continues to serve leases from the
cached Kea config. When the control plane comes back the agent logs
`control_plane_reconnected` and resumes normal long-poll.

## NTP via DHCP (option 42)

NTP server addresses supplied by the control plane in
`global_options.ntp_servers` (or per-subnet `options.ntp_servers`) are
rendered as DHCP option 42 (`ntp-servers`, RFC 2132 §8.3). Users rely on
this — do not strip it.

## Lease events

Kea's `lease_cmds` hook is enabled in the bundled image. The agent tails
the memfile lease CSV (`KEA_LEASE_FILE`) and posts batches to
`POST /api/v1/dhcp/agents/lease-events` every 5 seconds or every 100 events.
