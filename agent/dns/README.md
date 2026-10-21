# spatium-dns-agent

Sidecar agent baked into the SpatiumDDI managed BIND9 DNS container image
(`ghcr.io/spatiumnorth/dns-bind9`).

See [`docs/deployment/DNS_AGENT.md`](../../docs/deployment/DNS_AGENT.md) for
the protocol specification.

## Environment

| Variable | Purpose |
|---|---|
| `CONTROL_PLANE_URL` | e.g. `https://api.spatiumddi.example` |
| `DNS_AGENT_KEY` | Bootstrap PSK, matches the control plane |
| `SERVER_NAME` | Hostname reported to the control plane |
| `AGENT_DRIVER` | `bind9` (only supported backend) |
| `AGENT_GROUP` | Optional DNS server group to join |
| `AGENT_ROLES` | Comma-separated: `authoritative,recursive,forwarder` |
| `TLS_CA_PATH` | CA bundle to verify the control plane against (private CA or self-signed). Wins over the skip flag |
| `TLS_PINNED_CERTS_PATH` | Trust exactly the certificates in this file, with no hostname check (#1281). Read on every connection; fails closed while the file is missing. The appliance chart sets it to the supervisor's pinned certificate. Wins over `TLS_CA_PATH` and the skip flag |
| `SPATIUM_INSECURE_SKIP_TLS_VERIFY=1` | Turns verification off. Lab only: the agent key is readable on the network path. Logged as a warning on every start |

State directory: `/var/lib/spatium-dns-agent` (must be a volume).
