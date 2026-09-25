---
layout: default
title: Troubleshooting
---

# Troubleshooting

Recovery recipes for common incidents. Pages that cover a specific
feature (e.g. `docs/features/DHCP.md`) generally describe the *expected*
behaviour; this page covers what to do when something goes wrong.

---

## Recovering from an accidentally deleted DNS or DHCP server

**Symptom** — You deleted a managed DNS (`bind9`) or DHCP (`kea`) server
from the SpatiumDDI UI (or via the REST API) and it turned out to be one
of the real, running service containers rather than a stale row.

**What happened**

Deleting a server from the GUI drops the `dns_server` or `dhcp_server`
row from the control plane database. It does **not** touch the running
agent container. The agent still holds its cached JWT and agent-id on
disk under `/var/lib/spatium-dns-agent/` or
`/var/lib/spatium-dhcp-agent/` (cache layout is documented in
`CLAUDE.md` cross-cutting pattern #3).

**What the agent does automatically**

The agent will self-heal on its next poll. When the control plane
receives a request authenticated with a JWT that references a server row
that no longer exists it responds with **404**; the agent treats 401 *or*
404 as "bootstrap is invalid" and re-registers via its pre-shared key
(`DNS_AGENT_KEY` / `DHCP_AGENT_KEY`). A fresh server row appears in the
GUI within a heartbeat cycle (~30 s by default).

**When the auto-recovery is enough** — just wait. No manual steps.

**When you need to intervene**

- *The pre-shared key was rotated on the server.* The agent's bootstrap
  request will be rejected. Update the `DNS_AGENT_KEY` or
  `DHCP_AGENT_KEY` env var on the agent container (matching the value in
  SpatiumDDI settings) and restart:

  ```bash
  docker compose restart dns-bind9
  # or
  docker compose restart dhcp-kea
  ```

- *Auto-recovery appears stuck.* Force a clean re-bootstrap by wiping
  the cached credentials and restarting the container. The config cache
  is kept (so service keeps serving from last-known-good while the
  bootstrap runs) — only the identity files are removed:

  ```bash
  docker compose exec dns-bind9 sh -c \
      'rm -f /var/lib/spatium-dns-agent/agent_token.jwt \
             /var/lib/spatium-dns-agent/agent-id'
  docker compose restart dns-bind9
  ```

  Substitute `dhcp-kea` and `/var/lib/spatium-dhcp-agent/` for the DHCP
  side. You do **not** need to recreate the container — removing the two
  identity files is enough.

- *You want to start over from scratch.* Destroy the container and its
  volumes. This also clears the local config cache, so the agent will
  only come back online once the control plane is reachable.

  ```bash
  docker compose rm -sf dns-bind9
  docker volume rm spatiumddi_dns_bind9_state spatiumddi_dns_bind9_cache
  docker compose --profile dns up -d dns-bind9
  ```

**What doesn't come back automatically**

The re-bootstrapped server row inherits the agent's environment
variables (`SERVER_NAME`, `AGENT_GROUP`, `AGENT_ROLES`), **not** any
settings that had been edited in the GUI. Notes, credentials for Path B
drivers, per-server overrides, or TSIG keys that were rotated via the
UI all need to be re-applied on the new row.

Zones and records attached to a DNS server group, and DHCP scopes /
pools attached via `subnet_id`, are *not* lost — they live on the group
and subnet rows, not on the individual server. Deleting + recreating the
server just re-attaches the running agent to the same group config.

---

## DHCP server (Kea) doesn't respond to DISCOVER

**Symptom** — A client on the same L2 segment as the Kea server gets no
lease. Wireshark on the client shows the `DHCPDISCOVER` going out as a
broadcast, but no `DHCPOFFER` comes back. Static-IP connectivity between
the client and the server works fine, and the Kea service shows a green
**`healthy`** chip in the Fleet → Service health panel.

**Key point first** — the `healthy` chip only means the Kea *process is
up*. It does **not** mean Kea will answer for your client's subnet. There
are exactly two ways a DISCOVER ends in silence on an otherwise-healthy
server:

- **(A) The DISCOVER never reaches the Kea socket** — the broadcast is
  dropped before Kea sees it (host firewall, or the container isn't on
  the host NIC).
- **(B) Kea hears it but drops it** — no configured `subnet4` matches the
  interface the packet arrived on, or the matched subnet has no usable
  pool. Kea logs this and moves on; nothing goes on the wire.

For a first-time setup, **(B) is by far the most common.**

### Split (A) from (B) in two minutes

Run these on the appliance host (SSH as `admin`, or F1-login at the
console):

```bash
# 1. Does the broadcast actually arrive on the host NIC?
sudo tcpdump -ni any -v 'port 67 or port 68'
#    …then release/renew DHCP on the client.

# 2. Watch Kea react in real time (k3s appliance):
sudo k3s kubectl get pods -A | grep kea          # find pod + namespace
sudo k3s kubectl logs -n <ns> <kea-pod> -f
#    …on docker-compose installs: docker compose logs -f dhcp-kea
```

Read the result:

| tcpdump shows DISCOVER | Kea log | Conclusion |
|---|---|---|
| yes | logs DISCOVER, no OFFER (often `DHCP4_SUBNET_SELECTION_FAILED` / "no subnet selected") | **(B)** — subnet/scope mismatch. Most common. |
| yes | logs nothing | **(A)** — the packet reaches the host but not the Kea socket: the group is in **Relay-only (udp)** socket mode, or the firewall is dropping it. |
| no  | — | The broadcast isn't reaching the appliance VM at all (vSwitch port-group / VLAN). |

### Fixing (B) — scope/subnet mismatch (most common)

Kea selects a subnet for a broadcast (non-relayed) client by matching the
**receiving interface's own IP** against the configured `subnet4` ranges.
So if the appliance's NIC on that segment is `192.168.0.x/24` but your
DHCP scope was created for a different network, Kea silently ignores the
DISCOVER. Verify, in order:

- Run `ip -4 addr` on the appliance and note its IP on the client-facing
  interface.
- In the UI, confirm a **DHCP scope exists whose subnet CIDR contains
  that address**.
- The scope is **active** — inactive scopes are dropped from the agent's
  config bundle entirely.
- The scope is **IPv4** and has at least one **dynamic pool range** — a
  scope with no pool has nothing to offer.
- The scope is attached to the **same DHCP server group** as this Kea
  server. SpatiumDDI's DHCP model is group-centric (scopes / pools /
  statics live on the server group); only **active IPv4 scopes attached
  to that group** render into Kea's `subnet4`. If none qualify, Kea
  renders `subnet4: []` and answers nobody.

Confirm what Kea actually received by reading the agent's last-rendered
config (this is the source of truth for what the running Kea is using):

```bash
# k3s appliance:
sudo k3s kubectl exec -n <ns> <kea-pod> -- \
    cat /var/lib/spatium-dhcp-agent/rendered/kea-dhcp4.json | grep -A4 subnet4
# docker-compose:
docker compose exec dhcp-kea \
    cat /var/lib/spatium-dhcp-agent/rendered/kea-dhcp4.json | grep -A4 subnet4
```

An empty `"subnet4": []` confirms (B): no active IPv4 scope is reaching
the agent. Activate the scope / attach it to the right group / add a
pool, then the bundle ETag shifts and the agent re-renders within a
heartbeat. (The DHCP Activity tab on the **Logs** page surfaces the same
Kea log lines if you'd rather stay in the UI.)

### Fixing (A) — packet reaches the host but not Kea

Two causes; check the socket mode first.

**Socket mode (#365).** A directly-attached client can only be heard when
Kea's Dhcp4 daemon uses **raw** (AF_PACKET) sockets — UDP sockets are
relay-only and silently miss the broadcast. The DHCP **server group**
carries a *Client reachability* setting that controls this:

- **Directly attached / mixed** → `dhcp-socket-type: raw` (the default
  since #365). Hears broadcast DISCOVERs *and* relayed traffic.
- **Relay-only** → `dhcp-socket-type: udp`. Cannot receive direct L2
  broadcasts.

If the server is on the same LAN as its clients, the group must be
**Directly attached** (DHCP → the server group → Edit → *Client
reachability*). Confirm what's actually rendered:

```bash
# k3s appliance:
sudo k3s kubectl exec -n <ns> <kea-pod> -- \
    cat /var/lib/spatium-dhcp-agent/rendered/kea-dhcp4.json | grep socket-type
# docker-compose:
docker compose exec dhcp-kea \
    cat /var/lib/spatium-dhcp-agent/rendered/kea-dhcp4.json | grep socket-type
```

`"dhcp-socket-type": "udp"` on a direct-attached LAN is the problem —
switch the group to *Directly attached*; the agent re-renders within a
heartbeat. (Raw sockets need the `NET_RAW` capability, which the
appliance DaemonSet and the shipped compose files grant.)

> Installs predating #365 hardcoded `udp` and had no knob — that was the
> original bug. Upgraded installs default to `direct` (raw), so this is
> only a live cause if the group was deliberately set to Relay-only.

**Firewall.** UDP sockets are also subject to the host's nftables INPUT
chain (raw sockets bypass it). The DHCP role opens UDP **67 + 68**, and
**547** for DHCPv6 (#1139). DHCPv6 has no raw-socket mode, so every v6
packet goes through this chain. Confirm the rules are present and
haven't drifted:

```bash
sudo nft list chain inet filter input | grep -E 'dport (67|68|547)'
```

You should see `udp dport 67 accept`, `udp dport 68 accept` and
`udp dport 547 accept`. If they're missing, the per-role firewall didn't
apply. Re-saving the DHCP role assignment in **Fleet** re-renders the
drop-in.

**Relayed DHCPv6 gets no answer.** A relay sends its Relay-Forward to the
server's *global* IPv6 address, and kea-dhcp6 needs a unicast socket on
that address (#1140). The agent adds one for every stable global address
on the host. Confirm the socket exists:

```bash
ss -ulpn6 | grep 547
```

You should see the global address, not only `fe80::…%iface` and
`ff02::1:2`. If it's missing, check that the address is on the host and not
temporary, deprecated or still tentative (`ip -6 addr`). The agent re-reads
the addresses on every sync loop, about every 30 s, and logs
`dhcp6_unicast_addresses_changed` when it re-renders.

### Networking sanity check

On the k3s appliance the Kea DaemonSet runs with `hostNetwork: true` so
it sees broadcasts on the host NIC directly. On docker-compose the DHCP
container must use **host networking** (`DHCP_NETWORK_MODE=host`, the
default for supervisor-managed appliances) — a bridged/NAT network will
not receive the L2 broadcast. If tcpdump on the host shows the DISCOVER
but `kubectl exec … -- ip addr` / `docker compose exec dhcp-kea ip addr`
shows the container is *not* on the host's interfaces, the container is
on the wrong network.

---

## Resetting the admin password

Documented inline in `CLAUDE.md` under *Development Commands → Reset
admin password*. Reproduced here so operators don't need to open
`CLAUDE.md`:

```bash
docker compose exec api python - <<'EOF'
import asyncio
from sqlalchemy import update
from app.core.security import hash_password
from app.db import AsyncSessionLocal
from app.models.auth import User
async def reset():
    async with AsyncSessionLocal() as db:
        await db.execute(update(User).where(User.username == "admin")
            .values(hashed_password=hash_password("NewPass!"), force_password_change=True))
        await db.commit()
asyncio.run(reset())
EOF
```

---

## Subnet delete is refused

**Symptom** — A **permanent** subnet delete
(`DELETE /api/v1/ipam/subnets/{id}?permanent=true`) returns `409 Conflict`
with a body like *"Subnet is not empty: N allocated IP addresses,
M DHCP scopes. Delete the contents first, or retry with force=true to
cascade."*

This is deliberate. A non-empty permanent delete used to cascade silently
and wipe IPAM rows + DHCP scopes out from under running services. Note the
**default** `DELETE /api/v1/ipam/subnets/{id}` (no `permanent`) is now a
*soft*-delete — it never refuses, and the subnet (and its DHCP scopes)
stays restorable from `/admin/trash`. The non-empty check only guards the
permanent (hard) delete path, which refuses unless you either:

- Remove the contents first (unassign every non-system IP, detach any
  DHCP scopes), then retry; or
- Opt into the cascade by appending `?force=true` to the request. The
  same pre-delete cleanup still runs — agentless Windows DHCP gets a
  WinRM remove-scope, agent-based Kea gets its bundle ETag bumped — so
  no lease is orphaned on a running server.

System placeholder rows (the `.0` network and `.255` broadcast) and
DHCP-lease mirrored rows (`auto_from_lease=True`) do **not** count as
blockers — they're cleaned up automatically on delete.

---

## `/health/platform` says `celery-beat` is unhealthy

**Read the component name as a symptom, not a diagnosis.** Beat only
*schedules* `app.tasks.heartbeat.beat_tick`; a **worker** executes it and
writes the `spatium:beat:heartbeat` key the check reads. So a red
`celery-beat` means *no tick landed*, which has two very different causes —
and `celery-workers` cannot be used to rule the second one out, because
`inspect ping` is answered by the worker's MainProcess and stays green
while every prefork slot is blocked (see `docs/OBSERVABILITY.md` § Platform
health).

Split them in about a minute:

```bash
# 1. Is beat scheduling? Look for the send line, once per 30 s.
kubectl -n spatiumddi logs deploy/spatiumddi-beat --tail=20 | grep 'Sending due task'
docker compose logs --tail=20 beat | grep 'Sending due task'      # compose

# 2. Is a worker executing it? Look for the matching succeeded line.
kubectl -n spatiumddi logs deploy/spatiumddi-worker --tail=50 | grep beat_tick

# 3. Can the pool run anything at all? active == concurrency means it can't.
kubectl -n spatiumddi exec deploy/spatiumddi-worker -- \
  celery -A app.celery_app inspect active --timeout 5
```

| What you see | Where the fault is |
|---|---|
| No "Sending due task" | Beat really is stopped — check the pod / its `wait-for-migrate` init container |
| Sending, but no `beat_tick` succeeded | The worker is not consuming — check the pool (step 3) and the broker |
| `active` count equals `--concurrency` | The pool is wedged; every scheduled job across the platform has stopped, not just the heartbeat |

**The case #925 was filed for** is the third row, after a slot upgrade on a
multi-node control plane. `REDIS_URL` lists sentinels by their per-pod
headless DNS names (deliberately — a client must reach every sentinel
mid-failover), and those names keep resolving through the 20-40 s a
rebooting node takes to be marked NotReady. A connect to one of them with
no timeout blocks indefinitely — measured still blocked at 60 s — and a
tick is enqueued every 30 s regardless, so a 4-slot pool is gone in about
two minutes and never comes back. Every Redis client now gets a default
connect timeout (`app/core/redis_client.py`) and the heartbeat task carries
`soft_time_limit` / `time_limit`, both under its own 30 s interval, so a
tick fails and frees its slot instead of holding it. (`expires` is
deliberately absent — Celery stamps it from the *publisher's* clock and the
*worker* compares it, so on a skewed pair it would revoke every tick and
make this symptom permanent.)

A `warn` reading `last tick Ns in the future (clock skew)` means the node
that ran the tick and the node serving this endpoint disagree about the
time — check NTP on both rather than looking at Celery.

---

## Control-plane VIP stays `<pending>`

**Status: known bug, no fix released yet —
[#1103](https://github.com/spatiumnorth/spatiumddi/issues/1103).** Nothing
you can misconfigure causes this, and nothing you can do in the UI clears
it. Setting a control-plane VIP in `Appliance → Network & Host` currently
leaves MetalLB unable to install at all.

**Symptom.** The frontend Service never gets an external address, and the
MetalLB install Job keeps restarting:

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# The Service that should carry the VIP — EXTERNAL-IP stays <pending>.
k3s kubectl get svc -n spatium | grep LoadBalancer

# The install Job — CrashLoopBackOff, restart count climbing.
k3s kubectl get pods -n kube-system | grep helm-install-spatium-metallb

# No pool is ever created.
k3s kubectl get ipaddresspool,l2advertisement -A
```

**Confirm it is this bug** — the Job's log ends with a rejected webhook
call, not a config error:

```bash
k3s kubectl logs -n kube-system \
  "$(k3s kubectl get pods -n kube-system -o name | grep helm-install-spatium-metallb | tail -1)" \
  | tail -20
```

```
Error: INSTALLATION FAILED: Internal error occurred: failed calling webhook
"ipaddresspoolvalidationwebhook.metallb.io": ... no endpoints available for
service "metallb-webhook-service"
```

**Why it never recovers.** Helm 4 applies the MetalLB validating webhooks
*before* the `IPAddressPool` / `L2Advertisement`, so the pool is admitted
through a webhook whose controller Deployment was created moments earlier
in the same pass and is not ready — and at `failurePolicy: Fail` that is a
rejection. Every retry then runs `helm uninstall` first, deleting the
controller that backs the webhook, so each attempt destroys the
prerequisite the next one needs. The Job's `backOffLimit` is 1000, so it
will keep looping.

**Workaround.** Clear the control-plane VIP in `Appliance → Network &
Host`. The supervisor turns MetalLB back off within ~45 s, the Job stops,
and the cluster returns to normal. Reach the UI and point agents at a node
address instead of a VIP.

**What is unaffected.** Only the VIP. Everything else on the node keeps
working while the Job loops — etcd quorum, CNPG failover, Redis Sentinel,
the api/worker/frontend replicas and the Web UI are all unaffected. The
`FailedMount` warnings on `metallb-speaker` pods and `Unhealthy` probes on
`metallb-controller` are symptoms of the same loop, not separate faults.
