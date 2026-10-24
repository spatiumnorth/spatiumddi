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

## An IP address is owned by two integrations

**Symptom** — An address that two integrations both see (a host that is a
UniFi client *and* an OPNsense DHCP lease, a VM's LAN IP seen by Proxmox and
UniFi, a macvlan container seen by Docker and UniFi) stopped updating: its
hostname or MAC is stale, or it stayed in IPAM after the host went away.

Before #1135 an integration mirror could claim an address another
integration already owned. The claim also set `user_modified_at`, which
marks a row as edited by hand, so from then on neither integration updated
it, neither deleted it when the host disappeared, and deleting either
integration's target deleted the row. New claims are now refused with the
warning *"owned by another integration; not claiming"*, but rows claimed
before the upgrade stay as they are. They aren't cleaned up automatically,
because a claim's `user_modified_at` can't be told apart from a real
operator edit, and clearing it would let an integration overwrite edits
someone made by hand.

**Find them** (any `psql` session on the SpatiumDDI database; on Docker
Compose, `docker compose exec -T postgres psql -U spatiumddi spatiumddi`):

```sql
SELECT a.id, a.address, a.hostname, a.user_modified_at,
       concat_ws(', ',
         CASE WHEN a.kubernetes_cluster_id IS NOT NULL THEN 'kubernetes' END,
         CASE WHEN a.docker_host_id IS NOT NULL THEN 'docker' END,
         CASE WHEN a.proxmox_node_id IS NOT NULL THEN 'proxmox' END,
         CASE WHEN a.tailscale_tenant_id IS NOT NULL THEN 'tailscale' END,
         CASE WHEN a.unifi_controller_id IS NOT NULL THEN 'unifi' END,
         CASE WHEN a.cloud_endpoint_id IS NOT NULL THEN 'cloud' END,
         CASE WHEN a.opnsense_router_id IS NOT NULL THEN 'opnsense' END,
         CASE WHEN a.netbird_instance_id IS NOT NULL THEN 'netbird' END,
         CASE WHEN a.panos_firewall_id IS NOT NULL THEN 'paloalto' END,
         CASE WHEN a.fortinet_firewall_id IS NOT NULL THEN 'fortinet' END,
         CASE WHEN a.meraki_org_id IS NOT NULL THEN 'meraki' END
       ) AS owned_by
FROM ip_address a
WHERE num_nonnulls(
        a.kubernetes_cluster_id, a.docker_host_id, a.proxmox_node_id,
        a.tailscale_tenant_id, a.unifi_controller_id, a.cloud_endpoint_id,
        a.opnsense_router_id, a.netbird_instance_id, a.panos_firewall_id,
        a.fortinet_firewall_id, a.meraki_org_id) >= 2
ORDER BY a.address;
```

**Fix one** — Decide which integration should own the address: usually the
one that hands it out, such as the DHCP server for a LAN lease. Clear the
other integration's column. If nobody has edited the row by hand, clear
`user_modified_at` as well, so the remaining integration keeps it current
again:

```sql
-- e.g. keep OPNsense, drop the UniFi claim
UPDATE ip_address
SET unifi_controller_id = NULL, user_modified_at = NULL
WHERE id = '<id from the query>';
```

Leave `user_modified_at` alone if someone did edit the row, or their
hostname, description and MAC will be overwritten on the next sync. Edits
made in SQL bypass the audit log.

---

## An integration took IP addresses from another IP space

**Symptom** — Hand-allocated addresses disappeared from one IP space after
an integration (UniFi, Docker, Kubernetes, Proxmox, Tailscale, NetBird or
Cloud) was pointed at a *different* space covering the same range. Trying
to allocate a missing address again says it is already allocated, and the
address shows up in the integration's space instead. A Sync DNS on the
original subnet may also offer to delete many DNS records.

**What happened** — Before #2577 those seven reconcilers looked existing
addresses up across **every** IP space instead of only their own. When an
integration saw an address that an operator had allocated in another space,
it adopted that row: it set the integration's ownership column, stamped
`user_modified_at`, and moved the row into the integration's own space.
The row's DNS records moved with it. Later passes could delete the row
outright (a duplicate in the target subnet, or the host leaving the
integration's view), and deleting the integration's target or its space
deleted every row it had taken. A deleted row leaves its auto-generated DNS
records behind with no address, which is what Sync DNS then offers to
delete.

Upgrading stops it: every reconciler now only reads, adopts, moves, dedupes
and deletes rows inside its target's own space. Nothing already moved is put
back automatically, because the row's original subnet was never recorded,
and a wrong guess would move it a second time.

One kind of damage does repair itself. An operator row the old build
claimed but never managed to move still sits in its home space carrying the
integration's column. On the first sync after the upgrade the integration
**releases** everything it owns outside its own space: it clears its column
on such a row and leaves the row where it is, `user_modified_at` included.
It only ever deletes a row it can show is a pure mirror row of its own
(created after the integration, never edited or audited by a person, no
DHCP reservation, no other owner); when in doubt it un-claims. The same
release is what happens when you change an integration's IP space on
purpose. The sync warnings say what was released.

**Before anything else** — Upgrade first, so the integration stops moving
rows while you repair them. If the integration is still pointed at an
overlapping space, leave it running: it no longer touches the other space.
Do **not** commit DNS deletions from Sync DNS on an affected subnet until
the rows are back; those records are what you will be restoring.

### Find the rows it moved

As a superadmin, call the read-only report:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://<spatiumddi>/api/v1/ipam/integration-space-audit" | jq .
```

or ask the Operator Copilot to run `find_cross_space_integration_adoptions`.
Each row lists the address, the integration and target that own it now, the
subnet and space it sits in now, and:

- `evidence` — why it is suspected. `operator_create_audit` means someone
  created it through IPAM (`created_by` names them).
  `created_before_target` means the row is older than the integration
  target, which an integration-created row can't be.
  `outside_target_space` means it carries the integration's column but sits
  outside the integration's space; the integration's next sync releases it
  (see above), so these only show up until then.
  `dhcp_reservation_in_other_space` means a DHCP reservation linked to the
  row belongs to a scope in another space: it was made there.
  `predates_its_space_subnets` means the row is older than every subnet of
  its current space that contains it, while a subnet in another space that
  contains it is older than the row. A row can't be created before its
  subnet, so it was moved in. (A subnet split in its own space can produce
  this too, so it is evidence, not proof.)
- `likely_cross_space` — the row has operator-origin evidence AND one of
  the last two pieces of evidence that it lived in another space. These are
  the rows to repair.
- `needs_review` — the row has operator-origin evidence and some subnet in
  another space contains its address, but nothing shows it ever lived
  there. That is exactly what an ordinary adoption in the integration's
  **own** space looks like whenever the range also exists in another space,
  so do not move these on the report's word: confirm with whoever owns the
  address first. A row the old build stole after the integration was set
  up, and without a DHCP reservation, also lands here — which is why they
  are listed at all.
- `home_candidates` — the subnets in other spaces that contain the address,
  and `address_free`, whether nothing holds that address there now. The
  one with `address_free: true` in the space the address went missing from
  is almost always where the row came from.

`?include_same_space=true` also lists operator rows an integration adopted
inside its own space whose address exists in no other space. That is
normal, documented adoption, not this bug. `truncated: true` means more
rows matched than `limit` returned; raise `limit` (up to 5000).

### Put a row back

For each `likely_cross_space` row — and each `needs_review` row its owner
confirms came from another space — confirm the home subnet with whoever
owns the address, then move it back and release the integration's claim.
Use the column for the integration the report names (`unifi_controller_id`,
`docker_host_id`, `kubernetes_cluster_id`, `proxmox_node_id`,
`tailscale_tenant_id`, `netbird_instance_id`, `cloud_endpoint_id`):

```sql
BEGIN;
UPDATE ip_address
SET subnet_id = '<home_candidates[].subnet_id>',
    unifi_controller_id = NULL
WHERE id = '<ip_address_id>';
COMMIT;
```

Keep `user_modified_at` as it is: the row holds an operator's hostname,
description and MAC, and clearing it would let some later integration
overwrite them. If the `UPDATE` fails on `uq_ip_address_subnet_address`,
something now holds the address in the home subnet; decide which of the two
to keep before going further. Subnet and block utilization counters correct
themselves within the hour (the `recount_ipam_utilization` sweep). Edits
made in SQL bypass the audit log, so note what you changed.

Once the row is back, the integration creates its own row for the address
in its own space on its next sync. Then run **Sync DNS** on the home subnet
and confirm the address's records are reported in sync.

### Rows that were already deleted

The report can only find rows that still exist. A row the integration
deleted, or that went with a deleted integration target or space, is gone,
but its IPAM create audit row is not. This lists addresses created through
IPAM that no longer exist and were not deleted through IPAM:

```sql
SELECT c.timestamp, c.user_display_name, c.resource_display AS address,
       c.new_value
FROM audit_log c
WHERE c.resource_type = 'ip_address' AND c.action = 'create'
  AND c.resource_display NOT LIKE 'profile\_scan %'
  AND NOT EXISTS (SELECT 1 FROM ip_address a WHERE a.id::text = c.resource_id)
  AND NOT EXISTS (SELECT 1 FROM audit_log d
                  WHERE d.resource_type = 'ip_address' AND d.action = 'delete'
                    AND d.resource_id = c.resource_id)
ORDER BY c.timestamp;
```

This also lists rows removed by deleting their subnet, block or space,
which writes no per-address audit row, so read it next to what you know was
deleted on purpose. `new_value` carries what was typed at creation
(hostname, description, status, MAC); later edits are in `update` rows for
the same `resource_id`. Re-create the ones you want through IPAM. Their
orphaned DNS records stay where they are until Sync DNS on the subnet
reports them, so re-create the address before committing any deletions.

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
