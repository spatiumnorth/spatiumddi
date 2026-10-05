# Performance-test appliance setup (replication guide)

How to prepare a **clean single-node SpatiumDDI appliance** so the performance test
suite (`perf/`, see [`PERFORMANCE_TESTING.md`](PERFORMANCE_TESTING.md)) can drive it.
This is the exact sequence used to stand up the `ddi-demo` test box (issue #452);
follow it to replicate on a fresh appliance.

> The appliance under test here is the **#170 / #183 architecture**: a k3s
> single-node "control-plane" appliance with a `spatium-supervisor`. DNS/DHCP run as
> **hostNetwork DaemonSet pods** gated on per-role node labels — the supervisor
> stamps the label when you assign a role, and the pod binds the **node IP** directly
> (`:53` / `:67`). Postgres (CNPG) and Redis (Sentinel) are **ClusterIP-internal**.

## 0. Conventions

```bash
APP=192.168.0.125                 # appliance node IP
SSH="sshpass -p <ssh-pass> ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@$APP"
ADMIN_USER=admin ; ADMIN_PASS='<api-password>'
K(){ $SSH "echo <ssh-pass> | sudo -S -p '' kubectl $*"; }   # kubectl as root over ssh
tok(){ curl -sk -X POST https://$APP/api/v1/auth/login -H 'Content-Type: application/json' \
       -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq -r .access_token; }
```

Confirm the API is healthy first: `curl -sk https://$APP/health/platform | jq .status` → `ok`.

## 1. Mint a long-lived API token (24h runs need it)

The default JWT access token lives ~11 min — useless for a 24h run, and the suite's
user/password login fallback doesn't auto-refresh. Mint a 30-day API token instead:

```bash
TOK=$(tok)
curl -sk -X POST https://$APP/api/v1/api-tokens -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"perf-suite\",\"description\":\"perf test (#452) — destroy after\",\"expires_in_days\":30,\"scopes\":[],\"stepup_password\":\"$ADMIN_PASS\"}" \
  | jq -r .token          # ← record this ONCE; it is never shown again
```
Minting a token needs the owner's step-up (#1355): `stepup_password` for a local
account, or `stepup_totp_code` (an authenticator code) for an SSO one.
`scopes: []` = unrestricted (superadmin). Set `SPDDI_PERF_ADMIN_TOKEN` to this value.
Verify: `curl -sk https://$APP/api/v1/auth/me -H "Authorization: Bearer <token>" | jq '{username,is_superadmin}'`.

## 2. Bring up the DNS + DHCP data plane (assign roles)

A fresh appliance runs only the supervisor — no bind9/kea, and `:53`/`:67` are closed.
Create a DNS + DHCP group, then assign the roles **bound to those groups** (the
agents register into the bound group). The suite's seeder seeds zones/scopes into the
appliance's *assigned* groups, so record the IDs.

```bash
TOK=$(tok)
DNS_GID=$(curl -sk -X POST https://$APP/api/v1/dns/groups -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"name":"perf-dns","group_type":"internal","is_recursive":false}' | jq -r .id)   # is_recursive:false = §4.9 authoritative-only
DHCP_GID=$(curl -sk -X POST https://$APP/api/v1/dhcp/server-groups -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"name":"perf-dhcp","mode":"standalone","dhcp_socket_mode":"direct"}' | jq -r .id)

APP_ID=$(curl -sk https://$APP/api/v1/appliance/appliances -H "Authorization: Bearer $TOK" | jq -r '.appliances[0].id')
curl -sk -X PUT https://$APP/api/v1/appliance/appliances/$APP_ID/roles -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "{\"roles\":[\"dns-bind9\",\"dhcp\"],\"dns_group_id\":\"$DNS_GID\",\"dhcp_group_id\":\"$DHCP_GID\"}" | jq '{assigned_roles}'
```
The supervisor brings up bind9 + kea on its next heartbeat (~30–60 s). Verify:

```bash
K get pods -n spatium -o wide | grep -E 'bind9|kea'         # both Running, IP = node IP (hostNetwork)
$SSH 'echo <ssh-pass> | sudo -S ss -lntu' | grep -E ':53 |:67 '   # node IP listening on :53/:67
dig +short @$APP version.bind CH TXT                        # bind answers
dig +short @$APP google.com A                               # → SERVFAIL/REFUSED/empty (recursion OFF; a real IP = LEAK)
K exec -n spatium ds/dns-bind9 -- grep -iE 'recursion|allow-recursion' /etc/bind/named.conf.options
#   → "recursion no;"   (the §4.9 safety property)
```
The appliance capabilities must advertise `can_run_dns_bind9` / `can_run_dhcp` (they
do on a full appliance); the role PUT 422s otherwise.

> **⚠️ Recursion (perf #454).** The rendered `recursion no;` is driven by the bind9
> server **options** (`DNSServerOptions.recursion_enabled`), and historically the
> group's `is_recursive=false` did NOT propagate to it — so a group created per §1
> above could still render `recursion yes;` and resolve the public internet (a §4.9
> leak). Fixed so `is_recursive=false` now forces recursion off. **Always verify with
> the `dig google.com` above** — a real A record back means recursion is still on.
> Belt-and-braces (and the fix for appliances on a pre-#454 backend), force it off via
> the options endpoint:
>
> ```bash
> curl -sk -X PUT https://$APP/api/v1/dns/groups/$DNS_GID/options \
>   -H "Authorization: Bearer $(tok)" -H 'Content-Type: application/json' \
>   -d '{"recursion_enabled": false, "allow_recursion": []}'
> ```
>
> This bind returns **REFUSED/SERVFAIL** (not a real answer) for out-of-zone names
> once recursion is off — both mean "did not resolve". The §4.9 pre-flight treats
> *only* a real external answer (NOERROR + an A record) as a leak.

## 3. Expose Postgres + Redis off-box (NodePorts)

CNPG and Redis are ClusterIP-only. The war-room psql probe + Celery-queue LLEN run
off-box, so expose them via pinned NodePorts (the load-gen box then hits `node-ip:NodePort`):

```bash
$SSH 'cat > /tmp/perf-nodeports.yaml' <<'YAML'
apiVersion: v1
kind: Service
metadata: {name: perf-pg, namespace: spatium, labels: {perf-purpose: nodeport}}
spec:
  type: NodePort
  selector: {cnpg.io/cluster: spatium-control-spatiumddi-postgresql, cnpg.io/instanceRole: primary}
  ports: [{name: pg, port: 5432, targetPort: 5432, nodePort: 30432}]
---
apiVersion: v1
kind: Service
metadata: {name: perf-redis, namespace: spatium, labels: {perf-purpose: nodeport}}
spec:
  type: NodePort
  selector: {statefulset.kubernetes.io/pod-name: spatium-control-spatiumddi-redis-0}   # the master pod
  ports: [{name: redis, port: 6379, targetPort: 6379, nodePort: 30679}]
YAML
K apply -f /tmp/perf-nodeports.yaml
```
- **Postgres** selector targets the CNPG **primary** (writes/locks visible).
- **Redis** selector pins `redis-0` (the current Sentinel **master**). If a failover
  promotes another pod, re-point the selector. Celery queues live on **db 1** (the
  broker), so the URL ends `/1`.

Pull the credentials the suite needs (from the appliance, never committed):

```bash
K exec -n spatium deploy/spatium-control-spatiumddi-api -- printenv | grep -E 'DATABASE_URL|REDIS_URL|CELERY_BROKER'
K get secret -n spatium spatium-control-spatiumddi-postgresql -o jsonpath='{.data.password}' | base64 -d   # pg password
# pg user/db = spatiumddi/spatiumddi (CNPG superuser — sees all backends, good for pg_locks)
```

## 4. Wire the env vars (on the load-gen box)

```bash
# Point any manifest at this appliance without editing the committed placeholder:
export SPDDI_PERF_NODE_IP='192.168.0.125'         # → api_base derived automatically
export SPDDI_PERF_ADMIN_TOKEN='sddi_...'           # the §1 long-lived token
export SPDDI_PERF_PSQL_DSN='postgresql://spatiumddi:<pgpass>@192.168.0.125:30432/spatiumddi'
export SPDDI_PERF_REDIS_URL='redis://192.168.0.125:30679/1'    # db 1 = celery broker
# SPDDI_PERF_CA_BUNDLE: leave unset (suite uses verify=False; cert is self-signed CN=<hostname>)

# Critical for pre-prepared appliances: tell the seeder to reuse the existing
# DNS/DHCP groups that bind9/kea are already bound to, instead of creating new
# empty groups that no agent serves.
export SPDDI_PERF_DNS_GROUP_ID="$DNS_GID"         # from the §2 group-create output
export SPDDI_PERF_DHCP_GROUP_ID="$DHCP_GID"       # from the §2 group-create output
```

> **Why these matter:** `seed_scaffold` normally creates new `perf-dns-<run-id>` /
> `perf-dhcp-<run-id>` groups every run. New groups have no servers — so bind9/kea
> (which are bound to the manually-created groups from §2) would not serve the seeded
> zones/scopes. Setting `SPDDI_PERF_DNS_GROUP_ID` / `SPDDI_PERF_DHCP_GROUP_ID` skips
> group creation and seeds directly into the groups the agents are already serving.
> Zones are get-or-created (idempotent); the bulk record load is skipped on re-runs
> where the forward zone already exists.

> **One group, one manifest.** The skip above is what makes a re-run cheap, and it
> is only correct when the records already in the zone are *this* manifest's
> dataset. Every shipped manifest names the same forward zone, so running
> `smoke.yaml` and then `300k-ceiling.yaml` against one reused group would skip the
> 300k load and measure the ceiling against smoke's 10k. The seeder now counts what
> the reused zone holds and refuses to skip when it is short of the plan, or when a
> reverse zone was created empty this run ([#981](https://github.com/spatiumnorth/spatiumddi/issues/981)).
> Use a fresh group per manifest, delete the zones between manifests, or — if the
> partial dataset is deliberate — set `SPDDI_PERF_ALLOW_SHORT_REUSED_ZONE=1`. A zone
> holding *more* than the manifest plans is allowed and logged, since every planned
> name still resolves.

If you lost the group IDs, retrieve them:
```bash
TOK=$(tok)
curl -sk https://$APP/api/v1/dns/groups -H "Authorization: Bearer $TOK" | jq '.[] | {id,name}'
curl -sk https://$APP/api/v1/dhcp/server-groups -H "Authorization: Bearer $TOK" | jq '.[] | {id,name}'
```
> If you don't want NodePorts, SSH-tunnel instead (the appliance host can reach the
> ClusterIPs): `ssh -fNL 15432:<pg-clusterip>:5432 admin@$APP` etc., and point the
> DSN/URL at `127.0.0.1:15432`.

## 5. Verify end-to-end

```bash
nc -zv 192.168.0.125 30432 && nc -zv 192.168.0.125 30679       # ports open
make perf-validate MANIFEST=perf/manifests/smoke.yaml          # plan resolves
make perf-tui                                                  # interactive: pick smoke → Start
#   or headless:  make perf-smoke
```

## 6. Teardown (when finished)

```bash
TOK=$(tok)
K delete svc -n spatium perf-pg perf-redis                                          # NodePorts
curl -sk -X PUT https://$APP/api/v1/appliance/appliances/$APP_ID/roles -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"roles":[]}'                             # idle the data plane
# delete the perf-dns / perf-dhcp groups + the perf-suite API token via their DELETE endpoints
```
(For a throwaway box, just destroy the VM.)

## Architecture notes / gotchas learned

| What | Detail |
|---|---|
| **Data plane** | bind9/kea = hostNetwork k3s **pods** (not docker) gated on `spatium.io/role-*` node labels the supervisor stamps on role assignment. `docker ps` is empty; use `kubectl`. |
| **Recursion** | The DNS *group* `is_recursive:false` renders `recursion no;` — verified in the pod's `named.conf.options`. Out-of-zone → SERVFAIL (still safe; not a real answer). |
| **pg/redis reach** | ClusterIP-only. The appliance *host* can reach ClusterIPs/pod-IPs; a separate LAN box needs the NodePorts (§3) or an SSH tunnel. |
| **pg user** | `DATABASE_URL` user `spatiumddi` is the CNPG **superuser** → the psql probe sees all backends (`pg_stat_activity`/`pg_locks`). For least-privilege, create a read-only `pg_monitor` role later. |
| **Redis** | Sentinel HA, master = `redis-0:6379`, **no password**; broker = **db 1**. NodePort pins the master pod. |
| **Token TTL** | JWT access token ≈ 11 min; always use a minted **API token** (§1) for runs longer than the smoke. |
| **Groups** | The seeder seeds into the appliance's **assigned** DNS/DHCP groups — keep `is_recursive:false` on the DNS group so the rendered config stays authoritative-only. |
