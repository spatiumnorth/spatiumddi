# Docker Compose Deployment

> **For multi-VM / HA / hybrid-cloud deployments**, see
> [`TOPOLOGIES.md`](TOPOLOGIES.md) — six reference topologies with
> diagrams, sizing tips, and a "you have X → start with
> topology Y" picker.

## Prerequisites

- Docker Engine 25+ and Docker Compose v2.20+
- 2 GB RAM minimum (4 GB recommended)
- Ports 8077 (frontend, `HTTP_PORT`) and optionally 8000 (API direct access, `API_PORT`) free on the host

---

## 1. Port Reference

| Port | Service | Protocol | Notes |
|---|---|---|---|
| 8077 | Frontend (nginx) | HTTP | Host-published default; configurable via `HTTP_PORT` env var (container listens on 80) |
| 443 | Frontend (nginx) | HTTPS | When TLS is configured (see §5) |
| 8000 | API (uvicorn) | HTTP | Configurable via `API_PORT` env var; internal only in production |
| 5432 | PostgreSQL | TCP | Internal only — never expose externally |
| 6379 | Redis | TCP | Internal only — never expose externally |

All services communicate on the `spatiumddi` Docker bridge network. Only the frontend and API ports are published to the host.

---

## 2. First-Time Setup

```bash
# Clone the repository
git clone https://github.com/spatiumnorth/spatiumddi.git
cd spatiumddi

# Create your environment file
cp .env.example .env

# Edit .env — at minimum change POSTGRES_PASSWORD and SECRET_KEY
# SECRET_KEY: openssl rand -hex 32
nano .env

# Build images
docker compose build

# Run database migrations
docker compose run --rm migrate

# Start all services
docker compose up -d
```

The API automatically creates a default admin user on first startup if no users exist:
- **Username:** `admin`
- **Password:** `admin`
- **Force password change:** Yes — you will be redirected to the change-password page on first login.

Access the UI at `http://your-host-or-ip:8077/` (or `http://localhost:8077/` if running locally). The host port is set by `HTTP_PORT` (default `8077`).

---

## 3. Environment Variables

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | `changeme` | PostgreSQL password — **must change** |
| `SECRET_KEY` | (none) | JWT signing key — **must change** (use `openssl rand -hex 32`) |
| `HTTP_PORT` | `8077` | Host port for the frontend |
| `API_PORT` | `8000` | Host port for the API (set to `127.0.0.1:8000:8000` to restrict to localhost) |
| `DATABASE_URL` | auto-constructed | Override only if using an external PostgreSQL |
| `REDIS_URL` | `redis://redis:6379/0` | Override to point at an external Redis |
| `DEBUG` | `false` | Enable FastAPI debug mode |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | JWT access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |

---

## 4. Resetting the Admin Password (CLI)

If the admin password is lost, reset it directly against the database inside the API container:

```bash
docker compose exec api python - <<'EOF'
from app.core.security import hash_password
import asyncio
from sqlalchemy import update
from app.db import AsyncSessionLocal
from app.models.auth import User

async def reset():
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(User)
            .where(User.username == "admin")
            .values(
                hashed_password=hash_password("NewPassword123!"),
                force_password_change=True,
            )
        )
        await db.commit()
        print("Password reset OK")

asyncio.run(reset())
EOF
```

---

## 5. TLS / HTTPS

### Option A: Terminate TLS at the host with nginx (recommended for VMs)

Place a reverse proxy in front of the `spatiumddi-frontend-1` container:

```nginx
server {
    listen 443 ssl;
    server_name spatiumddi.example.com;

    ssl_certificate     /etc/letsencrypt/live/spatiumddi.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/spatiumddi.example.com/privkey.pem;

    location / {
        proxy_pass         http://localhost:8077;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
    }
}
```

### Option B: Caddy (automatic Let's Encrypt — simplest for appliance installs)

```caddyfile
spatiumddi.example.com {
    reverse_proxy localhost:8077
}
```

Caddy handles ACME certificate issuance and renewal automatically.

### Option C: TLS inside the nginx container

Mount your certificate files and an updated `nginx.conf` into the frontend container:

```yaml
# In docker-compose.override.yml
services:
  frontend:
    ports:
      - "443:443"
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - ./nginx-ssl.conf:/etc/nginx/conf.d/default.conf:ro
```

### ACME / DNS Challenge (for IPAM-integrated certificate management)

SpatiumDDI ships an [acme-dns](https://github.com/joohoi/acme-dns)-compatible HTTP surface under `/api/v1/acme/` for creating and removing ACME DNS-01 challenge TXT records. External ACME clients (certbot, lego, acme.sh) can complete DNS challenges using SpatiumDDI as the DNS backend by CNAME-ing `_acme-challenge.<their-domain>` to a SpatiumDDI-managed subdomain and updating the TXT record over the acme-dns protocol:

```bash
# Example with lego (supports acme-dns out of the box)
export ACME_DNS_API_BASE=https://spatiumddi.example.com/api/v1/acme
export ACME_DNS_STORAGE_PATH=./acme-dns-accounts.json
lego --email you@example.com --dns acme-dns -d your-domain.example.com run
```

See [`docs/features/ACME.md`](../features/ACME.md) for the full ACME provider specification.

---

## 6. PostgreSQL High Availability (Docker Compose)

For single-server deployments, the default single PostgreSQL container is sufficient. For HA:

- **Patroni + etcd + HAProxy**: See `k8s/ha/postgres-docker-compose.yaml`
- Connect your `.env` `DATABASE_URL` to HAProxy port 5000 (primary) instead of the `postgres` container

For multi-server deployments, use Kubernetes with CloudNativePG (see `k8s/README.md`).

---

## 7. Redis High Availability (Docker Compose)

The default single Redis container uses `maxmemory-policy allkeys-lru` for Celery task queues. For HA:

- Use Redis Sentinel (3 nodes) — see `k8s/ha/redis-sentinel.yaml` for the manifest pattern
- Or use Valkey Cluster (3+ nodes) for horizontal scale
- Update `REDIS_URL`, `CELERY_BROKER_URL`, and `CELERY_RESULT_BACKEND` to point at the Sentinel/cluster endpoint

---

## 8. Upgrading

> **Take a backup before upgrading.** Sign in as a superadmin → **System Admin → Backup → Manual → Build + download**, supply a passphrase you'll remember (or pick a configured destination's **Run now** button). The archive is the single rollback artifact if the upgrade goes sideways. See §9 below for the full backup / restore surface.

```bash
# Pull latest code
git pull

# Rebuild images
docker compose build

# Run new migrations (safe to run — Alembic is idempotent)
docker compose run --rm migrate

# Restart services with zero-downtime rolling update
docker compose up -d --force-recreate api worker beat frontend
```

If you skipped the backup and need to roll back: every restore takes a `pre-restore-{ts}.zip` safety dump under `/var/lib/spatiumddi/backups/` automatically (passphrase is the literal string `pre-restore-safety`). That gets you back to wherever the last restore landed — but it does **not** cover an upgrade you ran without a restore in between, so the build-and-download nudge above is the durable hedge.

---

## 9. Backup and Restore

The full backup + restore surface lives in **System Admin → Backup**: build-and-download, configured remote destinations (local volume, S3 / S3-compatible, SCP/SFTP, Azure Blob, SMB/CIFS, FTP/FTPS, Google Cloud Storage, WebDAV, NFS, HTTPS PUT/POST), scheduled cron + retention, restore-from-file, restore-from-destination, archive proxy-download, selective restore. See [`docs/features/SYSTEM_ADMIN.md`](../features/SYSTEM_ADMIN.md#29-backup-and-restore) for the full operator reference.

The shape that's specific to Docker Compose:

### Local-volume target

A `local_volume` destination writes archives to a filesystem path inside the containers, and two containers use it: the worker writes every scheduled run, and the api writes a manual **Run now** and lists, downloads and restores archives. So the path **must** be one volume mounted on both. Otherwise each container keeps its own copy in its writable layer: scheduled archives never appear in the target's archive list, and every archive is lost at the next container recreate. `docker-compose.yml` mounts `spatium_backups` on both at `/var/lib/spatiumddi/backups`, the path a new target suggests:

```yaml
# docker-compose.yml
services:
  api:
    volumes:
      - spatium_backups:/var/lib/spatiumddi/backups
  worker:
    volumes:
      - spatium_backups:/var/lib/spatiumddi/backups
volumes:
  spatium_backups:
```

To use another path, mount a volume there on **both** services. **Test connection** on the target warns when its path is not on a mounted volume. Restore's `pre-restore-{ts}.zip` safety dump is written to the same directory.

Upgrading from a compose file that had this volume commented out (every release up to and including `2026.09.04-1`): archives written before the upgrade exist only inside the running api and worker containers. Copy them out before the upgrade recreates the containers — `docker compose cp api:/var/lib/spatiumddi/backups ./backups-api`, and the same for `worker`.

### Out-of-band PostgreSQL dump (fallback only)

The in-app backup is the supported path — it captures the encrypted master key, the alembic head, and every Fernet-encrypted column in a single zip. A bare `pg_dump` of the postgres container does **not** capture the master key (which lives in the api container's env), so cross-install restores from a raw dump need the operator to manually copy `SECRET_KEY` to the destination. Use the in-app backup unless you specifically need a SQL dump for a migration script.

```bash
# Out-of-band dump — diagnostic / migration-script use only
docker compose exec -T postgres pg_dump -U spatiumddi spatiumddi | gzip > postgres-only-$(date +%Y%m%d).sql.gz

# Restore the SQL dump
gunzip -c postgres-only-YYYYMMDD.sql.gz | docker compose exec -T postgres psql -U spatiumddi spatiumddi
```

### Redis backup

Redis persistence (`appendonly yes`) is enabled. The RDB/AOF files are in the `redis_data` volume. There's no operator-facing data in Redis — Celery task scratch, session cache, ETag-poll bookkeeping — so a Redis backup is generally not needed. For point-in-time disaster recovery, copy the `redis_data` volume alongside the SpatiumDDI archive.

---

## 10. Distributed Agent Deployments

For real production use you generally don't want the Kea DHCP agent and the BIND9 DNS agent running on the same host as the control plane. SpatiumDDI ships standalone compose files for that shape:

| File | Purpose |
|---|---|
| `docker-compose.agent-dhcp.yml`           | Kea DHCP agent(s) only — no control plane |
| `docker-compose.agent-dns-bind9.yml`      | BIND9 DNS agent only — no control plane (renamed from `docker-compose.agent-dns.yml` in `2026.05.11-1`) |
| `docker-compose.agent-dns-powerdns.yml`   | PowerDNS DNS agent only — no control plane (issue #127) |
| `docker-compose.agent-dns-technitium.yml` | Technitium DNS agent only — no control plane (issue #746) |
| `docker-compose.agent-looking-glass.yml`  | Receive-only BGP Looking Glass collector only — no control plane (issue #566) |

The agent containers long-poll the remote control plane's API and cache the last-known-good config locally (non-negotiable #5), so the DHCP / DNS services keep serving even if the control plane is briefly unreachable.

The BGP Looking Glass collector can also run **co-located** with the control plane straight from the main `docker-compose.yml`, gated behind the `looking-glass` profile:

```bash
# On the control-plane host — requires LG_AGENT_KEY in .env (see .env.example):
docker compose --profile looking-glass up -d
```

The `looking-glass` service uses `network_mode: host` so BGP (TCP/179) originates from the host's real routable NIC — a router has no route to a bridged/NATed container IP. Use the standalone `docker-compose.agent-looking-glass.yml` (in the table above) instead when the collector needs to run on a separate VM.

### Prerequisites

1. Control plane already running somewhere reachable (e.g. `https://spatium.example.com`).
2. The pre-shared agent bootstrap key from the control plane. These are the `DNS_AGENT_KEY` / `DHCP_AGENT_KEY` env values the control plane was started with; reveal them from the UI at **Settings → Security → Agent bootstrap keys** (`POST /api/v1/admin/agent-keys/reveal`, superadmin + password-confirm). The agent must present this same key — the control plane rejects bootstrap attempts with an unknown key. The agent exchanges the pre-shared key for a rotating JWT on first contact and caches it locally, so it only needs the bootstrap key once.
3. If the control plane uses a self-signed cert, either mount a CA bundle at `/etc/ssl/spatium-ca.crt` and set `TLS_CA_PATH`, or (lab-only) leave `SPATIUM_INSECURE_SKIP_TLS_VERIFY=1`.

### DHCP-only VM

```bash
# On the DHCP VM (separate host from the control plane):
export SPATIUM_API_URL=https://spatium.example.com
export SPATIUM_AGENT_KEY=<DHCP_AGENT_KEY from the control plane>   # see Prerequisites
export DHCP_HOSTNAME=dhcp-kea-east    # unique across the deployment

# Single Kea node:
docker compose -f docker-compose.agent-dhcp.yml up -d

# Local HA pair (rare in prod — usually each peer goes on its own VM):
docker compose -f docker-compose.agent-dhcp.yml --profile dhcp-ha up -d
```

For a **true HA pair across two VMs**, run the same compose file on each VM with a different `DHCP_HOSTNAME` (say `dhcp-kea-east` and `dhcp-kea-west`) and the same `AGENT_GROUP`. On the control plane, edit the DHCP Server Group's HA mode (hot-standby or load-balancing) and set each server's `ha_peer_url` to **its own** HA listener URL (`http://<that VM's address>:8000/`). Each server's URL goes into every peer's `peers` list, which is how the partner reaches it. The agent resolves peer hostnames at render time and the `PeerResolveWatcher` thread keeps them fresh if IPs change.

#### Optional: passive DHCP fingerprinting

To enable Phase 2 device profiling (DHCP fingerprint capture +
fingerbank lookup), add the `NET_RAW` capability to the
`dhcp-kea` service in your override file and flip the env toggle:

```yaml
services:
  dhcp-kea:
    cap_add:
      - NET_RAW
    environment:
      DHCP_FINGERPRINT_ENABLED: "1"
      # Optional — interface name for the sniffer. Default "any"
      # works for host-networked containers; bridge-networked
      # containers should set this explicitly.
      DHCP_FINGERPRINT_IFACE: "any"
```

The capability is **not** added to the shipped `docker-compose.yml`
because the feature is default-off and we don't want to grant
sniffing privileges on installs that aren't using it. Set the
fingerbank API key in **Settings → IPAM → Device Profiling** on the
control plane to enable enrichment; without a key the agent still
ships raw signatures, fingerbank lookups just don't run. See
[`docs/features/DHCP.md`](../features/DHCP.md) §17 for the full design and privacy notes.

#### Optional: arpwatch-style new-device detection

To enable Phase 3 new-device detection (issue #459), the agent runs
an additional opt-in L2 sniffer that observes source MACs on the wire
via **ARP + IPv6 Neighbor Discovery** — so it catches statically
addressed and link-local-only hosts that never touch the DHCP server,
not just DHCP clients. First-sightings ship to the control plane,
which classifies them and surfaces unknowns in the new-device-watch
review queue.

It shares the same `NET_RAW` capability as passive fingerprinting (no
new capability is required) and is gated on its own env toggle:

```yaml
services:
  dhcp-kea:
    cap_add:
      - NET_RAW
    environment:
      DHCP_MAC_SIGHTING_ENABLED: "1"
      # Optional — interface name for the sniffer. Default "any"
      # works for host-networked containers; bridge-networked
      # containers should set this explicitly.
      DHCP_MAC_SIGHTING_IFACE: "any"
```

Like fingerprinting, this is **default-off** — flip the toggle (and
grant `NET_RAW` if you haven't already) to arm it. The control-plane
endpoint is a no-op until the new-device-watch feature module is
enabled server-side, so a locally-armed agent that hasn't been wired
up on the control plane just ships into a black hole at no cost.

### DNS-only VM

Pick the compose file that matches the driver on the control plane's
DNSServerGroup:

```bash
export CONTROL_PLANE_URL=https://spatium.example.com
export DNS_AGENT_KEY=<DNS_AGENT_KEY from the control plane>   # see Prerequisites

# BIND9 (default, ubiquitous, RNDC + RFC 2136 DDNS):
export DNS_HOSTNAME=dns-bind9-east
docker compose -f docker-compose.agent-dns-bind9.yml up -d

# PowerDNS (issue #127, native REST API + LMDB embedded backend,
# unlocks ALIAS / LUA in PowerDNS-only groups):
export DNS_HOSTNAME=dns-powerdns-east
docker compose -f docker-compose.agent-dns-powerdns.yml up -d

# Technitium (issue #746, REST API + its own embedded store — no config
# file and no external database; native DoT / DoH / DoQ listeners and
# encrypted upstream forwarding over all three):
export DNS_HOSTNAME=dns-technitium-east
docker compose -f docker-compose.agent-dns-technitium.yml up -d
```

All three compose files share the same `DNS_AGENT_KEY` bootstrap shape
and register against `CONTROL_PLANE_URL` the same way; the only
difference is the image (`dns-bind9` / `dns-powerdns` /
`dns-technitium`) and the driver baked into the image's `AGENT_DRIVER`
env. The control plane gates driver-specific features on **every server
in the group running that driver** — ALIAS / LUA need an all-PowerDNS
group, views and RPZ an all-BIND9 one, DoQ and encrypted-DoH/DoQ
forwarding an all-Technitium one. To run more than one side-by-side,
create a separate `DNSServerGroup` per driver.

For authoritative + secondary pairs, run the same compose file on each
additional DNS VM with a unique `DNS_HOSTNAME` and the same
`AGENT_GROUP`. Zone assignments and view membership are configured on
the control plane.

### Host vs bridge networking

Default ports in both files map to non-53 / non-67 host ports (1053/udp+tcp for DNS, 6767/udp for DHCP) so the containers don't collide with systemd-resolved or a running dhcp client on the host. The DNS default was 5353 prior to release `2026.05.11-1`; it changed to 1053 because 5353 is the well-known mDNS port that avahi (default-on in Ubuntu desktop, Fedora, most lab distros) already binds. Existing deployments that want to keep the old port can set `DNS_HOST_PORT=5353` in `.env`.

For **real DNS / DHCP serving** you want `network_mode: host` so the daemon binds 53 / 67 directly and, for DHCP, receives L2 broadcasts on the host NIC. Add to the service definition:

```yaml
services:
  dhcp-kea:
    network_mode: host
    # ...remove the `networks:` + `ports:` keys when host-networked.
```

### Observability

Once registered, the agent shows up on the control plane's Dashboard and in DHCP → Servers or DNS → Servers. Heartbeat / online status updates every 30s.
