# Running behind a reverse proxy

This page is for putting SpatiumDDI behind **your own** reverse proxy: an
nginx, Caddy, Traefik, HAProxy or Nginx Proxy Manager host that terminates
TLS, or a Kubernetes Ingress. It applies to Docker Compose and to the Helm
chart. (The OS appliance serves its own HTTPS and needs none of this.)

Done right it is three settings and four headers. Done wrong it fails in
confusing ways (see the [troubleshooting table](#troubleshooting)): a redirect
loop, a 400 on every call, SSO "redirect_uri mismatch", being signed out on
every reload, or `429 Too many login attempts` for the whole organisation.

## 1. Supported topology

```
browser ──https──> your proxy ──http──> SpatiumDDI frontend (nginx) ──> api
                  (terminates TLS)      Compose: host:8077
                                        Helm: frontend Service, port 80
```

- SpatiumDDI is served from the **root of its own hostname**
  (`https://ddi.example.com/`). **Sub-paths such as
  `https://example.com/spatium/` are not supported**: the single-page app uses
  absolute paths (`/login`, `/api/v1/...`) and the refresh cookie is scoped to
  `/api/v1/auth`. Use a hostname of its own. If a trusted proxy sends
  `X-Forwarded-Prefix`, the api logs `reverse_proxy_sub_path_unsupported`.
- The proxy terminates TLS and talks **plain HTTP** to the frontend. With Helm
  leave `frontend.tls.enabled=false`.
- The alternative is to proxy HTTPS to the Helm frontend's port 443 with
  `frontend.tls.enabled=true`. It also works with a proxy that terminates TLS
  and talks http to port 80 (see [Helm](#helm-and-kubernetes)).
- The browser must reach the proxy over **https**. Plain http outside while
  the proxy says `https` inside signs users out on every reload (the refresh
  cookie is `Secure`).

## 2. Required settings

| Setting | Value | Why |
|---|---|---|
| **Settings > General > External URL** | the public URL, `https://ddi.example.com` | **Mandatory for OIDC and SAML** (callback / ACS URLs are built from it), recommended always. Empty means the URL is rebuilt from each request; the api logs `sso_external_url_not_set` when it falls back |
| `FRONTEND_TRUSTED_PROXY_CIDRS` (Helm: `frontend.trustedProxyCidrs`) | the proxy's address, and nothing else | Lets the real client IP and scheme through, so the login throttle, audit log, `last_login_ip`, the Web UI allow-list and ACME source checks see the user, not the proxy, and the api sees `https` |
| `TRUSTED_HOSTS` | leave **unset**, or list the exact `Host` the proxy forwards | A proxy that rewrites `Host` to its upstream name gets `400` on every call; the api logs `trusted_hosts_refused_host` |

### `FRONTEND_TRUSTED_PROXY_CIDRS`

The frontend nginx believes `X-Forwarded-For` and `X-Forwarded-Proto` only
from a TCP peer in this list (comma-separated addresses or CIDRs). It walks
`X-Forwarded-For` from the right, skipping listed hops, and takes the first
address that is not listed, so an address a client puts at the front of the
header is never reached. It then hands the api that address in `X-Real-IP`,
which it always writes itself and never passes through. **Unset or empty
means no proxy is trusted**, which is exactly the behaviour of an install
with no proxy. An entry that is not an address or CIDR stops the frontend
container at start, with the entry named in its log.

```bash
# .env (Docker Compose). Proxy at 192.168.10.5:
FRONTEND_TRUSTED_PROXY_CIDRS=192.168.10.5/32
```

- **List only the proxy.** Every listed peer chooses the client address the
  api records, so a listed address that is not your proxy can make each
  request look like it came from somewhere new: past the login throttle, and
  into the audit log under an address of its choosing. Do not list whole
  private ranges unless nothing in them but the proxy can reach the
  frontend's port.
- **A proxy on the Docker host itself** usually connects from the compose
  network's gateway (for example `172.18.0.1`), not `127.0.0.1`. The
  frontend's access log (`docker compose logs frontend`) shows the address
  the proxy's requests arrive from before you set the variable.
- **`*` trusts every peer.** Then any client that can reach the frontend
  directly picks its own recorded address and scheme. Use it only when a
  firewall or network policy guarantees that nothing but the proxy reaches
  the frontend, and prefer a real address when you can.
- **This is not the api's `TRUSTED_PROXY_CIDRS`**, and that one needs no
  change. The api's TCP peer is always the frontend nginx, which its
  default (the private ranges) already covers. If you have narrowed the
  api's list, it must still cover the frontend's own address, as before.

## 3. Headers the proxy must send

| Header | Value |
|---|---|
| `Host` | the public hostname, **preserved** (not the upstream's name) |
| `X-Forwarded-Proto` | `https` |
| `X-Forwarded-For` | the client address (append, do not replace) |
| `X-Real-IP` | the client address (optional; nginx uses `X-Forwarded-For`) |

Most proxies (Caddy, Traefik, HAProxy with `option forwardfor`, Nginx Proxy
Manager) send these themselves. Plain nginx needs them written out.

## 4. Streaming

Three features are long-lived `fetch` streams (server-sent events): the AI
chat (`/api/v1/ai/chat`), the cluster-health stream
(`/api/v1/appliance/cluster/health/stream`) and the container-log follow
streams (`/api/v1/appliance/containers/.../logs/stream`; the nmap scan
progress stream behaves the same). The frontend nginx already serves them
unbuffered with a one hour timeout. **Your proxy must too**: response
buffering off and a read timeout of **at least an hour**. No websocket upgrade
is needed. A buffering or short-timeout proxy makes these features look
broken (a chat that hangs, a log view that stays empty), while everything
else works.

## 5. Examples

Replace `ddi.example.com`, the certificate paths and `docker-host` with
yours. `docker-host:8077` is the Compose frontend (`HTTP_PORT`).

### nginx

```nginx
server {
  listen 443 ssl;
  server_name ddi.example.com;
  ssl_certificate     /etc/ssl/ddi.example.com/fullchain.pem;
  ssl_certificate_key /etc/ssl/ddi.example.com/privkey.pem;

  location / {
    proxy_pass http://docker-host:8077;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    client_max_body_size 4g;   # backup restore and slot-image uploads
  }
}
```

Add `proxy_set_header Connection "";` if you serve other sites from the same
upstream block with keepalive.

### Caddy

```caddyfile
ddi.example.com {
    reverse_proxy docker-host:8077 {
        flush_interval -1
    }
}
```

Caddy sets `Host`, `X-Forwarded-For` and `X-Forwarded-Proto` itself, preserves
`Host`, and has no read timeout on a response stream by default.

### Traefik (Docker labels)

```yaml
services:
  traefik:
    image: traefik:v3.6
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.websecure.address=:443
      - --entrypoints.websecure.transport.respondingTimeouts.writeTimeout=0s
      - --entrypoints.websecure.transport.respondingTimeouts.idleTimeout=3600s
      - --certificatesresolvers.le.acme.tlschallenge=true
      - --certificatesresolvers.le.acme.email=you@example.com
      - --certificatesresolvers.le.acme.storage=/letsencrypt/acme.json
    ports: ["443:443"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./letsencrypt:/letsencrypt
    networks: [proxy]

  frontend:   # in SpatiumDDI's docker-compose.override.yml
    networks: [default, proxy]
    labels:
      - traefik.enable=true
      - traefik.docker.network=proxy
      - traefik.http.routers.ddi.rule=Host(`ddi.example.com`)
      - traefik.http.routers.ddi.entrypoints=websecure
      - traefik.http.routers.ddi.tls.certresolver=le
      - traefik.http.services.ddi.loadbalancer.server.port=80
      - traefik.http.services.ddi.loadbalancer.responseforwarding.flushinterval=-1ms

networks:
  proxy:
    external: true   # docker network create proxy
```

`writeTimeout` defaults to unlimited, so the `respondingTimeouts` lines are
there to make that explicit and to keep idle streams open; the load-bearing
part is `flushinterval=-1ms` (flush every write immediately). Traefik passes
`Host` through and sets the `X-Forwarded-*` headers itself.
Use Traefik 3.6 or later: against a current Docker Desktop, 3.5 built no
routers from these labels, so every request answered `404 page not found`.
`traefik.docker.network` matters because the frontend now sits on two
networks: without it Traefik may pick the address on SpatiumDDI's own network,
which it cannot reach, and answer `504`/`502`. Set
`FRONTEND_TRUSTED_PROXY_CIDRS` to Traefik's address on the `proxy` network
(`docker network inspect proxy` shows it, or use that network's subnet if
nothing else joins it). Mounting the Docker socket gives Traefik control of
the host; use a socket proxy if that matters to you.

### HAProxy

```
defaults
    mode http
    timeout connect 5s
    timeout client 1h
    timeout server 1h

frontend https_in
    bind :443 ssl crt /etc/haproxy/certs/ddi.example.com.pem
    option forwardfor
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Real-IP %[src]
    default_backend ddi

backend ddi
    server frontend docker-host:8077
```

`timeout client` and `timeout server` must be at least as long as the streams
you want (`1h`); HAProxy's own default is to have none, and it warns at start.
HAProxy does not buffer responses and preserves `Host`. `option forwardfor`
appends a second `X-Forwarded-For` header line rather than editing the
client's; the frontend nginx reads them together, so a value a client sends
is still never believed.

### Nginx Proxy Manager

This one is written from NPM's documentation and has not been run against
SpatiumDDI the way the four examples above were; NPM generates an nginx
`location` like the one under [nginx](#nginx), so the same settings apply.

On the proxy host (Details tab): scheme `http`, forward host `docker-host`,
port `8077`; leave **Websockets Support** off (not needed). SSL tab: pick the
certificate, enable **Force SSL** and **HTTP/2 Support**. NPM sends `Host`,
`X-Forwarded-For`, `X-Forwarded-Proto` and `X-Real-IP` itself. On the
**Advanced** tab paste:

```nginx
proxy_buffering off;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
client_max_body_size 4g;
```

To limit this to the streams instead, add custom locations for
`/api/v1/ai/chat`, `/api/v1/appliance/cluster/health/stream` and
`/api/v1/appliance/containers` with the same forward target, and put the
snippet in each location's gear icon. NPM's own container must be in a
network that can reach the frontend, and its address on that network goes in
`FRONTEND_TRUSTED_PROXY_CIDRS`.

### Kubernetes Ingress

See [Helm and Kubernetes](#helm-and-kubernetes) below and
[`KUBERNETES.md`](KUBERNETES.md#exposing-the-ui).

## Helm and Kubernetes

```yaml
# values.yaml
frontend:
  trustedProxyCidrs: "10.42.0.0/16"   # the ingress controller's pod network
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: ddi.example.com
      paths:
        - { path: /, pathType: Prefix }
  tls:
    - secretName: ddi-tls
      hosts: [ddi.example.com]
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-body-size: "4g"
```

- `frontend.trustedProxyCidrs` sets `FRONTEND_TRUSTED_PROXY_CIDRS` on the
  frontend pods. Use the ingress controller's pod network (`10.42.0.0/16` is
  the k3s default; `kubectl get pods -n ingress-nginx -o wide` shows yours),
  and keep `frontend.service.type=ClusterIP` so only the ingress reaches the
  frontend: NodePort or LoadBalancer traffic can arrive SNAT'd to a node
  address inside that same range, and would then be trusted.
- The api needs nothing: its own default already trusts the frontend pods.
- ingress-nginx forwards `Host`, `X-Forwarded-For`, `X-Forwarded-Proto` and
  `X-Real-IP` itself. Other controllers: check theirs.
- Keep `frontend.tls.enabled=false` behind an Ingress. With it enabled the
  frontend's port 80 answers `301` to https for everyone **except** a request
  a trusted proxy marks `X-Forwarded-Proto: https`; with
  `frontend.trustedProxyCidrs` empty the redirect is unconditional, so a
  TLS-terminating proxy that talks http loops.
- Plain Kubernetes manifests (`k8s/base/`): uncomment the
  `FRONTEND_TRUSTED_PROXY_CIDRS` env in `frontend.yaml`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Redirect loop (`ERR_TOO_MANY_REDIRECTS`) | Helm `frontend.tls.enabled=true` behind a TLS-terminating proxy that talks http to port 80, with no trusted proxy | Set `frontend.trustedProxyCidrs` to the proxy and send `X-Forwarded-Proto: https`, or set `frontend.tls.enabled=false` |
| `400 Invalid host header` on every call | `TRUSTED_HOSTS` is set and the proxy forwards a different `Host` (nginx `proxy_pass` without `proxy_set_header Host`) | Preserve `Host`, or add the name the proxy sends to `TRUSTED_HOSTS`, or unset it. The api log names the refused host |
| SSO `redirect_uri mismatch`; SAML `Destination` error or `saml_requires_https` | External URL is empty, so the callback is built as `http://` from the request | Set **Settings > General > External URL** to the public `https://` URL |
| Signed out on every reload | The refresh cookie is `Secure` but the browser is on an `http://` page, or the proxy is not sending `X-Forwarded-Proto: https` from a trusted address | Serve the public side over https; check `FRONTEND_TRUSTED_PROXY_CIDRS` covers the proxy |
| `429 Too many login attempts` for everyone | Every user arrives from one address: the proxy is not in `FRONTEND_TRUSTED_PROXY_CIDRS`, or (if you narrowed it) the api's `TRUSTED_PROXY_CIDRS` no longer covers the frontend | Set `FRONTEND_TRUSTED_PROXY_CIDRS` to the address the proxy connects from; check Audit Log source IPs show real clients |
| `429` from `/health/*` or `/metrics` | The frontend allows each client 5 requests a second there, with a burst of 20 (#2944). Behind a proxy that is not in `FRONTEND_TRUSTED_PROXY_CIDRS`, every client shares the proxy's one allowance | Set `FRONTEND_TRUSTED_PROXY_CIDRS`; point a fast monitor at the api directly rather than through the frontend |
| AI chat or log view hangs or stays empty | The proxy buffers responses or times out after 60 s | `proxy_buffering off`, read timeout of an hour or more (section 4) |
| Blank page, or 404 on `/assets/...` | Served under a sub-path | Not supported: use a hostname of its own |
| Backup restore or slot-image upload fails with 413 | Proxy body-size limit | Raise it (`client_max_body_size 4g`) |

To see what the api actually receives, send a request through the proxy to
`/api/v1/auth/login` with a wrong password and look at the source IP of the
resulting audit row: it must be your client, not the proxy.
