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
| `TRUSTED_PROXY_CIDRS` | the proxy's address **plus** the network the frontend runs in | Lets the real client IP and scheme through, so the login throttle, audit log, `last_login_ip`, the Web UI allow-list and ACME source checks see the user, not the proxy |
| `TRUSTED_HOSTS` | leave **unset**, or list the exact `Host` the proxy forwards | A proxy that rewrites `Host` to its upstream name gets `400` on every call; the api logs `trusted_hosts_refused_host` |

### `TRUSTED_PROXY_CIDRS`

The same variable configures both the api and the frontend nginx, and it
means "the TCP peers whose forwarded headers are believed":

- The **frontend nginx** believes `X-Forwarded-For` and `X-Forwarded-Proto`
  only from a peer in the list, and walks `X-Forwarded-For` from the right
  past every listed hop, so an address a client invents is never reached.
  **Unset or empty means no proxy is trusted**, which is exactly the
  behaviour of an install with no proxy.
- The **api** believes `X-Real-IP` and `X-Forwarded-Proto` only from a peer in
  the list. It receives them from the frontend nginx, so the list **must also
  cover the frontend's own network**, or every user shares the frontend
  container's address again.
  The api's default is the private ranges, which already covers it.

So set it to the proxy plus the compose / pod network:

```bash
# .env (Docker Compose). Proxy at 192.168.10.5, compose network in 172.16/12:
TRUSTED_PROXY_CIDRS=192.168.10.5/32,172.16.0.0/12
```

If the proxy sits in a private range and you are happy to trust the private
ranges, use the default list from `.env.example`. Only do that when the
frontend port is reachable by nothing but the proxy (firewall it): a client
inside a trusted range that can reach the frontend directly could choose the
address recorded for it. `*` trusts every peer and is only safe when nothing
but the proxy can reach the frontend.

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
    image: traefik:v3
    command:
      - --providers.docker=true
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

  frontend:   # in SpatiumDDI's docker-compose.override.yml, on a network Traefik shares
    labels:
      - traefik.enable=true
      - traefik.http.routers.ddi.rule=Host(`ddi.example.com`)
      - traefik.http.routers.ddi.entrypoints=websecure
      - traefik.http.routers.ddi.tls.certresolver=le
      - traefik.http.services.ddi.loadbalancer.server.port=80
      - traefik.http.services.ddi.loadbalancer.responseforwarding.flushinterval=-1ms
```

`writeTimeout` defaults to unlimited, so the `respondingTimeouts` lines are
there to make that explicit and to keep idle streams open; the load-bearing
part is `flushinterval=-1ms` (flush every write immediately). Traefik passes
`Host` through and sets the `X-Forwarded-*` headers itself. Mounting the
Docker socket gives Traefik control of the host; use a socket proxy if that
matters to you.

### HAProxy

```
frontend https_in
    bind :443 ssl crt /etc/haproxy/certs/ddi.example.com.pem
    mode http
    option forwardfor
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Real-IP %[src]
    default_backend ddi

backend ddi
    mode http
    timeout server 1h
    timeout tunnel 1h
    server frontend docker-host:8077
```

`timeout client` on the frontend should be at least as long as the streams you
want (`1h`). HAProxy does not buffer responses by default and preserves
`Host`.

### Nginx Proxy Manager

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
network that can reach the frontend, and its address (or its Docker network)
goes in `TRUSTED_PROXY_CIDRS`.

### Kubernetes Ingress

See [Helm and Kubernetes](#helm-and-kubernetes) below and
[`KUBERNETES.md`](KUBERNETES.md#exposing-the-ui).

## Helm and Kubernetes

```yaml
# values.yaml
trustedProxyCidrs: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10"
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

- `trustedProxyCidrs` sets `TRUSTED_PROXY_CIDRS` on both the api and the
  frontend pods. Narrow it to your ingress controller's pod network plus the
  network the frontend pods use, if you know them.
- ingress-nginx forwards `Host`, `X-Forwarded-For`, `X-Forwarded-Proto` and
  `X-Real-IP` itself. Other controllers: check theirs.
- Keep `frontend.tls.enabled=false` behind an Ingress. With it enabled the
  frontend's port 80 answers `301` to https for everyone **except** a request
  a trusted proxy marks `X-Forwarded-Proto: https`; with `trustedProxyCidrs`
  empty the redirect is unconditional, so a TLS-terminating proxy that talks
  http loops.
- Plain Kubernetes manifests (`k8s/base/`): uncomment the
  `TRUSTED_PROXY_CIDRS` env in `frontend.yaml` and set the same value on the
  api Deployment.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Redirect loop (`ERR_TOO_MANY_REDIRECTS`) | Helm `frontend.tls.enabled=true` behind a TLS-terminating proxy that talks http to port 80, with no trusted proxy | Set `trustedProxyCidrs` to the proxy and send `X-Forwarded-Proto: https`, or set `frontend.tls.enabled=false` |
| `400 Invalid host header` on every call | `TRUSTED_HOSTS` is set and the proxy forwards a different `Host` (nginx `proxy_pass` without `proxy_set_header Host`) | Preserve `Host`, or add the name the proxy sends to `TRUSTED_HOSTS`, or unset it. The api log names the refused host |
| SSO `redirect_uri mismatch`; SAML `Destination` error or `saml_requires_https` | External URL is empty, so the callback is built as `http://` from the request | Set **Settings > General > External URL** to the public `https://` URL |
| Signed out on every reload | The refresh cookie is `Secure` but the browser is on an `http://` page, or the proxy is not sending `X-Forwarded-Proto: https` from a trusted address | Serve the public side over https; check `TRUSTED_PROXY_CIDRS` covers the proxy |
| `429 Too many login attempts` for everyone | Every user arrives from one address: the proxy is not in `TRUSTED_PROXY_CIDRS` (frontend), or the frontend's network is not (api) | Set `TRUSTED_PROXY_CIDRS` to cover both; check Audit Log source IPs show real clients |
| AI chat or log view hangs or stays empty | The proxy buffers responses or times out after 60 s | `proxy_buffering off`, read timeout of an hour or more (section 4) |
| Blank page, or 404 on `/assets/...` | Served under a sub-path | Not supported: use a hostname of its own |
| Backup restore or slot-image upload fails with 413 | Proxy body-size limit | Raise it (`client_max_body_size 4g`) |

To see what the api actually receives, send a request through the proxy to
`/api/v1/auth/login` with a wrong password and look at the source IP of the
resulting audit row: it must be your client, not the proxy.
