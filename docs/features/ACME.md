---
layout: default
title: ACME (DNS-01 provider)
---

# ACME DNS-01 Provider

SpatiumDDI ships an [acme-dns](https://github.com/joohoi/acme-dns)-compatible HTTP
surface under `/api/v1/acme/` so external ACME clients (certbot, lego,
acme.sh, etc.) can prove control of a FQDN hosted — or delegated to —
a SpatiumDDI-managed zone and issue public certs from Let's Encrypt
(or any other RFC 8555 CA).

**Who this is for**

- You own a public domain, and you want public certs (including
  wildcards) issued against it.
- Your DNS is either hosted directly on SpatiumDDI, or you can add a
  single CNAME in your existing registrar and delegate a small
  subzone to SpatiumDDI.
- You run the ACME client yourself — certbot / lego / acme.sh on
  whatever host needs the cert. SpatiumDDI does not issue certs; it
  answers the DNS challenge for you.

If instead you want SpatiumDDI to issue a CA-trusted cert for **its
own** Web UI, that's the embedded ACME *client* — a separate surface
documented below under
[ACME client (issuing certs for the Web UI)](#acme-client-issuing-certs-for-the-web-ui).
The two don't overlap: the *provider* answers DNS challenges for
external clients; the *client* asks Let's Encrypt for a cert and
solves its own DNS-01 challenge through SpatiumDDI's managed zones.

---

## How it works

DNS-01 is the only ACME challenge type that supports wildcards. The
client asks the CA for a cert, the CA says "prove you control this
domain by putting a specific TXT record at
`_acme-challenge.<domain>`", the client writes the record, the CA
polls DNS, if the record is there the cert is issued.

SpatiumDDI's role is only the "write the TXT record" half. The
acme-dns protocol shape decouples cert-issuing from DNS authority:

1. An operator registers an **ACME account** on SpatiumDDI. The
   account is bound to a specific DNS zone and gets a unique random
   subdomain label plus a username + password shown **once**.
2. The operator adds a CNAME in their *upstream* DNS provider:
   `_acme-challenge.<their-fqdn>` → `<subdomain>.<spatium-zone>`.
3. When the ACME client wants a cert, it hits SpatiumDDI's
   `/api/v1/acme/update` endpoint (authenticated with the
   credentials issued in step 1) and sets the TXT. SpatiumDDI writes
   the record through the normal DNS op pipeline and waits until the
   primary DNS server acknowledges it, so the CA's subsequent poll
   finds the record live.
4. The CA validates, issues the cert, the client cleans up by
   calling `DELETE /api/v1/acme/update`.

Security property: a leaked ACME credential can write TXT records
only at its one subdomain — it cannot rewrite the rest of the zone
or any other customer's data.

---

## Prerequisites

### 1. A SpatiumDDI-managed DNS zone to hold the TXT records

Create it like any other zone (DNS → Zones → **+ New Zone**). The
zone's FQDN is your choice; a common pattern is
`acme.<your-apex>.` (e.g. `acme.example.com.`). You'll delegate
**this subzone** to SpatiumDDI from your upstream registrar — the
rest of your zone can stay wherever it already lives.

The zone must have at least one **primary** DNS server attached
(server's `is_primary=True` flag). Record ops fan out from the
primary; without one, the server responds with 503 because it has
nowhere to write.

### 2. Delegation from your upstream registrar

If `example.com` lives on Route 53 (or Cloudflare, or whatever) and
you've created `acme.example.com.` on SpatiumDDI, add two records in
your upstream zone:

- `NS acme.example.com → ns1.spatium.yourdomain.com.`
- `NS acme.example.com → ns2.spatium.yourdomain.com.`

(Use however many NS records you have SpatiumDDI name servers.)

That's it — the delegation means upstream resolvers that look up
`<anything>.acme.example.com` will be pointed to SpatiumDDI.

### 3. A role with `acme_account` permission

Creating / listing / revoking ACME accounts is gated by the standard
RBAC. Superadmin bypasses. For a delegated admin, give a custom role
`admin` on `acme_account`:

```json
{
  "action": "admin",
  "resource_type": "acme_account"
}
```

The ACME **client** auth (username / password) is a separate
protocol and doesn't use SpatiumDDI roles at all.

---

## Worked example: certbot + ACME DNS-01 for `*.foo.example.com`

### Step 1 — Register an ACME account on SpatiumDDI

```bash
curl -X POST https://spatium.example.com/api/v1/acme/register \
  -H "Authorization: Bearer $SPATIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "zone_id": "9f9b3c1e-0000-0000-0000-000000000000",
    "description": "certbot on foo.example.com",
    "allowed_source_cidrs": ["203.0.113.0/24"]
  }'
```

Response:

```json
{
  "username": "a1b2c3d4e5f6a7b8c9d0e1f2g3h4i5j6k7l8m9n0",
  "password": "o1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d6e7f8g9h0",
  "subdomain": "6c48a6ed-8fa3-4f1d-b9ad-12f15a3e8c77",
  "fulldomain": "6c48a6ed-8fa3-4f1d-b9ad-12f15a3e8c77.acme.example.com",
  "allowfrom": ["203.0.113.0/24"]
}
```

**The `username` and `password` are shown exactly once.** Record
them now — SpatiumDDI stores only a bcrypt hash. If you lose them
you'll have to revoke the account and register a fresh one.

### Step 2 — Add the CNAME in your upstream registrar

In your public DNS zone for `foo.example.com` (upstream — the
registrar that *isn't* SpatiumDDI), create:

```
_acme-challenge.foo.example.com.   CNAME   6c48a6ed-8fa3-4f1d-b9ad-12f15a3e8c77.acme.example.com.
```

**Wildcard certs:** `_acme-challenge.example.com` (no leading
subdomain) covers both `example.com` and `*.example.com`. LE will
request two different validation tokens during wildcard issuance;
SpatiumDDI stores the two most-recent values at the label, so LE's
double-poll finds both simultaneously.

### Step 3 — Wire the credentials into your ACME client

**certbot** (via `certbot-dns-acmedns`):

```bash
pip install certbot certbot-dns-acmedns

# Creds file — one per account, 0600 perms
cat > /etc/letsencrypt/acmedns.json <<EOF
{
  "foo.example.com": {
    "username": "a1b2c3d4...",
    "password": "o1p2q3r4...",
    "fulldomain": "6c48a6ed-....acme.example.com",
    "subdomain": "6c48a6ed-...",
    "allowfrom": ["203.0.113.0/24"]
  }
}
EOF
chmod 600 /etc/letsencrypt/acmedns.json
```

Issue the cert:

```bash
certbot certonly \
  --authenticator dns-acmedns \
  --dns-acmedns-credentials /etc/letsencrypt/acmedns.json \
  --dns-acmedns-api-url https://spatium.example.com/api/v1/acme \
  -d foo.example.com -d '*.foo.example.com'
```

**lego** (supports acme-dns out of the box):

```bash
export ACME_DNS_API_BASE=https://spatium.example.com/api/v1/acme
export ACME_DNS_STORAGE_PATH=./acme-dns-accounts.json

lego --email you@example.com --dns acme-dns \
  -d foo.example.com -d '*.foo.example.com' run
```

Lego will prompt for the creds on first run and cache them in the
storage path for next time.

**acme.sh** (also native):

```bash
export ACMEDNS_BASE_URL="https://spatium.example.com/api/v1/acme"
export ACMEDNS_USERNAME="a1b2c3d4..."
export ACMEDNS_PASSWORD="o1p2q3r4..."
export ACMEDNS_SUBDOMAIN="6c48a6ed-..."

acme.sh --issue --dns dns_acmedns -d foo.example.com -d '*.foo.example.com'
```

### Step 4 — Auto-renewal

All three clients keep state across runs, so standard cron / systemd
timer setups (`certbot renew`, `lego renew`, `acme.sh --cron`) just
work. Renewals re-hit `/api/v1/acme/update` with fresh tokens; the
CNAME from step 2 stays in place forever.

---

## Protocol reference

All endpoints live under `/api/v1/acme/`.

### `POST /register`

**Auth:** SpatiumDDI JWT or API token; caller needs `write` on
`acme_account`.

**Request:**

```json
{
  "zone_id": "<uuid>",
  "description": "foo.example.com cert",
  "allowed_source_cidrs": ["203.0.113.0/24"]
}
```

**Response (201):**

```json
{
  "username": "<40-char>",
  "password": "<40-char, shown once>",
  "subdomain": "<uuid>",
  "fulldomain": "<subdomain>.<zone-fqdn>",
  "allowfrom": ["203.0.113.0/24"]
}
```

### `POST /update`

**Auth:** `X-Api-User` + `X-Api-Key` headers with the account's
username and password. No JWT.

**Request:**

```json
{
  "subdomain": "<subdomain>",
  "txt": "<43-char base64url validation token from the CA>"
}
```

**Response (200):**

```json
{"txt": "<same value echoed back>"}
```

**Blocking behaviour:** the endpoint blocks until the TXT write is
acknowledged by the zone's primary DNS server. On healthy systems
this typically resolves in 1-5 s. The timeout is 30 s, or longer on a
server whose renders are slow: an agent receives the record with its
next render, which takes about 30 s at a million records, so the wait
is two of that server's slowest recent renders plus 10 s, capped at
55 s so it ends before the web frontend's 60 s proxy timeout (#1184).
If the agent is unreachable or the wait runs out, the endpoint
returns 504; LE / ACME clients retry automatically.

**Wildcard certs:** at most the two most recent values are kept at
the same subdomain. A third `/update` evicts the oldest. This
matches canonical acme-dns behaviour and is the reason the DNS-01
wildcard flow works at all (the `_acme-challenge.example.com` label
holds both validation tokens during a wildcard+base request).

**Idempotent retries:** posting the exact same `(subdomain, txt)`
pair a second time is a no-op and returns 200 immediately.

### `DELETE /update`

**Auth:** same as `POST /update`.

Clears every TXT record at the account's subdomain. Well-behaved
clients call this after validation. Records that aren't cleaned up
get swept automatically after 24 h by a Celery janitor.

### `GET /accounts`

**Auth:** `read` on `acme_account`.

Lists every ACME account, no credentials. Each row includes
`last_used_at` so operators can tell dead accounts from live ones.

### `DELETE /accounts/{id}`

**Auth:** `delete` on `acme_account`.

Hard-deletes the account and removes any TXT records it owns. Any
in-flight `/update` call using those credentials returns 401 on its
next attempt.

---

## Security and operational notes

- **Credential shape.** Username + password are each 40 chars of
  URL-safe random entropy (~240 bits each). Password is bcrypt-hashed
  at rest. The username is stored in plaintext since it's the
  lookup key.
- **Source IP allowlist.** `allowed_source_cidrs` is checked on every
  `/update` call against the HTTP client address. If you're behind a
  reverse proxy you'll want X-Forwarded-For trust configured on the
  proxy AND a known-good SpatiumDDI trusted-proxy list — without
  that, `allowed_source_cidrs` sees the proxy IP, not the real
  client. For unambiguous source gating, terminate TLS on SpatiumDDI
  directly or use network-level ACLs.
- **Rate limiting.** The v1 release does not ship a rate limiter
  specifically for `/api/v1/acme/`. Operators running the surface
  publicly should front it with a WAF or proxy-level rate limit.
  The `wait_for_op_applied` loop caps at 55 s so even an aggressive
  attacker can't tie up more than a fixed number of connections per
  second.
- **Audit log.** Every register / update / delete writes an
  `audit_log` entry. The TXT value is NEVER logged in full — only a
  12-char prefix for correlation. Credentials are never logged,
  hashed or otherwise.
- **Stale record sweep.** A Celery beat task clears any ACME-owned
  TXT records older than 24 h. Registered accounts are never
  auto-revoked — operators manage those manually.
- **Wildcard certs and delegation together.** The tiny subzone
  delegation means an attacker who steals one ACME credential from
  customer A cannot issue certs for customer B's names, even if both
  point at the same SpatiumDDI instance.

---

## Troubleshooting

- **Client says "DNS record not found" even though you just
  `/update`d.** The endpoint blocks until the *primary* ack returns,
  but your client might be polling a secondary/caching resolver that
  hasn't transferred yet. Check the zone's primary ↔ secondary sync
  (DNS → Zone → *Server state*). If primary shows applied but
  secondary doesn't, the delegation NS records in your upstream zone
  may not include both SpatiumDDI servers.
- **504 on `/update`.** Primary DNS server is unreachable from the
  control plane or the agent isn't heartbeating. Check
  *DNS → Servers → Status*.
- **401 on `/update` with known-good credentials.** Either the
  subdomain in the request body doesn't match the authenticated
  account (common copy-paste error), the source IP isn't in
  `allowed_source_cidrs`, or the account was revoked.
- **CA validation still fails after `/update` returns 200.** The TXT
  is live on SpatiumDDI's primary — check the CNAME chain from
  `_acme-challenge.<your-fqdn>` outward with `dig +trace` and verify
  the delegation NS records in your upstream zone point to
  SpatiumDDI.

---

## ACME client (issuing certs for the Web UI)

> **Issue [#438](https://github.com/spatiumnorth/spatiumddi/issues/438)
> — landed on `issue-438`.** Distinct from the ACME *provider*
> documented above. The provider answers DNS-01 challenges for
> *external* ACME clients (certbot / lego / acme.sh). The client
> documented here is SpatiumDDI itself acting as an ACME client
> against a public CA (Let's Encrypt) to issue a **CA-trusted TLS
> cert for the appliance Web UI** — solving its own challenge through
> SpatiumDDI's own managed DNS zones (or, for HTTP-01, through the
> appliance's own web server). Phases 1–5 are implemented; Phase 6
> (per-appliance certs) is resolved as not-applicable. The
> phase-by-phase detail is in the sections below.

The embedded client closes the loop the provider couldn't: an
appliance that hosts its own public DNS zone no longer needs an
external client at all. It asks Let's Encrypt for a cert, proves
control of the name by writing a `_acme-challenge` TXT into the
matching managed zone, and lands the issued chain in the same
`ApplianceCertificate` storage + deploy path the self-signed and
operator-uploaded certs use — with `source="letsencrypt"`. The
`SourceBadge` in the Web UI renders the new source.

This is a **fleet-level** cert (the control plane's Web UI), not a
per-appliance cert — see *Phase 6* below.

### Feature module

The whole surface lives behind the **`security.certificates`**
feature module (group **Security**, label *Certificates (ACME /
Let's Encrypt)*). It's **default-enabled** as a discovery toggle so
operators see the "Issue via Let's Encrypt" affordance exists — but
enabling the module does **not** auto-issue anything. Issuance is
separately RBAC-gated (`admin` on `appliance`) and requires the
operator's explicit `platform_settings.acme_enabled` intent. When
the module is off, every `/api/v1/appliance/acme` endpoint 404s.

### DNS-01 self-solve flow (the default path)

DNS-01 over SpatiumDDI's own managed zones is the default
`challenge_type` and the original Phase 1 flow. HTTP-01 and
cloud-hosted DNS-01 layer on top of it (Phases 3–4 below).

1. The operator configures the install's **ACME account** (`PUT
   /account`). A fresh EC-P256 account key is generated locally and
   Fernet-encrypted at rest; it is **never** returned by the API.
   The CA-side `account_url` is filled lazily on the first order.
   External Account Binding (`eab_kid` + `eab_hmac_b64`) is accepted
   for CAs that require it (ZeroSSL, some private CAs) — both NULL for
   Let's Encrypt; the HMAC is write-only and exposed only as an
   `eab_hmac_set` boolean.
2. The operator requests a cert (`POST /issue`) with one or more
   domains. This creates a `pending` `ACMEOrder` and enqueues the
   Celery task `app.tasks.acme.run_acme_order`, which drives the rest
   off the request thread. Poll `GET /orders/{id}` for progress.
3. The orchestrator
   (`backend/app/services/acme_client/orchestrator.py`) ensures the
   account exists at the CA, creates the order, and fetches its
   authorizations.
4. For each authorization it solves the `dns-01` challenge
   (`backend/app/services/acme_client/dns01.py`): the challenge FQDN
   is resolved to the **most specific managed primary zone** that is a
   suffix of the name (longest-suffix match), a
   `_acme-challenge.<domain>` TXT record is written through the exact
   same `record_ops` pipeline the rest of DNS uses
   (`enqueue_record_op` + `bump_zone_serial` + `wait_for_op_applied`),
   and the solve **blocks until the DNS agent acknowledges the op as
   applied** — so the record is live before the CA validates. The wait
   scales with the group's render time (#1184): one render per server in
   the group, plus the one that may already be running, from the slowest
   render the servers have stored, plus 10 s. It is at least 30 s and at
   most 5 minutes. A
   best-effort dnspython lookup runs afterward but never gates
   success. If no managed primary zone covers the FQDN, the order
   fails with a clear `last_error`.
5. The orchestrator tells the CA each challenge is ready, polls every
   authorization to `valid`, generates a fresh EC-P256 cert key + CSR
   (reusing `generate_csr_and_key` from
   `services/appliance/tls.py`), finalizes the order, polls to
   `valid`, and downloads the full PEM chain.
6. The chain lands in an `ApplianceCertificate` row
   (`source="letsencrypt"`, identity columns from
   `parse_pem_certificate`, cert key Fernet-encrypted), is made the
   sole active cert, and is deployed to nginx via
   `deploy_and_reload`. **Deploy failure is logged, not raised** — the
   DB is the source of truth and the api boot re-deploys the active
   row.
7. The challenge TXT records are **always** torn down in a `finally`
   block (each cleanup on a fresh session), so a failed issuance
   doesn't leave zone noise behind.

On success the order is `valid` with `certificate_id` pointing at the
new row. On any protocol / DNS failure the order is `invalid` with a
populated `last_error`; the task records the failure rather than
crash-looping. The whole flow is idempotent + re-runnable — a re-run
for the same order updates the existing cert row in place.

The CA directory defaults to Let's Encrypt **staging**
(`https://acme-staging-v02.api.letsencrypt.org/directory`) — which
issues untrusted certs but has far higher rate limits — until an
operator explicitly points the account at production
(`https://acme-v02.api.letsencrypt.org/directory`). `directory_url`
must be an `https://` URL; `http://` / unschemed values are rejected.

### Endpoints

All under `/api/v1/appliance/acme` (full path; mounted inside the
appliance router behind `require_module("security.certificates")`).
Mutations require `admin` on `appliance`; reads accept `read` on
`appliance`. Secret material — the account key and the EAB HMAC — is
**never** returned; the account responses expose only an
`eab_hmac_set` boolean. Every mutation is audited.

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/account` | read | Account metadata, or `null` if none configured (not 404). |
| `PUT` | `/account` | admin | Upsert the install's ACME account. `directory_url` https-validated; `eab_hmac_b64` write-only (omit to leave unchanged). |
| `DELETE` | `/account` | admin | 204. Orders cascade (`ON DELETE CASCADE`). |
| `POST` | `/preview` | read | Body `domains[]`. Returns one `ACMEDomainResolution` per domain — whether the name is auto-solvable, and how (`managed` boolean + `zone_name` / `record_name` / `driver`). No mutation; safe to call before `/issue`. |
| `POST` | `/issue` | admin | Body `domains[]` + `challenge_type` (`dns-01` default, or `http-01`; `tls-alpn-01` → 422) + optional `dns_provider` + `allow_manual`. Creates a `pending` order + enqueues the task. 201. Requires an account to exist first. |
| `GET` | `/orders` | read | All orders, newest first. |
| `GET` | `/orders/{id}` | read | One order — poll while `status` ∈ {`pending`, `processing`}. `manual_challenges[]` carries the TXT pairs to add when `allow_manual` left a domain unsolvable automatically. |
| `POST` | `/orders/{id}/cancel` | admin | Local bookkeeping cancel (marks `invalid`); RFC 8555 has no client-driven order recall. Only `pending` / `processing` orders. |

One more route lives **outside** `/api/v1` and outside the auth
chain: `GET /.well-known/acme-challenge/{token}` returns the HTTP-01
key-authorization as `text/plain`. It is CA-facing only — the
frontend nginx proxies it to the api so Let's Encrypt can reach it on
port 80/443. There is no UI for it; see *Phase 4* below.

### Operator Copilot tools

Matching MCP tools surface cert state to the copilot:
`find_certificates` (read, default enabled, no key material),
`count_certificates_expiring` (read, default enabled), and
`get_acme_account` (default **disabled**, exposes `eab_hmac_set`
boolean only — never key/HMAC material). `propose_*` issuance writes
are deferred.

### Phase 2 — auto-renewal

Once a cert is issued, SpatiumDDI keeps it fresh on its own. A Celery
beat task — `app.tasks.acme.renew_due_certificates` — runs every
**12 hours** and re-issues any active Let's Encrypt cert that falls
within **30 days of its `valid_to`**. The re-issue reuses the exact
`POST /issue` machinery (same orchestrator, same self-solve), so a
renewal is just a normal order against the stored account.

The task is **gated on two flags** — it does nothing unless both
`platform_settings.acme_enabled` and
`platform_settings.acme_auto_renew` are on. `acme_enabled` is set
automatically the first time you save an ACME account; `acme_auto_renew`
is the operator's "keep it renewed" intent and is the knob to flip if
you'd rather renew by hand.

It is **idempotent and advisory-locked**: the task takes a Postgres
advisory lock so two overlapping beat ticks can't both drive the same
renewal, and a cert already comfortably inside its validity window is
skipped. A renewal failure is recorded on the order's `last_error`
and retried on the next 12 h tick — it never crash-loops.

The shipped **`secret_expiring`** alert rule now also watches the
Let's Encrypt Web-UI cert (subject `appliance_cert_tls:<id>`), so even
if auto-renew is off — or a renewal keeps failing — the alerts surface
fires before the cert lapses.

### Phase 3 — cloud-hosted DNS-01 + manual TXT fallback

Phase 1 only self-solved against zones SpatiumDDI hosts directly.
Phase 3 widens DNS-01 to names whose zones live on a **cloud DNS
provider** SpatiumDDI already drives as an agentless driver —
**Cloudflare, Route 53, Azure DNS, and Google Cloud DNS**. When the
challenge FQDN maps to such a zone, the orchestrator writes the
`_acme-challenge` TXT straight through that driver and tears it down
afterward, exactly as it does for a managed zone.

There is **no extra configuration on the ACME screen** for this — you
configure the provider's credentials once under **DNS** (the same
cloud-DNS driver config the rest of DNS uses), and the ACME client
reuses it. The `dns_provider` field on `POST /issue` just lets you pin
a specific provider when a name is ambiguous.

**Preview first.** `POST /preview` takes the same `domains[]` and
returns, per domain, whether it is auto-solvable and how — `managed`
(true if a managed *or* cloud-driver zone covers it), the `zone_name`,
the `record_name` that will hold the TXT, and the `driver`. The Web UI
calls this in the Issue modal so the operator sees green "auto" rows
vs. amber "manual" rows before committing.

**Manual TXT fallback.** For a domain that *no* driver can solve —
e.g. a name whose authoritative DNS is somewhere SpatiumDDI has no
credentials — set **`allow_manual: true`** on `POST /issue`. Instead
of failing, the order goes to `processing` and exposes the work to do
in **`manual_challenges[]`**: each entry is the `fqdn` /
`record_name` / `txt_value` pair you must publish in your own DNS. The
orchestrator then **polls public DNS** for those TXT values and
finalizes the order automatically once they're visible to resolvers —
no second click required. Domains that *can* be solved automatically
in the same order are still solved automatically; `allow_manual` only
changes the fallback for the ones that can't.

### Phase 4 — HTTP-01

`challenge_type: "http-01"` solves the challenge over HTTP instead of
DNS. The CA fetches
`http://<fqdn>/.well-known/acme-challenge/<token>`; SpatiumDDI answers
it from the unauthenticated root route described under *Endpoints*
above, with the frontend nginx proxying that path through to the api.

HTTP-01 is the right choice when you **don't** host the name's DNS in
SpatiumDDI (or any cloud driver) but the appliance *is* the host the
name points at. The trade-offs vs. DNS-01:

- The appliance must be **reachable from the public internet on
  port 80/443 at the exact cert FQDN** — the CA connects inbound to
  validate. Behind NAT or a firewall that blocks :80, use DNS-01.
- HTTP-01 **cannot issue wildcards** — that's an RFC 8555 limitation,
  not ours. Wildcards still require DNS-01.

### Phase 5 — TLS-ALPN-01 (not supported)

`tls-alpn-01` is **not supported** on the appliance topology, and
`POST /issue` returns **422** if you request it. The Web UI shows the
option disabled with this reason.

TLS-ALPN-01 requires the validating server to terminate the TLS
handshake itself and present a special self-signed cert in the
`acme-tls/1` ALPN protocol on port 443. On the SpatiumDDI appliance,
443 is owned by nginx (and, in the HA topology, fronted by a MetalLB
VIP) — there's no seam to hand a single connection's ALPN negotiation
to the ACME client mid-handshake without a custom nginx/Lua build we
don't ship. DNS-01 and HTTP-01 cover every case TLS-ALPN-01 would,
so it stays unsupported by design rather than as a missing feature.

### Phase 6 — per-appliance certs (resolved: not applicable)

Phase 1 left "a distinct cert per appliance host" as an open seam.
On reflection it's **not applicable** to how SpatiumDDI serves its
Web UI: the UI is served **only by the control plane**, behind a
single shared cert (the MetalLB VIP / hostname in the HA topology, or
the single control-plane host otherwise). DNS/DHCP-role appliances run
no operator-facing Web UI of their own — they're agents. So there is
exactly one **fleet-singleton** Web-UI cert to manage, not one per
box, and the embedded ACME client correctly issues and renews that
one cert. No per-appliance code is needed or planned.

---

## Roadmap (deferred from the MVP)

- Dedicated rate-limit bucket with fail2ban-style temp-ban on
  repeated `/update` auth failures.
- Per-op `asyncio.Event` signaling to replace the DB-polling wait
  (shaves ~250 ms off the typical `/update` latency).
- Janitor metrics exposed on the admin dashboard (sweep count,
  oldest-record-age).
- Pass-through of `allowfrom` enforcement to the CNAME-delegation
  side so upstream resolvers can prune queries they're not
  delegated.
