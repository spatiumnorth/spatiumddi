# REST API

> **Implementation status (shipped):** Every UI action is backed by a
> REST endpoint under the `/api/v1` prefix (non-negotiable #1). The
> surface is a FastAPI app with bearer-token auth (session JWTs +
> `sddi_*` API tokens with coarse scopes and per-resource grants),
> server-side RBAC enforcement, feature-module gating that returns
> `404` for disabled modules, and an MCP (Model Context Protocol)
> JSON-RPC endpoint for the Operator Copilot. Interactive Swagger /
> ReDoc are served from the running API. List endpoints come in two
> shapes — a bare JSON array (the core IPAM/DNS/DHCP routers) and an
> `{items, total, limit, offset}` envelope (the network-modeling
> routers); both are documented below.

This document covers the cross-cutting API conventions. For
authentication providers (LDAP / OIDC / SAML / RADIUS / TACACS+), MFA,
sessions and the token model in depth see
[`features/AUTH.md`](features/AUTH.md); for the permission grammar and
built-in roles see [`PERMISSIONS.md`](PERMISSIONS.md).

---

## 1. Base URL & Versioning

All application endpoints are mounted under a single version prefix:

```
/api/v1
```

The version router family is assembled in
[`backend/app/api/v1/router.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/api/v1/router.py) and
mounted by [`backend/app/main.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/main.py):

```python
app.include_router(api_v1_router, prefix="/api/v1")
```

A handful of routes live **outside** `/api/v1` because they are
infrastructure rather than application surface:

| Path | Purpose | Auth |
|---|---|---|
| `/health/live` | Liveness probe — 200 if the process is up | none |
| `/health/ready` | Readiness probe — DB connectivity + **schema-at-head** + Redis | none |
| `/health/startup` | Same logic as `/health/ready`, for slow-start k8s containers | none |
| `/health/platform` | Per-component rollup (db / redis / celery workers / beat) for the dashboard | none |
| `/.well-known/acme-challenge/{token}` | HTTP-01 ACME challenge (issue #438) | none |
| `/metrics` | Prometheus exposition (when `PROMETHEUS_METRICS_ENABLED`) | none |

`/api/v1` is the only API version. When the surface changes shape in a
non-additive way a `/api/v2` prefix would be introduced alongside it;
today there is exactly one version. New routers are inserted into
`router.py` in **alphabetical order** so the generated docs list
sections A → Z.

---

## 2. Interactive Documentation

The FastAPI app serves the standard interactive docs and the raw
OpenAPI schema (configured in `create_app()` in
[`backend/app/main.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/main.py)
and [`backend/app/api/docs.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/api/docs.py)):

| Route | What it serves |
|---|---|
| `/api/docs` | Swagger UI |
| `/api/redoc` | ReDoc |
| `/api/openapi.json` | The OpenAPI 3.x schema document |

Note the `/api/` prefix on the docs routes — they are **not** under
`/api/v1`. The api serves the Swagger UI and ReDoc bundles itself, from
`/api/docs/static/`, not from a CDN. So both pages work through the web
port, under the console's Content-Security-Policy, and on an air-gapped
install. The schema is auto-generated from the Pydantic request /
response models on every route, so it always reflects the running
build. Each router carries a `tags=[...]` label (alphabetised in
`router.py`) so the Swagger / ReDoc sidebar groups endpoints by
feature area.

### 2.1 The versioned contract (`openapi.json` release asset)

`/api/openapi.json` always describes the **running** build, which is the
right answer for a browser and the wrong one for a client generated ahead
of time. Since #903 the same document is attached to every CalVer release
as `openapi.json`, so an out-of-repo client — the native app in
[`spatiumnorth/spatiumddi-mobile`](https://github.com/spatiumnorth/spatiumddi-mobile)
— can codegen against an exact server version rather than against whatever
`main` happens to be:

```
https://github.com/spatiumnorth/spatiumddi/releases/download/<tag>/openapi.json
```

Reproduce the identical file locally at any tag:

```bash
make openapi VERSION=2026.08.22-1     # writes ./openapi.json
```

Both go through [`scripts/export_openapi.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/scripts/export_openapi.py),
which is the only supported way to generate it. Three things that script
guarantees and a hand-rolled dump would not:

- **It calls `app.openapi()`, never `fastapi.openapi.utils.get_openapi`.**
  `create_app()` replaces `app.openapi` with a wrapper that widens
  `HTTPValidationError.detail` to admit the string form ~270 handlers
  actually return (see §8). Re-deriving the document loses that silently,
  and a generated client then rejects a large share of this server's real
  4xx bodies as schema violations.
- **`info.version` is the release tag.** It was hardcoded `0.1.0` until
  #903 — every release would have shipped a spec claiming to be 0.1.0,
  which defeats pinning entirely. A running server now reports the same
  value in its own `/api/openapi.json`.
- **`info.title` is pinned to `SpatiumDDI`.** The served title follows
  `app_title`, which operators can rebrand, so exporting from a branded
  install would otherwise publish that install's name as the name of the
  public API.

**Version handshake.** A client knows which spec it was built against, and
`GET /api/v1/version` (unauthenticated — see §7.2) reports what the server
is running. Gating a feature is then a version comparison rather than
probing for an endpoint and interpreting the 404.

The document declares no `servers` block. That is deliberate: there is no
canonical host, so per OpenAPI 3.1 it means "relative to wherever this is
served" and the client supplies the operator's base URL.

The asset is retained on **every** release, including ones past the
heavy-asset keep window — pinning to an *older* server is exactly what it
is for. `scripts/prune-release-assets.sh` achieves that through its
"unknown / future asset — leave untouched" default branch, so **do not add
a pattern for `openapi.json` to the pruner**.

### 2.2 Two shapes the document commits to for code generators

A generated client fails *quietly*: it compiles, passes review, and is
missing whatever the generator could not model. Both rules below exist
because a client generated from this document was silently wrong (#907),
and both apply to the served document and the release asset alike — a
client built against a running server and one built against a pinned tag
must not disagree.

**Nullable is expressed by absence from `required`, not by a `null`
union.** OpenAPI 3.1 spells an optional value as a union with the JSON
Schema `null` type, and FastAPI emits exactly that. Strict generators
that cannot model the `null` arm skip the member — and skipping a member
drops **the whole property** from the generated type, with a warning
rather than an error. So `app.openapi()` rewrites every such union to the
plain schema and takes the property out of `required`:

What FastAPI emits:

```json
{ "anyOf": [ { "type": "string" }, { "type": "null" } ], "title": "Feed Url" }
```

What the document publishes — and `feed_url` is no longer listed in the
schema's `required`:

```json
{ "type": "string", "title": "Feed Url" }
```

A union with more than one non-`null` arm stays a union, minus the
`null`; a nullable `$ref` collapses to a bare `$ref` (keeping any
`description`, dropping the generated title).

**Request bodies keep their `required` list.** On the way out `required`
describes what the server sends; on the way in it is what the server
*enforces*, and a field the model declares `X | None` with no default is
a key pydantic demands. So a schema reachable from a `requestBody` is
collapsed but never has a property taken out of `required` — a client
that believed otherwise and omitted the key would get a 422 back. A
schema used in both directions (the preview → commit payloads) is
resolved the same way, so a model in that position should carry a
default rather than rely on the document to paper over it.

Note what this trades: the server still **sends** `"feed_url": null`
rather than omitting the key, so a strict response validator sees an
explicit null against a schema that no longer admits one. That is
deliberate — the alternative (dropping nulls from responses) changes the
wire for every existing client, and a validator complaint is loud where
the generated-code failure is silent. Decoding loses nothing: an absent
key and an explicit null both land as `nil` / `undefined`.

**Timestamps are RFC 3339 with exactly three fractional digits.**

```
2026-05-14T21:59:10.586Z
2026-05-14T21:59:10.000Z     ← a whole second still carries .000
```

Python's `isoformat()` emits six fractional digits, and none at all when
the value lands on a whole second. Both are legal RFC 3339 and neither is
what most generated decoders accept — Foundation's
`ISO8601DateFormatter` rejects fractional seconds unless configured for
them, and then rejects the values that have none. A fixed shape removes a
hand-written workaround from every client. `format: date-time` on the
property is unchanged, so a generator still emits a date decoder rather
than a string; only the precision is pinned. See
[`backend/app/core/json_datetime.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/core/json_datetime.py).

The rule covers every `datetime`-typed field the API returns. It does
**not** reach a timestamp parked inside an untyped payload — an `Any` /
`dict[str, Any]` field such as an evidence trail or an agent telemetry
blob, or one a handler formatted into a string itself. Those publish as
untyped JSON or bare strings, so no generated decoder points at them and
nothing fails to decode; the fix for one of them is to declare the field
as a `datetime` and let it serialise normally.

---

### 2.3 Every route declares a response schema

A route with no `response_model` publishes an unconstrained object, so a
generated client gets a dictionary where it should get a model: every field
access is stringly-typed and every rename is a silent break. That is the same
failure §2.2 describes for nullable properties, arriving through a different
door — and it is not fixed by annotating the handler `-> dict[str, Any]`,
because FastAPI infers a response model from the return annotation and the
inferred one is still `{"type": "object"}` with no properties.

**91 routes were in that state when issue #917 catalogued it.** Retyping all of
them at once was not the point; stopping the set from growing was, so
`scripts/lint_untyped_routes.py` guards it the way `scripts/lint_migrations.py`
guards destructive migrations:

```bash
make lint-untyped-routes            # the check CI runs
make lint-untyped-routes-baseline   # re-record after typing some
```

The baseline lives at `backend/untyped_routes_baseline.txt` and **may shrink,
never grow**. A new entry means a route shipped without a schema — declare a
`response_model` instead of baselining it.

Detection runs against the generated OpenAPI document rather than the route
attributes, because that is what a client actually consumes. Routes whose
handler returns a `Response` subclass (file downloads, SSE streams) are
excluded from *that* check: they have no JSON body to describe. They have
their own obligation instead — see §2.3.1.

#### 2.3.1 A non-JSON response must declare its media type

FastAPI documents a bare `-> Response` as `application/json`. A route that
then streams a zip, a PDF, a pcap or an SSE stream is publishing a success
response it does not produce, so a generated client cannot decode the 200 and
a strict validator rejects it — schemathesis reports *"Undocumented
Content-Type — Received: application/zip, Documented: application/json"*.

Set `response_class` to one of the typed helpers in `app/core/responses.py`:

```python
from app.core.responses import ZipResponse

@router.post("", response_class=ZipResponse, responses={200: {"description": "The archive"}})
async def download_support_bundle(...) -> Response:
    return Response(content=blob, media_type="application/zip")
```

**`response_class`, not `responses={200: {"content": ...}}`.** The latter —
the shape #861 first used — *merges* with the inferred `application/json`
rather than replacing it, so the route ends up declaring both. That silences
the conformance failure while still telling a generator the endpoint might
return JSON, which it never does. It also has to be a subclass that declares
`media_type`: a bare `Response` or `StreamingResponse` leaves it `None` and
FastAPI then documents *no* content at all.

`backend/tests/test_response_media_types.py` compares each handler's own
`media_type=` against the generated document and fails a route that serves
something it did not declare **or** that declares `application/json`
alongside a non-JSON body. Fourteen routes were in the first state when #921
was filed — three `export.pdf` routes had been fixed one at a time in #861,
and the sweep found eleven more; all seventeen now use `response_class`.

### 2.4 Copilot tools and REST routes are two views of one capability

Non-negotiable #13 requires every new REST surface to get matching MCP tools.
**The converse is equally required**, and was not enforced until #917: a
capability reachable only from the Operator Copilot is invisible to every
external client, because the copilot tools are written against the service
layer rather than against HTTP.

Five issues from the mobile client turned out to be instances of this
(#903, #906, #907, #913, #914), and a sweep of every registered tool against
the route table found four more: **fleet-wide lease search**, **IPAM hygiene
findings**, the **vendor rollup**, and the **customer decommission summary**.
(Pool occupancy was the same shape and shipped earlier as #913.)

When adding a tool that computes something, add the route too, and have both
call one shared service function so they cannot answer the same question
differently.

## 3. Authentication

The API authenticates via the HTTP **`Authorization: Bearer <token>`**
header. Two credential kinds are accepted on the same header, resolved
in [`backend/app/api/deps.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/api/deps.py)
(`get_current_user`):

1. **Session JWT** — a short-lived access token issued by
   `POST /api/v1/auth/login`.
2. **API token** — a long-lived `sddi_*` token issued by
   `POST /api/v1/api-tokens`, for scripts and machine clients.

Tokens that start with the `sddi_` prefix are routed straight to the
API-token validator; everything else is JWT-decoded. A missing or
invalid credential returns `401`; an authenticated-but-disabled user
returns `403`.

### 3.1 Login

`POST /api/v1/auth/login`

```json
{ "username": "admin", "password": "admin" }
```

On success (and no MFA) the response is:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "9c2f...e1",
  "token_type": "bearer",
  "force_password_change": true,
  "mfa_required": false,
  "mfa_token": null
}
```

When the local user has TOTP enabled, login instead returns a
challenge with **no tokens**, and the caller must complete the second
factor at `POST /api/v1/auth/login/mfa`:

```json
{
  "access_token": null,
  "refresh_token": null,
  "token_type": "bearer",
  "force_password_change": false,
  "mfa_required": true,
  "mfa_token": "eyJ...type=mfa...(5-minute TTL)"
}
```

The access token's default lifetime is **15 minutes**
(`ACCESS_TOKEN_EXPIRE_MINUTES`); the refresh token's is **7 days**
(`REFRESH_TOKEN_EXPIRE_DAYS`). The default credentials on a fresh
install are `admin` / `admin` with `force_password_change=true` — the
API bars a forced-change account from every endpoint except the
password-recovery allowlist (`/auth/change-password`, `/auth/logout`,
`/auth/me`, `/auth/password-policy`) until the password is rotated.

### 3.2 Refresh & rotation

`POST /api/v1/auth/refresh`

```json
{ "refresh_token": "9c2f...e1" }
```

returns a fresh `{ access_token, refresh_token, token_type,
force_password_change }`. Refresh is **rotating**: the presented
refresh token's session is revoked and a new session (and new refresh
token) is issued. Each access token carries the issuing session's UUID
as its `jti` claim, so revoking the session (`POST /api/v1/auth/logout`
or a superadmin force-logout via the sessions surface) invalidates
every access token minted from it on the next request.

### 3.3 API tokens

API tokens are minted at `POST /api/v1/api-tokens`. The raw token is
returned **exactly once** in the create response (the DB stores only a
sha256 hash plus a short display prefix). They authenticate on the same
`Authorization: Bearer` header as session JWTs.

Two narrowing mechanisms apply, both enforced in `deps.py`
*before* RBAC:

- **Scopes** (`scopes: [...]`) — a coarse, closed vocabulary defined in
  [`backend/app/services/api_token_scopes.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/api_token_scopes.py):
  `read`, `ipam:write`, `dns:write`, `dhcp:write`, `agent`. An empty
  list means no scope restriction. A non-empty list is checked against
  the request method + path; a request matching none of the token's
  scopes returns `401 "Token scope insufficient for this request"`.
  `read` permits only safe methods (`GET` / `HEAD` / `OPTIONS`) — plus
  a JSON-RPC `POST` to the read-only MCP endpoint.
- **Per-resource grants** (`resource_grants: [...]`) — bind a token to a
  specific `subnet` or `dns_zone` instance with an
  `{action, resource_type, resource_id}` triple (issue #374). At
  mint time the issuer must already hold the grant ("a token cannot
  grant more than its creator"), and the bound resource must exist.

A token can never exceed its owner's RBAC: the scope / grant check is
an *additional* gate, applied on top of the owning user's permissions.

See [`features/AUTH.md`](features/AUTH.md) for the full auth provider,
MFA, and session model.

---

## 4. Authorization (RBAC)

Authorization is enforced **server-side, independently of the UI**
(non-negotiable #3). Permissions are `{action, resource_type,
resource_id?}` triples with wildcard support; the helpers
(`require_permission` / `require_any_permission` /
`require_resource_permission` and friends) live in
`backend/app/core/permissions.py`. Most routers apply the gate at the
router-include level — e.g. the IPAM router carries a
`require_any_resource_or_scoped(...)` dependency over all of its IPAM
resource types — so every handler under the prefix is gated uniformly.
Superadmins (the legacy `User.is_superadmin` column **or** a group →
`{*, *}` wildcard role grant) bypass these checks.

A caller can introspect its own effective grants at
`GET /api/v1/auth/me/permissions`. The full grammar, built-in roles
(Superadmin / Viewer / IPAM-DNS-DHCP Editors / Auditor / Compliance
Editor / Change Approver / …), and wildcard semantics are in
[`PERMISSIONS.md`](PERMISSIONS.md).

---

## 5. Feature-Module Gating

Top-level resource families can be turned off as **feature modules**
(non-negotiable #14). A disabled module's router is gated with
`Depends(require_module("..."))` and returns **`404 Not Found`** — not
`403` — so the API surface mirrors an air-gapped deployment where the
feature simply isn't installed
([`backend/app/services/feature_modules.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/feature_modules.py)):

```json
{ "detail": "Feature 'network.circuit' is disabled." }
```

A module's shipped default lives in `default_enabled` on its catalog
entry and nowhere else — a `feature_module` row means an operator
changed it. A module ships **enabled** only if it is core IPAM / DNS /
DHCP workflow, a zero-footprint UI convenience, or a hand-invoked
read-only diagnostic; everything else ships **disabled**
([#1069](https://github.com/spatiumnorth/spatiumddi/issues/1069)). 14 of
53 are on out of the box. Settings → Features lists every module with
its description either way, so a disabled one is still discoverable.
Examples of gated prefixes (from `router.py`):

| Prefix | Module id |
|---|---|
| `/api/v1/ai` | `ai.copilot` |
| `/api/v1/circuits` | `network.circuit` |
| `/api/v1/cloud` | `integrations.cloud` |
| `/api/v1/conformity` | `compliance.conformity` |
| `/api/v1/kubernetes` | `integrations.kubernetes` |
| `/api/v1/nmap` | `tools.nmap` |
| `/api/v1/saved-views` | `ui.saved_views` |

Operators toggle modules via the admin feature-modules surface under
`/api/v1/admin`.

---

## 6. Pagination

There are two list shapes in the codebase. New routers should use the
envelope; the legacy core routers return bare arrays.

### 6.1 `{items, total, limit, offset}` envelope (preferred)

The network-modeling and newer routers (circuits, services, ASNs,
VRFs, overlays, multicast, TLS certs, …) accept `limit` + `offset`
query params and return a typed envelope. From
[`backend/app/api/v1/circuits/router.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/api/v1/circuits/router.py):

```
GET /api/v1/circuits?limit=100&offset=0
```

```json
{
  "items": [ /* … CircuitRead objects … */ ],
  "total": 312,
  "limit": 100,
  "offset": 0
}
```

`limit` is validated per-endpoint (commonly `ge=1, le=500`, with a few
routers allowing higher ceilings); `offset` is `ge=0`. `total` is the
unpaginated row count so clients can compute page counts. These
endpoints also expose resource-specific filter params (e.g.
`provider_id`, `status`, `search`, `tag`) alongside the page controls.

### 6.2 Bare array (core IPAM / DNS / DHCP)

The core IPAM, DNS, and DHCP list endpoints return a plain JSON array
of the resource. For example `GET /api/v1/ipam/spaces` is declared with
`response_model=list[IPSpaceResponse]` and returns:

```json
[
  { "id": "…", "name": "Corporate", "is_default": true, "…": "…" },
  { "id": "…", "name": "DMZ", "is_default": false, "…": "…" }
]
```

These predate the envelope convention; the client filters/sorts these
in the browser or via query params on the specific endpoint.

**Exception — address listing (#517, 2026.07.04-1).**
`GET /api/v1/ipam/subnets/{id}/addresses` stays backward-compatible
(still a bare `list[IPAddressResponse]`) but now accepts optional
`q` / `hostname` / `mac` / `sort` / `order` / `limit` / `offset`, and
sets an `X-Total-Count` response header (CORS-exposed) when the result
is windowed. For **cross-subnet** address queries use the envelope
endpoints `GET /api/v1/ipam/addresses/search` (paginated, joined
subnet/space context) and `GET /api/v1/ipam/addresses/search/ids`
(a capped id list for select-all-matches). Both are permission-scoped
in SQL.

---

## 7. Request / Response Examples

### 7.1 Create an IP space

`POST /api/v1/ipam/spaces`

Request body (`IPSpaceCreate` — only `name` is required; everything
else has a default):

```json
{
  "name": "Corporate",
  "description": "Primary internal routing domain",
  "is_default": true,
  "color": null,
  "tags": { "env": "prod" }
}
```

Response — `201 Created`, `IPSpaceResponse`:

```json
{
  "id": "4f6c2a9e-3b1d-4e7a-9c2f-1a2b3c4d5e6f",
  "name": "Corporate",
  "description": "Primary internal routing domain",
  "is_default": true,
  "tags": { "env": "prod" },
  "color": null,
  "dns_group_ids": [],
  "dns_zone_id": null,
  "dns_additional_zone_ids": [],
  "ddns_enabled": false,
  "ddns_hostname_policy": "client_or_generated",
  "created_at": "2026-06-27T12:00:00.000Z",
  "modified_at": "2026-06-27T12:00:00.000Z"
}
```

Creating a space whose `name` already exists returns `409 Conflict`
with `{"detail": "An IP space named 'Corporate' already exists"}`.
Every mutation is written to the append-only `audit_log` before the
response returns (non-negotiable #4).

### 7.2 Read the running version (public)

`GET /api/v1/version` is unauthenticated (the login page calls it for
the release-check banner); the host-identity fields are only populated
for authenticated callers:

```json
{
  "version": "2026.06.25-1",
  "latest_version": null,
  "update_available": false,
  "latest_release_url": null,
  "latest_checked_at": null,
  "release_check_enabled": true,
  "latest_check_error": null,
  "appliance_mode": false,
  "appliance_version": null,
  "appliance_hostname": null
}
```

---

## 8. Errors

Application errors use FastAPI's standard error envelope: a JSON object
with a `detail` field and the appropriate HTTP status code.

```json
{ "detail": "Invalid credentials" }
```

`detail` is usually a human-readable string, but some handlers return a
structured object — e.g. a password-policy failure returns
`{"detail": {"reason": "password_policy", "errors": [...]}}`, and an IP
collision returns `{"detail": {"warnings": [...], "requires_confirmation": true}}`.

Common status codes across the surface:

| Status | Meaning |
|---|---|
| `400 Bad Request` | Semantically invalid input (e.g. wrong current password) |
| `401 Unauthorized` | Missing / invalid / expired credential, or insufficient token scope |
| `403 Forbidden` | Authenticated but not permitted (RBAC denial, superadmin-only, disabled account, forced password change) |
| `404 Not Found` | Resource doesn't exist **or** its feature module is disabled |
| `409 Conflict` | Uniqueness / overlap / collision conflict, or a delete refused because rows still reference the target |
| `422 Unprocessable Entity` | Pydantic request-body / query-param validation failure, or a request-supplied reference to a row that does not exist |
| `429 Too Many Requests` | Per-IP login rate limit tripped |
| `503 Service Unavailable` | Maintenance mode, transient DB-connection-closed (carries `Retry-After`), or a failing readiness check |

A `422` validation error carries FastAPI's structured field-error list:

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "name"],
      "msg": "Field required"
    }
  ]
}
```

Validation, permission, and auth errors are raised as typed
`HTTPException`s and turned into clean 4xx responses by FastAPI's own
machinery. Anything that slips past every handler is caught by a
last-resort exception handler in `main.py` that records the failure for
the diagnostics surface and returns a generic
`500 {"detail": "Internal Server Error"}` (it never echoes the
exception text). Transient DB-connection-closed errors (e.g. during a
backup restore) are converted to a `503` with `Retry-After: 1` so agent
long-polls back off rather than cascading.

#### Database integrity errors

Three SQLSTATEs are mapped to client errors before that last-resort handler
sees them (`app/core/integrity_errors.py`, wired in `main.py`):

| SQLSTATE | Condition | Answer |
|---|---|---|
| `23505` | Unique violation | `409` — the data conflicts |
| `23503` | Foreign key, referent missing, **value came from this request** | `422` — `"<column> references a <table> row that does not exist."` |
| `23503` | Foreign key, row still referenced, **value came from this request** | `409` |
| class `22` | Value Postgres refuses as data (over-length, NUL byte, malformed literal) | `422` |

**Everything else re-raises to the 500 path deliberately.** NOT NULL (23502)
and CHECK (23514) violations mean the *server* built a bad row, and answering
4xx would both misattribute the fault and hide it — a 4xx is invisible to the
conformance fuzz's no-5xx assertion, which is the only thing watching for that
class.

The "value came from this request" qualifier is what splits the foreign-key
arm (#922). Postgres names the offending column and value in the error's
`DETAIL`; the value is compared against every scalar in the request body, path
params and query string, and the request is only blamed when **every**
offending value is one it actually carried. A dangling reference the server
computed — including one half of a composite key — still answers 500, on
purpose.

If you are adding a similar mapping, note that `IntegrityError.orig` is
SQLAlchemy's `AsyncAdapt_asyncpg_dbapi` wrapper: it re-exports `sqlstate` but
**not** `detail`. The asyncpg error carrying the DETAIL line hangs off its
`__cause__`, so reading `orig.detail` returns `""` for every error and the
handler silently does nothing.

### Request correlation

Every request gets an `X-Request-ID` (read from the inbound header or
minted as a UUID) bound into the structured logs and echoed back on the
response header, so a client can correlate a response with the
server-side log lines for that request (non-negotiable #7).

---

## 9. CORS, Trusted Hosts, Maintenance Mode

- **CORS** — origins come from the `CORS_ORIGINS` env var (comma-
  separated; default `*`). With a wildcard, credentialed CORS is
  disabled by construction (the API authenticates via the
  `Authorization` header, not cookies). Pin explicit origins to enable
  `allow_credentials`.
- **Trusted hosts** — `TRUSTED_HOSTS` (default `*`) gates the inbound
  `Host` header; set it to your real hostnames to harden against
  Host-header injection / DNS-rebinding.
- **Maintenance mode** (issue #57) — when enabled, mutating requests
  are short-circuited with `503` (superadmin + exempt paths bypass);
  reads pass through. The banner state is surfaced on
  `/health/platform`.

---

## 10. MCP (Operator Copilot) Endpoint

The Operator Copilot exposes a **Model Context Protocol** server over
JSON-RPC 2.0 (the MCP spec's "Streamable HTTP" transport) at:

```
/api/v1/ai/mcp
```

It is part of the `/api/v1/ai` router, gated by the `ai.copilot`
feature module — disable the module and the endpoint 404s. It shares
the same auth surface as the rest of the API: a session JWT for browser
clients, or an API token for external MCP clients (Claude Desktop /
Cursor / any MCP-speaking client). External clients use a token with
the `read` scope, which is explicitly allowed to `POST` the JSON-RPC
frame even though it is a write method.

A bare `GET /api/v1/ai/mcp` returns server identity (handy for a sanity
check; auth still required):

```json
{
  "server": { "name": "spatiumddi", "version": "1.0.0" },
  "protocol_version": "2025-06-18",
  "available_tools": 0,
  "transport": "streamable_http"
}
```

`POST /api/v1/ai/mcp` handles one JSON-RPC request (or a batch).
Supported methods are `initialize`, `notifications/initialized`,
`tools/list`, `tools/call`, and `ping`; `resources/*`, `prompts/*`,
`sampling/*`, and `completion/*` return method-not-found. A
`tools/list` call returns the registry's read-only tools — the
hundreds of `find_*` / `count_*` reads, deliberately excluding
`propose_*` write tools so the MCP surface never even stages a mutation
(writes go through the C2-gated `/api/v1/ai/proposals` apply flow in
the chat UI instead). Per-tool default-enabled state and feature-module
filtering both apply, so the advertised set reflects what the operator
has actually turned on.

---

## See also

- [`features/AUTH.md`](features/AUTH.md) — auth providers, MFA, sessions, token model
- [`PERMISSIONS.md`](PERMISSIONS.md) — RBAC grammar, built-in roles, wildcards
- [`deployment/DOCKER.md`](deployment/DOCKER.md) — ports, env vars, first-time setup
- [`features/IPAM.md`](features/IPAM.md) · [`features/DNS.md`](features/DNS.md) · [`features/DHCP.md`](features/DHCP.md) — per-feature endpoint detail
