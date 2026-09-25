# Auth & Permissions

> **Implementation status (shipped):** Local auth
> (JWT + rotating refresh token), TOTP MFA, API tokens with scopes,
> five external identity provider types configured at runtime from the
> admin UI (LDAP, OIDC, SAML, RADIUS, TACACS+), failover to backup
> servers on LDAP / RADIUS / TACACS+, group-based RBAC enforced on every
> API router, and a set of builtin roles seeded at startup (see
> `PERMISSIONS.md`). Deferred: SCIM provisioning.

## Overview

SpatiumDDI's auth stack has three layers:

1. **Authentication** — verifying who you are. Local password login, plus
   any mix of enabled external providers. All external providers funnel
   through a unified `sync_external_user()` that creates / updates the
   local `User` and replaces their group membership from the provider's
   group mappings. A login with **no** group mapping match is rejected.
2. **Session** — the login handler issues a short-lived JWT access token
   (15 min default) and a longer-lived rotating refresh token stored as a
   hashed row in `user_session`.
3. **Authorization** — every API router uses a permission helper
   (`require_permission` / `require_resource_permission` /
   `require_any_permission`) to check that the caller's groups carry a
   role with a matching permission entry. See [PERMISSIONS.md](../PERMISSIONS.md)
   for the grammar.

<p align="center">
  <img src="../assets/diagrams/auth-login-flow.svg" alt="Login flow — three authentication paths, one identity sync" width="900"/>
</p>

## Local auth

- `POST /auth/login` accepts JSON `{username, password}`. Returns
  `{access_token, refresh_token, force_password_change}`.
- Passwords are `bcrypt` hashed. New users default `force_password_change=True`
  so the UI redirects them to `/change-password` before they can do anything
  else.
- Access token expires in 15 min. Refresh token expires in 7 days
  (`refresh_token_expire_days` default) and rotates on every use.
- `admin` / `admin` is seeded on first start with `force_password_change=True`.
  Reset the password from the CLI with the one-liner in the README.

## TOTP MFA (issue #69)

Local-user 2FA stacks on top of the password flow. As of #408, TOTP
enrolment is also open to external-identity users (LDAP / OIDC / SAML /
RADIUS / TACACS+) — **not for login** (they still authenticate at their
provider), but so an SSO superadmin can re-confirm sensitive reveals
(appliance kubeconfig, pairing codes, agent bootstrap keys, SNMP
community) with a TOTP code, since those reveals demand a credential the
session alone doesn't prove and an SSO account has no local password.

- **Enrolment**: Settings → Security → "Enable MFA" generates a fresh
  TOTP secret stored Fernet-encrypted in the `User.totp_secret_encrypted`
  column (recovery codes in `recovery_codes_encrypted`, `totp_enabled`
  flag flips true only after the first valid code). The
  backend emits the `otpauth://` provisioning URI via
  `pyotp.TOTP(secret).provisioning_uri(...)`; the frontend renders
  the QR code client-side from that URI. The operator scans with
  Authenticator / Authy / 1Password / Bitwarden, enters a 6-digit code
  to confirm enrolment, and the next page shows 10 single-use backup
  codes (persisted hashed). Backup codes are only shown once.
- **Login flow**: when MFA is enabled, the `POST /auth/login` response
  carries a short-lived **pre-token** instead of the full access token.
  The UI prompts for either a 6-digit TOTP code or a backup code and
  exchanges the pre-token via `POST /auth/login/mfa` for the
  real `{access_token, refresh_token}` pair. Backup codes are
  invalidated on use.
- **Disable**: a user clears their own MFA via `POST /auth/mfa/disable`
  (local users supply their password AND a current TOTP code;
  password-less external-auth users supply just the current TOTP code).
  The action lands in the audit log (`action="mfa.disabled"`) and the
  user can re-enrol from scratch.
- **Re-confirming sensitive reveals (#408)**: the secret-reveal
  endpoints (agent keys / SNMP community / appliance kubeconfig / pairing
  codes) re-verify the operator right before handing back the cleartext,
  via the shared `app.services.reauth.reverify_operator` helper. A **local
  user proves their password**; a **password-less external-auth user
  proves a current TOTP code** (so they must enrol MFA first, hence the
  open enrolment above). TOTP is deliberately **not** accepted in lieu of
  a local user's password — that would downgrade the password step-up,
  since MFA enrolment needs only a session and a hijacked session could
  otherwise self-enrol and reveal. Disable / regenerate-recovery-codes
  follow the same shape (password for local, TOTP-only for SSO).

## External identity providers

All providers are configured at runtime from `/admin/auth-providers`. The
`AuthProvider` row carries:

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | |
| `name` | str | Display name shown on the login page. |
| `type` | str | `"ldap"`, `"oidc"`, `"saml"`, `"radius"`, or `"tacacs"`. |
| `is_enabled` | bool | Disabled providers are skipped at login. |
| `priority` | int | Lower = tried first (password-flow fallthrough). |
| `auto_create_users` | bool | Create missing users at first login. |
| `auto_update_users` | bool | Update email / display name on every login. |
| `config` | jsonb | Public config (see per-provider fields below). |
| `secrets_encrypted` | bytes | Fernet-encrypted secrets dict. |

**Secrets at rest.** Everything in `secrets_encrypted` is wrapped with
Fernet. The encryption key is derived from `settings.credential_encryption_key`
(explicit) or `SHA-256(secret_key)` (fallback), so a fresh deploy that only
sets `SECRET_KEY` still works. See `backend/app/core/crypto.py`.

**Group mappings.** Each provider owns a list of `AuthGroupMapping` rows
(`external_group` → `internal_group_id`). The unified sync in
`backend/app/core/auth/user_sync.py` resolves the user's provider-reported
groups case-insensitively and **rejects the login if no mapping matches**.

### LDAP

Driver: `backend/app/core/auth/ldap.py` (`ldap3`).

Flow per login:
1. Bind as the service account (`config.bind_dn` + `secrets.bind_password`).
2. Search under `config.user_base_dn` using
   `config.user_filter` (must contain the `{username}` placeholder).
3. Bind as the returned DN + the user's password to verify credentials.
4. Extract groups from the `memberOf` attribute (or `config.attr_member_of`).

Key config fields:

| Field | Default | Notes |
|---|---|---|
| `host` | — | FQDN or IP of the primary directory. |
| `port` | 636 (SSL) / 389 | |
| `backup_hosts` | `[]` | List of `"host"` or `"host:port"` entries. Bracketed IPv6 (`[::1]:389`) allowed. |
| `use_ssl` | `true` | `ldaps://` on port 636. |
| `start_tls` | `false` | Upgrade a plain connection after bind. |
| `bind_dn` | — | Service account DN. |
| `user_base_dn` | — | Search base for user lookups. |
| `user_filter` | `(&(objectClass=user)(sAMAccountName={username}))` | Must contain `{username}`. |
| `attr_username` / `attr_email` / `attr_display_name` | `sAMAccountName` / `mail` / `displayName` | |
| `attr_member_of` | `memberOf` | |
| `tls_ca_cert_file` | — | Container path to a custom CA. |

### OIDC

Driver: `backend/app/core/auth/oidc.py` (`authlib`).

Flow:
1. Login page calls `GET /auth/{provider_id}/authorize` — 302 redirects to
   the IdP's authorization endpoint with a signed-JWT state+nonce cookie
   (`oidc_flow`).
2. IdP redirects back to `/auth/{provider_id}/callback` with an authorization
   code.
3. Backend validates the state+nonce cookie, exchanges the code, validates
   the ID token via `authlib.jose` (discovery + JWKS cached), and redirects
   to `/auth/callback#token=…&refresh=…` on the frontend.
4. Frontend's `LoginCallbackPage` consumes tokens from the URL hash and
   routes into the app.

Key config fields:

| Field | Notes |
|---|---|
| `discovery_url` | e.g. `https://accounts.google.com/.well-known/openid-configuration` |
| `client_id` | From the IdP. |
| `scopes` | Array. Defaults to `["openid", "profile", "email"]`. |
| `claim_username` / `claim_email` / `claim_display_name` / `claim_groups` | Claim names to pull from the ID token. |

Secrets: `client_secret`.

### SAML

Driver: `backend/app/core/auth/saml.py` (`python3-saml`).

Flow:
1. Login page calls `GET /auth/{provider_id}/authorize` — builds an
   HTTP-Redirect `AuthnRequest` and 302s to the IdP's SSO URL.
2. IdP POSTs the `SAMLResponse` back to `/auth/{provider_id}/callback`
   (ACS endpoint).
3. Backend consumes the assertion and redirects to `/auth/callback#token=…`.
4. `GET /auth/{provider_id}/metadata` returns SP metadata XML so admins
   can register SpatiumDDI at the IdP.

Key config fields:

| Field | Notes |
|---|---|
| `idp_metadata_url` | Optional — backend can pull IdP details automatically. |
| `idp_entity_id` / `idp_sso_url` / `idp_slo_url` | Set these when you don't provide a metadata URL. |
| `idp_x509_cert` | Base64 or PEM — used to verify the assertion. |
| `sp_entity_id` | Defaults to the app URL. |
| `attr_username` / `attr_email` / `attr_display_name` / `attr_groups` | SAML attribute names. |

Secrets: `sp_private_key` (PEM, optional — only needed for signed requests).

**SAML needs HTTPS with any hosted IdP.** Step 2 above is a *cross-site
POST*: the browser is on the IdP's origin and submits the assertion to
SpatiumDDI. The short-lived `saml_flow` cookie set in step 1 — which
binds the assertion to the browser that started the flow — only rides
that POST when it is marked `SameSite=None`, and browsers honour
`SameSite=None` only when the cookie is also `Secure`. A `Lax` cookie is
withheld from every cross-site POST, which is what made all logins
against a hosted IdP fail with `error=saml_state_missing`
([#873](https://github.com/spatiumnorth/spatiumddi/issues/873)). Note the
contrast with OIDC, whose flow cookie is legitimately `SameSite=Lax`:
the OIDC provider returns the browser with a cross-site **GET**
redirect, which Lax permits.

The cookie policy is therefore picked per deployment, from the external
URL's scheme:

| External URL | Flow cookie | Works with |
|---|---|---|
| `https://…` | `SameSite=None; Secure` | any IdP |
| `http://…` | `SameSite=Lax` | only an IdP sharing SpatiumDDI's registrable domain (its POST is same-site) |

`SameSite=None` cannot be used over plain HTTP at all — the browser
drops such a cookie at *set* time — so HTTP keeps Lax rather than
losing the same-site case too. When that Lax cookie does not come back,
the ACS reports `/login?error=saml_requires_https` instead of
`saml_state_missing`, because on an HTTP deployment a missing cookie is
the signature of a cross-site IdP and the fix is TLS, not a retry.

The URL whose scheme decides all this is the admin-set **External URL**
(Settings → General, `platform_settings.app_base_url`) when configured,
otherwise the incoming request URL — the same value the SP metadata
advertises as the ACS, i.e. the origin the IdP actually posts to.
**Behind a TLS-terminating proxy, set the External URL to the public
`https://` address.** Relying on `X-Forwarded-Proto` alone is not enough
with the shipped Docker Compose stack: the frontend container's nginx
listens on `:80` and hard-sets `X-Forwarded-Proto $scheme`, so it
overwrites the `https` an outer terminator sent (the TLS recipes in
[DOCKER.md §5](../deployment/DOCKER.md) Options A and B both put the
terminator *in front of* that container). The request then looks like
plain HTTP to the API, and the SP metadata would advertise an `http://`
ACS URL anyway. The forwarded header does carry the real scheme where
nginx itself terminates TLS: DOCKER.md Option C, and the Helm chart's
TLS-enabled frontend.

### RADIUS

Driver: `backend/app/core/auth/radius.py` (`pyrad`).

Flow: one UDP round-trip per login. The driver sends `Access-Request` with
`User-Name` + `User-Password` (pyrad encrypts). `Access-Accept` with group
info lifted from the reply attribute (`Filter-Id` by default) is a success;
`Access-Reject` is bad credentials; timeout / MAC mismatch raises
`RADIUSServiceError` so the caller can fall through to the next provider.

Key config fields:

| Field | Default | Notes |
|---|---|---|
| `server` | — | Primary RADIUS host. |
| `port` | `1812` | Auth port. |
| `backup_servers` | `[]` | List of `"host"` or `"host:port"` entries. |
| `timeout` | `5` | Seconds per attempt. |
| `retries` | `3` | Per server, before failing over. |
| `nas_identifier` | `"spatiumddi"` | Stamped into every Access-Request. |
| `attr_groups` | `"Filter-Id"` | Attribute that carries group info. |
| `dictionary_path` | — | Optional extra RADIUS dictionary file path. |

Secrets: `secret` (shared secret — bytes).

### TACACS+

Driver: `backend/app/core/auth/tacacs.py` (`tacacs_plus`).

Flow:
1. `client.authenticate(username, password)` over TCP; `valid=True` is a
   success.
2. `client.authorize(username)` round-trip pulls AV pairs. `priv-lvl`
   numeric values are surfaced as `priv-lvl:N` so admins can map e.g.
   `priv-lvl:15` → `Admins` in the group-mapping UI.

Key config fields:

| Field | Default | Notes |
|---|---|---|
| `server` | — | Primary TACACS+ host. |
| `port` | `49` | |
| `backup_servers` | `[]` | List of `"host"` or `"host:port"` entries. |
| `timeout` | `5` | Seconds. |
| `attr_groups` | `"priv-lvl"` | AV pair used for group mapping. |

Secrets: `secret`.

## Backup server failover (LDAP / RADIUS / TACACS+)

Each password provider accepts an optional list of backup hosts via
`config.backup_hosts` (LDAP) or `config.backup_servers` (RADIUS / TACACS+).
Entries are strings of the form `"host"` or `"host:port"`; bracketed IPv6
literals (`[::1]:389`) are supported. The admin UI exposes a "Backup hosts /
servers" textarea (one entry per line).

**LDAP failover** uses `ldap3.ServerPool(pool_strategy=FIRST, active=True,
exhaust=True)`:
- `active=True` — the pool checks reachability before issuing operations.
- `exhaust=True` — once a host fails it is removed for the lifetime of the
  pool, so subsequent binds in the same Connection don't keep retrying
  a dead host.

**RADIUS + TACACS+ failover** iterates primary → backups manually:
- A **definitive auth answer** (Access-Accept / Access-Reject,
  `valid=True` / `valid=False`) stops iteration. The first server that
  gives you an answer wins — failing over on a rejection is wrong.
- **Network / timeout / protocol errors** (pyrad's `MAC mismatch` on a
  bad shared secret, `socket.timeout`, `ConnectionError`, etc.) fail over
  to the next target.
- All backups share the primary's shared secret, `nas_identifier`,
  `timeout`, and dictionary.

## Test-connection probe

Every provider type exposes a probe under `backend/app/core/auth/` that
returns `{ok, message, details}` without raising — `test_connection` for
LDAP / RADIUS / TACACS+, `probe_discovery` for OIDC, and `probe_metadata`
for SAML. The admin UI's "Test" button hits
`POST /api/v1/auth-providers/{id}/test` to run the
probe. For LDAP + OIDC + SAML the probe does a real service bind /
discovery fetch / metadata fetch; for RADIUS + TACACS+ it sends a stub
Access-Request — a `Reject` for the bogus credentials still proves the
server is reachable and the shared secret is correct (the MAC would not
validate otherwise).

## Provider priority

When a password-grant login arrives at `/auth/login`:

1. Local credentials are tried first. If the `User` exists and has a
   hashed password, that wins (or loses) on its own.
2. Otherwise the handler iterates every enabled provider whose type is in
   `PASSWORD_PROVIDER_TYPES = ("ldap", "radius", "tacacs")` in
   `(priority, name)` order. Each `authenticate_*()` call runs in a worker
   thread (`asyncio.to_thread`) with a 20 s timeout.
3. The first definitive answer wins. Service errors (unreachable /
   misconfigured) are logged and fall through to the next provider.
4. If nothing accepted, a single `401` + a `login` audit row are emitted.

OIDC and SAML are redirect flows — they are never tried at `/auth/login`.
The login page lists every enabled OIDC/SAML provider as a "Sign in with
…" button that kicks off the redirect flow directly.

## Permission enforcement

See [PERMISSIONS.md](../PERMISSIONS.md) for the full grammar + built-in
roles. In short:

- Every router has a `Depends(require_resource_permission(<type>))`
  dependency that maps HTTP method → action (`GET`=read,
  `POST`/`PUT`/`PATCH`=write, `DELETE`=delete).
- Handlers doing resource-scoped checks also call
  `user_has_permission(user, action, resource_type, resource_id)` before
  mutating.
- `Superadmin` short-circuits every check without writing a denial
  audit row.
- `Inactive` users are refused regardless of permissions.

## Audit

Every login attempt — success, failure, LDAP service error — writes an
`AuditLog` row with `action="login"`, `result="success"|"failure"`, the
auth source (`local`, `ldap`, `oidc`, `saml`, `radius`, `tacacs`), source
IP, user agent, and for failures a `new_value.reason` string. Failed
logins for unknown usernames still get a row (`user_id=NULL`,
`user_display_name=<attempted name>`) so brute-force attempts are visible
in the audit viewer.

## API tokens

Long-lived bearer credentials for scripts, CI pipelines, and
automation. As of issue #74, tokens carry an explicit `scopes` set
that **narrows** the owning user's permissions — a token can do at
most what its scope set allows AND what the owning user has
permission for. Tokens are indistinguishable from JWTs on the wire
(both use `Authorization: Bearer …`); the auth middleware peeks at
the prefix to pick the validation path.

**Scopes (issue #74).** `APIToken.scopes` is a JSONB list drawn from
a closed coarse-grained vocabulary (`backend/app/services/api_token_scopes.py`),
checked against `TOKEN_SCOPE_VOCABULARY` at create time so a typo is
rejected with `422` rather than silently locking the operator out:

- `read` — restricts the token to safe-method requests
  (`GET` / `HEAD` / `OPTIONS`); any mutation `401`s.
- `ipam:write` — allows mutations under `/api/v1/ipam/*`, `/vlans*`,
  `/vrfs*`, `/network-devices*`.
- `dns:write` — allows mutations under `/api/v1/dns/*`, `/dns-pools*`.
- `dhcp:write` — allows mutations under `/api/v1/dhcp/*`.
- `agent` — allows only the agent push surface
  (`/api/v1/dns/agents/*`, `/api/v1/dhcp/agents/*`).

Multiple scopes compose by **union** (any single match passes). An
**empty** scope set means no scope restriction at all (the token still
inherits the owning user's RBAC, which is the only gate) — equivalent
to the pre-#74 behaviour. New tokens pick scopes via a chip selector in
the create modal.

Scope enforcement runs **before** RBAC: a non-empty scope set narrows the
token, and the owning user's RBAC still applies on top, so a `read`-scoped
token owned by an IPAM Editor can list subnets but cannot create one. A
per-token resource-instance binding (`resource_grants`, #374) can narrow
further to specific `{action, resource_type, resource_id}` grants, validated
at create time to be a subset of what the issuing user holds.

**Wire format.** Raw tokens start with `sddi_` followed by 40 bytes of
url-safe base64 entropy (`secrets.token_urlsafe(40)`). Operators typically see only the first
10 characters (`sddi_AbCdE`) in the UI as an identifier — this is
the `APIToken.prefix` column, sufficient to pick a token out of a
list without leaking entropy to an observer.

**At rest.** Only the SHA-256 hash is stored (`APIToken.token_hash`).
The raw value is returned exactly once from `POST /api/v1/api-tokens`
and never again — losing it means creating a new token.

### Device enrolment QR code (issue #906)

The only way to get a token onto a phone used to be typing or pasting
it between devices. That is the worst step in the mobile sign-in flow,
and worse than merely annoying: an operator who cannot paste cleanly
emails the token to themselves or reads it aloud, and the credential
ends up somewhere it should never have been.

The reveal-token modal therefore offers a QR code in two shapes:

| Shape | Payload |
|---|---|
| **Token only** | the bare token string — no format needed |
| **Server + token** | `spatiumddi://enrol?host=…&port=…&scheme=…&token=…&fingerprint=…` |

The enrolment URI is a **contract with the mobile client**
([spatiumddi-mobile](https://github.com/spatiumnorth/spatiumddi-mobile)),
which already parses both shapes. `port` is omitted when it is the
scheme default, and `scheme` only appears when it is `http` — being
explicit about the insecure case is the right way round, since a code
that silently downgrades is the failure worth preventing. IPv6 hosts
are bracketed so the client cannot reparse them as `host:port`. The
builder lives in `frontend/src/lib/enrolment.ts`.

**The connection comes from the browser, not the server.** Behind a
reverse proxy, split DNS or NAT the control plane does not know its own
externally-reachable address, and would guess wrong on exactly the
deployments this is most useful for. The UI starts from
`window.location` and lets the operator correct it — a laptop on a VPN
and a handset on wifi routinely disagree about how to reach one server.

**Why the fingerprint is the interesting part.** A self-hosted control
plane usually presents a certificate from a private CA or the
appliance's own root, so the client has to ask the operator to confirm
it rather than blanket-trusting an unknown certificate. Comparing 64
hex characters by eye on a phone is precisely the check people skim.
Putting the fingerprint in a code the operator scans from inside an
authenticated session makes that comparison machine-checked — the
weakest step in the trust flow becomes the strongest, for one query
parameter.

`GET /api/v1/api-tokens/enrolment-context` supplies it, gated on
authentication only (matching token creation — a TLS fingerprint is not
a secret; it is what the server hands every client that connects).
It answers **only** when SpatiumDDI actually owns the TLS termination,
i.e. there is an active `ApplianceCertificate` — the row deployed to
the TLS secret the frontend serves. On a Compose or plain-Kubernetes
install an external proxy terminates TLS with a certificate this
process has never seen, and the honest answer is `null` with a reason,
not a guess: a fingerprint that disagrees with the wire would make the
client report a mismatch on a *correct* setup, training operators to
click through the one warning this exists to make meaningful. The UI
also lets the operator untick certificate pinning for the case where
something in front of SpatiumDDI re-terminates TLS.

**Exposure.** The QR is hidden behind an explicit reveal, like the
token text beside it, and is not rendered into the DOM until then. That
is not decoration: a QR makes the credential *camera-readable*, so it
is strictly easier to capture over a shoulder — or from a screen-share
— than the masked string. The code carries no exposure the displayed
token does not, but it is easier to capture at a distance.

Short-lived enrolment codes would be better still: if minting ever
moves to a device-token grant, the QR could carry a single-use code and
the token would never leave the server. The URI format above does not
preclude that.

**Validation path.** `app/api/deps.py:get_current_user` checks for the
`sddi_` prefix first; if present it hashes the bearer, looks the row
up by hash, enforces `is_active` and `expires_at`, then loads the
owning user and records the use in `last_used_at`. The write is at most
once a minute per token and commits on its own, so a token used only for
reads shows its use too (#1158). JWTs take the original path. A
missing / wrong / revoked token returns the same generic 401 as an
invalid JWT to avoid confirming token existence to an attacker.

**Lifecycle.**
- Create via the Admin → API Tokens UI or `POST /api/v1/api-tokens`
  (JSON: `{name, description?, expires_in_days?}`). The create
  response contains the raw `token` field **once** — the UI forces a
  "copy now" dialog before it disappears.
- List via `GET /api/v1/api-tokens` (your tokens only; superadmins
  see everyone's).
- Revoke softly via `PATCH /api/v1/api-tokens/{id}` with
  `{is_active: false}` — the row stays so `last_used_at` is still
  visible for incident forensics.
- Delete hard via `DELETE /api/v1/api-tokens/{id}` — same outward
  behaviour (401 on next use), audit row written on both paths.

**TTL.** The UI defaults to 90 days and flags "Never" in amber so
operators have to opt into long-lived bearers. The backend accepts
both `expires_in_days` (UX-friendly) and `expires_at` (ISO timestamp,
for automation). Expired tokens 401 with a distinct detail message
so clients can detect "refresh me" vs "reconfigure me".

## Open items

- **SCIM provisioning** — not planned for Phase 1.
- **Per-provider signing key rotation** — manual today; automate in a
  later wave.
- **Global-scope / service-account tokens** — the `APIToken.scope`
  column supports `global`, but validation rejects them today pending
  a proper service-account user model. Token-only `allowed_paths` and
  per-token permission overrides exist on the model but aren't
  exposed on create yet.

## Rules & constraints

Server-side validations that reject requests with a human-readable
error. Clients should surface the response `detail` to the operator
rather than swallowing the failure. Permission-related rejections
(`403 forbidden`) are covered separately in `docs/PERMISSIONS.md`.

### Login & session

- **Invalid credentials.** Local password verification failure returns
  `401`. Enforced at `backend/app/api/v1/auth/router.py`.
- **Account disabled.** Login is refused with `403` when
  `user.is_active` is false — regardless of auth source.
  `backend/app/api/v1/auth/router.py`.
- **Empty external ID from IdP.** External login (LDAP / OIDC / SAML /
  RADIUS / TACACS+) with no stable external identifier in the IdP
  response is rejected — we won't create a `User` row we can't
  correlate later. `backend/app/core/auth/user_sync.py`.
- **No group-mapping match.** An external user whose IdP group claim
  doesn't match any `AuthGroupMapping` row for that provider is
  rejected with `401`, even if the IdP authenticated them. This is
  deliberately strict — there is no implicit "default group" fallback.
  `backend/app/core/auth/user_sync.py`.
- **Auto-create disabled.** First external login for a new subject is
  refused with `401` if `provider.auto_create_users=False`. An
  administrator must create the `User` row manually.
  `backend/app/core/auth/user_sync.py`.
- **Username collision across auth sources.** An external user whose
  `external_id` is new but whose preferred username already belongs to
  a user on a different `auth_source` is rejected to prevent silently
  hijacking an existing account.
  `backend/app/core/auth/user_sync.py`.
- **Refresh token invalid or expired.** Refresh is rejected with `401`
  when the token is not in the sessions table, has been revoked, or
  has passed `expires_at`. `backend/app/api/v1/auth/router.py`.
- **User deactivated mid-session.** A refresh request from a disabled
  user returns `401` even if the refresh token itself is still valid
  — deactivating a user revokes their session on the next refresh.
  `backend/app/api/v1/auth/router.py`.

### Password management

- **One length authority, and it is the configured policy.** The
  Pydantic-validator baseline rejects only an *empty* password (`422`),
  so a legacy client still fails before reaching the handler; every
  length verdict comes from the configurable policy (length / character
  classes / history / age, issue #70), which runs server-side against
  `PlatformSettings` and returns `400` with a per-rule error list.
  `backend/app/api/v1/auth/router.py`,
  `backend/app/services/password_policy.py`.

  That baseline used to be **8 characters**
  ([#1004](https://github.com/spatiumnorth/spatiumddi/issues/1004)) — a
  second minimum, unconfigurable, contradicting the default policy's 12
  and making a relaxed 6-character policy unreachable through the API
  while the UI offered it. It also fired as a Pydantic `422`, whose
  `detail` is an error **array** rather than the `{reason, errors}`
  object the policy path returns, and the change-password screen parsed
  neither shape: a 7-character password was reported to the operator as
  "check your current password". Any new `field_validator` on these
  request models emits that same array shape, so the frontend parses it
  (`frontend/src/lib/password-policy.ts`).

- **The browser evaluates the policy too, and gates on what it
  evaluated.** `GET /auth/password-policy` is unauthenticated so the
  login and change-password forms can render the rule list before a
  token exists; the Change Password screen disables submit while any
  *evaluated* rule fails, sparing a round trip whose outcome it can
  already predict. The server stays authoritative — this never permits
  anything. Password history is excluded from the gate and rendered as
  a note, because the browser cannot check it; giving it the same green
  tick as the checkable rules made a failing password read as nearly
  complete. `frontend/src/lib/password-policy.ts`.
- **Current password required.** Change-password endpoints verify
  `current_password` before accepting the new value; a mismatch
  returns `400` rather than silently succeeding.
  `backend/app/api/v1/auth/router.py`.

### Auth providers

- **Duplicate provider name.** Two `AuthProvider` rows with the same
  `name` are rejected with `409`, regardless of type.
  `backend/app/api/v1/auth_providers/router.py`.
- **Invalid provider type.** `type` must be one of the values in
  `PROVIDER_TYPES` (`ldap`, `oidc`, `saml`, `radius`, `tacacs`).
  `backend/app/api/v1/auth_providers/router.py`.
- **Group mapping target must exist.** `AuthGroupMapping` rows reject
  `internal_group_id` values that don't resolve to an existing
  `Group`. `backend/app/api/v1/auth_providers/router.py`.
