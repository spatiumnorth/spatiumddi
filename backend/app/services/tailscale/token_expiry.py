"""When does a Tailscale tenant's API access token expire? (#2138)

Tailscale caps an API access token at 90 days. When it lapses, every sync
answers HTTP 401 and the mirror silently stops updating, so the expiry is
read and stored on the tenant, and ``secret_expiring`` warns before it.

**What the Tailscale API offers** (verified against the published OpenAPI
spec, ``https://api.tailscale.com/api/v2?outputOpenapiSchema=true``):

* ``GET /api/v2/tailnet/{tailnet}/keys/{keyId}`` (``getKey``) returns a
  ``Key`` object for "an api access token, OAuth client, federated identity,
  or auth key", carrying ``created`` / ``expires`` (RFC 3339 date-time),
  ``revoked``, ``keyType`` (``api`` for access tokens) and ``invalid`` (true
  for a revoked or expired key). It answers with the normal bearer token.
* Access tokens "are identifiable by the prefix tskey-api-", and the spec
  says "the identity of the key is embedded in the key itself and can be
  used to perform operations on the key (e.g., revoking it or retrieving
  information about it)". Its examples show keys as
  ``tskey-<type>-<id>-<secret>`` with an id like ``k123456CNTRL``, so the
  key id is the segment after ``tskey-api-``.
* There is no "self" / whoami endpoint and no response header carrying the
  caller's expiry.

So the read derives the key id from the token and asks ``getKey`` for it.
Anything that does not fit that shape — a token that is not ``tskey-api-``,
a 403 / 404 from the keys endpoint, an unparseable ``expires`` — reports
"could not read" and leaves the stored value alone, so an operator-entered
date survives. Nothing here ever logs or returns the token; error text
carries the status code and our own message only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from app.models.tailscale import (
    API_KEY_EXPIRY_SOURCE_API,
    API_KEY_EXPIRY_SOURCE_OPERATOR,
    TailscaleTenant,
)

_BASE_URL = "https://api.tailscale.com/api/v2"

# ``tskey-api-<keyId>-<secret>``. The id is alphanumeric in every example
# Tailscale publishes; anything else is refused rather than put in a path.
_ACCESS_TOKEN_RE = re.compile(r"^tskey-api-([A-Za-z0-9]{1,64})-.+$")


@dataclass(frozen=True)
class TokenExpiryRead:
    """Outcome of one attempt to read a token's expiry from Tailscale.

    ``expires_at`` is None whenever the expiry could not be read, with the
    reason in ``note``. ``invalid`` mirrors the API's own flag for a revoked
    or expired key.
    """

    expires_at: datetime | None
    invalid: bool = False
    note: str | None = None

    @property
    def ok(self) -> bool:
        return self.expires_at is not None


def key_id_from_token(token: str) -> str | None:
    """The key id embedded in an API access token, or None.

    Only ``tskey-api-`` tokens: an OAuth client secret (``tskey-client-``)
    does not expire, and an auth key is not an API credential at all.
    """
    m = _ACCESS_TOKEN_RE.match((token or "").strip())
    return m.group(1) if m else None


def parse_key_expiry(payload: Any) -> TokenExpiryRead:
    """Read ``expires`` / ``invalid`` out of a ``getKey`` response body."""
    if not isinstance(payload, dict):
        return TokenExpiryRead(None, note="keys endpoint returned no key object")
    invalid = bool(payload.get("invalid", False))
    raw = payload.get("expires")
    if not isinstance(raw, str) or not raw.strip():
        return TokenExpiryRead(None, invalid=invalid, note="key carries no expiry")
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return TokenExpiryRead(None, invalid=invalid, note="key expiry is not a date-time")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    # Go's zero time is how Tailscale spells "never" on device keys; a key
    # that never expires has no expiry to warn about.
    if parsed.year <= 1:
        return TokenExpiryRead(None, invalid=invalid, note="key reports no expiry")
    return TokenExpiryRead(parsed, invalid=invalid)


async def fetch_token_expiry(
    *,
    api_key: str,
    tailnet: str,
    timeout: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> TokenExpiryRead:
    """Ask Tailscale when ``api_key`` expires. Never raises."""
    key_id = key_id_from_token(api_key)
    if key_id is None:
        return TokenExpiryRead(
            None, note="token is not a tskey-api- access token, so its key id is unknown"
        )
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(
            base_url=_BASE_URL, headers=headers, timeout=timeout, transport=transport
        ) as client:
            # The tailnet is operator-typed; quote it so it stays one path
            # segment (the key id is alphanumeric by the regex above).
            r = await client.get(f"/tailnet/{quote(tailnet, safe='@')}/keys/{key_id}")
    except Exception as exc:  # noqa: BLE001
        # Broad on purpose: "never raises" is what lets the daily refresh
        # move on to the next tenant and a save succeed. ``httpx.InvalidURL``
        # derives from Exception, not ``HTTPError``. Only the exception's
        # TYPE is reported: its text can echo the request.
        return TokenExpiryRead(None, note=f"could not reach Tailscale ({type(exc).__name__})")
    if r.status_code == 401:
        return TokenExpiryRead(None, invalid=True, note="HTTP 401 — token invalid or revoked")
    if r.status_code >= 400:
        return TokenExpiryRead(None, note=f"keys endpoint answered HTTP {r.status_code}")
    try:
        body = r.json()
    except ValueError:
        return TokenExpiryRead(None, note="keys endpoint returned non-JSON")
    return parse_key_expiry(body)


def apply_operator_expiry(tenant: TailscaleTenant, expires_at: datetime | None) -> None:
    """Record an operator-entered expiry (or clear it, given None)."""
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    tenant.api_key_expires_at = expires_at
    tenant.api_key_expiry_source = API_KEY_EXPIRY_SOURCE_OPERATOR if expires_at else None


def apply_read(tenant: TailscaleTenant, read: TokenExpiryRead) -> bool:
    """Store a successful read on the tenant. Returns True when it changed.

    A failed read changes nothing: the stored value — read earlier, or typed
    by the operator — is still the best answer available, and replacing it
    with NULL would turn "expires on the 3rd" into "unknown" on a blip.
    """
    if read.expires_at is None:
        return False
    changed = (
        tenant.api_key_expires_at != read.expires_at
        or tenant.api_key_expiry_source != API_KEY_EXPIRY_SOURCE_API
    )
    tenant.api_key_expires_at = read.expires_at
    tenant.api_key_expiry_source = API_KEY_EXPIRY_SOURCE_API
    return changed


__all__ = [
    "TokenExpiryRead",
    "apply_operator_expiry",
    "apply_read",
    "fetch_token_expiry",
    "key_id_from_token",
    "parse_key_expiry",
]
