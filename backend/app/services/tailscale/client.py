"""Minimal async Tailscale REST client.

Endpoints consumed:

* ``GET /api/v2/tailnet/{tn}/devices?fields=all`` — full device
  inventory (the only call we actually need for Phase 1). Returns
  one ``Device`` per machine with ``addresses[]`` (Tailscale CGNAT
  IPv4 + IPv6 ULA), ``name`` (FQDN), ``user``, ``os``,
  ``clientVersion``, ``tags[]``, ``authorized``, ``lastSeen``,
  ``expires``, ``advertisedRoutes[]`` / ``enabledRoutes[]``,
  ``keyExpiryDisabled``, ``updateAvailable``, ``id`` (stable),
  ``nodeId``.

Auth is PAT — ``Authorization: Bearer <api_key>``.

Tailnet path segment is either the operator's tailnet slug from
the admin console, or the literal ``-`` to mean "the PAT's
default tailnet". We forward whatever's stored on the tenant row.

Convention: every Tailscale response is a JSON object. The
``/devices`` shape is ``{"devices": [...]}``. We unwrap the list
in ``list_devices`` so callers speak raw dicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.services._mirror_shape import require_keyed_list
from app.services.backup.targets.base import describe_exc

logger = structlog.get_logger(__name__)

_BASE_URL = "https://api.tailscale.com/api/v2"


# Every 401 message this integration writes to ``last_sync_error`` starts
# with this — the client below and the router's test-connection probe both.
# ``secret_expiring`` and the credential chip key on it (#2138), so the two
# messages must keep the prefix.
AUTH_REJECTED_PREFIX = "HTTP 401"


def is_auth_rejected(error: str | None) -> bool:
    """True when a stored sync error is Tailscale refusing the token."""
    return bool(error) and str(error).startswith(AUTH_REJECTED_PREFIX)


class TailscaleClientError(Exception):
    """Raised when the Tailscale API returns an error we can't recover from."""


@dataclass
class _TailscaleDevice:
    """Normalised Tailscale device entry.

    Carries only the fields we actually use in the reconciler.
    The full ``?fields=all`` payload has more (postureIdentity,
    isExternal, machineKey, blocksIncomingConnections, ...) — drop
    them here so the reconciler signature is small.
    """

    id: str  # stable Tailscale device id
    node_id: str  # node-key public ID
    name: str  # FQDN (`<host>.<tailnet>.ts.net`)
    hostname: str  # short hostname
    addresses: list[str] = field(default_factory=list)  # ["100.x.y.z", "fd7a:..."]
    os: str = ""
    client_version: str = ""
    user: str = ""  # owner email/login
    tags: list[str] = field(default_factory=list)
    authorized: bool = True
    last_seen: str | None = None  # ISO 8601
    expires: str | None = None  # ISO 8601
    key_expiry_disabled: bool = False
    update_available: bool = False
    advertised_routes: list[str] = field(default_factory=list)
    enabled_routes: list[str] = field(default_factory=list)


class TailscaleClient:
    """Async context-managed REST client.

    ``async with TailscaleClient(api_key=..., tailnet="-") as c:``

    On enter we build an ``httpx.AsyncClient`` with the bearer
    token + 15 s timeout. On exit we close it. All public methods
    raise ``TailscaleClientError`` with a usable operator-facing
    message on failure.
    """

    def __init__(self, *, api_key: str, tailnet: str = "-", timeout: float = 15.0) -> None:
        self._api_key = api_key
        self._tailnet = tailnet
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> TailscaleClient:
        self._client = httpx.AsyncClient(
            base_url=_BASE_URL,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
            },
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str, **params: Any) -> Any:
        assert self._client is not None, "TailscaleClient used outside async with"
        try:
            r = await self._client.get(path, params=params or None)
        except httpx.ConnectError as exc:
            raise TailscaleClientError(
                f"Could not reach api.tailscale.com: {describe_exc(exc)}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise TailscaleClientError(f"Request to {path} timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise TailscaleClientError(f"HTTP error on {path}: {exc}") from exc

        if r.status_code == 401:
            raise TailscaleClientError(
                f"{AUTH_REJECTED_PREFIX} — API key invalid, expired or revoked. "
                "Generate a new PAT at https://login.tailscale.com/admin/settings/keys."
            )
        if r.status_code == 403:
            raise TailscaleClientError(
                "HTTP 403 — API key does not have permission to read this tailnet. "
                "Confirm the key was issued in the same tailnet you're querying."
            )
        if r.status_code == 404:
            raise TailscaleClientError(
                f"HTTP 404 — tailnet '{self._tailnet}' not found. "
                f"Use '-' for the PAT's default tailnet, or copy the slug "
                f"from https://login.tailscale.com/admin/settings/general."
            )
        if r.status_code >= 400:
            body = (r.text or "")[:200]
            raise TailscaleClientError(f"HTTP {r.status_code} from {path}: {body}")

        try:
            return r.json()
        except ValueError as exc:
            raise TailscaleClientError(f"Non-JSON response from {path}: {exc}") from exc

    async def list_devices(self) -> list[_TailscaleDevice]:
        """Fetch every device in the tailnet (one round-trip).

        Tailscale returns the full device list in a single call —
        no pagination today. The ``?fields=all`` selector unlocks
        ``advertisedRoutes`` / ``enabledRoutes`` / ``user`` /
        ``tags`` / ``clientConnectivity`` / etc which are omitted
        from the default ``?fields=default`` shape.
        """
        data = await self._get(f"/tailnet/{self._tailnet}/devices", fields="all")
        # #430 — a 200 without a "devices" list (CDN/auth maintenance page,
        # envelope change) must raise so the reconciler keeps existing rows,
        # not collapse to [] and mass-delete the tailnet. Empty tailnet is
        # {"devices": []}.
        items = require_keyed_list(
            data, "devices", make_error=TailscaleClientError, context="list_devices"
        )
        out: list[_TailscaleDevice] = []
        for d in items:
            out.append(
                _TailscaleDevice(
                    id=str(d.get("id") or ""),
                    node_id=str(d.get("nodeId") or ""),
                    name=str(d.get("name") or ""),
                    hostname=str(d.get("hostname") or ""),
                    addresses=[str(a) for a in (d.get("addresses") or [])],
                    os=str(d.get("os") or ""),
                    client_version=str(d.get("clientVersion") or ""),
                    user=str(d.get("user") or ""),
                    tags=[str(t) for t in (d.get("tags") or [])],
                    authorized=bool(d.get("authorized", True)),
                    last_seen=d.get("lastSeen") or None,
                    expires=d.get("expires") or None,
                    key_expiry_disabled=bool(d.get("keyExpiryDisabled", False)),
                    update_available=bool(d.get("updateAvailable", False)),
                    advertised_routes=[str(r) for r in (d.get("advertisedRoutes") or [])],
                    enabled_routes=[str(r) for r in (d.get("enabledRoutes") or [])],
                )
            )
        return out


def derive_tailnet_domain(devices: list[_TailscaleDevice]) -> str | None:
    """Pull the tailnet domain off the first device with an FQDN.

    Tailscale device names are always ``<host>.<tailnet>.ts.net``.
    We strip the leading hostname label and return the rest, e.g.
    ``rooster-trout.ts.net``. Returns ``None`` when the tailnet is
    empty or no device carries a usable FQDN.
    """
    for d in devices:
        name = (d.name or "").strip().rstrip(".")
        if "." not in name:
            continue
        # First label is the hostname, everything else is the
        # tailnet domain.
        return name.split(".", 1)[1]
    return None


__all__ = [
    "AUTH_REJECTED_PREFIX",
    "TailscaleClient",
    "TailscaleClientError",
    "_TailscaleDevice",
    "derive_tailnet_domain",
    "is_auth_rejected",
]
