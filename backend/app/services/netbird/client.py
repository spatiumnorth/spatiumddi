"""Minimal async NetBird REST client.

Endpoints consumed:

* ``GET /api/peers`` — full peer inventory (the only call we need for
  Phase 1). Returns a bare JSON array of peer objects, each with
  ``id``, ``name``, ``ip`` (single IPv4 overlay address), ``dns_label``
  (FQDN, e.g. ``host.netbird.cloud``), ``hostname``, ``os``,
  ``version``, ``connected``, ``last_seen``, ``login_expired``,
  ``login_expiration_enabled``, ``groups[]``, ``user_id``,
  ``ssh_enabled``, ``approval_required``.

Auth is a personal-access token — ``Authorization: Token <api_key>``
(NetBird's scheme; note it is ``Token``, not ``Bearer``).

Base URL is per-instance and operator-supplied: cloud is
``https://api.netbird.io``; a self-hosted install is the
dashboard/management host (API served under ``/api``). Because the URL
is operator-controlled, the API layer runs it through the advisory
SSRF guard (``app.core.ssrf``) at the test-connection boundary — the
same place every operator-URL integration guards — unlike the
fixed-host Tailscale client, which needs no guard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from app.services._mirror_shape import require_list
from app.services.backup.targets.base import describe_exc


class NetbirdClientError(Exception):
    """Raised when the NetBird API returns an error we can't recover from."""


@dataclass
class _NetbirdPeer:
    """Normalised NetBird peer entry.

    Carries only the fields the reconciler uses. The full ``/api/peers``
    payload has more (geoname_id, city_name, serial_number,
    accessible_peers_count, …) — drop them here.
    """

    id: str
    name: str
    ip: str  # single IPv4 overlay address
    dns_label: str = ""  # FQDN (`<host>.<domain>`)
    hostname: str = ""
    os: str = ""
    version: str = ""
    user_id: str = ""
    connected: bool = False
    last_seen: str | None = None  # ISO 8601
    login_expired: bool = False
    login_expiration_enabled: bool = False
    ssh_enabled: bool = False
    approval_required: bool = False
    groups: list[str] = field(default_factory=list)  # group names


def _normalise_base_url(api_url: str) -> str:
    """Strip a trailing slash and an accidental trailing ``/api`` so the
    caller can pass either ``https://host`` or ``https://host/api`` and
    we always dial ``<host>/api/peers`` exactly once."""
    base = (api_url or "").strip().rstrip("/")
    if base.endswith("/api"):
        base = base[: -len("/api")]
    return base


class NetbirdClient:
    """Async context-managed REST client.

    ``async with NetbirdClient(api_key=..., api_url=..., verify=True) as c:``
    """

    def __init__(
        self,
        *,
        api_key: str,
        api_url: str,
        verify: bool = True,
        timeout: float = 15.0,
    ) -> None:
        self._api_key = api_key
        self._base_url = _normalise_base_url(api_url)
        self._verify = verify
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> NetbirdClient:
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Token {self._api_key}",
                "Accept": "application/json",
            },
            timeout=self._timeout,
            verify=self._verify,
        )
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str, **params: Any) -> Any:
        assert self._client is not None, "NetbirdClient used outside async with"
        try:
            r = await self._client.get(path, params=params or None)
        except httpx.ConnectError as exc:
            raise NetbirdClientError(
                f"Could not reach NetBird at {self._base_url}: {describe_exc(exc)}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise NetbirdClientError(f"Request to {path} timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise NetbirdClientError(f"HTTP error on {path}: {exc}") from exc

        if r.status_code == 401:
            raise NetbirdClientError(
                "HTTP 401 — token invalid or revoked. Create a new personal-access "
                "token under Settings → Users in the NetBird dashboard."
            )
        if r.status_code == 403:
            raise NetbirdClientError(
                "HTTP 403 — token lacks permission to list peers. "
                "Use a token for an account admin (or a service user with read access)."
            )
        if r.status_code == 404:
            raise NetbirdClientError(
                f"HTTP 404 from {path} — check the management URL "
                f"({self._base_url}); it should be the API base, e.g. "
                f"https://api.netbird.io or your self-hosted dashboard host."
            )
        if r.status_code >= 400:
            body = (r.text or "")[:200]
            raise NetbirdClientError(f"HTTP {r.status_code} from {path}: {body}")

        try:
            return r.json()
        except ValueError as exc:
            raise NetbirdClientError(f"Non-JSON response from {path}: {exc}") from exc

    async def list_peers(self) -> list[_NetbirdPeer]:
        """Fetch every peer in the account (one round-trip).

        ``/api/peers`` returns a bare JSON array — no pagination today.
        """
        data = await self._get("/api/peers")
        # #430 — a 200 that isn't a JSON array (proxy error page, auth
        # downgrade, envelope change) must raise so the reconciler keeps
        # existing rows rather than collapsing to [] and mass-deleting.
        items = require_list(data, make_error=NetbirdClientError, context="list_peers")
        out: list[_NetbirdPeer] = []
        for p in items:
            if not isinstance(p, dict):
                continue
            groups = [
                str(g.get("name") or "")
                for g in (p.get("groups") or [])
                if isinstance(g, dict) and g.get("name")
            ]
            out.append(
                _NetbirdPeer(
                    id=str(p.get("id") or ""),
                    name=str(p.get("name") or ""),
                    ip=str(p.get("ip") or ""),
                    dns_label=str(p.get("dns_label") or ""),
                    hostname=str(p.get("hostname") or ""),
                    os=str(p.get("os") or ""),
                    version=str(p.get("version") or ""),
                    user_id=str(p.get("user_id") or ""),
                    connected=bool(p.get("connected", False)),
                    last_seen=p.get("last_seen") or None,
                    login_expired=bool(p.get("login_expired", False)),
                    login_expiration_enabled=bool(p.get("login_expiration_enabled", False)),
                    ssh_enabled=bool(p.get("ssh_enabled", False)),
                    approval_required=bool(p.get("approval_required", False)),
                    groups=groups,
                )
            )
        return out


def derive_netbird_domain(peers: list[_NetbirdPeer]) -> str | None:
    """Pull the management DNS domain off the first peer with an FQDN.

    NetBird peer ``dns_label`` values are ``<host>.<domain>`` (e.g.
    ``server-1.netbird.cloud``). We strip the leading hostname label and
    return the rest. Returns ``None`` when no peer carries a usable FQDN.
    """
    for p in peers:
        label = (p.dns_label or "").strip().rstrip(".")
        if "." not in label:
            continue
        return label.split(".", 1)[1]
    return None


__all__ = [
    "NetbirdClient",
    "NetbirdClientError",
    "_NetbirdPeer",
    "derive_netbird_domain",
]
