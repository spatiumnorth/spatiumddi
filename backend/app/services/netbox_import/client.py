"""Async httpx NetBox REST client for the one-shot importer (issue #36 §3).

Raw ``httpx`` rather than ``pynetbox`` — pynetbox pulls sync
``requests`` / ``urllib3`` + an ORM layer we don't need for a handful of
read endpoints, and SpatiumDDI is async-throughout (non-negotiable #2).
``httpx`` is already a vendored dependency, so this adds no new component.

The client handles, per the issue plan:

* **Dual token auth** (§3.2): ``Authorization: Token <hex>`` (v1, all
  versions) vs ``Authorization: Bearer nbt_<key>.<token>`` (v2,
  NetBox 4.5+) — prefix-detected from the operator-pasted token.
* **Version detection** (§3.3): ``GET /api/status/`` — the response's
  ``API-Version`` header (or the ``netbox-version`` body field) drives
  the prefix/VLAN ``site`` → ``scope`` parse branch in ``fetch.py``.
* **Pagination** (§3.4): follow the absolute ``next`` URL from the DRF
  envelope, ``limit=500``, never hand-compute offsets.
* **Retry / throttle** (§3.7): 429 honours ``Retry-After``; 502/503/504
  exponential backoff; 401/403/404 surface the JSON ``detail`` field to
  the operator.
* **TLS verify toggle** (§3.5): ``verify_tls=False`` flips
  ``httpx.AsyncClient(verify=False)`` and emits a structured WARNING on
  every connect (the proxmox / unifi / ftp client convention).
* **Pull ceiling** (§3.8): ``PULL_CEILING`` caps total imported rows so a
  50k-prefix install doesn't OOM the worker — callers enforce it.

The token is operator-supplied in the request body and **never logged**
(non-negotiable #6) — only the base URL appears in log lines.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
import structlog

from app.core.exc_text import describe_exc

logger = structlog.get_logger(__name__)

# DRF page size we request. NetBox's default is 50; 500 keeps the round
# trips low without tipping the server's max_page_size (1000) ceiling.
MAX_PAGE_SIZE = 500

# Pull-side ceiling on the total number of rows a single import may pull
# (§3.8). Mirrors the PowerDNS importer's ~5000-zone cap — rejects an
# oversized pull and asks the operator to narrow scope with filters
# rather than OOM the worker. The committer itself has no per-row cap.
PULL_CEILING = 25_000

# Default per-request timeouts. Generous read so a slow NetBox under a
# fronting proxy doesn't trip mid-page; short connect so a wrong host
# fails fast.
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)

# Backoff ceiling for the 429 / 5xx retry loop.
_RETRY_BACKOFF_CAP = 60.0
_MAX_RETRIES = 5


class NetBoxClientError(ValueError):
    """Raised when the NetBox API can't be reached or returns an error.

    A ``ValueError`` subclass so the router can map it to a 502 (bad
    upstream) the same way the PowerDNS importer maps
    ``PowerDNSImportError``. The operator-facing message surfaces the
    NetBox JSON ``detail`` field on 401/403/404 where available.
    """


def _auth_header(token: str) -> dict[str, str]:
    """Build the ``Authorization`` header, picking the scheme word.

    NetBox 4.5+ ships v2 tokens prefixed ``nbt_`` that use the standard
    ``Bearer`` scheme; every earlier token (and the v1 tokens still valid
    on 4.5/4.6) uses NetBox's custom ``Token`` scheme. The operator
    pastes the full token string; we detect the scheme from the prefix.
    """
    scheme = "Bearer" if token.startswith("nbt_") else "Token"
    return {"Authorization": f"{scheme} {token}", "Accept": "application/json"}


def _normalize_base(base_url: str) -> str:
    """Strip a trailing slash + any trailing ``/api`` from the base URL.

    The operator may paste ``https://netbox.example.com``,
    ``…/`` or ``…/api`` — normalize so endpoint paths concatenate cleanly
    (``{base}/api/status/``).
    """
    base = base_url.strip().rstrip("/")
    if base.endswith("/api"):
        base = base[: -len("/api")]
    return base


class NetBoxClient:
    """Async NetBox REST client scoped to one import run.

    Use as an async context manager::

        async with NetBoxClient(base_url=..., token=..., verify_tls=...) as nb:
            version = await nb.detect_version()
            async for obj in nb.paginate("/api/ipam/prefixes/"):
                ...

    Holds one :class:`httpx.AsyncClient` for the lifetime of the import so
    connection pooling carries across every endpoint pull.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        verify_tls: bool = True,
        timeout: httpx.Timeout | None = None,
    ) -> None:
        self._base = _normalize_base(base_url)
        self._headers = _auth_header(token)
        self._verify_tls = verify_tls
        self._timeout = timeout or DEFAULT_TIMEOUT
        self._client: httpx.AsyncClient | None = None
        # Cached detected version ("major.minor") once probed.
        self.netbox_version: str | None = None
        self.api_version: str | None = None

    @property
    def base_url(self) -> str:
        return self._base

    async def __aenter__(self) -> NetBoxClient:
        if not self._verify_tls:
            # Operator opted out of TLS verification for this endpoint.
            # Surface it on every connect so the insecure posture is
            # visible in the centralized logs; the who/when of enabling
            # it lives in the import audit row. Token never logged.
            logger.warning("netbox_import.tls_verification_disabled", endpoint=self._base)
        self._client = httpx.AsyncClient(
            headers=self._headers,
            verify=self._verify_tls,
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _abs(self, path: str) -> str:
        """Resolve a relative endpoint path against the base URL.

        Absolute URLs (the DRF ``next`` link) pass through unchanged.
        """
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self._base}/{path.lstrip('/')}"

    async def _get_with_retry(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        *,
        max_tries: int = _MAX_RETRIES,
    ) -> httpx.Response:
        """GET with 429 / 5xx retry + operator-facing error surfacing.

        * 429 → sleep ``Retry-After`` (or the current backoff) and retry.
        * 502 / 503 / 504 → exponential backoff and retry.
        * 401 / 403 / 404 → raise :class:`NetBoxClientError` surfacing the
          NetBox JSON ``detail`` field (bad token, ACL denial, bad
          endpoint).
        * any other 4xx/5xx → raise with a truncated body snippet.
        """
        assert self._client is not None, "use within 'async with'"
        target = self._abs(url)
        delay = 1.0
        for _ in range(max_tries):
            try:
                resp = await self._client.get(target, params=params)
            except httpx.HTTPError as exc:
                raise NetBoxClientError(f"{target}: {describe_exc(exc)}") from exc

            status = resp.status_code
            if status == 429:
                retry_after = resp.headers.get("Retry-After")
                sleep_for = float(retry_after) if retry_after else delay
                await asyncio.sleep(sleep_for)
                delay = min(delay * 2, _RETRY_BACKOFF_CAP)
                continue
            if status in (502, 503, 504):
                await asyncio.sleep(delay)
                delay = min(delay * 2, _RETRY_BACKOFF_CAP)
                continue
            if status in (401, 403, 404):
                raise NetBoxClientError(self._error_detail(resp))
            if status >= 400:
                raise NetBoxClientError(f"{target}: HTTP {status} {resp.text[:200]}")
            return resp

        # Exhausted retries on a throttle / transient 5xx (network errors
        # raise immediately above, so this is only the retry-loop give-up).
        raise NetBoxClientError(
            f"{target}: gave up after {max_tries} retries (throttled / upstream 5xx)"
        )

    @staticmethod
    def _error_detail(resp: httpx.Response) -> str:
        """Pull the operator-facing message out of a NetBox error body."""
        code = resp.status_code
        label = {401: "no / invalid token", 403: "token ACL denied", 404: "not found"}.get(
            code, "error"
        )
        detail = ""
        try:
            body = resp.json()
            if isinstance(body, dict):
                detail = str(body.get("detail") or "")
        except (ValueError, httpx.HTTPError):
            detail = resp.text[:200]
        suffix = f": {detail}" if detail else ""
        return f"HTTP {code} ({label}){suffix}"

    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET one endpoint and return its parsed JSON body."""
        resp = await self._get_with_retry(path, params)
        return resp.json()

    async def detect_version(self) -> str:
        """Probe ``GET /api/status/`` and return ``"major.minor"``.

        Prefers the ``API-Version`` response header (present on every
        NetBox); falls back to the body's ``netbox-version`` field. The
        result drives the prefix / VLAN ``site`` → ``scope`` parse branch
        in :mod:`app.services.netbox_import.fetch`. Caches the result on
        the client for repeat callers.
        """
        resp = await self._get_with_retry("/api/status/")
        header_version = resp.headers.get("API-Version")
        body: dict[str, Any] = {}
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                body = parsed
        except (ValueError, httpx.HTTPError):
            body = {}
        nb_full = str(body.get("netbox-version") or "")
        version = header_version or ".".join(nb_full.split(".")[:2])
        self.api_version = header_version
        self.netbox_version = nb_full or version
        logger.info(
            "netbox_import.version_detected",
            endpoint=self._base,
            api_version=header_version,
            netbox_version=nb_full,
        )
        return version

    async def paginate(
        self,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield every object from a paginated NetBox list endpoint.

        Follows the DRF envelope's absolute ``next`` URL (which bakes in
        the filters + offset) so we never hand-compute pagination. The
        caller's ``params`` are applied only on the first request — the
        ``next`` link already carries them forward.
        """
        merged = {"limit": MAX_PAGE_SIZE, **(params or {})}
        next_url: str | None = url
        first = True
        while next_url:
            body = await self.get_json(next_url, merged if first else None)
            if not isinstance(body, dict):
                raise NetBoxClientError(f"{self._abs(next_url)}: unexpected non-object response")
            for obj in body.get("results", []):
                if isinstance(obj, dict):
                    yield obj
            raw_next = body.get("next")
            next_url = self._normalize_next(raw_next) if raw_next else None
            first = False

    def _normalize_next(self, raw_next: str) -> str:
        """Rebase the ``next`` URL onto the operator's base URL.

        NetBox builds the absolute ``next`` link from its own configured
        hostname, which may differ from the URL the operator pasted (a
        reverse-proxy / split-horizon DNS case). Keep the path + query
        from ``next`` but force the scheme + host of our base so we keep
        talking to the same endpoint we authenticated against.
        """
        nxt = urlsplit(raw_next)
        base = urlsplit(self._base)
        return urlunsplit((base.scheme, base.netloc, nxt.path, nxt.query, ""))

    async def authentication_check(self) -> bool:
        """Validate creds without pulling data (NetBox 4.5+).

        ``GET /api/authentication-check/`` is a cheap auth probe. On older
        NetBox the endpoint is absent (404) — we treat that as "couldn't
        check here" and let the caller fall back to ``/api/status/``.
        Returns ``True`` on 200, ``False`` on a 404 (endpoint absent);
        re-raises a real auth error (401/403).
        """
        try:
            await self._get_with_retry("/api/authentication-check/")
            return True
        except NetBoxClientError as exc:
            if "404" in str(exc):
                return False
            raise
