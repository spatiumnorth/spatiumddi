"""Async httpx phpIPAM REST client for the one-shot importer (issue #4734).

phpIPAM's API lives at ``{base}/api/{app_id}/{controller}/`` and wraps every
answer in an envelope, ``{"code": 200, "success": true, "data": ...}``. The
client handles:

* **Auth** — either the app's own code, sent as the ``token`` header (the
  "SSL with app code token" security mode), or a username + password exchanged
  once for a session token with ``POST /user/`` (HTTP Basic), which is then
  sent as the same header. Credentials are operator-supplied per request and
  **never logged or echoed** (non-negotiable #6); only the base URL is.
* **Empty answers** — phpIPAM answers an empty list with HTTP 404 and an
  envelope ``{"code": 404, "success": false, "message": "No subnets found"}``.
  :meth:`get_list` turns exactly that (a 404 that carries a JSON envelope) into
  ``[]``; a 404 from anything else (a wrong base URL answers an HTML page) is an
  error.
* **Bounds** — phpIPAM has no pagination: a list endpoint answers in one body.
  What bounds a pull instead is :data:`MAX_RESPONSE_BYTES` per response, the
  caller's :data:`PULL_CEILING` row ceiling, and the per-subnet shape of the
  address pull (one request per subnet, never one request for everything).
* **Retry / throttle** — 429 honours ``Retry-After``; 502 / 503 / 504 back off
  exponentially, a bounded number of times, unless the body is phpIPAM's own
  ``success: false`` envelope (a real refusal, e.g. 503 "SSL connection is
  required for API" for a plain-http URL), which is raised at once.
* **TLS** — verification is on; ``verify_tls=False`` is an explicit opt-out
  that logs a WARNING on every connect.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.core.exc_text import describe_exc

logger = structlog.get_logger(__name__)

# Ceiling on the prefix + address rows one import may pull, so a very large
# phpIPAM does not exhaust the worker. Over it the preview refuses and asks the
# operator to narrow the pull (section / family / within_include).
PULL_CEILING = 25_000

# One response body larger than this is refused (a hostile or misconfigured
# endpoint must not fill memory). A 25 000-address subnet is a few MB.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)

_RETRY_BACKOFF_CAP = 60.0
_MAX_RETRIES = 5

_APP_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class PhpipamClientError(ValueError):
    """phpIPAM could not be reached, refused the credentials, or answered badly.

    A ``ValueError`` subclass so the router maps it to a 502 (bad upstream), the
    way the NetBox importer maps its client error.
    """


def _normalize_base(base_url: str) -> str:
    """Strip a trailing slash, ``/api`` or ``/api/<app_id>`` from the base URL.

    The operator may paste the site root or the API root; either way endpoint
    paths concatenate as ``{base}/api/{app_id}/...``.
    """
    base = base_url.strip().rstrip("/")
    base = re.sub(r"/api(/[^/]+)?$", "", base)
    return base


class PhpipamClient:
    """Async phpIPAM client scoped to one import run.

    Use as an async context manager; it authenticates on entry::

        async with PhpipamClient(base_url=..., app_id=..., token=...) as ipam:
            sections = await ipam.get_list("/sections/")
    """

    def __init__(
        self,
        *,
        base_url: str,
        app_id: str,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool = True,
        timeout: httpx.Timeout | None = None,
    ) -> None:
        if not _APP_ID_RE.match(app_id or ""):
            raise PhpipamClientError("app_id must be the phpIPAM API application id")
        if not token and not (username and password):
            raise PhpipamClientError("provide an app-code token, or a username and password")
        self._base = _normalize_base(base_url)
        self._api = f"{self._base}/api/{quote(app_id, safe='')}"
        self._token = token or None
        self._username = username
        self._password = password
        self._verify_tls = verify_tls
        self._timeout = timeout or DEFAULT_TIMEOUT
        self._client: httpx.AsyncClient | None = None

    @property
    def base_url(self) -> str:
        return self._base

    async def __aenter__(self) -> PhpipamClient:
        if not self._verify_tls:
            # The who/when of opting out lives in the audit row; this makes the
            # insecure posture visible in the centralized logs on every connect.
            logger.warning("phpipam_import.tls_verification_disabled", endpoint=self._base)
        self._client = httpx.AsyncClient(
            verify=self._verify_tls, timeout=self._timeout, headers={"Accept": "application/json"}
        )
        try:
            if self._token is None:
                self._token = await self._login()
        except BaseException:
            await self._client.aclose()
            self._client = None
            raise
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _login(self) -> str:
        """Exchange username + password for a session token (``POST /user/``)."""
        assert self._client is not None
        try:
            resp = await self._client.post(
                f"{self._api}/user/", auth=(self._username or "", self._password or "")
            )
        except httpx.HTTPError as exc:
            raise PhpipamClientError(f"{self._base}: {describe_exc(exc)}") from exc
        body = self._envelope(resp.content)
        data = body.get("data") if isinstance(body, dict) else None
        token = data.get("token") if isinstance(data, dict) else None
        if resp.status_code >= 400 or not isinstance(token, str) or not token:
            raise PhpipamClientError(self._error_text(resp.status_code, body))
        return token

    @staticmethod
    def _envelope(raw: bytes) -> Any:
        try:
            return json.loads(raw)
        except ValueError:
            return None

    @staticmethod
    def _error_text(code: int, body: Any) -> str:
        label = {
            401: "unauthorised: bad token or credentials",
            403: "forbidden",
            404: "not found",
            503: "refused by phpIPAM",
        }.get(code, "error")
        detail = ""
        if isinstance(body, dict):
            detail = str(body.get("message") or "")
        return f"HTTP {code} ({label}){': ' + detail if detail else ''}"

    async def _get(self, path: str) -> tuple[int, Any]:
        """GET one API path, return ``(http_status, parsed_envelope_or_None)``.

        Retries 429 / 502 / 503 / 504; raises on a transport error, an oversized
        body, or any other 4xx / 5xx except a JSON 404 (the empty-list answer,
        which the caller interprets).
        """
        assert self._client is not None, "use within 'async with'"
        url = f"{self._api}/{path.lstrip('/')}"
        delay = 1.0
        for _ in range(_MAX_RETRIES):
            try:
                status, retry_after, raw = await self._fetch_capped(url, path)
            except httpx.HTTPError as exc:
                raise PhpipamClientError(f"{self._base}: {describe_exc(exc)}") from exc
            if status == 429:
                await asyncio.sleep(float(retry_after) if retry_after.isdigit() else delay)
                delay = min(delay * 2, _RETRY_BACKOFF_CAP)
                continue
            body = self._envelope(raw)
            # phpIPAM itself answers 503 with a JSON envelope for a refusal that
            # retrying never fixes ("SSL connection is required for API" on a
            # plain-http URL); only a 503 / 502 / 504 without one is a transient
            # gateway failure.
            phpipam_refusal = isinstance(body, dict) and body.get("success") is False
            if status in (502, 503, 504) and not phpipam_refusal:
                await asyncio.sleep(delay)
                delay = min(delay * 2, _RETRY_BACKOFF_CAP)
                continue
            if status == 404 and isinstance(body, dict) and body.get("success") is False:
                return 404, body
            if status >= 400:
                raise PhpipamClientError(self._error_text(status, body))
            return status, body
        raise PhpipamClientError(f"{url}: gave up after {_MAX_RETRIES} retries (throttled / 5xx)")

    async def _fetch_capped(self, url: str, path: str) -> tuple[int, str, bytes]:
        """GET ``url``; ``(status, Retry-After, body)``, the body capped at
        :data:`MAX_RESPONSE_BYTES`.

        Streamed so an oversized answer is refused as it arrives, not after it
        has been buffered whole.
        """
        assert self._client is not None
        async with self._client.stream("GET", url, headers={"token": self._token or ""}) as resp:
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise PhpipamClientError(
                        f"{path}: response over the {MAX_RESPONSE_BYTES // (1024 * 1024)} MB "
                        "limit; narrow the import with a section / family / within_include filter"
                    )
                chunks.append(chunk)
            return resp.status_code, resp.headers.get("Retry-After", ""), b"".join(chunks)

    async def get_data(self, path: str) -> Any:
        """The envelope's ``data`` for one path, or ``None`` when it answered 404."""
        status, body = await self._get(path)
        if status == 404:
            return None
        if not isinstance(body, dict) or body.get("success") is False:
            raise PhpipamClientError(f"{path}: unexpected answer from phpIPAM")
        return body.get("data")

    async def get_list(self, path: str) -> list[dict[str, Any]]:
        """Every object of a list endpoint; ``[]`` for phpIPAM's empty-list 404.

        A single-object answer (some endpoints return the object, not a list) is
        wrapped so callers always iterate.
        """
        data = await self.get_data(path)
        if data is None:
            return []
        if isinstance(data, dict):
            return [data]
        if not isinstance(data, list):
            raise PhpipamClientError(f"{path}: unexpected non-list answer from phpIPAM")
        return [o for o in data if isinstance(o, dict)]
