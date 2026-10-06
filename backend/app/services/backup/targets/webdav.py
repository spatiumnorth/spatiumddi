"""WebDAV backup destination (issue #117 Phase 3 — Tier 3).

Writes archives to a WebDAV server — Nextcloud, ownCloud, Apache
``mod_dav``, IIS WebDAV, or any RFC 4918 server. Implemented over
``httpx`` (already a platform dependency) using the four verbs we
need: ``PUT`` (write), ``GET`` (read / download), ``PROPFIND``
(list), ``DELETE`` (delete). No SDK dependency; the WebDAV
protocol surface is small enough to drive directly.

Config shape:

* ``url`` — full base URL of the WebDAV collection
  (``https://nextcloud.example/remote.php/dav/files/alice/backups``).
  The driver does not auto-discover Nextcloud / ownCloud paths;
  operators paste the full URL.
* ``username`` — required.
* ``password`` — required, **secret** (Fernet-wrapped at rest).
  Nextcloud users who've enabled 2FA need to mint an "app
  password" in their settings; the operator-facing label below
  flags this.
* ``verify_tls`` — ``"true"`` (default) for production. Set
  ``"false"`` only for self-signed homelabs.

Implementation notes:

* httpx is sync-by-default but we drive the async client so the
  driver doesn't need ``asyncio.to_thread`` wrapping. Per-call
  client construction matches the other destinations — the SDK
  reuses HTTP connections internally so per-call cost is small.
* PROPFIND replies are XML; we use stdlib ``xml.etree`` to walk
  ``<d:response>`` elements rather than pulling in ``lxml``.
* Listings reuse the same archive-name regex as the other
  drivers — a shared collection with unrelated files stays
  clean.
* WebDAV servers vary on the ``Depth: 1`` PROPFIND envelope. We
  send a minimal request body with ``getlastmodified`` +
  ``getcontentlength`` + ``resourcetype`` properties, which
  every RFC 4918 implementation honours.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote, unquote, urljoin, urlsplit

import httpx
import structlog

from app.services.backup.targets.base import (
    ARCHIVE_NAME_RE,
    ArchiveListing,
    BackupDestination,
    BackupDestinationError,
    ConfigFieldSpec,
    DestinationConfigError,
    safe_filename,
    safe_url,
    scrub_url,
)

logger = structlog.get_logger(__name__)


# Generous timeout — WebDAV against a residential Nextcloud over a
# slow link can stall for tens of seconds on a multi-MB upload.
_WEBDAV_TIMEOUT = httpx.Timeout(120.0)

# Minimal PROPFIND body — just the properties we display in the
# archive list. Servers that don't honour ``allprop`` are happy
# with this explicit form.
_PROPFIND_BODY = b"""<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:getlastmodified/>
    <d:getcontentlength/>
    <d:resourcetype/>
  </d:prop>
</d:propfind>
"""

# DAV: namespace for ElementTree XPath. Webdav servers occasionally
# echo the namespace under a different prefix (``D:`` vs ``d:``); the
# fully-qualified namespace string is the only stable handle.
_DAV_NS = "{DAV:}"


def _ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


class WebDAVDestination(BackupDestination):
    kind = "webdav"
    label = "WebDAV (Nextcloud / ownCloud)"
    config_fields = (
        ConfigFieldSpec(
            name="url",
            label="Collection URL",
            type="text",
            required=True,
            description=(
                "Full URL of the WebDAV collection where archives "
                "land. Nextcloud example: "
                "https://nc.example.com/remote.php/dav/files/alice/backups"
            ),
        ),
        ConfigFieldSpec(
            name="username",
            label="Username",
            type="text",
            required=True,
        ),
        ConfigFieldSpec(
            name="password",
            label="Password",
            type="password",
            required=True,
            secret=True,
            description=(
                "If the user has 2FA enabled (typical on Nextcloud), "
                "create an 'app password' in their settings and paste "
                "that here — the regular login password won't work."
            ),
        ),
        ConfigFieldSpec(
            name="verify_tls",
            label="Verify TLS certificate",
            type="text",
            required=False,
            description="'true' (default) for production. Set 'false' only for self-signed labs.",
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> None:
        for required in ("url", "username", "password"):
            value = config.get(required)
            if not value or not isinstance(value, str):
                raise DestinationConfigError(
                    f"{required!r} is required and must be a non-empty string"
                )
        url = config["url"]
        if not (url.startswith("http://") or url.startswith("https://")):
            raise DestinationConfigError("'url' must start with http:// or https://")
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise DestinationConfigError(f"'url' is not a parseable URL: {exc}") from exc
        if not parts.hostname:
            # A scheme-prefixed string with no host ("https:///x")
            # passed the prefix check and only failed later, inside
            # httpx, as an InvalidURL the old catches missed (#1515).
            raise DestinationConfigError("'url' must name a host, e.g. https://host/path")

    def _client(self, config: dict[str, Any]) -> httpx.AsyncClient:
        verify = (config.get("verify_tls") or "true").strip().lower() != "false"
        return httpx.AsyncClient(
            auth=(config["username"], config["password"]),
            timeout=_WEBDAV_TIMEOUT,
            verify=verify,
            follow_redirects=True,
        )

    def _archive_url(self, config: dict[str, Any], filename: str) -> str:
        # Percent-encoded, not just checked (#1243): ``safe_filename``
        # refuses a literal ``..``, but a name that ARRIVES encoded
        # (``%2E%2E``) is one plain component to us and a dot-segment to
        # a server that normalises after decoding (RFC 3986 §2.3 makes
        # ``%2E`` equivalent to ``.``). Quoting sends it as ``%252E%252E``,
        # which decodes to the literal name and nothing else. The names we
        # write are ``[A-Za-z0-9._-]``, which ``quote`` leaves alone.
        return urljoin(
            _ensure_trailing_slash(config["url"]),
            quote(safe_filename(filename), safe=""),
        )

    async def write(
        self,
        *,
        config: dict[str, Any],
        filename: str,
        archive_bytes: bytes,
    ) -> None:
        target = self._archive_url(config, filename)
        async with self._client(config) as client:
            try:
                resp = await client.put(
                    target,
                    content=archive_bytes,
                    headers={"Content-Type": "application/zip"},
                )
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                # ``httpx.InvalidURL`` does not derive from
                # ``httpx.HTTPError`` (the #889 trap, #1515) — caught
                # explicitly at every call site in this driver, like
                # https_put, so a malformed stored URL is a 502-shaped
                # destination error, not a runner-escaping exception.
                raise BackupDestinationError(
                    f"WebDAV PUT failed: {scrub_url(str(exc), target)}"
                ) from exc
        if resp.status_code not in (200, 201, 204):
            raise BackupDestinationError(
                f"WebDAV PUT returned {resp.status_code}: {resp.text[:300]}"
            )

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        from xml.etree import ElementTree as ET  # noqa: PLC0415, S405

        url = _ensure_trailing_slash(config["url"])
        async with self._client(config) as client:
            try:
                resp = await client.request(
                    "PROPFIND",
                    url,
                    content=_PROPFIND_BODY,
                    headers={
                        "Depth": "1",
                        "Content-Type": "application/xml",
                    },
                )
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                raise BackupDestinationError(
                    f"WebDAV PROPFIND failed: {scrub_url(str(exc), url)}"
                ) from exc
        if resp.status_code == 404:
            raise BackupDestinationError(
                f"WebDAV collection {safe_url(url)!r} not found — verify the URL is correct"
            )
        if resp.status_code != 207:
            raise BackupDestinationError(
                f"WebDAV PROPFIND returned {resp.status_code}: {resp.text[:300]}"
            )
        try:
            tree = ET.fromstring(resp.content)  # noqa: S314 - server-controlled XML
        except ET.ParseError as exc:
            raise BackupDestinationError(f"WebDAV PROPFIND xml parse failed: {exc}") from exc

        rows: list[ArchiveListing] = []
        for response in tree.findall(f"{_DAV_NS}response"):
            href_el = response.find(f"{_DAV_NS}href")
            if href_el is None or not href_el.text:
                continue
            # Skip the collection itself — its href ends with the
            # collection path.
            href = href_el.text
            # Decoded, because ``_archive_url`` encodes: a name returned
            # still encoded would be encoded twice on the way back and
            # name an object that does not exist.
            name = unquote(os.path.basename(href.rstrip("/")))
            if not ARCHIVE_NAME_RE.match(name):
                continue
            propstat = response.find(f"{_DAV_NS}propstat/{_DAV_NS}prop")
            if propstat is None:
                continue
            # Skip directories
            rt = propstat.find(f"{_DAV_NS}resourcetype")
            if rt is not None and rt.find(f"{_DAV_NS}collection") is not None:
                continue
            size_el = propstat.find(f"{_DAV_NS}getcontentlength")
            modified_el = propstat.find(f"{_DAV_NS}getlastmodified")
            if modified_el is None or not modified_el.text:
                continue
            try:
                ts = parsedate_to_datetime(modified_el.text)
            except (TypeError, ValueError):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            try:
                size = int(size_el.text or "0") if size_el is not None else 0
            except ValueError:
                size = 0
            rows.append(
                ArchiveListing(
                    filename=name,
                    size_bytes=size,
                    created_at=ts.astimezone(UTC),
                )
            )
        rows.sort(key=lambda r: r.created_at, reverse=True)
        return rows

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        target = self._archive_url(config, filename)
        async with self._client(config) as client:
            try:
                resp = await client.get(target)
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                raise BackupDestinationError(f"WebDAV GET failed: {exc}") from exc
        if resp.status_code == 404:
            raise BackupDestinationError(
                f"archive {safe_filename(filename)!r} not found at {safe_url(target)}"
            )
        if resp.status_code != 200:
            raise BackupDestinationError(
                f"WebDAV GET returned {resp.status_code}: {resp.text[:300]}"
            )
        return resp.content

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        target = self._archive_url(config, filename)
        async with self._client(config) as client:
            try:
                resp = await client.delete(target)
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                raise BackupDestinationError(f"WebDAV DELETE failed: {exc}") from exc
        # 404 is idempotent; 200 / 204 are success
        if resp.status_code in (200, 204, 404):
            return
        raise BackupDestinationError(
            f"WebDAV DELETE returned {resp.status_code}: {resp.text[:300]}"
        )

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            self.validate_config(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}
        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"
        probe_target = self._archive_url(config, probe_name)
        async with self._client(config) as client:
            try:
                # Step 1: write a 16-byte probe.
                put = await client.put(
                    probe_target,
                    content=os.urandom(16),
                    headers={"Content-Type": "application/octet-stream"},
                )
                if put.status_code in (401, 403):
                    return {
                        "ok": False,
                        "error": (
                            f"auth failed ({put.status_code}). On Nextcloud, generate an "
                            "'app password' if 2FA is enabled."
                        ),
                    }
                if put.status_code not in (200, 201, 204):
                    return {
                        "ok": False,
                        "error": f"PUT returned {put.status_code}: {put.text[:200]}",
                    }
                # Step 2: HEAD to confirm it's there + the size matches.
                head = await client.head(probe_target)
                content_length = int(head.headers.get("content-length", "0"))
                if content_length != 16:
                    return {
                        "ok": False,
                        "error": (
                            f"wrote probe but HEAD reported {content_length} bytes, " "expected 16"
                        ),
                    }
                # Step 3: clean up.
                delete = await client.delete(probe_target)
                if delete.status_code not in (200, 204, 404):
                    return {
                        "ok": False,
                        "error": (
                            f"probe written but DELETE returned {delete.status_code} — "
                            "fix permissions before scheduling"
                        ),
                    }
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                return {"ok": False, "error": f"webdav: {exc}"}
        return {
            "ok": True,
            "detail": f"wrote + verified + deleted probe at {safe_url(probe_target)}",
        }
