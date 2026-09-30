"""Google Cloud Storage backup destination (issue #117 Phase 2 — Tier 2).

Writes archives to a GCS bucket. Authentication is via a
service-account JSON key the operator pastes into the form;
the backend doesn't lean on Application Default Credentials
because the api / worker containers don't carry GCP metadata
identity by default.

Config shape:

* ``bucket`` — required.
* ``prefix`` — optional object-name prefix
  (``"backups/"``) so multiple installs can share a bucket.
* ``service_account_json`` — required, **secret** (Fernet-
  wrapped at rest). The full JSON key as exported from GCP
  IAM ("Keys → ADD KEY → JSON").

Implementation notes:

* google-cloud-storage is sync; every method wraps the
  underlying calls in :func:`asyncio.to_thread`.
* A fresh ``Client`` is created per call. The SDK caches HTTP
  connections internally, so per-call cost is negligible.
* We parse the JSON key once per call and feed it through
  ``Credentials.from_service_account_info``. Failing fast on
  invalid JSON is more useful than letting the SDK crash on
  the first API call.
* Listings reuse the same archive-name regex as the other
  drivers — a shared bucket with unrelated objects stays
  clean.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.backup.targets.base import (
    ARCHIVE_NAME_RE,
    ArchiveListing,
    BackupDestination,
    BackupDestinationError,
    ConfigFieldSpec,
    DestinationConfigError,
    safe_filename,
)

logger = structlog.get_logger(__name__)


def _client(config: dict[str, Any]):
    """Build a fresh GCS ``Client``. Lazy import keeps installs
    that don't use GCS off the import-graph cost.
    """
    from google.cloud.storage import Client  # noqa: PLC0415
    from google.oauth2.service_account import Credentials  # noqa: PLC0415

    raw = config.get("service_account_json") or ""
    try:
        info = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DestinationConfigError(f"'service_account_json' is not valid JSON: {exc}") from exc
    try:
        creds = Credentials.from_service_account_info(info)
    except Exception as exc:  # noqa: BLE001
        raise DestinationConfigError(
            f"'service_account_json' rejected by GCP credentials parser: {exc}"
        ) from exc
    project = info.get("project_id")
    return Client(project=project, credentials=creds)


def _object_name(config: dict[str, Any], filename: str) -> str:
    """Compose the object name from the optional prefix +
    filename. ``safe_filename`` refuses operator-supplied paths
    that would escape the prefix.
    """
    prefix = (config.get("prefix") or "").strip("/")
    safe = safe_filename(filename)
    return f"{prefix}/{safe}" if prefix else safe


def _strip_prefix(config: dict[str, Any], name: str) -> str:
    prefix = (config.get("prefix") or "").strip("/")
    if prefix and name.startswith(prefix + "/"):
        return name[len(prefix) + 1 :]
    return name


class GcsDestination(BackupDestination):
    kind = "gcs"
    label = "Google Cloud Storage"
    config_fields = (
        ConfigFieldSpec(
            name="bucket",
            label="Bucket",
            type="text",
            required=True,
            description="Existing bucket name. The driver doesn't create it.",
        ),
        ConfigFieldSpec(
            name="prefix",
            label="Object name prefix",
            type="text",
            required=False,
            description="Optional. e.g. spatiumddi/backups/",
        ),
        ConfigFieldSpec(
            name="service_account_json",
            label="Service-account key JSON",
            type="password",
            required=True,
            secret=True,
            description=(
                "Full JSON key as exported from GCP IAM "
                "('Keys → ADD KEY → JSON'). Encrypted at rest."
            ),
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> None:
        for required in ("bucket", "service_account_json"):
            value = config.get(required)
            if not value or not isinstance(value, str):
                raise DestinationConfigError(
                    f"{required!r} is required and must be a non-empty string"
                )
        prefix = config.get("prefix")
        if prefix and not isinstance(prefix, str):
            raise DestinationConfigError("'prefix' must be a string")
        # Sanity-check JSON syntax up-front so the operator gets a
        # clear error from validate_config rather than a 500 from
        # the first write.
        try:
            info = json.loads(config["service_account_json"])
        except json.JSONDecodeError as exc:
            raise DestinationConfigError(
                f"'service_account_json' is not valid JSON: {exc}"
            ) from exc
        if not isinstance(info, dict) or info.get("type") != "service_account":
            raise DestinationConfigError(
                "'service_account_json' must be a service-account key "
                "(JSON object with type=service_account)"
            )

    async def write(
        self,
        *,
        config: dict[str, Any],
        filename: str,
        archive_bytes: bytes,
    ) -> None:
        name = _object_name(config, filename)

        def _do() -> None:
            from google.api_core.exceptions import GoogleAPIError  # noqa: PLC0415

            client = _client(config)
            try:
                bucket = client.bucket(config["bucket"])
                blob = bucket.blob(name)
                blob.upload_from_string(
                    archive_bytes,
                    content_type="application/zip",
                )
            except GoogleAPIError as exc:
                raise BackupDestinationError(f"GCS upload failed: {exc}") from exc

        await asyncio.to_thread(_do)

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        prefix = (config.get("prefix") or "").strip("/")
        list_prefix = f"{prefix}/" if prefix else ""

        def _do() -> list[ArchiveListing]:
            from google.api_core.exceptions import GoogleAPIError  # noqa: PLC0415

            client = _client(config)
            rows: list[ArchiveListing] = []
            try:
                blobs = client.list_blobs(config["bucket"], prefix=list_prefix)
                for blob in blobs:
                    name = _strip_prefix(config, blob.name)
                    if not ARCHIVE_NAME_RE.match(name):
                        continue
                    if blob.time_created is None:
                        continue
                    ts = blob.time_created
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)
                    rows.append(
                        ArchiveListing(
                            filename=name,
                            size_bytes=int(blob.size or 0),
                            created_at=ts.astimezone(UTC),
                        )
                    )
            except GoogleAPIError as exc:
                raise BackupDestinationError(f"GCS list_blobs failed: {exc}") from exc
            rows.sort(key=lambda r: r.created_at, reverse=True)
            return rows

        return await asyncio.to_thread(_do)

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        name = _object_name(config, filename)

        def _do() -> bytes:
            from google.api_core.exceptions import (  # noqa: PLC0415
                GoogleAPIError,
                NotFound,
            )

            client = _client(config)
            try:
                bucket = client.bucket(config["bucket"])
                blob = bucket.blob(name)
                return blob.download_as_bytes()
            except NotFound as exc:
                raise BackupDestinationError(
                    f"archive {filename!r} not found in bucket {config['bucket']!r}"
                ) from exc
            except GoogleAPIError as exc:
                raise BackupDestinationError(f"GCS download failed: {exc}") from exc

        return await asyncio.to_thread(_do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        name = _object_name(config, filename)

        def _do() -> None:
            from google.api_core.exceptions import (  # noqa: PLC0415
                GoogleAPIError,
                NotFound,
            )

            client = _client(config)
            try:
                bucket = client.bucket(config["bucket"])
                bucket.blob(name).delete()
            except NotFound:
                return  # idempotent
            except GoogleAPIError as exc:
                raise BackupDestinationError(f"GCS delete failed: {exc}") from exc

        await asyncio.to_thread(_do)

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            self.validate_config(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}
        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"
        probe_object = _object_name(config, probe_name)

        def _do() -> dict[str, Any]:
            from google.api_core.exceptions import (  # noqa: PLC0415
                Forbidden,
                GoogleAPIError,
                NotFound,
                Unauthorized,
            )

            try:
                client = _client(config)
            except DestinationConfigError as exc:
                return {"ok": False, "error": str(exc)}
            try:
                bucket = client.bucket(config["bucket"])
                blob = bucket.blob(probe_object)
                blob.upload_from_string(
                    os.urandom(16),
                    content_type="application/octet-stream",
                )
                blob.reload()
                ok = (blob.size or 0) == 16
                blob.delete()
            except (Unauthorized, Forbidden) as exc:
                return {"ok": False, "error": f"auth failed: {exc}"}
            except NotFound as exc:
                return {
                    "ok": False,
                    "error": f"bucket not found or no access: {exc}",
                }
            except GoogleAPIError as exc:
                return {"ok": False, "error": str(exc)}
            if not ok:
                return {
                    "ok": False,
                    "error": "wrote probe but reload disagreed on size",
                }
            return {
                "ok": True,
                "detail": (
                    f"wrote + verified + deleted probe at " f"{config['bucket']}/{probe_object}"
                ),
            }

        try:
            return await asyncio.to_thread(_do)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"unexpected: {exc}"}
