"""Azure Blob Storage backup destination (issue #117 Phase 1d).

Writes archives to a container in an Azure Storage account. The
SDK supports two auth modes; we ship both:

* ``account_key`` — classic shared-key auth (operator pastes the
  account name + a primary/secondary access key).
* ``connection_string`` — the multi-line ``DefaultEndpointsProtocol=…``
  blob Azure shows in the portal. Easier to copy-paste; the SDK
  pulls account name + key out of it itself.

Either credential lands in the operator's hands as a single
``secret=True`` field that's Fernet-wrapped at rest.

Config shape:

* ``account_name`` — required when using account_key auth (with
  connection_string the SDK derives it).
* ``container`` — required.
* ``prefix`` — optional virtual-directory prefix
  (``"backups/"``).
* ``account_key`` — optional, **secret.** Set ONE of
  account_key / connection_string.
* ``connection_string`` — optional, **secret.**

Implementation notes:

* azure-storage-blob is sync; every method wraps the underlying
  client calls in ``asyncio.to_thread``.
* A fresh client is created per call. The SDK caches HTTP
  connections internally so per-call cost is negligible.
* Listing reuses the same archive-name regex as the other
  drivers — a shared container with unrelated blobs stays
  clean.
"""

from __future__ import annotations

import asyncio
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


class AzureBlobDestination(BackupDestination):
    kind = "azure_blob"
    label = "Azure Blob Storage"
    config_fields = (
        ConfigFieldSpec(
            name="account_name",
            label="Storage account name",
            type="text",
            required=False,
            description="Required when using account-key auth. Inferred from the connection string otherwise.",
        ),
        ConfigFieldSpec(
            name="container",
            label="Container",
            type="text",
            required=True,
            description="Existing container — the driver doesn't create it.",
        ),
        ConfigFieldSpec(
            name="prefix",
            label="Blob name prefix",
            type="text",
            required=False,
            description="Optional. e.g. spatiumddi/backups/",
        ),
        ConfigFieldSpec(
            name="account_key",
            label="Account key",
            type="password",
            required=False,
            secret=True,
            description="Set ONE of account_key / connection_string.",
        ),
        ConfigFieldSpec(
            name="connection_string",
            label="Connection string",
            type="password",
            required=False,
            secret=True,
            description="The multi-line DefaultEndpointsProtocol=... blob from the Azure portal.",
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> None:
        container = config.get("container")
        if not container or not isinstance(container, str):
            raise DestinationConfigError("'container' is required and must be a non-empty string")
        has_key = bool(config.get("account_key"))
        has_conn = bool(config.get("connection_string"))
        if not has_key and not has_conn:
            raise DestinationConfigError("set ONE of 'account_key' or 'connection_string'")
        if has_key and not config.get("account_name"):
            raise DestinationConfigError("'account_name' is required when using account-key auth")

    def _container_client(self, config: dict[str, Any]):
        """Return a fresh ``ContainerClient``. Lazy SDK import so
        installs that never use Azure don't pay the import cost.
        """
        from azure.storage.blob import (  # noqa: PLC0415
            BlobServiceClient,
        )

        if config.get("connection_string"):
            svc = BlobServiceClient.from_connection_string(config["connection_string"])
        else:
            account_url = f"https://{config['account_name']}.blob.core.windows.net"
            svc = BlobServiceClient(account_url=account_url, credential=config["account_key"])
        return svc.get_container_client(config["container"])

    def _blob_name(self, config: dict[str, Any], filename: str) -> str:
        prefix = (config.get("prefix") or "").strip("/")
        safe = safe_filename(filename)
        return f"{prefix}/{safe}" if prefix else safe

    def _strip_prefix(self, config: dict[str, Any], blob_name: str) -> str:
        prefix = (config.get("prefix") or "").strip("/")
        if prefix and blob_name.startswith(prefix + "/"):
            return blob_name[len(prefix) + 1 :]
        return blob_name

    async def write(
        self,
        *,
        config: dict[str, Any],
        filename: str,
        archive_bytes: bytes,
    ) -> None:
        blob_name = self._blob_name(config, filename)

        def _do() -> None:
            from azure.core.exceptions import (  # noqa: PLC0415
                AzureError,
            )

            client = self._container_client(config)
            try:
                client.upload_blob(
                    name=blob_name,
                    data=archive_bytes,
                    overwrite=True,
                    content_settings=_content_settings("application/zip"),
                )
            except AzureError as exc:
                raise BackupDestinationError(f"Azure upload_blob failed: {exc}") from exc

        await asyncio.to_thread(_do)

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        prefix = (config.get("prefix") or "").strip("/")
        list_prefix = f"{prefix}/" if prefix else ""

        def _do() -> list[ArchiveListing]:
            from azure.core.exceptions import (  # noqa: PLC0415
                AzureError,
            )

            client = self._container_client(config)
            rows: list[ArchiveListing] = []
            try:
                for blob in client.list_blobs(name_starts_with=list_prefix):
                    name = self._strip_prefix(config, blob.name)
                    if not ARCHIVE_NAME_RE.match(name):
                        continue
                    last_modified = blob.last_modified
                    if last_modified is None:
                        continue
                    if last_modified.tzinfo is None:
                        last_modified = last_modified.replace(tzinfo=UTC)
                    rows.append(
                        ArchiveListing(
                            filename=name,
                            size_bytes=int(blob.size or 0),
                            created_at=last_modified.astimezone(UTC),
                        )
                    )
            except AzureError as exc:
                raise BackupDestinationError(f"Azure list_blobs failed: {exc}") from exc
            rows.sort(key=lambda r: r.created_at, reverse=True)
            return rows

        return await asyncio.to_thread(_do)

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        blob_name = self._blob_name(config, filename)

        def _do() -> bytes:
            from azure.core.exceptions import (  # noqa: PLC0415
                AzureError,
                ResourceNotFoundError,
            )

            client = self._container_client(config)
            try:
                stream = client.get_blob_client(blob_name).download_blob()
                return stream.readall()
            except ResourceNotFoundError as exc:
                raise BackupDestinationError(
                    f"archive {filename!r} not found in container " f"{config['container']!r}"
                ) from exc
            except AzureError as exc:
                raise BackupDestinationError(f"Azure download_blob failed: {exc}") from exc

        return await asyncio.to_thread(_do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        blob_name = self._blob_name(config, filename)

        def _do() -> None:
            from azure.core.exceptions import (  # noqa: PLC0415
                AzureError,
                ResourceNotFoundError,
            )

            client = self._container_client(config)
            try:
                client.delete_blob(blob_name)
            except ResourceNotFoundError:
                return  # idempotent
            except AzureError as exc:
                raise BackupDestinationError(f"Azure delete_blob failed: {exc}") from exc

        await asyncio.to_thread(_do)

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            self.validate_config(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}

        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"
        probe_blob = self._blob_name(config, probe_name)

        def _do() -> dict[str, Any]:
            from azure.core.exceptions import (  # noqa: PLC0415
                AzureError,
                ClientAuthenticationError,
                ResourceNotFoundError,
            )

            client = self._container_client(config)
            try:
                client.upload_blob(
                    name=probe_blob,
                    data=os.urandom(16),
                    overwrite=True,
                )
                props = client.get_blob_client(probe_blob).get_blob_properties()
                ok = (props.size or 0) == 16
                client.delete_blob(probe_blob)
            except ClientAuthenticationError as exc:
                return {"ok": False, "error": f"auth failed: {exc}"}
            except ResourceNotFoundError as exc:
                return {
                    "ok": False,
                    "error": f"container or path not found: {exc}",
                }
            except AzureError as exc:
                return {"ok": False, "error": str(exc)}
            if not ok:
                return {
                    "ok": False,
                    "error": "wrote probe but get_blob_properties disagreed on size",
                }
            return {
                "ok": True,
                "detail": f"wrote + verified + deleted probe at {probe_blob}",
            }

        return await asyncio.to_thread(_do)


def _content_settings(content_type: str):
    """Lazy ContentSettings constructor — only imported when a
    write actually happens.
    """
    from azure.storage.blob import ContentSettings  # noqa: PLC0415

    return ContentSettings(content_type=content_type)
