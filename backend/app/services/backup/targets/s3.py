"""AWS S3 + S3-compatible backup destination (issue #117 Phase 1c).

Covers AWS S3 plus every S3-compatible service we care about
via the ``endpoint_url`` config field — MinIO, Wasabi, Backblaze
B2, Cloudflare R2, DigitalOcean Spaces, Linode Object Storage.
Operators leaving ``endpoint_url`` blank get the AWS endpoint
for the configured region.

Config shape:

* ``bucket`` — required.
* ``region`` — required even for S3-compatible (boto3 still
  needs one in the signing path; ``us-east-1`` is the safe
  default for non-AWS endpoints).
* ``prefix`` — optional key prefix (``"backups/"``) so multiple
  installs can share a bucket.
* ``endpoint_url`` — optional; populates for S3-compatible.
* ``access_key_id`` — required, plaintext.
* ``secret_access_key`` — required, **secret** (Fernet-wrapped
  in JSONB via :mod:`app.services.backup.targets.secrets_config`).
* ``addressing_style`` — optional (``"virtual"`` / ``"path"``).
  Defaults to virtual; some MinIO deploys + older bucket names
  with dots need ``"path"``.
* ``object_lock_mode`` — optional ``none`` (default) /
  ``governance`` / ``compliance`` (issue #989 item 1).
* ``object_lock_days`` — retention period in days when a lock mode
  is set.

Object Lock (#989 item 1)
-------------------------

``compliance`` is the interesting one: not even the bucket owner can
delete an object before its retain-until date, so retention holds
regardless of what credential leaks. Paired with
``backup_target.write_only`` and an IAM key carrying ``PutObject`` +
``GetObject`` + ``ListBucket`` and **no** ``DeleteObject``, nothing
SpatiumDDI holds can shorten retention — while restore-from-destination
and restore drills keep working, because those only read.

Two details that are easy to get wrong:

* The **probe object is written without lock headers.** Writing a probe
  under a 30-day compliance lock would leave undeletable litter in the
  bucket every time an operator clicks Test. If the bucket carries a
  *default* retention rule the probe is retained anyway — that is the
  bucket's choice, not ours, and ``test_connection`` reports it as
  ``probe_retained`` rather than failing.
* The prune reads ``ObjectLockRetainUntilDate`` from ``head_object``
  and skips a locked object **quietly**. A refused delete on a locked
  bucket is the feature working; logging it per file per night would
  make correct configuration indistinguishable from breakage.

Implementation notes:

* boto3 is sync; every driver method wraps the underlying
  client calls in :func:`asyncio.to_thread` so the asyncio
  event loop never blocks on a slow upstream.
* A fresh client is created per call. Per-call cost is minimal
  (no real HTTP traffic until the first operation), and the
  alternative (a per-target singleton) introduces lifecycle
  bugs we don't need.
* Probe / archive listings filter to the same regex as the
  local-volume driver — operators sharing a bucket with
  unrelated objects don't see them in our list.
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.backup.targets.base import (
    ArchiveListing,
    BackupDestination,
    BackupDestinationError,
    ConfigFieldSpec,
    DestinationConfigError,
    RetentionLockedError,
    safe_filename,
)

logger = structlog.get_logger(__name__)

# Same archive-name pattern as the local-volume driver.
_ARCHIVE_NAME_RE = re.compile(r"^(spatiumddi-backup-|pre-restore-).*\.zip$")

# boto3 ClientError import is lazy — keeps the import-graph cost off
# the hot path and avoids forcing every install to ship boto3 once
# we add destinations that don't need it.


def _client(config: dict[str, Any]):
    """Build a fresh boto3 S3 client. Lazy boto3 import keeps the
    backup module light for installs that don't use S3.
    """
    import boto3  # noqa: PLC0415
    from botocore.config import Config as BotoConfig  # noqa: PLC0415

    addressing_style = config.get("addressing_style") or "virtual"
    if addressing_style not in {"virtual", "path", "auto"}:
        raise DestinationConfigError(
            f"addressing_style must be 'virtual' / 'path' / 'auto' " f"(got {addressing_style!r})"
        )
    boto_cfg = BotoConfig(
        signature_version="s3v4",
        retries={"max_attempts": 3, "mode": "standard"},
        s3={"addressing_style": addressing_style},
    )
    kwargs: dict[str, Any] = {
        "service_name": "s3",
        "aws_access_key_id": config["access_key_id"],
        "aws_secret_access_key": config["secret_access_key"],
        "region_name": config["region"],
        "config": boto_cfg,
    }
    if config.get("endpoint_url"):
        kwargs["endpoint_url"] = config["endpoint_url"]
    return boto3.client(**kwargs)


def _key(config: dict[str, Any], filename: str) -> str:
    """Compose the object key from the optional prefix + filename.
    ``safe_filename`` refuses operator-typed paths in ``filename``
    that would escape the prefix.
    """
    prefix = (config.get("prefix") or "").strip("/")
    safe = safe_filename(filename)
    if prefix:
        return f"{prefix}/{safe}"
    return safe


#: The two real Object Lock modes, plus the spellings that mean "off".
_LOCK_MODES = {"governance": "GOVERNANCE", "compliance": "COMPLIANCE"}


def _lock_mode(config: dict[str, Any]) -> str | None:
    """Return the S3 API's spelling of the configured lock mode, or
    ``None`` when locking is off. Raises for a value that is neither.
    """
    raw = (config.get("object_lock_mode") or "").strip().lower()
    if raw in ("", "none", "off", "disabled"):
        return None
    if raw not in _LOCK_MODES:
        raise DestinationConfigError(
            f"'object_lock_mode' must be 'none', 'governance' or 'compliance' " f"(got {raw!r})"
        )
    return _LOCK_MODES[raw]


def _lock_headers(config: dict[str, Any]) -> dict[str, Any]:
    """``put_object`` kwargs that apply the configured retention.

    Deliberately NOT applied to the connection probe — see the module
    docstring.
    """
    mode = _lock_mode(config)
    if mode is None:
        return {}
    from datetime import timedelta  # noqa: PLC0415

    days = int(config["object_lock_days"])
    return {
        "ObjectLockMode": mode,
        "ObjectLockRetainUntilDate": datetime.now(UTC) + timedelta(days=days),
    }


def _strip_prefix(config: dict[str, Any], key: str) -> str:
    prefix = (config.get("prefix") or "").strip("/")
    if prefix and key.startswith(prefix + "/"):
        return key[len(prefix) + 1 :]
    return key


class S3Destination(BackupDestination):
    kind = "s3"
    label = "AWS S3 / S3-compatible"
    config_fields = (
        ConfigFieldSpec(
            name="bucket",
            label="Bucket",
            type="text",
            required=True,
            description="Existing bucket name. The driver doesn't create the bucket itself.",
        ),
        ConfigFieldSpec(
            name="region",
            label="Region",
            type="text",
            required=True,
            description=(
                "e.g. us-east-1. Required even for S3-compatible — "
                "boto3 needs one for request signing."
            ),
        ),
        ConfigFieldSpec(
            name="prefix",
            label="Key prefix",
            type="text",
            required=False,
            description="Optional. e.g. spatiumddi/backups/ — useful when sharing a bucket.",
        ),
        ConfigFieldSpec(
            name="endpoint_url",
            label="Endpoint URL",
            type="text",
            required=False,
            description=(
                "Leave blank for AWS S3. Set for S3-compatible "
                "(MinIO, Wasabi, Backblaze B2, Cloudflare R2)."
            ),
        ),
        ConfigFieldSpec(
            name="addressing_style",
            label="Addressing style",
            type="text",
            required=False,
            description=("'virtual' (default), 'path' (MinIO + buckets " "with dots), or 'auto'."),
        ),
        ConfigFieldSpec(
            name="access_key_id",
            label="Access key ID",
            type="text",
            required=True,
        ),
        ConfigFieldSpec(
            name="secret_access_key",
            label="Secret access key",
            type="password",
            required=True,
            secret=True,
            description="Encrypted at rest. Leave the existing field unchanged on edit to keep the previous value.",
        ),
        ConfigFieldSpec(
            name="object_lock_mode",
            label="Object Lock mode",
            type="text",
            required=False,
            description=(
                "'none' (default), 'governance', or 'compliance'. Requires a bucket "
                "created with Object Lock enabled. Under 'compliance' not even the "
                "bucket owner can delete an object before its retain-until date, so "
                "retention survives a leaked credential; 'governance' can be "
                "overridden by a principal holding "
                "s3:BypassGovernanceRetention."
            ),
        ),
        ConfigFieldSpec(
            name="object_lock_days",
            label="Object Lock retention (days)",
            type="text",
            required=False,
            description=(
                "How long each archive is locked. Required when a lock mode is set. "
                "Pair this with the target's write-only setting and a lifecycle rule "
                "for expiry."
            ),
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> None:
        for required in ("bucket", "region", "access_key_id", "secret_access_key"):
            value = config.get(required)
            if not value or not isinstance(value, str):
                raise DestinationConfigError(
                    f"{required!r} is required and must be a non-empty string"
                )
        endpoint = config.get("endpoint_url")
        if endpoint and not isinstance(endpoint, str):
            raise DestinationConfigError("'endpoint_url' must be a string")
        if endpoint and not (endpoint.startswith("http://") or endpoint.startswith("https://")):
            raise DestinationConfigError("'endpoint_url' must start with http:// or https://")
        prefix = config.get("prefix")
        if prefix and not isinstance(prefix, str):
            raise DestinationConfigError("'prefix' must be a string")
        mode = _lock_mode(config)
        if mode is not None:
            days = config.get("object_lock_days")
            if days in (None, ""):
                raise DestinationConfigError(
                    "'object_lock_days' is required when 'object_lock_mode' is set — "
                    "a lock with no retention period would be a no-op"
                )
            try:
                day_n = int(days)
            except (TypeError, ValueError) as exc:
                raise DestinationConfigError(
                    f"'object_lock_days' must be a number ({exc})"
                ) from exc
            if day_n < 1:
                raise DestinationConfigError("'object_lock_days' must be at least 1")

    async def write(
        self,
        *,
        config: dict[str, Any],
        filename: str,
        archive_bytes: bytes,
    ) -> None:
        key = _key(config, filename)

        def _do() -> None:
            from botocore.exceptions import (  # noqa: PLC0415
                BotoCoreError,
                ClientError,
            )

            client = _client(config)
            try:
                client.put_object(
                    Bucket=config["bucket"],
                    Key=key,
                    Body=archive_bytes,
                    ContentType="application/zip",
                    **_lock_headers(config),
                )
            except (ClientError, BotoCoreError) as exc:
                raise BackupDestinationError(f"S3 put_object failed: {exc}") from exc

        await asyncio.to_thread(_do)

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        prefix = (config.get("prefix") or "").strip("/")
        list_prefix = f"{prefix}/" if prefix else ""

        def _do() -> list[ArchiveListing]:
            from botocore.exceptions import (  # noqa: PLC0415
                BotoCoreError,
                ClientError,
            )

            client = _client(config)
            rows: list[ArchiveListing] = []
            try:
                paginator = client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=config["bucket"], Prefix=list_prefix):
                    for obj in page.get("Contents") or []:
                        key = obj["Key"]
                        filename = _strip_prefix(config, key)
                        if not _ARCHIVE_NAME_RE.match(filename):
                            continue
                        last_modified = obj.get("LastModified")
                        if last_modified is None:
                            continue
                        if last_modified.tzinfo is None:
                            last_modified = last_modified.replace(tzinfo=UTC)
                        rows.append(
                            ArchiveListing(
                                filename=filename,
                                size_bytes=int(obj.get("Size") or 0),
                                created_at=last_modified.astimezone(UTC),
                            )
                        )
            except (ClientError, BotoCoreError) as exc:
                raise BackupDestinationError(f"S3 list_objects_v2 failed: {exc}") from exc
            rows.sort(key=lambda r: r.created_at, reverse=True)
            return rows

        return await asyncio.to_thread(_do)

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        key = _key(config, filename)

        def _do() -> bytes:
            from botocore.exceptions import (  # noqa: PLC0415
                BotoCoreError,
                ClientError,
            )

            client = _client(config)
            try:
                resp = client.get_object(Bucket=config["bucket"], Key=key)
                return resp["Body"].read()
            except (ClientError, BotoCoreError) as exc:
                raise BackupDestinationError(f"S3 get_object failed: {exc}") from exc

        return await asyncio.to_thread(_do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        key = _key(config, filename)

        def _do() -> None:
            from botocore.exceptions import (  # noqa: PLC0415
                BotoCoreError,
                ClientError,
            )

            client = _client(config)
            # Ask before pushing: an object under an unexpired retention
            # lock cannot be deleted, and finding that out from a 403 is
            # both slower and ambiguous (a missing DeleteObject grant
            # answers the same way). ``head_object`` distinguishes them,
            # which is what lets the retention sweep skip a locked object
            # quietly instead of warning about it every night.
            try:
                head = client.head_object(Bucket=config["bucket"], Key=key)
            except (ClientError, BotoCoreError):
                # No head grant, or the object is already gone. Neither is
                # a reason to refuse the delete — fall through and let the
                # delete itself answer.
                head = {}
            retain_until = head.get("ObjectLockRetainUntilDate")
            if retain_until is not None:
                if retain_until.tzinfo is None:
                    retain_until = retain_until.replace(tzinfo=UTC)
                if retain_until > datetime.now(UTC):
                    raise RetentionLockedError(
                        f"{filename!r} is under an S3 Object Lock "
                        f"({head.get('ObjectLockMode') or 'unknown'} mode) until "
                        f"{retain_until.isoformat()} and cannot be deleted before then"
                    )
            if (head.get("ObjectLockLegalHoldStatus") or "").upper() == "ON":
                raise RetentionLockedError(
                    f"{filename!r} is under an S3 Object Lock legal hold and cannot "
                    "be deleted until the hold is released"
                )
            try:
                client.delete_object(Bucket=config["bucket"], Key=key)
            except (ClientError, BotoCoreError) as exc:
                raise BackupDestinationError(f"S3 delete_object failed: {exc}") from exc

        await asyncio.to_thread(_do)

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            self.validate_config(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}
        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"
        probe_key = _key(config, probe_name)

        def _do() -> dict[str, Any]:
            from botocore.exceptions import (  # noqa: PLC0415
                BotoCoreError,
                ClientError,
            )

            client = _client(config)
            probe_retained = False
            retained_reason = ""
            try:
                # NOTE: no ``**_lock_headers(config)`` here, deliberately.
                # A probe written under a 30-day compliance lock is
                # undeletable litter, created every time somebody clicks
                # Test. The bucket's own default retention rule may still
                # retain it, which is reported rather than treated as a
                # failure.
                client.put_object(
                    Bucket=config["bucket"],
                    Key=probe_key,
                    Body=os.urandom(16),
                    ContentType="application/octet-stream",
                )
                head = client.head_object(Bucket=config["bucket"], Key=probe_key)
                ok = head.get("ContentLength", 0) == 16
                try:
                    client.delete_object(Bucket=config["bucket"], Key=probe_key)
                except (ClientError, BotoCoreError) as del_exc:
                    # A refused delete is expected — and correct — on the
                    # recommended shape: a PutObject+GetObject+ListBucket
                    # key with no DeleteObject, against an Object Lock
                    # bucket. Failing the probe here is what trains
                    # operators to widen the key, so instead the probe
                    # passes and says the probe object was left behind.
                    probe_retained = True
                    retained_reason = str(del_exc)
            except (ClientError, BotoCoreError) as exc:
                # Distinguish auth errors from missing-bucket so the
                # operator gets a useful nudge.
                msg = str(exc)
                if "InvalidAccessKeyId" in msg or "SignatureDoesNotMatch" in msg:
                    return {"ok": False, "error": f"auth failed: {msg}"}
                if "NoSuchBucket" in msg or "404" in msg:
                    return {
                        "ok": False,
                        "error": f"bucket not found or no access: {msg}",
                    }
                return {"ok": False, "error": msg}
            if not ok:
                return {
                    "ok": False,
                    "error": "wrote probe but head_object disagreed on size",
                }
            if probe_retained:
                return {
                    "ok": True,
                    "probe_retained": True,
                    "detail": (
                        f"wrote + verified probe at {config['bucket']}/{probe_key}, but "
                        f"could not delete it ({retained_reason[:200]}). That is expected "
                        "on a write-only key or an Object Lock bucket — the probe object "
                        "stays until the bucket's own lifecycle rule removes it. Mark the "
                        "target write-only so retention is not attempted from here."
                    ),
                }
            return {
                "ok": True,
                "detail": (
                    f"wrote + verified + deleted probe at " f"{config['bucket']}/{probe_key}"
                ),
            }

        try:
            return await asyncio.to_thread(_do)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"unexpected: {exc}"}
