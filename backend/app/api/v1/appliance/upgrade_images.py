"""Upgrade-image management for appliance OS upgrades (#170 follow-up, #199).

An *upgrade image* is the ``.raw.xz`` artifact an operator makes
available for an appliance OS upgrade. ("Upgrade image" is the
operator-facing name; "slot" stays the name of the lower-level A/B dd
mechanism the bytes ultimately land on — see
``services/appliance/slot.py``.) It arrives one of two ways:

* **Upload (air-gap).** Operators on disconnected networks can't reach
  ``https://github.com/spatiumnorth/spatiumddi/releases/...`` to feed the
  supervisor a ``desired_slot_image_url``. They download the ``.raw.xz``
  out-of-band, upload it here, and the control plane stores it on a
  local volume + serves it back under an authenticated internal URL.
* **Import from GitHub (connected, #199).** For appliances with
  internet access the control plane can list the matching release
  assets and download + verify the image on the operator's behalf —
  no out-of-band download + re-upload round trip.

Either way the supervisor's existing heartbeat → trigger-file → host
runner pipeline pulls from the stored row unchanged.

Endpoints (all superadmin-gated unless noted):

* ``POST /api/v1/appliance/upgrade-images`` — multipart upload.
* ``GET  /api/v1/appliance/upgrade-images`` — list metadata.
* ``GET  /api/v1/appliance/upgrade-images/available`` — list GitHub
  releases carrying the appliance upgrade-image asset + its ``.sha256``
  sidecar, so the connected-install picker has something to pick from.
* ``POST /api/v1/appliance/upgrade-images/import-from-github`` —
  download + sha256-verify + store a release's upgrade image.
* ``GET  /api/v1/appliance/upgrade-images/{id}`` — single row metadata.
* ``GET  /api/v1/appliance/upgrade-images/{id}/raw.xz`` — stream the
  file back (token-auth — the host runner has no operator session).
* ``DELETE /api/v1/appliance/upgrade-images/{id}`` — remove from disk +
  drop the row.

The legacy ``/api/v1/appliance/slot-images/*`` paths are kept for one
release cut as 308 redirect shims (see the bottom of this module) so
existing operator bookmarks / scripts don't break.

Storage layout — ``/var/lib/spatiumddi/slot-images/{id}.raw.xz``. The
on-disk dir keeps the historical ``slot-images`` name + the
``SPATIUM_SLOT_IMAGE_DIR`` env var: it's pure storage plumbing (named
docker volume / PVC mount), not operator-facing, so renaming it would
orphan existing bytes for zero UI benefit (#199 scope: operator-facing
only). The filename on disk is always the UUID with the ``.raw.xz``
suffix so we never trust operator input for filesystem paths; the
operator-supplied ``filename`` is display-only.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
import structlog
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.api.v1.appliance.slot_image_mirror import mirror_auth_token
from app.config import settings
from app.core.permissions import is_effective_superadmin, require_permission
from app.core.responses import OctetStreamResponse
from app.models.appliance import ApplianceUpgradeImage
from app.models.audit import AuditLog
from app.services.appliance import releases as releases_service
from app.services.appliance.architecture import ApplianceArchitecture

logger = structlog.get_logger(__name__)

router = APIRouter()


# On-disk storage. The api container's docker-compose entry binds
# ``spatium_slot_images:/var/lib/spatiumddi/slot-images`` — a dedicated
# named volume so the bytes don't share fate with database backups or
# anything else under /var. The path + env var keep the historical
# ``slot-images`` name (storage plumbing, not operator-facing — #199
# renames the surface, not the volume). Mode 0700 because the bytes
# themselves don't need to be world-readable — fastapi streams them
# back through the same auth gate every other appliance endpoint uses.
SLOT_IMAGE_DIR = Path(os.environ.get("SPATIUM_SLOT_IMAGE_DIR", "/var/lib/spatiumddi/slot-images"))
# Cap on a single upload/import — upgrade images are ~800 MiB-1.2 GiB
# compressed today; 4 GiB ceiling leaves headroom for kernel +
# initramfs growth without letting an operator accidentally ship
# a multi-GiB blob that's clearly wrong.
MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024
# Streaming-read chunk for upload / import / sha256 computation. 4 MiB
# is small enough to keep the api event-loop responsive (asyncio
# coroutine yields between chunks) + large enough to avoid syscall
# overhead.
_CHUNK_BYTES = 4 * 1024 * 1024
# Fallback display name for a GitHub-imported image, used only when the
# asset URL doesn't end in a recognisable filename. Normally the row
# records the asset actually downloaded — which is the VERSIONED name,
# since that is what ``_pick_upgrade_assets`` resolves (the stable name is
# pruned from every non-latest release, #392). Stamping the stable name
# unconditionally used to leave the Fleet picker showing a filename that
# matched no asset on the release it came from.
_GITHUB_IMAGE_FILENAME = "spatiumddi-appliance-slot-amd64.raw.xz"


def _github_asset_filename(asset_url: str) -> str:
    """Last path segment of a release-asset URL, minus any query string."""
    tail = urlparse(asset_url).path.rsplit("/", 1)[-1]
    return tail if tail.endswith(".raw.xz") else _GITHUB_IMAGE_FILENAME


def _require_superadmin(user: CurrentUser) -> None:
    if not is_effective_superadmin(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Upgrade-image management is restricted to superadmins.",
        )


def _image_path(image_id: uuid.UUID) -> Path:
    return SLOT_IMAGE_DIR / f"{image_id}.raw.xz"


def _partial_path(image_id: uuid.UUID) -> Path:
    # In-flight upload temp file, atomically renamed to ``_image_path``
    # on success. Append ".partial" to the full ``<id>.raw.xz`` name —
    # NOT ``with_suffix(".raw.xz.partial")``, which replaces only the
    # final ``.xz`` component and doubles the ``.raw`` into the bogus
    # ``<id>.raw.raw.xz.partial`` (#415).
    target = _image_path(image_id)
    return target.with_name(target.name + ".partial")


def _ensure_storage_dir() -> None:
    SLOT_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        SLOT_IMAGE_DIR.chmod(0o700)
    except OSError:
        # Mount source may be on a filesystem that doesn't honour the
        # chmod (e.g. tmpfs with default mode). Not load-bearing —
        # the api container's user owns the path already.
        pass


# ── Mirror routing (#296 Phase B) ──────────────────────────────────────
#
# When ``settings.slot_image_mirror_url`` is set, the upload / import /
# download / delete handlers stream byte ops through the mirror
# Deployment via its in-cluster Service. The api keeps owning DB
# metadata + the operator-facing endpoint shape; only the bytes
# themselves leave the api pod. When the URL is unset (single-instance
# docker-compose / a plain k8s install with the mirror disabled), the
# handlers fall back to direct local-FS access — the pre-Phase-B
# behaviour. The mirror infra keeps its ``slot-image-mirror`` name +
# ``/internal/slot-images`` path (#199 scope: operator-facing only).
#
# All three proxy helpers raise HTTPException on transport / status
# failure so the operator-facing handler returns a clean error code
# rather than a stack trace.


def _mirror_url(image_id: uuid.UUID) -> str:
    base = settings.slot_image_mirror_url.rstrip("/")
    return f"{base}/api/v1/appliance/internal/slot-images/{image_id}"


# Generous timeout — upgrade-image uploads/imports are 1-4 GiB streams.
# 30 min read budget covers a slow LAN / VPN tunnel; the api will
# already have streamed enough body to trip a Starlette timeout long
# before this if something's truly wedged.
_MIRROR_HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=1800.0, write=1800.0, pool=30.0)


async def _stream_upload_through_mirror(
    image_id: uuid.UUID,
    body: AsyncIterator[bytes],
) -> None:
    """Stream the upload body to the mirror via PUT.

    The api hashes + size-counts the chunks separately in the caller;
    this helper just pipes bytes onward. A non-2xx from the mirror
    raises 502 — the upload failed downstream, not at the operator.
    """
    headers = {"X-Mirror-Auth": mirror_auth_token("put", image_id)}
    async with httpx.AsyncClient(timeout=_MIRROR_HTTP_TIMEOUT) as client:
        try:
            resp = await client.put(
                _mirror_url(image_id),
                content=body,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                f"Mirror upload failed: {exc}",
            ) from exc
    if resp.status_code not in (200, 201, 204):
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"Mirror upload returned {resp.status_code}: {resp.text[:200]!r}",
        )


class MirrorUnavailable(Exception):
    """The mirror could not be reached at all — connect / read failure.

    Deliberately distinct from an HTTP error the mirror itself returned
    (#787). Those two say very different things about the fleet:

    * unreachable — the mirror pod is gone. Its PVC is RWO local-path, so
      the single replica is pinned to one node, and losing that node leaves
      it Pending indefinitely. Nothing about the stored image is wrong.
    * answered with an error — the mirror is alive and refusing or failing.
      A mismatched ``X-Mirror-Auth`` secret is the likely cause, and it is a
      configuration fault that will never self-heal.

    The download handler serves a local copy for the first and surfaces the
    second, which is only expressible if the two do not collapse into one
    status code.
    """


async def _stream_download_from_mirror(
    image_id: uuid.UUID,
    *,
    filename: str | None = None,
) -> StreamingResponse:
    """Stream bytes from the mirror back to the requester.

    The mirror serves a FileResponse; we open a streaming GET against
    it and pass the chunks through. The mirror's content-length passes
    through too, so the host runner's progress bar still works.

    Raises :class:`MirrorUnavailable` when the mirror cannot be reached,
    a 404 ``HTTPException`` when it reports the bytes absent, and a 502
    ``HTTPException`` when it answers with anything else — three outcomes
    the caller has to tell apart (#787).

    ``filename`` controls the ``Content-Disposition`` header so the
    browser / host runner sees the same filename as the local-FS path
    (``FileResponse(..., filename=row.filename)``). Without it the
    mirror path returns a no-Content-Disposition response + browsers
    save the raw UUID as the filename. Defaults to ``<image_id>.raw.xz``
    when not supplied so the host runner still gets a sensible name
    even for direct mirror-only flows.
    """
    headers = {"X-Mirror-Auth": mirror_auth_token("get", image_id)}
    client = httpx.AsyncClient(timeout=_MIRROR_HTTP_TIMEOUT)
    try:
        # Build the request manually so we can keep the client open
        # for the duration of the stream — closing it inside the
        # ``StreamingResponse`` generator yields a clean shutdown
        # when the operator's tcp connection closes.
        request = client.build_request("GET", _mirror_url(image_id), headers=headers)
        upstream = await client.send(request, stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        raise MirrorUnavailable(str(exc)) from exc
    if upstream.status_code == 404:
        await upstream.aclose()
        await client.aclose()
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Upgrade image bytes missing on mirror — re-upload required.",
        )
    if upstream.status_code != 200:
        body_preview = (await upstream.aread())[:200]
        await upstream.aclose()
        await client.aclose()
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"Mirror returned {upstream.status_code}: {body_preview!r}",
        )

    async def _iter() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream.aiter_bytes(_CHUNK_BYTES):
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    # Preserve upstream content-length so progress bars work end-to-
    # end. ``StreamingResponse`` doesn't set it on its own. Also set
    # Content-Disposition with the original filename so the mirror
    # path matches FileResponse's behaviour for the local path —
    # without this, browsers + the host runner would see the
    # response without a filename hint + fall back to the URL's last
    # path segment ("raw.xz") or save the raw UUID.
    resp_filename = filename or f"{image_id}.raw.xz"
    resp_headers: dict[str, str] = {
        "Content-Disposition": f'attachment; filename="{resp_filename}"',
    }
    if "content-length" in upstream.headers:
        resp_headers["Content-Length"] = upstream.headers["content-length"]
    return StreamingResponse(
        _iter(),
        media_type="application/octet-stream",
        headers=resp_headers,
    )


async def _bytes_present_in_active_store(image_id: uuid.UUID) -> bool:
    """Does the store a download would actually read from hold these bytes?

    #787 — this is what makes "re-upload the image" a real remedy instead
    of a no-op. Both ingest paths short-circuit on a duplicate SHA-256, so
    an operator whose bytes are missing from the active store could
    re-upload forever and change nothing.

    When the mirror is configured the answer is about the MIRROR only,
    deliberately, even though the api may also hold a local copy: a local
    copy is readable on exactly one node, which is the condition being
    repaired. Saying "present" because this replica happens to have the
    file would leave the fleet in the state the re-upload was meant to fix.

    A mirror that cannot be reached raises rather than guessing. Guessing
    "absent" would re-download gigabytes from GitHub into a PUT that is
    about to fail anyway; guessing "present" would silently skip a repair
    the operator asked for.
    """
    if not settings.slot_image_mirror_url:
        return _image_path(image_id).exists()

    headers = {"X-Mirror-Auth": mirror_auth_token("get", image_id)}
    async with httpx.AsyncClient(timeout=_MIRROR_HTTP_TIMEOUT) as client:
        try:
            # Starlette routes a GET as HEAD too, so this costs headers
            # rather than the 1-4 GiB body.
            resp = await client.head(_mirror_url(image_id), headers=headers)
        except httpx.HTTPError as exc:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                f"Could not reach the upgrade-image mirror: {exc}",
            ) from exc
    if resp.status_code == 404:
        return False
    if resp.status_code != 200:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"Upgrade-image mirror returned {resp.status_code} on a presence check.",
        )
    return True


async def _delete_from_mirror(image_id: uuid.UUID) -> None:
    """Issue DELETE against the mirror; tolerate 404 (already gone)."""
    headers = {"X-Mirror-Auth": mirror_auth_token("delete", image_id)}
    async with httpx.AsyncClient(timeout=_MIRROR_HTTP_TIMEOUT) as client:
        try:
            resp = await client.delete(_mirror_url(image_id), headers=headers)
        except httpx.HTTPError as exc:
            # Log + continue — the DB row delete is the authoritative
            # "this image is gone" signal. Stale bytes get reaped by
            # the future prune task.
            logger.warning(
                "upgrade_image_mirror_delete_failed",
                image_id=str(image_id),
                error=str(exc),
            )
            return
    if resp.status_code not in (200, 204, 404):
        logger.warning(
            "upgrade_image_mirror_delete_failed",
            image_id=str(image_id),
            status=resp.status_code,
        )


# ── Shared verified-storage helper ─────────────────────────────────
#
# Both the upload (operator multipart) + import-from-github (control
# plane streams from a release asset) paths funnel their byte stream
# through here so the size cap, SHA-256 verification, atomic
# .partial→final rename, and mirror-vs-local routing live in exactly
# one place.


async def _store_verified_image(
    image_id: uuid.UUID,
    source: AsyncIterator[bytes],
    expected_sha: str,
) -> int:
    """Stream ``source`` into storage, enforce the size cap + verify SHA.

    In #296 Phase B mirror mode the bytes are teed into the mirror PUT;
    otherwise they're written to local FS via an atomic ``.partial`` →
    final rename. On size overflow raises 413; on hash mismatch cleans
    up the partial bytes (mirror DELETE or local unlink) + raises 422.
    Returns the number of bytes written on success.
    """
    hasher = hashlib.sha256()
    bytes_written = 0

    if settings.slot_image_mirror_url:
        # Tee the stream: every chunk goes both into the hasher + the
        # mirror PUT body. We validate the SHA after the PUT completes
        # (we can't pre-compute it without buffering the whole 1-4 GiB
        # body). On mismatch, fire a DELETE to clean the orphan bytes.

        async def _tee() -> AsyncIterator[bytes]:
            nonlocal bytes_written
            async for chunk in source:
                bytes_written += len(chunk)
                if bytes_written > MAX_UPLOAD_BYTES:
                    # Bailing the generator aborts the PUT body mid-
                    # stream → mirror cleans up its .partial file.
                    raise HTTPException(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        f"Upgrade image exceeds {MAX_UPLOAD_BYTES} bytes.",
                    )
                hasher.update(chunk)
                yield chunk

        await _stream_upload_through_mirror(image_id, _tee())
        actual_sha = hasher.hexdigest()
        if actual_sha != expected_sha:
            await _delete_from_mirror(image_id)
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                (
                    f"SHA-256 mismatch — expected {expected_sha}, got "
                    f"{actual_sha}. Re-download the file + retry."
                ),
            )
        return bytes_written

    # Single-instance / docker-compose path — write to local FS with
    # an atomic .partial → final rename.
    _ensure_storage_dir()
    target_path = _image_path(image_id)
    tmp_path = _partial_path(image_id)
    try:
        with tmp_path.open("wb") as out:
            async for chunk in source:
                bytes_written += len(chunk)
                if bytes_written > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        f"Upgrade image exceeds {MAX_UPLOAD_BYTES} bytes.",
                    )
                hasher.update(chunk)
                out.write(chunk)
        actual_sha = hasher.hexdigest()
        if actual_sha != expected_sha:
            tmp_path.unlink(missing_ok=True)
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                (
                    f"SHA-256 mismatch — expected {expected_sha}, got "
                    f"{actual_sha}. Re-download the file + retry."
                ),
            )
        # Bytes pass verification — atomically move into place.
        tmp_path.replace(target_path)
    except HTTPException:
        # Re-raise validation errors after cleaning up the partial.
        tmp_path.unlink(missing_ok=True)
        raise
    except OSError as exc:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Failed to write upgrade image to disk: {exc}",
        ) from exc
    return bytes_written


# ── Schemas ────────────────────────────────────────────────────────


class UpgradeImageRow(BaseModel):
    id: uuid.UUID
    filename: str
    size_bytes: int
    sha256: str
    appliance_version: str
    # #1026 — None on every image stored before the column existed, and
    # on any upload where the operator left it unset. The UI renders
    # that as "unknown" rather than guessing, and the scheduling gate
    # treats it as "do not block, the host will check".
    architecture: str | None
    uploaded_by_user_id: uuid.UUID | None
    uploaded_at: datetime
    notes: str | None


class UpgradeImageList(BaseModel):
    images: list[UpgradeImageRow]


class AvailableUpgradeImageRow(BaseModel):
    tag: str
    name: str
    published_at: datetime
    body: str
    html_url: str
    is_prerelease: bool
    is_installed: bool
    image_asset_url: str
    checksum_asset_url: str
    size_bytes: int | None
    # #1026 — a release publishing both architectures appears as two
    # rows, so the picker shows which is which instead of silently
    # offering one of them.
    architecture: str


class AvailableUpgradeImagesResponse(BaseModel):
    # ``github_reachable`` lets the picker auto-detect: false ⇒ default
    # the UI to the air-gap upload tab; true + non-empty ⇒ default to
    # the pick-from-GitHub tab.
    github_reachable: bool
    available: list[AvailableUpgradeImageRow]


class ImportFromGithubRequest(BaseModel):
    release_tag: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description=(
            "The release tag to import the appliance upgrade image from "
            "(e.g. 2026.05.14-1). Must be one of the tags returned by "
            "``GET /api/v1/appliance/upgrade-images/available``."
        ),
    )
    architecture: ApplianceArchitecture | None = Field(
        default=None,
        description=(
            "Which architecture's image to import (#1026). Optional when "
            "the release publishes exactly one; required — 422 otherwise "
            "— when it publishes several, because choosing for you would "
            "be choosing which nodes boot afterwards."
        ),
    )


def _row_to_schema(row: ApplianceUpgradeImage) -> UpgradeImageRow:
    return UpgradeImageRow(
        id=row.id,
        filename=row.filename,
        size_bytes=row.size_bytes,
        sha256=row.sha256,
        appliance_version=row.appliance_version,
        architecture=row.architecture,
        uploaded_by_user_id=row.uploaded_by_user_id,
        uploaded_at=row.uploaded_at,
        notes=row.notes,
    )


# ── Endpoints ──────────────────────────────────────────────────────


@router.post(
    "/upgrade-images",
    response_model=UpgradeImageRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Upload an upgrade image for an air-gapped appliance upgrade",
)
async def upload_upgrade_image(
    current_user: CurrentUser,
    db: DB,
    file: UploadFile = File(
        ...,
        description=(
            "The .raw.xz upgrade image. Downloaded out-of-band from the "
            "github release and re-uploaded here for air-gapped fleets."
        ),
    ),
    sha256: str = Form(
        ...,
        min_length=64,
        max_length=64,
        description=(
            "Expected SHA-256 (hex, lowercase) of the file bytes. "
            "Get it from the ``.sha256`` sidecar published alongside "
            "the upgrade-image raw.xz. The server computes the hash on "
            "the received bytes + rejects on mismatch (422) so a "
            "corrupted upload can't be applied silently."
        ),
    ),
    appliance_version: str = Form(
        ...,
        min_length=1,
        max_length=64,
        description=(
            "The release tag this upgrade image carries "
            "(e.g. 2026.05.14-1, or 1.0.0 from 1.0.0 on). Used by the supervisor's "
            "auto-clear logic — installed_appliance_version must "
            "match this once the upgrade lands."
        ),
    ),
    architecture: ApplianceArchitecture | None = Form(
        default=None,
        description=(
            "Which architecture this image's rootfs is built for "
            "(``amd64`` / ``arm64``). Declared, like ``appliance_version`` "
            "beside it — a slot image is a bare ext4 filesystem inside a "
            "non-seekable xz stream, so the server cannot read it out of "
            "the bytes without decompressing the whole ~8 GiB on an "
            "upload request. Leave unset if unsure: the value is used to "
            "refuse an obviously-wrong upgrade early, and "
            "``spatium-upgrade-slot`` re-checks the real image against "
            "the node's own architecture before writing it either way."
        ),
    ),
    notes: str | None = Form(
        default=None,
        description="Optional operator note shown in the Fleet UI list.",
    ),
) -> UpgradeImageRow:
    _require_superadmin(current_user)

    expected_sha = sha256.lower().strip()
    if not all(c in "0123456789abcdef" for c in expected_sha):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "sha256 must be 64 lowercase hex characters.",
        )

    # Duplicate-by-hash short-circuit — if the operator re-uploads a
    # file we already have, just return the existing row. This lets
    # the UI's "re-upload to refresh" path be safe (no orphaned bytes
    # on disk).
    existing = (
        await db.execute(
            select(ApplianceUpgradeImage).where(ApplianceUpgradeImage.sha256 == expected_sha)
        )
    ).scalar_one_or_none()

    async def _file_iter() -> AsyncIterator[bytes]:
        while True:
            chunk = await file.read(_CHUNK_BYTES)
            if not chunk:
                return
            yield chunk

    if existing is not None:
        # ...unless the bytes are GONE from the active store, in which
        # case the short-circuit is the bug (#787). Re-uploading is the
        # documented remedy after a promote flips the mirror on and its
        # PVC starts empty, and it has to actually store something.
        if not await _bytes_present_in_active_store(existing.id):
            # Re-store under the EXISTING id, not a new one: appliance
            # rows may already carry a ``desired_slot_image_url`` built
            # from it, and a fresh id would leave those pointing at
            # nothing while the operator watches a "successful" upload.
            repaired = await _store_verified_image(existing.id, _file_iter(), expected_sha)
            db.add(
                AuditLog(
                    user_id=current_user.id,
                    user_display_name=current_user.display_name,
                    auth_source=current_user.auth_source,
                    action="appliance.upgrade_image_bytes_restored",
                    resource_type="appliance_upgrade_image",
                    resource_id=str(existing.id),
                    resource_display=f"{existing.filename} ({existing.appliance_version})",
                    result="success",
                    new_value={"size_bytes": repaired, "sha256": expected_sha},
                )
            )
            await db.commit()
            logger.info(
                "appliance_upgrade_image_bytes_restored",
                image_id=str(existing.id),
                size_bytes=repaired,
                user=current_user.username,
            )
            return _row_to_schema(existing)
        # Drain + discard the upload body so the client doesn't see a
        # half-read socket (httpx waits for the server's read before
        # closing the request — stalling here on a stale connection
        # would surface as a timeout on the UI).
        while await file.read(_CHUNK_BYTES):
            pass
        return _row_to_schema(existing)

    image_id = uuid.uuid4()

    bytes_written = await _store_verified_image(image_id, _file_iter(), expected_sha)

    row = ApplianceUpgradeImage(
        id=image_id,
        filename=file.filename or f"{image_id}.raw.xz",
        size_bytes=bytes_written,
        sha256=expected_sha,
        appliance_version=appliance_version.strip(),
        architecture=architecture,
        uploaded_by_user_id=current_user.id,
        notes=notes.strip() if notes else None,
    )
    db.add(row)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.upgrade_image_uploaded",
            resource_type="appliance_upgrade_image",
            resource_id=str(row.id),
            resource_display=f"{row.filename} ({appliance_version})",
            result="success",
            new_value={
                "size_bytes": bytes_written,
                "sha256": expected_sha,
                "appliance_version": appliance_version,
            },
        )
    )
    await db.commit()
    logger.info(
        "appliance_upgrade_image_uploaded",
        image_id=str(row.id),
        size_bytes=bytes_written,
        appliance_version=appliance_version,
        user=current_user.username,
    )
    return _row_to_schema(row)


@router.get(
    "/upgrade-images",
    response_model=UpgradeImageList,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="List uploaded / imported upgrade images",
)
async def list_upgrade_images(current_user: CurrentUser, db: DB) -> UpgradeImageList:
    _require_superadmin(current_user)
    rows = (
        (
            await db.execute(
                select(ApplianceUpgradeImage).order_by(ApplianceUpgradeImage.uploaded_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return UpgradeImageList(images=[_row_to_schema(r) for r in rows])


@router.get(
    "/upgrade-images/available",
    response_model=AvailableUpgradeImagesResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="List GitHub releases carrying an importable appliance upgrade image",
)
async def list_available_upgrade_images(
    current_user: CurrentUser,
) -> AvailableUpgradeImagesResponse:
    """Connected-install picker source.

    Proxies the existing GitHub releases listing and filters to
    releases that carry both the appliance upgrade-image ``.raw.xz``
    asset + its ``.sha256`` sidecar. ``github_reachable`` is false on
    any fetch error (rate-limited / offline / air-gapped) so the UI
    can fall back to the upload tab cleanly.
    """
    _require_superadmin(current_user)
    reachable, releases = await releases_service.list_available_upgrade_images()
    return AvailableUpgradeImagesResponse(
        github_reachable=reachable,
        available=[
            AvailableUpgradeImageRow(
                tag=r.tag,
                name=r.name,
                published_at=r.published_at,
                body=r.body,
                html_url=r.html_url,
                is_prerelease=r.is_prerelease,
                is_installed=r.is_installed,
                image_asset_url=r.image_asset_url,
                checksum_asset_url=r.checksum_asset_url,
                size_bytes=r.size_bytes,
                architecture=r.architecture,
            )
            for r in releases
        ],
    )


@router.post(
    "/upgrade-images/import-from-github",
    response_model=UpgradeImageRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Import an upgrade image from a GitHub release",
)
async def import_upgrade_image_from_github(
    body: ImportFromGithubRequest,
    current_user: CurrentUser,
    db: DB,
) -> UpgradeImageRow:
    """Download + sha256-verify + store a release's appliance upgrade image.

    The control plane fetches the ``.sha256`` sidecar first (cheap),
    short-circuits to the existing row if we already hold that hash
    (idempotent), then streams the ``.raw.xz`` through the same
    verified-storage path the upload flow uses. Off-prem call — the
    api reaches out to github.com (or the release asset CDN).
    """
    _require_superadmin(current_user)
    tag = body.release_tag.strip()

    choice = await releases_service.resolve_upgrade_image_choice(tag, body.architecture)
    spec = choice.spec
    if spec is None:
        # #1026 — "this release publishes several architectures and you
        # did not say which" is not a missing asset, it is a missing
        # decision, and answering both with the same 404 would send an
        # operator looking for a build that is right there.
        arches = ", ".join(choice.available)
        if body.architecture is None and len(choice.available) > 1:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                (
                    f"Release {tag!r} publishes upgrade images for {arches}. "
                    "Pass ``architecture`` to say which one to import."
                ),
            )
        if body.architecture is not None and choice.available:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                (
                    f"Release {tag!r} has no {body.architecture} upgrade "
                    f"image (it publishes: {arches})."
                ),
            )
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            (
                f"Release {tag!r} has no importable appliance upgrade-image "
                "assets (need both the .raw.xz + its .sha256 sidecar), or "
                "GitHub is unreachable."
            ),
        )

    # 1. Fetch + parse the .sha256 sidecar (``<hash>  <filename>`` or a
    #    bare hash). Small text file — a 30 s timeout is plenty.
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=True) as client:
            sha_resp = await client.get(spec.checksum_asset_url)
            sha_resp.raise_for_status()
            sha_text = sha_resp.text
    except httpx.HTTPError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"Failed to fetch the .sha256 sidecar for {tag}: {exc}",
        ) from exc
    tokens = sha_text.split()
    expected_sha = (tokens[0].lower() if tokens else "").strip()
    if len(expected_sha) != 64 or not all(c in "0123456789abcdef" for c in expected_sha):
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"The .sha256 sidecar for {tag} did not contain a 64-char hex digest.",
        )

    # 2. Idempotent short-circuit — already imported/uploaded this hash
    #    AND the bytes are still in the active store. #787: re-importing
    #    is the connected-install equivalent of re-uploading, so when the
    #    store has lost them (a promote moved it to a fresh mirror PVC)
    #    the import has to re-fetch rather than report success and do
    #    nothing. Re-stores under the existing id so any already-stamped
    #    ``desired_slot_image_url`` keeps resolving.
    existing = (
        await db.execute(
            select(ApplianceUpgradeImage).where(ApplianceUpgradeImage.sha256 == expected_sha)
        )
    ).scalar_one_or_none()
    if existing is not None and await _bytes_present_in_active_store(existing.id):
        return _row_to_schema(existing)

    # 3. Stream-download the .raw.xz + store with verification.
    image_id = existing.id if existing is not None else uuid.uuid4()
    try:
        async with httpx.AsyncClient(timeout=_MIRROR_HTTP_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("GET", spec.image_asset_url) as resp:
                if resp.status_code != 200:
                    raise HTTPException(
                        status.HTTP_502_BAD_GATEWAY,
                        f"GitHub returned {resp.status_code} for the {tag} upgrade image.",
                    )

                async def _gh_iter() -> AsyncIterator[bytes]:
                    async for chunk in resp.aiter_bytes(_CHUNK_BYTES):
                        yield chunk

                bytes_written = await _store_verified_image(image_id, _gh_iter(), expected_sha)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"Failed to download the {tag} upgrade image from GitHub: {exc}",
        ) from exc

    if existing is not None:
        # Bytes-only repair of a row we already had — keep its metadata
        # (filename / notes / who staged it) rather than rewriting the
        # provenance of an image the operator staged some other way.
        row = existing
        action = "appliance.upgrade_image_bytes_restored"
    else:
        row = ApplianceUpgradeImage(
            id=image_id,
            filename=_github_asset_filename(spec.image_asset_url),
            size_bytes=bytes_written,
            sha256=expected_sha,
            appliance_version=tag,
            # From the release asset name we just resolved — the one
            # place an architecture can be stated by us rather than
            # taken on trust (#1026).
            architecture=spec.architecture,
            uploaded_by_user_id=current_user.id,
            notes=f"Imported from GitHub release {tag}",
        )
        db.add(row)
        action = "appliance.upgrade_image_imported"
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action=action,
            resource_type="appliance_upgrade_image",
            resource_id=str(row.id),
            resource_display=f"{row.filename} ({tag})",
            result="success",
            new_value={
                "size_bytes": bytes_written,
                "sha256": expected_sha,
                "appliance_version": tag,
                "source": "github",
            },
        )
    )
    await db.commit()
    logger.info(
        "appliance_upgrade_image_imported",
        image_id=str(row.id),
        size_bytes=bytes_written,
        appliance_version=tag,
        user=current_user.username,
    )
    return _row_to_schema(row)


@router.get(
    "/upgrade-images/{image_id}",
    response_model=UpgradeImageRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Fetch upgrade image metadata",
)
async def get_upgrade_image(
    image_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> UpgradeImageRow:
    _require_superadmin(current_user)
    row = await db.get(ApplianceUpgradeImage, image_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Upgrade image not found.")
    return _row_to_schema(row)


def slot_image_download_token(image_id: uuid.UUID) -> str:
    """HMAC token granting download access to a specific upgrade image.

    Built from ``image_id`` + ``SECRET_KEY`` so anyone who knows the
    UUID alone (e.g. from a leaked URL) can't replay against a
    different image. No expiry — the upgrade flow needs the URL to
    work for the lifetime of the pending trigger, which can stretch
    across host reboots if the operator-set apply happens overnight.

    Used by ``apply_upgrade`` to mint the ``?t=...`` query param on
    the URL it stamps into ``appliance.desired_slot_image_url`` so the
    host-side ``spatium-upgrade-slot`` runner (which does an
    unauthenticated ``urllib.request.urlopen``) can pull the bytes.

    Name kept (vs ``upgrade_image_download_token``) because it mints a
    token for the lower-level slot-apply mechanism (#199 scope:
    operator-facing only). The HMAC message string is likewise frozen
    so tokens already minted into ``desired_slot_image_url`` rows stay
    valid across the upgrade.
    """
    mac = hmac.new(
        settings.secret_key.encode("utf-8"),
        f"slot-image:{image_id}".encode(),
        hashlib.sha256,
    )
    return mac.hexdigest()


def _verify_slot_image_download_token(image_id: uuid.UUID, token: str) -> bool:
    """Constant-time compare of the supplied ``?t=...`` query param
    against the expected HMAC."""
    expected = slot_image_download_token(image_id)
    return hmac.compare_digest(expected, token)


@router.get(
    "/upgrade-images/{image_id}/raw.xz",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=OctetStreamResponse,
    responses={200: {"description": "The .raw.xz upgrade image"}},
    summary="Download an upgrade image",
    # Return type is FileResponse on the local path, StreamingResponse
    # on the mirror-proxy path. FastAPI can't derive a pydantic model
    # from that union — and there isn't one (raw bytes). Tell it
    # explicitly to skip response-model generation.
    response_model=None,
)
async def download_upgrade_image(
    image_id: uuid.UUID,
    db: DB,
    t: str | None = None,
) -> FileResponse | StreamingResponse:
    """Stream the raw.xz back — **token-only** access.

    Only one auth path is currently accepted: a valid ``?t=<hmac>``
    query param minted by the upgrade scheduler + embedded in the
    ``desired_slot_image_url`` the supervisor relays to the host-side
    ``spatium-upgrade-slot`` runner. The runner has no operator
    session / mTLS material, which is why the token mechanism exists.

    In multi-node mirror mode (#296 Phase B) the api proxies the
    byte stream from the mirror Service; in single-instance mode it
    serves directly from local FS.
    """
    row = await db.get(ApplianceUpgradeImage, image_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Upgrade image not found.")

    # Token-only auth path. No fallback to browser auth — a missing
    # token gets 401 with a clear hint at what's missing.
    if t is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Upgrade-image downloads require a ``?t=<token>`` query "
            "param minted by the upgrade scheduler. Operator-direct "
            "browser downloads aren't supported here today; use "
            "``GET /api/v1/appliance/upgrade-images`` for metadata + "
            "the row's sha256, then re-verify bytes through a separate "
            "shell workflow against the mirror PVC.",
        )
    if not _verify_slot_image_download_token(image_id, t):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Invalid upgrade-image download token.",
        )

    if settings.slot_image_mirror_url:
        # #296 Phase B — bytes live on the mirror Deployment. Stream through.
        #
        # #787 — two of the three ways that can fail mean "the mirror cannot
        # answer right now", not "this image is wrong", and this replica may
        # be holding the exact bytes. Both are real now that the mirror is on
        # the mandatory upgrade path of every multi-node appliance:
        #
        # * 404 — the image predates the promote that enabled the mirror, so
        #   it is on this node's hostPath while the mirror's PVC is empty.
        # * unreachable — the mirror's PVC is RWO local-path, so the single
        #   pod is pinned to one node; losing that node leaves it Pending
        #   indefinitely. Refusing to serve a local copy would make an
        #   unrelated node loss block every upgrade in the fleet, including
        #   the one that repairs it.
        #
        # A mirror that ANSWERS with an error is the third case and is NOT
        # covered. It is alive and refusing or failing — a mismatched
        # X-Mirror-Auth secret being the likely cause — which is a
        # configuration fault that never self-heals. Falling back there would
        # let nodes holding a stale local copy quietly succeed while the rest
        # of the fleet 502s, so the fault would be discovered as an
        # inexplicably half-working upgrade instead of an error. It surfaces.
        #
        # Serving local bytes in the two covered cases is not a correctness
        # risk: the host runner verifies them against the sha256 stamped
        # alongside the URL, and delete_upgrade_image now clears local copies
        # too, so a deleted image cannot resurface here.
        try:
            return await _stream_download_from_mirror(row.id, filename=row.filename)
        except MirrorUnavailable as exc:
            local = _image_path(row.id)
            if not local.exists():
                raise HTTPException(
                    status.HTTP_502_BAD_GATEWAY,
                    f"Mirror download failed: {exc}",
                ) from exc
            logger.warning(
                "appliance_upgrade_image_served_from_local_mirror_unreachable",
                image_id=str(row.id),
                error=str(exc)[:200],
            )
        except HTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                raise
            local = _image_path(row.id)
            if not local.exists():
                raise
            logger.info(
                "appliance_upgrade_image_served_from_local_after_mirror_miss",
                image_id=str(row.id),
            )
        return FileResponse(
            local,
            media_type="application/octet-stream",
            filename=row.filename,
        )

    path = _image_path(row.id)
    if not path.exists():
        # Row + file out of sync (manual /var cleanup, container
        # restart with the named volume detached, …). Treat as a 404
        # rather than a 500 — operators can drop the row + re-upload.
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Upgrade image bytes missing on disk — re-upload required.",
        )
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=row.filename,
    )


@router.delete(
    "/upgrade-images/{image_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Delete an uploaded / imported upgrade image",
)
async def delete_upgrade_image(image_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    _require_superadmin(current_user)
    row = await db.get(ApplianceUpgradeImage, image_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Upgrade image not found.")
    if settings.slot_image_mirror_url:
        # #296 Phase B — delete from the mirror Deployment. Best-effort:
        # the DB row delete below is the authoritative signal; stale
        # bytes on the mirror get reaped by the future prune task.
        await _delete_from_mirror(row.id)
    # #787 — always sweep local FS too, not just on the no-mirror branch.
    # The appliance keeps the slot-images hostPath mounted even with the
    # mirror on (so a pre-promote image is still readable), which means a
    # local copy can exist in mirror mode. Skipping it here would strand
    # 1-4 GiB per deleted image on the seed's /var forever — the "future
    # prune task" the mirror branch defers to does not exist, and would
    # not cover local FS anyway. It also removes the stale-bytes hazard
    # the download fallback would otherwise inherit: without this, a
    # deleted image could still be served from a node's local copy.
    try:
        _image_path(row.id).unlink(missing_ok=True)
    except OSError as exc:
        # Disk-side cleanup is best-effort — the row delete below is the
        # authoritative "this image is gone" signal. Logged rather than
        # swallowed so a permission / read-only-mount problem is visible
        # instead of quietly accumulating gigabytes.
        logger.warning(
            "upgrade_image_local_unlink_failed",
            image_id=str(row.id),
            error=str(exc),
        )
    filename = row.filename
    version = row.appliance_version
    await db.delete(row)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.upgrade_image_deleted",
            resource_type="appliance_upgrade_image",
            resource_id=str(image_id),
            resource_display=f"{filename} ({version})",
            result="success",
        )
    )
    await db.commit()
    logger.info(
        "appliance_upgrade_image_deleted",
        image_id=str(image_id),
        filename=filename,
        user=current_user.username,
    )


# ── Legacy /slot-images shim (#199) ────────────────────────────────
#
# The operator-facing surface renamed slot-images → upgrade-images.
# Keep the old paths alive for one release cut as redirects so existing
# bookmarks / scripts don't hard-break. We use 308 (not the issue's
# literal "301"): a 301 coerces POST/DELETE to GET per RFC 7231, which
# would silently break the air-gap upload + delete shims; 308 preserves
# the method + body. For GETs the two are equivalent. Drop these in the
# release after the one that ships #199.


def _shim_redirect(request: Request) -> RedirectResponse:
    # Relative redirect (path + query only) so it resolves against the
    # same host the client already reached — avoids leaking the
    # behind-nginx internal hostname. Rewrites just the first
    # ``/slot-images`` path segment; preserves the ``?t=`` download
    # token + any other query params.
    path = request.url.path.replace("/slot-images", "/upgrade-images", 1)
    query = request.url.query
    target = f"{path}?{query}" if query else path
    return RedirectResponse(url=target, status_code=status.HTTP_308_PERMANENT_REDIRECT)


@router.api_route(
    "/slot-images",
    methods=["GET", "POST"],
    include_in_schema=False,
    deprecated=True,
)
async def _shim_slot_images_collection(request: Request) -> RedirectResponse:
    return _shim_redirect(request)


@router.api_route(
    "/slot-images/{image_id}",
    methods=["GET", "DELETE"],
    include_in_schema=False,
    deprecated=True,
)
async def _shim_slot_images_item(request: Request) -> RedirectResponse:
    # ``{image_id}`` stays in the path (so the route matches) but is
    # left out of the signature — FastAPI doesn't require declaring
    # path params, and we rebuild the target from request.url anyway.
    return _shim_redirect(request)


@router.api_route(
    "/slot-images/{image_id}/raw.xz",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=OctetStreamResponse,
    responses={200: {"description": "The .raw.xz slot image"}},
    methods=["GET"],
    include_in_schema=False,
    deprecated=True,
)
async def _shim_slot_images_download(request: Request) -> RedirectResponse:
    return _shim_redirect(request)


__all__ = ["router", "SLOT_IMAGE_DIR", "slot_image_download_token"]

# Silence ruff F401 — shutil is imported for future "prune older
# than" support; keep it on the import line to avoid a follow-up
# diff when that lands.
_ = shutil
