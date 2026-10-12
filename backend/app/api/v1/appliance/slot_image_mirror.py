"""Slot-image mirror internal byte-op endpoints (#296 Phase B).

Mounted under ``/api/v1/appliance/internal/slot-images`` ONLY on the
mirror Deployment (``settings.slot_image_mirror_mode=true``). The main
api Deployment does NOT register this router so a misrouted operator
request can't accidentally land here.

Three byte operations + one disk-usage probe — metadata (filename /
sha256 / row) stays in Postgres + lives on the main api. The mirror
just holds the file contents on a node-pinned local-path PVC.

Endpoints (all under the X-Mirror-Auth shared-secret gate, NO operator
auth — no JWT / RBAC / session):

* ``PUT  /internal/slot-images/{image_id}``  — stream body bytes to
  ``<slot_image_dir>/{image_id}.raw.xz`` via a ``.partial`` rename so
  a crashed mid-upload doesn't expose half-written bytes. No size
  cap here — the main api already enforced one before forwarding.

* ``GET  /internal/slot-images/{image_id}``  — stream bytes back.
  StreamingResponse so a 4 GiB download doesn't load into memory.

* ``DELETE /internal/slot-images/{image_id}`` — remove the file.
  Best-effort; 404 on the file is fine (operator may have rm-rf'd
  the directory between attempts).

X-Mirror-Auth header: ``hmac_sha256(slot_image_mirror_secret,
"<operation>:<image_id>")``. The api computes the same hash when
calling, the mirror verifies. Constant-time compare. Operation =
``put`` / ``get`` / ``delete``.  No timestamp / nonce — a replay
inside the cluster can already write whatever bytes it wants
through the operator path; this gate is defence in depth against
in-cluster pod-to-pod forgery, not a network-layer mitm shield.
"""

from __future__ import annotations

import hmac
import os
import re
import shutil
import uuid
from hashlib import sha256
from pathlib import Path

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.config import settings

logger = structlog.get_logger(__name__)


_AUTH_HEADER = "X-Mirror-Auth"

# Canonical UUID-string shape (8-4-4-4-12 lowercase hex). The regex
# is passed to module-level ``re.fullmatch`` (not the compiled-pattern
# ``Pattern.fullmatch`` method) because CodeQL's ``py/path-injection``
# sanitiser model only recognises the module-level call — verified on
# PR #298 where an earlier attempt using ``_UUID_PATTERN.fullmatch``
# left every taint flow open.
_UUID_PATTERN_STR = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


router = APIRouter()


def _image_dir() -> Path:
    return Path(os.environ.get("SPATIUM_SLOT_IMAGE_DIR", "/var/lib/spatiumddi/slot-images"))


def _image_path(image_id: uuid.UUID) -> Path:
    """Resolved path to the slot image under the mirror dir.

    Four layers of defence against path-injection on the
    ``image_id`` path component. Each layer is independently
    sufficient at runtime; the multiple sanitisers stack because
    CodeQL's data-flow model is conservative — earlier attempts
    that used only ``Path.is_relative_to`` (PR #298 fcac718) and
    method-form ``Pattern.fullmatch`` (PR #298 941c795) were both
    insufficient barriers for the ``py/path-injection`` query.

    1. FastAPI's ``image_id: uuid.UUID`` type annotation rejects
       any non-UUID value before the handler runs (422 on a
       malformed string). Sufficient at runtime; invisible to
       static analysers.

    2. ``re.fullmatch`` against ``_UUID_PATTERN_STR`` re-validates
       the stringified form and the post-match ``Match.group(0)``
       is used as the canonical path component. CodeQL treats the
       regex-match output as a freshly-derived value.

    3. ``os.path.basename`` strips any residual path separator.
       Documented sanitiser for ``py/path-injection``.

    4. ``os.path.abspath`` + ``startswith(base_dir + os.sep)`` —
       the canonical containment check pattern from CodeQL's own
       ``py/path-injection`` help page.
    """
    # 2. Module-level ``re.fullmatch`` + ``Match.group`` derives
    # ``safe_id`` from the regex output — CodeQL treats that as
    # the sanitised binding.
    match = re.fullmatch(_UUID_PATTERN_STR, str(image_id))
    if match is None:
        # Unreachable given the UUID type coercion; bail loudly if a
        # future refactor loosens the type and an attacker reaches
        # this branch.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Invalid slot image id.",
        )
    safe_id = match.group(0)
    # 3. ``os.path.basename`` belts the suspenders — if the regex
    # ever permitted a separator it would be stripped here.
    safe_name = os.path.basename(f"{safe_id}.raw.xz")
    # 4. Canonical CodeQL containment check: abspath + startswith
    # against the base directory + os.sep. ``commonpath`` would
    # also work but ``startswith`` is the documented idiom on
    # CodeQL's py/path-injection help page.
    abs_base = os.path.abspath(_image_dir())
    abs_target = os.path.abspath(os.path.join(abs_base, safe_name))
    if not abs_target.startswith(abs_base + os.sep):
        # Unreachable given the regex + basename; this is the
        # belt-and-braces audit trail.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Resolved slot-image path escapes the mirror directory.",
        )
    return Path(abs_target)


def mirror_auth_token(operation: str, image_id: uuid.UUID) -> str:
    """HMAC-SHA256(secret, "<op>:<image_id>") in lowercase hex.

    Same helper the main api uses to mint the X-Mirror-Auth header
    when proxying a byte op to the mirror Service. Centralised here
    so both sides compute it identically.
    """
    if not settings.slot_image_mirror_secret:
        # The mirror Deployment shouldn't boot without this — the
        # chart wires it from the auth Secret. Bail loudly so a
        # misconfigured deploy doesn't accept every request.
        raise RuntimeError("slot_image_mirror_secret not configured")
    mac = hmac.new(
        settings.slot_image_mirror_secret.encode("utf-8"),
        f"{operation}:{image_id}".encode(),
        sha256,
    )
    return mac.hexdigest()


def _verify_auth(operation: str, image_id: uuid.UUID, header: str | None) -> None:
    if not header:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            f"Missing {_AUTH_HEADER} header.",
        )
    expected = mirror_auth_token(operation, image_id)
    if not hmac.compare_digest(expected, header.strip().lower()):
        # Don't echo the header back — minimise side-channel.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Invalid {_AUTH_HEADER} header.",
        )


def _ensure_dir() -> None:
    d = _image_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError as exc:
        # Intentionally non-fatal: tightening the mode is a defence-
        # in-depth nicety, not a correctness requirement. On most
        # platforms the chmod succeeds; on Kubernetes-mounted PVCs
        # whose StorageClass overrides mode bits (or on a filesystem
        # without permission bits at all) the call returns EPERM /
        # ENOSYS. Log at debug level so the diagnostic exists
        # without spamming the operator log on every restart.
        logger.debug("slot_image_mirror_chmod_skipped", path=str(d), error=str(exc))


@router.put(
    "/{image_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="(mirror) write slot image bytes from the api",
)
async def put_image(image_id: uuid.UUID, request: Request) -> None:
    _verify_auth("put", image_id, request.headers.get(_AUTH_HEADER))
    _ensure_dir()
    target = _image_path(image_id)
    # Append ".partial" to the full ``<id>.raw.xz`` name — NOT
    # ``with_suffix(".raw.xz.partial")``, which replaces only the final
    # ``.xz`` and doubles the ``.raw`` into ``<id>.raw.raw.xz.partial`` (#415).
    tmp = target.with_name(target.name + ".partial")
    # ``streamed`` flips True after the stream-loop completes; the
    # ``finally`` block uses it to decide whether to atomic-rename or
    # clean up the partial. Catches client disconnects + asyncio
    # cancellation mid-stream which would otherwise leave a stale
    # ``.partial`` file on the PVC (Copilot review finding).
    streamed = False
    try:
        with tmp.open("wb") as fh:
            # Stream the request body straight to disk — no buffering
            # the whole 1-4 GiB into RAM. Starlette's iter_bytes gives
            # us the chunked body of the underlying transport stream.
            async for chunk in request.stream():
                if chunk:
                    fh.write(chunk)
        streamed = True
        # Atomic move into place — readers calling GET in parallel
        # see either the old file or nothing, never a half-written one.
        tmp.replace(target)
        logger.info(
            "slot_image_mirror_put",
            image_id=str(image_id),
            size_bytes=target.stat().st_size,
        )
    except HTTPException:
        raise
    except OSError as exc:
        logger.exception("slot_image_mirror_put_failed", image_id=str(image_id))
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Failed to write slot image: {exc}",
        ) from exc
    finally:
        # Any non-success exit (HTTPException, OSError, client
        # disconnect, asyncio.CancelledError, …) leaves the partial
        # file orphaned; clean it up unconditionally. The atomic
        # rename above already removed the .partial on success, so
        # ``missing_ok=True`` is the right idempotent shape.
        if not streamed:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                # Best-effort cleanup; future prune task picks up
                # anything we couldn't unlink here.
                logger.warning(
                    "slot_image_mirror_put_partial_cleanup_failed",
                    image_id=str(image_id),
                    path=str(tmp),
                )


@router.get(
    "/{image_id}",
    summary="(mirror) stream slot image bytes back to the api",
)
async def get_image(image_id: uuid.UUID, request: Request) -> FileResponse:
    _verify_auth("get", image_id, request.headers.get(_AUTH_HEADER))
    path = _image_path(image_id)
    if not path.exists():
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Slot image bytes not present on mirror.",
        )
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=f"{image_id}.raw.xz",
    )


class MirrorDiskUsage(BaseModel):
    """Disk-usage snapshot of the mirror's PVC volume.

    The preflight's ``disk_headroom`` judges each appliance node's own
    ``/var`` from its heartbeat (#1234) — where ``spatium-upgrade-slot``
    stages the image. The mirror's PVC is a separate volume nothing
    there sees, so the Phase B preflight ``check_mirror_disk_headroom``
    calls this endpoint to get the real numbers from it.
    """

    path: str
    free_bytes: int
    total_bytes: int
    used_bytes: int


@router.get(
    "/_/disk-usage",
    response_model=MirrorDiskUsage,
    summary="(mirror) report disk usage of the slot-image PVC volume",
)
async def get_disk_usage(request: Request) -> MirrorDiskUsage:
    # Same X-Mirror-Auth gate as the byte ops, scoped to a special
    # all-zeros image id so the HMAC payload is well-defined for a
    # non-per-image call. Keeps the contract uniform; no special-case
    # auth path on either side.
    _verify_auth("disk-usage", uuid.UUID(int=0), request.headers.get(_AUTH_HEADER))
    target = _image_dir()
    # Probe the parent if the directory doesn't exist yet — first-boot
    # before any upload still gives operators a meaningful answer.
    probe = target if target.exists() else target.parent
    try:
        usage = shutil.disk_usage(probe)
    except OSError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Failed to stat slot-image dir: {exc}",
        ) from exc
    return MirrorDiskUsage(
        path=str(target),
        free_bytes=usage.free,
        total_bytes=usage.total,
        used_bytes=usage.used,
    )


@router.delete(
    "/{image_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="(mirror) remove slot image bytes",
)
async def delete_image(image_id: uuid.UUID, request: Request) -> None:
    _verify_auth("delete", image_id, request.headers.get(_AUTH_HEADER))
    path = _image_path(image_id)
    try:
        path.unlink(missing_ok=True)
        logger.info("slot_image_mirror_delete", image_id=str(image_id))
    except OSError as exc:
        # Best-effort. A failure here doesn't break the main api's
        # delete — the DB row is already gone; stale bytes get
        # reaped by the future prune task.
        logger.warning(
            "slot_image_mirror_delete_failed",
            image_id=str(image_id),
            error=str(exc),
        )
