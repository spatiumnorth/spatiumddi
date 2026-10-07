"""Support-bundle endpoints (issue #875).

* ``POST /system/support-bundle/preview`` — dry run. Returns the file
  list, sizes, what the scrubber replaced, and a redacted excerpt, so
  the operator can review before deciding to share. Proposal 3 of the
  issue.
* ``POST /system/support-bundle`` — the archive itself.
* ``POST /system/support-bundle/decode-map`` — synthetic → real, for the
  operator only. Never inside the archive.

Deliberately **stateless**: every call regenerates. The alternative was
holding the archive in Redis between preview and download, which buys
consistency between the two at the cost of parking a file full of an
operator's diagnostics in a shared cache with a TTL. Since the scrubber
is seeded by ``SECRET_KEY`` via HMAC, a regenerated map is *identical*
for every value it has in common — so the decode call works against a
bundle downloaded minutes earlier without either being stored anywhere.

The consequence, stated rather than hidden: a preview and the download
that follows are separate snapshots, so a busy install may log a line
between them and shift a byte count. The preview is a faithful account
of what a bundle contains, not a checksum of one particular archive.

Superadmin-only and audited. This reads logs, config shape and an audit
tail across the whole platform — a narrower gate would be a way to
exfiltrate all three.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.api.deps import DB, CurrentUser
from app.core.content_disposition import content_disposition
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import is_effective_superadmin
from app.core.responses import ZipResponse
from app.models.audit import AuditLog
from app.services.support_bundle import generate

logger = structlog.get_logger(__name__)
router = APIRouter()

# Typed exactly, and compared case-sensitively, for the unscrubbed
# variant. Not a checkbox: the difference between the two bundles is
# whether real addresses and hostnames leave the building, and a
# mis-click should not be able to produce the wrong one.
UNSCRUBBED_CONFIRM = "I understand this bundle is not anonymised"


class BundleRequest(BaseModel):
    scrubbed: bool = Field(
        default=True,
        description=(
            "Pseudonymise IPs / hostnames / MACs / usernames. Leave true for "
            "anything you intend to share. Credentials are excluded either way."
        ),
    )
    confirm_unscrubbed: str | None = Field(
        default=None,
        description=(f"Required verbatim when scrubbed=false: {UNSCRUBBED_CONFIRM!r}"),
    )


class FilePreviewOut(BaseModel):
    path: str
    bytes: int
    truncated: bool


class BundlePreviewOut(BaseModel):
    scrubbed: bool
    filename: str
    total_bytes: int
    files: list[FilePreviewOut]
    manifest: dict[str, Any]
    section_errors: list[str]
    sample: str
    warning: str


def _require_superadmin(user: Any) -> None:
    if not is_effective_superadmin(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Support bundles are superadmin-only: one archive carries "
                "platform logs, configuration shape and an audit tail."
            ),
        )


def _check_unscrubbed(body: BundleRequest) -> None:
    if body.scrubbed:
        return
    if body.confirm_unscrubbed != UNSCRUBBED_CONFIRM:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "An unscrubbed bundle contains real hostnames, IP addresses, "
                "MAC addresses and usernames, and must never be attached to a "
                f"public issue. To generate one, send confirm_unscrubbed="
                f"{UNSCRUBBED_CONFIRM!r} verbatim."
            ),
        )


def _audit(user: Any, scrubbed: bool, action: str) -> AuditLog:
    return AuditLog(
        user_id=user.id,
        user_display_name=user.display_name,
        auth_source=user.auth_source,
        action=action,
        resource_type="support_bundle",
        resource_id="-",
        resource_display=("scrubbed" if scrubbed else "UNSCRUBBED"),
        result="success",
    )


@router.post("/preview", response_model=BundlePreviewOut)
async def preview_support_bundle(
    body: BundleRequest, db: DB, current_user: CurrentUser
) -> BundlePreviewOut:
    """Dry run — what a bundle generated right now would contain."""
    _require_superadmin(current_user)
    # Gated like the download it precedes. The preview is not a summary:
    # it returns an excerpt of the real activity log plus the whole file
    # inventory, so leaving it open on a shared demo instance would read
    # out most of what blocking the download is meant to prevent.
    forbid_in_demo_mode()
    _check_unscrubbed(body)

    result = await generate(db, scrubbed=body.scrubbed)
    # Audited like the download. A preview reads exactly the same data;
    # only the response body differs, so auditing one and not the other
    # would leave a gap that looks like a way to read without a trace.
    db.add(_audit(current_user, body.scrubbed, "read"))
    await db.commit()

    return BundlePreviewOut(
        scrubbed=result.scrubbed,
        filename=result.filename,
        total_bytes=len(result.archive),
        files=[FilePreviewOut(**vars(f)) for f in result.files],
        manifest=result.manifest,
        section_errors=result.errors,
        sample=result.sample,
        warning=str(result.manifest.get("READ_THIS", "")),
    )


@router.post(
    "",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=ZipResponse,
    responses={200: {"description": "The support-bundle archive"}},
)
async def download_support_bundle(
    body: BundleRequest, db: DB, current_user: CurrentUser
) -> Response:
    """Generate and return the archive."""
    _require_superadmin(current_user)
    forbid_in_demo_mode()
    _check_unscrubbed(body)

    result = await generate(db, scrubbed=body.scrubbed)
    db.add(_audit(current_user, body.scrubbed, "export"))
    await db.commit()

    return Response(
        content=result.archive,
        media_type="application/zip",
        headers={
            "Content-Disposition": content_disposition(result.filename),
            "Content-Length": str(len(result.archive)),
        },
    )


class DecodeMapOut(BaseModel):
    warning: str
    mappings: dict[str, dict[str, str]]
    counts: dict[str, int]


@router.post("/decode-map", response_model=DecodeMapOut)
async def support_bundle_decode_map(db: DB, current_user: CurrentUser) -> DecodeMapOut:
    """Synthetic → real, so support's answers can be acted on.

    Kept out of the archive on purpose. The mapping is regenerated here
    rather than stored: it is deterministic per install, so a token from
    an earlier bundle resolves the same way.
    """
    _require_superadmin(current_user)
    forbid_in_demo_mode()

    result = await generate(db, scrubbed=True)
    db.add(_audit(current_user, True, "read"))
    await db.commit()

    return DecodeMapOut(
        warning=(
            "This mapping reverses the scrubbing. Keep it local — sharing it "
            "alongside a bundle undoes the anonymisation completely."
        ),
        mappings=result.decode_map,
        counts={k: len(v) for k, v in result.decode_map.items()},
    )
