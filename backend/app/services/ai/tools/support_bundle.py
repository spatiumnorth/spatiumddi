"""Operator Copilot access to the support bundle (issue #875)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.services.ai.tools.base import register_tool


class SupportBundlePreviewArgs(BaseModel):
    """No arguments — the preview describes the whole bundle."""


@register_tool(
    name="get_support_bundle_preview",
    permission="superadmin",
    description=(
        "Describe what a support bundle generated right now would "
        "contain: the file list with sizes, how many IPs / hostnames / "
        "MACs / usernames the scrubber replaced, which credential "
        "columns were dropped, and any section that failed to collect. "
        "Use for 'what goes into a support bundle?', 'is my bundle "
        "safe to attach to a GitHub issue?' or 'why is section X "
        "missing?'. Does NOT return the archive — download that from "
        "System > Support bundle, where the confirm-and-review step is."
    ),
    args_model=SupportBundlePreviewArgs,
    category="system",
    # Default OFF. This is a broad read: generating the preview walks
    # platform logs, the settings row, an audit tail and recent errors.
    # Everything it RETURNS is scrubbed metadata rather than content, but
    # the operator should still opt in deliberately rather than discover
    # it is on.
    default_enabled=False,
)
async def get_support_bundle_preview(
    db: AsyncSession, user: User, args: SupportBundlePreviewArgs
) -> dict[str, Any]:
    from app.services.support_bundle import generate  # noqa: PLC0415

    if not is_effective_superadmin(user):
        return {
            "error": (
                "Support bundles are superadmin-only — one archive carries "
                "platform logs, configuration shape and an audit tail."
            )
        }

    result = await generate(db, scrubbed=True)
    return {
        "filename": result.filename,
        "total_bytes": len(result.archive),
        "files": [
            {"path": f.path, "bytes": f.bytes, "truncated": f.truncated} for f in result.files
        ],
        "scrub_summary": result.manifest.get("scrub", {}),
        "section_errors": result.errors,
        "warning": result.manifest.get("READ_THIS", ""),
        "note": (
            "Scrubbing is best-effort, like `sos report --clean`. Review the "
            "archive before attaching it to a public issue — attachments "
            "there are readable by anyone who can see the issue."
        ),
    }
