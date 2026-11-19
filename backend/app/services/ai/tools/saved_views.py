"""Operator Copilot tools for saved searches / saved views (issue #77).

Two read-only tools, both scoped to the *calling* user — a saved view
is personal and never shared, so the Copilot only ever sees the current
operator's own views:

* ``find_saved_views`` — list the user's saved list-page presets
  (filter/sort/column state), optionally filtered to one page key.
* ``count_saved_views`` — how many the user has, optionally per page.

Both carry ``module="ui.saved_views"`` so disabling the feature module
strips them from the AI surface (NN #14). No ``propose_*`` write — a
saved view is a trivial personal preference the operator sets in one
click from the page header; there's nothing the model needs to mutate.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.saved_view import SavedView
from app.services.ai.tools.base import register_tool


def _view_to_dict(row: SavedView) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "page": row.page,
        "name": row.name,
        "is_default": row.is_default,
        "payload": row.payload or {},
        "modified_at": row.modified_at.isoformat(),
    }


# ── find_saved_views ────────────────────────────────────────────────


class FindSavedViewsArgs(BaseModel):
    page: str | None = Field(
        default=None,
        description=(
            "Filter to one page key (e.g. 'network.services'). Omit to "
            "list the user's views across every page."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_saved_views",
    permission="self",
    description=(
        "List the current user's saved views — named filter/sort/column "
        "presets for list pages. Each row carries the page key, the view "
        "name, whether it's the page default, and the stored payload. Use "
        "to answer 'what saved views do I have?' or 'show my services "
        "filters'. Personal-only and read-only — never shows another "
        "user's views."
    ),
    args_model=FindSavedViewsArgs,
    category="read",
    default_enabled=True,
    module="ui.saved_views",
)
async def find_saved_views(
    db: AsyncSession, user: User, args: FindSavedViewsArgs
) -> dict[str, Any]:
    stmt = select(SavedView).where(SavedView.user_id == user.id)
    if args.page is not None:
        stmt = stmt.where(SavedView.page == args.page)
    stmt = stmt.order_by(SavedView.modified_at.desc()).limit(args.limit)
    rows = list((await db.execute(stmt)).scalars().all())
    return {
        "saved_views": [_view_to_dict(r) for r in rows],
        "count": len(rows),
    }


# ── count_saved_views ───────────────────────────────────────────────


class CountSavedViewsArgs(BaseModel):
    page: str | None = Field(
        default=None,
        description="Optional page key to count views for. Omit for all pages.",
    )


@register_tool(
    name="count_saved_views",
    permission="self",
    description=(
        "Count the current user's saved views, optionally for one page "
        "key. Personal-only and read-only."
    ),
    args_model=CountSavedViewsArgs,
    category="read",
    default_enabled=True,
    module="ui.saved_views",
)
async def count_saved_views(
    db: AsyncSession, user: User, args: CountSavedViewsArgs
) -> dict[str, Any]:
    stmt = select(func.count(SavedView.id)).where(SavedView.user_id == user.id)
    if args.page is not None:
        stmt = stmt.where(SavedView.page == args.page)
    count = (await db.execute(stmt)).scalar_one()
    return {"count": int(count), "page": args.page}


__all__ = ["find_saved_views", "count_saved_views"]
