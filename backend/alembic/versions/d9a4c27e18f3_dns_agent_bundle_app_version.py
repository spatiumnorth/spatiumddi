"""Stored DNS agent bundles: the release that rendered them, and when they fell behind (#1111).

Three nullable-or-defaulted columns, no backfill.

``dns_agent_bundle.app_version`` / ``dns_server.bundle_app_version``: the
release (``settings.version``) whose code rendered the bundle. A stored
bundle is current only when its watermark has caught up with the dirty
sequence AND it was rendered by the running release. Without the second
half, an upgrade that changes what the renderer emits — a rendering fix,
a new bundle key — kept serving the previous release's bytes until some
unrelated change happened to mark the server. Every bundle rendered before
this migration carries the empty string, so each server re-renders once
after the upgrade.

``dns_server.bundle_dirty_at``: when the stored bundle first fell behind.
Set by the dirty mark, kept across further marks, cleared by a render that
catches up (and restarted by one that finishes still behind, because
changes landed while it ran). The ``agent_bundle_render_failed`` rule reads
it: a bundle that stays behind with no render landing — the worker is not
consuming the ``bundles`` queue, or its renders are being killed — never
records a failure, so the failure columns alone cannot see it.

A separate migration rather than an edit to ``c4d1e7f90a2b``, so a rig that
ran the earlier build of the branch can still take that migration's own
downgrade.

Revision ID: d9a4c27e18f3
Revises: c4d1e7f90a2b
Create Date: 2026-09-24
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d9a4c27e18f3"
down_revision = "c4d1e7f90a2b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_agent_bundle",
        sa.Column("app_version", sa.String(64), nullable=False, server_default=""),
    )
    op.add_column("dns_server", sa.Column("bundle_app_version", sa.String(64), nullable=True))
    op.add_column(
        "dns_server", sa.Column("bundle_dirty_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("dns_server", "bundle_dirty_at")
    op.drop_column("dns_server", "bundle_app_version")
    op.drop_column("dns_agent_bundle", "app_version")
