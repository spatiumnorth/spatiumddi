"""Stored DNS agent bundles: the renderer revision that produced them (#1185).

Two nullable integer columns, no backfill.

``dns_agent_bundle.renderer_revision`` / ``dns_server.bundle_renderer_revision``:
the ``RENDERER_REVISION`` of the code that rendered the bundle. It replaces
``app_version`` as the currency check (the version columns stay, for
diagnostics). Comparing release strings for equality made two releases that
both have the store replace each other's renders every 30 s during a rolling
upgrade, and made every release re-render every server even when it did not
touch the renderer. A revision is compared with ``>=``: no process replaces a
render from a newer revision, and a release that leaves the renderer alone
re-renders nothing.

Every bundle stored before this migration has NULL, which reads as stale, so
each server re-renders once after the upgrade.

Revision ID: e6b2d94f1a37
Revises: b8e2d5c07a14
Create Date: 2026-09-25
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e6b2d94f1a37"
down_revision = "b8e2d5c07a14"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dns_agent_bundle", sa.Column("renderer_revision", sa.Integer(), nullable=True))
    op.add_column("dns_server", sa.Column("bundle_renderer_revision", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("dns_server", "bundle_renderer_revision")
    op.drop_column("dns_agent_bundle", "renderer_revision")
