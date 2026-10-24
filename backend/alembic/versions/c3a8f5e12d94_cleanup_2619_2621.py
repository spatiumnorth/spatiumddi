"""Data cleanup: unmeetable password minimum (#2619) and dead role grants (#2621).

* #2619: passwords over 72 bytes are refused (bcrypt's limit), so a
  ``platform_settings.password_min_length`` above 72 can never be met. Clamp it
  to 72.
* #2621: role grants whose ``resource_type`` is ``asn`` or ``domain`` are
  checked by no route (the real types are ``manage_asns`` / ``manage_domains``).
  Remove exactly those entries from ``role.permissions``; every other grant on
  the role is left untouched. They are deliberately NOT rewritten to the new
  names: the operator chose to drop them.

The downgrade is a no-op: the previous values are not recoverable and
restoring a never-satisfiable minimum or dead grants would be meaningless.

Revision ID: c3a8f5e12d94
Revises: e7b2d4c81f06
Create Date: 2026-10-24
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "c3a8f5e12d94"
down_revision = "e7b2d4c81f06"
branch_labels = None
depends_on = None

_DEAD_TYPES = ("asn", "domain")


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE platform_settings SET password_min_length = 72 "
            "WHERE password_min_length > 72"
        )
    )
    rows = conn.execute(sa.text("SELECT id, permissions FROM role")).fetchall()
    for role_id, perms in rows:
        if not isinstance(perms, list):
            continue
        kept = [
            p for p in perms if not (isinstance(p, dict) and p.get("resource_type") in _DEAD_TYPES)
        ]
        if len(kept) != len(perms):
            conn.execute(
                sa.text("UPDATE role SET permissions = CAST(:p AS jsonb) WHERE id = :id"),
                {"p": json.dumps(kept), "id": role_id},
            )


def downgrade() -> None:
    # Data cleanup; the removed values cannot be restored meaningfully.
    pass
