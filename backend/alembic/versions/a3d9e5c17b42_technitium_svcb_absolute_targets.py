"""Technitium SVCB / HTTPS targets: write the trailing dot they were served with (#1513).

Until #1513 both Technitium paths (the agent and the agentless
``technitium_api`` driver) stripped the dot off an SVCB / HTTPS target and
sent the rest as-is, and Technitium has no relative names — so a stored
``1 cdn.example.net alpn=h2`` was served as ``cdn.example.net.``. The #744
importer and the Sync-with-Servers pull wrote exactly that shape, without
the dot, for every record they read off a Technitium daemon.

#1513 makes those paths read a target the way a zone file does — no
trailing dot means relative to the zone — so the same stored value would
now be sent as ``cdn.example.net.<zone>``: every such record re-pointed on
upgrade. This migration writes the dot those records were already served
with, so nothing served changes.

Only multi-label targets, and only in groups running a Technitium driver.
A single label (``svc``) is left alone: it was served as the TLD-shaped
``svc.``, which nothing means, and #1513 now serves it as ``svc.<zone>.`` —
the fix, not something to preserve. BIND9 / PowerDNS groups always read a
dot-less target as relative, so their records mean today what they meant
before.

Revision ID: a3d9e5c17b42
Revises: c2f7a94e1d58
Create Date: 2026-10-09
"""

from __future__ import annotations

import re

import sqlalchemy as sa

from alembic import op

revision = "a3d9e5c17b42"
down_revision = "c2f7a94e1d58"
branch_labels = None
depends_on = None

# priority, whitespace, target, then the params verbatim.
_VALUE = re.compile(r"^(\s*\S+\s+)(\S+)(.*)$", re.S)


def _dot_terminate(value: str) -> str:
    m = _VALUE.match(value or "")
    if not m:
        return value
    head, target, rest = m.groups()
    if target in (".", "@") or target.endswith(".") or "." not in target:
        return value
    return f"{head}{target}.{rest}"


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            """
            SELECT r.id, r.value
            FROM dns_record r
            JOIN dns_zone z ON z.id = r.zone_id
            WHERE r.record_type IN ('SVCB', 'HTTPS')
              AND EXISTS (
                  SELECT 1 FROM dns_server s
                  WHERE s.group_id = z.group_id
                    AND s.driver IN ('technitium', 'technitium_api')
              )
            """
        )
    ).fetchall()
    for rid, value in rows:
        new = _dot_terminate(value)
        if new != value:
            conn.execute(
                sa.text("UPDATE dns_record SET value = :v WHERE id = :id"),
                {"v": new, "id": rid},
            )


def downgrade() -> None:
    # The added dot is correct under either reading (an absolute name is
    # absolute whether or not the old code would have added the dot), so
    # there is nothing to undo.
    pass
