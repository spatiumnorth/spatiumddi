"""DHCP client classes get an address family (#1229, #1295).

Every client class was rendered into both Kea daemons. A test expression
using a DHCPv4-only token (``pkt4``, ``relay4``) makes kea-dhcp6 reject the
whole config, and a DHCPv6-only one (``pkt6``, ``relay6``) does the same to
kea-dhcp4 — and the agent reverts the WHOLE bundle, v4 included.

New column ``dhcp_client_class.address_family`` (``ipv4`` | ``ipv6`` |
``dual``). The backfill keeps what worked:

* a test naming ``pkt6`` / ``relay6`` → ``ipv6`` (it could only ever have
  loaded in Dhcp6);
* a test naming ``pkt4`` / ``relay4`` → ``ipv4``;
* otherwise, a class whose group has a live DHCPv6 scope → ``dual``, which is
  what it rendered as before; any other → ``ipv4``, since Dhcp6 was never
  rendered for its group.

A test naming both families' tokens could never load anywhere; it becomes
``ipv4`` so the Dhcp4 half at least is back in the operator's hands.

Revision ID: c2f7a94e1d58
Revises: e6b2d94f1a37
Create Date: 2026-09-29
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c2f7a94e1d58"
down_revision = "e6b2d94f1a37"
branch_labels = None
depends_on = None

# Postgres word boundaries (\m / \M), so ``mypkt4`` is not a match.
_V4_TOKENS = r"\m(pkt4|relay4)\M"
_V6_TOKENS = r"\m(pkt6|relay6)\M"

BACKFILL = f"""
UPDATE dhcp_client_class c
SET address_family = CASE
    WHEN c.match_expression ~ '{_V4_TOKENS}' THEN 'ipv4'
    WHEN c.match_expression ~ '{_V6_TOKENS}' THEN 'ipv6'
    WHEN EXISTS (
        SELECT 1 FROM dhcp_scope s
        WHERE s.group_id = c.group_id
          AND s.address_family = 'ipv6'
          AND s.deleted_at IS NULL
    ) THEN 'dual'
    ELSE 'ipv4'
END
"""


def upgrade() -> None:
    op.add_column(
        "dhcp_client_class",
        sa.Column("address_family", sa.String(4), nullable=False, server_default="ipv4"),
    )
    op.execute(BACKFILL)


def downgrade() -> None:
    op.drop_column("dhcp_client_class", "address_family")
