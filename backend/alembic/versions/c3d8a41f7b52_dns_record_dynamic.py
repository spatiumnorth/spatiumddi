"""``dns_record.dynamic`` — was the record registered dynamically (#2251).

Windows DNS stamps a record a DHCP server or a client registered
dynamically with an aging timestamp; a static record carries none. The
pull importer (Path B, ``Get-DnsServerResourceRecord``) now reads that and
stores ``True`` (dynamic) or ``False`` (static) here, so "Populate IPAM
from DNS" can leave DDNS-owned records out by default.

NULL means UNKNOWN: every row that existed before this column, and every
record read over AXFR (Path A, BIND9, Technitium), which carries no
timestamp. Nothing is backfilled.

Revision ID: c3d8a41f7b52
Revises: ede3bcd2aff4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "c3d8a41f7b52"
down_revision: str | None = "ede3bcd2aff4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dns_record", sa.Column("dynamic", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("dns_record", "dynamic")
