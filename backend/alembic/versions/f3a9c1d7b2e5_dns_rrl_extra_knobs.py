"""DNS RRL extra knobs (#3577)

Adds the optional BIND ``rate-limit`` knobs (nxdomains / errors / referrals /
nodata / all per second, IPv4 / IPv6 prefix length, max-table-size) to
dns_server_options. All nullable with no default: null renders nothing, so
every existing group's named.conf is byte-identical after the upgrade.

Revision ID: f3a9c1d7b2e5
Revises: ede3bcd2aff4
Create Date: 2026-11-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f3a9c1d7b2e5"
down_revision: str | None = "ede3bcd2aff4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    "rrl_nxdomains_per_second",
    "rrl_errors_per_second",
    "rrl_referrals_per_second",
    "rrl_nodata_per_second",
    "rrl_all_per_second",
    "rrl_ipv4_prefix_length",
    "rrl_ipv6_prefix_length",
    "rrl_max_table_size",
)


def upgrade() -> None:
    for col in _COLUMNS:
        op.add_column("dns_server_options", sa.Column(col, sa.Integer(), nullable=True))


def downgrade() -> None:
    for col in reversed(_COLUMNS):
        op.drop_column("dns_server_options", col)
