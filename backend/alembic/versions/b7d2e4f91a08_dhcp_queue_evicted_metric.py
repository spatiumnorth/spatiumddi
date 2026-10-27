"""#2889 — ``dhcp_metric_sample.queue_evicted``: requests Kea's queue evicted.

One column. kea-dhcp4 3.0 discards the oldest packets in its
multi-threading queue when a burst outruns its worker, and keeps no
statistic for it, so none of the #980 counters move: ``socket_drop`` is
the kernel dropping before Kea reads, and ``receive_drop`` /
``pkt4-received`` are counted by the worker, after the queue. The agent now
derives the eviction from DHCPv4 arrivals at Kea's intake (counted in the
kernel), less the DHCPv4 share of ``socket_drop``, less ``pkt4-received``.

NULLABLE with no server_default, exactly like ``socket_drop``: NULL means
nobody measured it — an agent older than this change, one without
``CAP_NET_RAW``, a v6-only server, or a bucket that straddled a Kea restart
— and 0 means measured and nothing evicted. A default of 0 would label every
existing bucket as a server whose queue never overflowed, which is the
false reassurance the issue was filed about. No backfill, for the same
reason.

Revision ID: b7d2e4f91a08
Revises: a2866c5e7d41
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "b7d2e4f91a08"
down_revision: str | None = "a2866c5e7d41"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "dhcp_metric_sample",
        sa.Column("queue_evicted", sa.BigInteger(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dhcp_metric_sample", "queue_evicted")
