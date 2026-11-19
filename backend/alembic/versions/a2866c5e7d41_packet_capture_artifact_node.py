"""packet_capture.artifact_node: the node whose disk holds the artifact (#2866).

On a multi-node appliance ``pcap_path`` is the per-node ``pcaps`` hostPath,
so a capture's file exists only on the disk of the node whose api pod took
the supervisor's upload (or whose worker ran a server-side capture). A
download answered by another node's api could only say "pruned or volume
drift". This adds one nullable column, stamped from the pod's ``NODE_NAME``
when the artifact is recorded. NULL means unknown: a capture from before
this migration, or a deployment with no node name (Compose). No backfill,
since no existing row can say where its file was written.

Revision ID: a2866c5e7d41
Revises: c34ff60a954f
Create Date: 2026-10-27
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a2866c5e7d41"
down_revision: str | None = "c34ff60a954f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "packet_capture",
        sa.Column("artifact_node", sa.String(253), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("packet_capture", "artifact_node")
