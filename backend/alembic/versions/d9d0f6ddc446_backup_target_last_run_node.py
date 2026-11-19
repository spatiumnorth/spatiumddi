"""backup_target.last_run_node: the node that wrote the last archive (#1838).

On a multi-node appliance a ``local_volume`` target's directory is a
per-node hostPath, so an archive exists only on the disk of the node whose
pod wrote it. Nothing recorded which node that was, so a restore, download
or drill answered by another node's api could only say "not found".

This adds one nullable column, stamped by the backup runner on every
successful run from the pod's ``NODE_NAME`` (downward API) and cleared when
a run is claimed, alongside ``last_run_filename``. NULL means unknown: a run
from before this migration, or a deployment with no node name (Compose).
No backfill, since no existing row can say where its archive was written.

Revision ID: d9d0f6ddc446
Revises: b8e41c7a2d95
Create Date: 2026-10-14
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d9d0f6ddc446"
down_revision: Union[str, None] = "b8e41c7a2d95"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "backup_target",
        sa.Column("last_run_node", sa.String(253), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("backup_target", "last_run_node")
