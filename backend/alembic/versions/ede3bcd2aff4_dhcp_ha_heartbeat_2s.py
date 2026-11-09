"""Move DHCP HA groups still at the old 10 s heartbeat default to 2 s (#3779).

Every Kea ``config-reload`` restarts the HA hook's state machine, and its
WAITING -> READY -> HOT-STANDBY transitions are paced by ``heartbeat-delay``.
At 10000 ms a scope change on an HA pair takes about 21 s out of
hot-standby; at 2000 ms about 4 s. The model default moved to 2000, but the
column has no server default and every row stores its value explicitly
(the group-centric migration seeded 10000, and the create API and the UI
both sent 10000), so without this the change would reach only new groups.

Only rows at exactly 10000 move. A group an operator deliberately set to
10000 cannot be told apart from one left at the default, and is moved too;
any other value is an operator choice and is kept. Partner-down detection
is governed by ``max-response-delay`` (60000 by default), not by the
heartbeat, so the shorter heartbeat does not make failover more eager.

The downgrade does nothing: after the upgrade, a row at 2000 may be one
this migration moved or one an operator set, and putting 10000 back on
both would overwrite the second.

Revision ID: ede3bcd2aff4
Revises: e2a9c5d71f30
"""

from __future__ import annotations

from alembic import op

revision: str = "ede3bcd2aff4"
down_revision: str | None = "e2a9c5d71f30"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE dhcp_server_group SET heartbeat_delay_ms = 2000 WHERE heartbeat_delay_ms = 10000"
    )


def downgrade() -> None:
    # Deliberately irreversible, see the module docstring.
    pass
