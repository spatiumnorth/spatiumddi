"""dns_server: clear the stale ``agent v2026.04.14.1`` note (#2112)

Before #2078 a DNS agent registering a new server wrote
``agent v<version>`` into the operator's ``notes``, and every agent released
back then sent the fixed literal ``2026.04.14.1``. #2091 stopped writing
``notes`` and shows the real version in its own field, but left existing
notes alone, so an upgraded install showed the stale note under the correct
Agent version.

Only a note equal to exactly ``agent v2026.04.14.1`` is cleared: that is the
literal every pre-fix agent wrote and it names no build, so no operator
wrote it. Any other text, including a real ``agent v<other>`` an operator
may have kept, is untouched. A data cleanup: the downgrade does nothing,
since the cleared text carried no information.

Revision ID: d3a7f19c52e8
Revises: c8e2a5f71d39
Create Date: 2026-10-19 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "d3a7f19c52e8"
down_revision = "c8e2a5f71d39"
branch_labels = None
depends_on = None

# Module-level so the tests, which build their schema with ``create_all``,
# run the exact statement.
CLEAR_STALE_NOTE_SQL = sa.text(
    "UPDATE dns_server SET notes = '' WHERE notes = 'agent v2026.04.14.1'"
)


def upgrade() -> None:
    op.execute(CLEAR_STALE_NOTE_SQL)


def downgrade() -> None:
    pass
