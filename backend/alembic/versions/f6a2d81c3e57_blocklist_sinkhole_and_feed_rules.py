"""DNS blocklists: retire block_mode 'refused'; feed exceptions + skip counts (#2124, #2123)

#2124 — ``refused`` is no longer a block mode: BIND's RPZ has no action that
answers REFUSED, and the agent (the renderer that serves production) always
rendered it as NXDOMAIN. Stored ``refused`` rows are rewritten to
``nxdomain``, so what every such list answers with does not change.

#2123 — an adblock feed's own ``@@||name^`` rules become the list's
exceptions, so ``dns_blocklist_exception`` gains ``source`` (``manual`` |
``feed``; existing rows are all operator-added, hence the ``manual``
default), letting a refresh add and remove its own rows without touching the
operator's. ``dns_blocklist.feed_parse_skipped`` records how many rules the
last adblock refresh could not enforce, by category. Nullable, no backfill:
NULL means no adblock refresh has run since, never "nothing was lost".

Revision ID: f6a2d81c3e57
Revises: b4d81f2e6a93
Create Date: 2026-10-19

"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "f6a2d81c3e57"
down_revision = "b4d81f2e6a93"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE dns_blocklist SET block_mode = 'nxdomain' WHERE block_mode = 'refused'")
    op.add_column(
        "dns_blocklist",
        sa.Column("feed_parse_skipped", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "dns_blocklist_exception",
        sa.Column(
            "source",
            sa.String(length=20),
            nullable=False,
            server_default="manual",
        ),
    )


def downgrade() -> None:
    # The ``refused`` → ``nxdomain`` rewrite is not reversed: the rows it
    # touched are indistinguishable from lists created as ``nxdomain``, and
    # both rendered identically on the agent anyway.
    op.drop_column("dns_blocklist_exception", "source")
    op.drop_column("dns_blocklist", "feed_parse_skipped")
