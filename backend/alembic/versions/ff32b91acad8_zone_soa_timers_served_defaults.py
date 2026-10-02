"""#1171 — zones still at the old SOA defaults keep serving what they serve today.

Data-only. No schema change, no new table, no new column.

Until this release the BIND9 agent never received a zone's SOA timers and
wrote ``3600 600 86400 300`` (REFRESH, RETRY, EXPIRE, MINIMUM) into every
zone it served. The stored values were never read. Zones were created with
different stored defaults, ``86400 / 7200 / 3600000 / 3600``, so on upgrade,
when the agent starts rendering the stored timers, every zone left at the
defaults would change on the wire: negative answers cached for an hour
instead of five minutes, secondaries refreshing daily and serving a zone for
41 days without its primary instead of one.

WHAT IT DOES
------------
A zone whose four timers are exactly the old defaults gets the values it is
served with today, which are also the new defaults
(``app.models.dns.ZONE_DEFAULT_*``). So nothing changes on the wire at the
upgrade, and a zone created afterwards matches. A zone with any timer edited
keeps all four as they are: those values start being served, which is what
the operator asked for when they set them. Every zone is matched, whichever
driver serves it; only the BIND9 agent renders these timers, so for the
others nothing changes on the wire either way.

A zone that was given exactly ``86400 / 7200 / 3600000 / 3600`` on purpose
(RIPE-203's recommendation, or imported from a server that used it) cannot
be told apart from one left at the defaults, and is rewritten too. Those
values were never served either, so it keeps serving what it served before.

No serial bump: the zones this touches serve the same SOA before and after.

DOWNGRADE IS A NO-OP
--------------------
Which zones were at the old defaults is not recorded, and the release
before this one never reads the timers, so the values it finds make no
difference to what it serves.

Revision ID: ff32b91acad8
Revises: f4a8c2e71d09
Create Date: 2026-10-02
"""

from __future__ import annotations

import logging

import sqlalchemy as sa

from alembic import op

revision = "ff32b91acad8"
down_revision = "f4a8c2e71d09"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    # Literal values, not the model constants: a migration must keep meaning
    # what it meant when it was written, whatever the defaults become later.
    result = op.get_bind().execute(
        sa.text(
            "UPDATE dns_zone "
            "SET refresh = 3600, retry = 600, expire = 86400, minimum = 300 "
            "WHERE refresh = 86400 AND retry = 7200 AND expire = 3600000 "
            "AND minimum = 3600"
        )
    )
    logger.info(
        "#1171: %s zone(s) at the old SOA defaults keep their served timers",
        result.rowcount,
    )


def downgrade() -> None:
    # Deliberately a no-op; see the module docstring.
    pass
