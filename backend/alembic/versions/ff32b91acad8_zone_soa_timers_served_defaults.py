"""#1171 — a zone's SOA timers change on the wire only where someone set them.

Data-only. No schema change, no new table, no new column.

Until this release the BIND9 agent never received a zone's SOA timers and
wrote ``3600 600 86400 300`` (REFRESH, RETRY, EXPIRE, MINIMUM) into every
zone it served. The stored values were never read. Zones were created with
different stored defaults, ``86400 / 7200 / 3600000 / 3600``, so once the
agent renders the stored timers, every timer left at its default would
change on the wire: negative answers cached for an hour instead of five
minutes, secondaries refreshing daily and serving a zone for 41 days without
its primary instead of one.

WHAT IT DOES
------------
1. Each timer still at its old stored default gets the value it is served
   with today, which is also its new default (``app.models.dns.ZONE_DEFAULT_*``):
   refresh 86400 -> 3600, retry 7200 -> 600, expire 3600000 -> 86400,
   minimum 3600 -> 300. Each timer on its own, so a zone where an operator
   set only ``minimum`` keeps serving today's refresh, retry and expire,
   values nobody chose otherwise. A timer that was set to something else
   keeps it, and starts being served: that is the #1171 fix.
2. Every zone whose timers are not ``3600 / 600 / 86400 / 300`` after step 1
   is exactly a zone whose served SOA changes at this upgrade, so its serial
   moves. Without it the primary serves the new timers under the old serial,
   and a secondary asking for the zone is told it is already up to date and
   keeps the old ones until something else moves the serial. The rule is
   ``bump_zone_serial``'s (``compute_next_serial``), which always comes to the
   larger of today's ``YYYYMMDD00`` and the current serial plus one; a zone
   stored at 0 is served as 1, and today's base is above both.

Every zone is matched, whichever driver serves it. Only the BIND9 agent
renders these timers; for the others the values make no difference to what
they serve, and the serial bump only affects zones an operator edited.

A timer an operator set on purpose to exactly its old default (RIPE-203's
recommendation, or imported from a server that used it) cannot be told apart
from one left alone, and is rewritten too. That value was never served
either, so the timer keeps serving what it served before.

DOWNGRADE IS A NO-OP
--------------------
Which timers were at the old defaults is not recorded, and the release
before this one never reads the timers, so the values it finds make no
difference to what it serves. A serial never goes backwards, so upgrading
again after a downgrade moves the edited zones' serials once more, which
costs their secondaries one extra transfer and nothing else.

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

# (column, old stored default, value served today). Literals, not the model
# constants: a migration must keep meaning what it meant when it was written.
_TIMERS = (
    ("refresh", 86400, 3600),
    ("retry", 7200, 600),
    ("expire", 3600000, 86400),
    ("minimum", 3600, 300),
)


def upgrade() -> None:
    bind = op.get_bind()
    for column, old, served in _TIMERS:
        result = bind.execute(
            sa.text(f"UPDATE dns_zone SET {column} = :served WHERE {column} = :old"),
            {"served": served, "old": old},
        )
        logger.info(
            "#1171: %s zone(s) keep serving %s %s (was stored as %s)",
            result.rowcount,
            column,
            served,
            old,
        )
    result = bind.execute(
        sa.text(
            "UPDATE dns_zone SET last_serial = GREATEST("
            "CAST(to_char(now() AT TIME ZONE 'UTC', 'YYYYMMDD') AS integer) * 100, "
            "last_serial + 1) "
            "WHERE NOT (refresh = 3600 AND retry = 600 AND expire = 86400 "
            "AND minimum = 300)"
        )
    )
    logger.info(
        "#1171: %s zone(s) serve edited SOA timers from now on; their serial moved",
        result.rowcount,
    )


def downgrade() -> None:
    # Deliberately a no-op; see the module docstring.
    pass
