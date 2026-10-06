"""#1171 — a zone's SOA timers change on the wire only where someone set them,
and never under a serial an older BIND9 agent served.

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
2. Two columns record who can serve them (``app.services.dns.soa_timers``):
   ``dns_server.agent_renders_soa_timers``, which an agent's register and
   heartbeat set (``X-Spatium-Agent-Features: soa-timers``), and
   ``dns_server_group.serves_soa_timers``, whether the group's bundles carry
   each zone's own timers or the literal ``3600 600 86400 300``. Every group
   with a BIND9 agent starts on the literal: at this point its agents are the
   previous release's, and that is what they write.
3. No serial moves here. A group switches to the zones' own timers when its
   last BIND9 agent reports it renders them, and that same transaction moves
   the serial of each of its zones whose timers are not the literal, so the
   new SOA goes out under a serial no agent ever served with the old one.

The first version of this revision moved those serials here. The previous
release's DNS agent, still running when the new release's first bundle
reached it, then served each moved serial with the literal until its pod was
replaced: 44 s and 52 s on a single node upgraded from 2026.10.02-1, longer on
a cluster rolling one node at a time. A secondary that transferred inside
that window kept the literal, told it was up to date.

A timer an operator set on purpose to exactly its old default (RIPE-203's
recommendation, or imported from a server that used it) cannot be told apart
from one left alone, and is rewritten too. That value was never served
either, so the timer keeps serving what it served before.

DOWNGRADE
---------
Which timers were at the old defaults is not recorded, and the release
before this one never reads the timers, so their values stay. That release
writes the literal for every zone: where a group was serving a zone's own
timers, the zone's SOA changes back, so its serial moves, as the switch did.
Then the two columns go.

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

_NOT_THE_LITERAL = "NOT (refresh = 3600 AND retry = 600 AND expire = 86400 AND minimum = 300)"

# ``soa_timers._every_bind9_agent_renders``, with every agent at "no": a BIND9
# server an agent runs that is sent bundles.
_HAS_A_BIND9_AGENT = (
    "EXISTS (SELECT 1 FROM dns_server s WHERE s.group_id = dns_server_group.id "
    "AND s.driver = 'bind9' AND s.agent_id IS NOT NULL AND s.is_enabled "
    "AND NOT s.pending_approval)"
)

# ``compute_next_serial``: the larger of today's YYYYMMDD00 and serial + 1.
_NEXT_SERIAL = (
    "GREATEST(CAST(to_char(now() AT TIME ZONE 'UTC', 'YYYYMMDD') AS integer) * 100, "
    "last_serial + 1)"
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

    op.add_column(
        "dns_server",
        sa.Column(
            "agent_renders_soa_timers",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "dns_server_group",
        sa.Column(
            "serves_soa_timers",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )
    groups = bind.execute(
        sa.text(f"UPDATE dns_server_group SET serves_soa_timers = false WHERE {_HAS_A_BIND9_AGENT}")
    ).rowcount
    waiting = bind.scalar(
        sa.text(
            f"SELECT count(*) FROM dns_zone WHERE {_NOT_THE_LITERAL} "
            "AND group_id IN (SELECT id FROM dns_server_group WHERE NOT serves_soa_timers)"
        )
    )
    logger.info(
        "#1171: %s group(s) serve 3600 600 86400 300 until every BIND9 agent in them "
        "renders a zone's own SOA timers; then the serial of their %s zone(s) with "
        "other timers moves",
        groups,
        waiting,
    )


def downgrade() -> None:
    bind = op.get_bind()
    result = bind.execute(
        sa.text(
            f"UPDATE dns_zone SET last_serial = {_NEXT_SERIAL} WHERE {_NOT_THE_LITERAL} "
            "AND group_id IN (SELECT id FROM dns_server_group WHERE serves_soa_timers)"
        )
    )
    logger.info(
        "#1171: %s zone(s) go back to 3600 600 86400 300; their serial moved",
        result.rowcount,
    )
    op.drop_column("dns_server_group", "serves_soa_timers")
    op.drop_column("dns_server", "agent_renders_soa_timers")
