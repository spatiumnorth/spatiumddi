"""dns_blocklist: ``feed_wildcard_mode`` replaces ``feed_entries_are_wildcard`` (#4190)

The per-list switch was a boolean (#894): every feed entry became
``name`` plus ``*.name`` in the RPZ, whatever the feed's own syntax said.
A hosts-format line (``0.0.0.0 host``) names one host, so a hosts list
rendered twice the records it needs and blocked more than AdGuard Home
or any hosts-file resolver does with the same list.

It is now a tri-state, ``by_syntax`` (each entry follows its own line:
adblock ``||name^`` and ``*.name`` are wildcard, a hosts line or bare
domain is exact), ``always`` (the old true) or ``never`` (the old
false).

Mapping of existing rows:

* ``false`` -> ``never``. An operator who unticked the box keeps exact
  feeds exact.
* ``true`` -> ``by_syntax``. That is the point of the change, with one
  carve-out: a subscription to a feed whose publisher means "this
  domain and everything under it" in plain-domain syntax (HaGeZi's
  ``wildcard/`` lists, OISD ``domainswild``) is mapped to ``always``,
  so it keeps its coverage. The next refresh restamps ``by_syntax``
  lists' stored rows; until then they are what they were.

The old boolean column stays (expand/contract, #296) so a not-yet-upgraded
api pod keeps working during a rolling upgrade; it is deprecated and a later
release removes it.

Revision ID: b6d2e9f41a07
Revises: a3c9e5d1b7f2
Create Date: 2026-11-14 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "b6d2e9f41a07"
down_revision = "a3c9e5d1b7f2"
branch_labels = None
depends_on = None


#: Existing rows onto the new column (exercised by a test against a scratch table).
MAPPING_SQL = [
    "UPDATE dns_blocklist SET feed_wildcard_mode = 'never' WHERE NOT feed_entries_are_wildcard",
    "UPDATE dns_blocklist SET feed_wildcard_mode = 'always' "
    "WHERE feed_entries_are_wildcard AND feed_url IS NOT NULL AND ("
    "feed_url LIKE 'https://raw.githubusercontent.com/hagezi/dns-blocklists/%/wildcard/%' "
    "OR feed_url LIKE 'https://%.oisd.nl/domainswild%')",
]


def upgrade() -> None:
    op.add_column(
        "dns_blocklist",
        sa.Column(
            "feed_wildcard_mode",
            sa.String(16),
            nullable=False,
            server_default="by_syntax",
        ),
    )
    for stmt in MAPPING_SQL:
        op.execute(stmt)
    # ``feed_entries_are_wildcard`` is deliberately kept (expand/contract,
    # #296): an api pod still on the old release reads and writes it during a
    # rolling upgrade. The new code keeps it consistent on write (true unless
    # the mode is ``never``). Deprecated; a later release drops it.


def downgrade() -> None:
    # The old column was never dropped; bring it in line with the mode first.
    op.execute(
        "UPDATE dns_blocklist SET feed_entries_are_wildcard = (feed_wildcard_mode <> 'never')"
    )
    op.drop_column("dns_blocklist", "feed_wildcard_mode")
