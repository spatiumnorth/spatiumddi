"""#1356 — persistent pairing codes minted before this release expire too.

Data-only. No schema change, no new table, no new column.

From this release a persistent pairing code expires 30 days after it is
minted unless it is created with ``expires_in_minutes: 0``. That covers
codes minted from now on. A code minted earlier carries
``expires_at IS NULL``, which still means "never expires", so without
this migration every persistent code already in the field would stay a
standing fleet-join credential: eight digits, valid until someone
revokes it, which is the thing #1356 closes.

Before this release "never" was the only behaviour a persistent code
had: ``expires_in_minutes`` omitted and ``0`` both stored NULL. So a
NULL here records no decision by the operator, and giving it the new
default does not overrule one.

WHAT IT DOES
------------
Every persistent code that is not revoked and has no expiry gets one,
30 days after the upgrade rather than 30 days after it was minted: a
code minted a year ago would otherwise expire at the moment of the
upgrade, cutting off a rollout the operator has in flight with no
warning. Thirty days leaves time to re-mint, with
``expires_in_minutes: 0`` if a code that never expires is really what
is wanted. Revoked codes are left alone; they can never be claimed
again either way. Ephemeral codes always had an expiry and are not
touched, and neither are the codes the product mints for itself (the
self-bootstrap and replacement codes), which are ephemeral.

DOWNGRADE IS A NO-OP
--------------------
Which rows were NULL before is not recorded, and putting NULL back
would turn every persistent code into one that never expires, including
the ones minted on this release with a real 30-day expiry. An older
release reads a non-NULL ``expires_at`` the same way this one does, so
leaving the values in place is correct for it.

Revision ID: 5e6d56b39ab7
Revises: f4a8c2e71d09
Create Date: 2026-10-02
"""

from __future__ import annotations

import logging

import sqlalchemy as sa

from alembic import op

revision = "5e6d56b39ab7"
down_revision = "f4a8c2e71d09"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    result = op.get_bind().execute(
        sa.text(
            "UPDATE pairing_code "
            "SET expires_at = now() + interval '30 days' "
            "WHERE persistent AND expires_at IS NULL AND revoked_at IS NULL"
        )
    )
    logger.info(
        "#1356: gave %s persistent pairing code(s) a 30-day expiry",
        result.rowcount,
    )


def downgrade() -> None:
    # Deliberately a no-op; see the module docstring.
    pass
