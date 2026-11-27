"""spatiumddi#3807 — the DDNS name-holder check reads its name from an index.

``_name_holder`` matches ``lower(name)`` inside a zone; ``(zone_id, name)``
cannot serve that, so each renewal read every record of the zone.

The test proves the lower(name) index is *usable* for the predicate, not that
the planner prefers it: on an empty table every zone_id-leading index costs the
same and the tie-break is not ours to assert (#4400). The competing indexes
are dropped inside the (rolled-back) transaction, so the only index that can
serve the predicate is the one under test.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord


@pytest.mark.asyncio
async def test_name_holder_predicate_uses_the_lower_name_index(db_session: AsyncSession) -> None:
    stmt = select(DNSRecord.id).where(
        DNSRecord.zone_id.in_(["00000000-0000-0000-0000-000000000001"]),
        func.lower(DNSRecord.name) == "www",
    )
    sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    for competitor in ("ix_dns_record_zone_id", "ix_dns_record_zone_name"):
        await db_session.execute(text(f"DROP INDEX IF EXISTS {competitor}"))
    await db_session.execute(text("SET LOCAL enable_seqscan = off"))
    plan = "\n".join(r[0] for r in (await db_session.execute(text("EXPLAIN " + sql))).all())
    assert "ix_dns_record_zone_lower_name" in plan, plan
