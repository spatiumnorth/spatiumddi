"""BIND allows at most 64 zones in one ``response-policy`` statement (#3564).

SpatiumDDI folds every list a scope draws on into ONE RPZ zone per view (and
one group zone), so the number of zones in any ``response-policy`` is 1 no
matter how many lists are assigned. The limit is on policy zones, not lists,
so no assignment-time refusal is needed. These guard that folding: if a
renderer ever went back to one zone per list, 65 assignments would produce a
``named.conf`` that fails ``named-checkconf`` and stops the group converging.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSView
from app.models.settings import PlatformSettings
from app.services.dns.agent_config import render_bundle_body
from tests.test_dns_agent_bundle_blocklist_stream_1662 import _assign, _blocklist, _id, _server

BIND_MAX_POLICY_ZONES = 64
LISTS = BIND_MAX_POLICY_ZONES + 6


@pytest.mark.asyncio
@pytest.mark.parametrize("views", [False, True])
async def test_many_assigned_lists_fold_into_one_rpz_zone_per_scope(
    db_session: AsyncSession, views: bool
) -> None:
    db_session.add(PlatformSettings(id=1))
    await db_session.flush()
    base = 0x7000 if views else 0x6000
    group, server = await _server(db_session, base, f"rpz-cap-{views}")
    target_views = []
    if views:
        for i, name in enumerate(("internal", "external")):
            v = DNSView(
                id=_id(base + 0x50 + i),
                group_id=group.id,
                name=name,
                match_clients=["192.0.2.0/24"] if i == 0 else ["any"],
                order=i,
            )
            db_session.add(v)
            target_views.append(v)
        await db_session.flush()
    for i in range(LISTS):
        bl = await _blocklist(
            db_session,
            base + 0x10000 + i * 0x1000,
            f"list-{base:x}-{i:03d}",
            [(f"d{i:03d}.example.com", "block", None, False)],
        )
        await _assign(db_session, bl, group=group)
        if views:
            await _assign(db_session, bl, view=target_views[0])
    await db_session.commit()

    db_session.expunge_all()
    fresh = await db_session.get(DNSServer, server.id)
    assert fresh is not None
    zones = (await render_bundle_body(db_session, fresh)).body["blocklists"]

    assert zones, "the fixture must ship RPZ zones"
    per_scope: dict[str | None, int] = {}
    for z in zones:
        per_scope[z["view_name"]] = per_scope.get(z["view_name"], 0) + 1
    assert max(per_scope.values()) == 1
    assert max(per_scope.values()) <= BIND_MAX_POLICY_ZONES
    # All 70 lists' entries are in that one zone.
    folded = {name: z for z in zones for name in [z["view_name"]]}
    scope = "internal" if views else None
    assert len(folded[scope]["entries"]) >= LISTS
