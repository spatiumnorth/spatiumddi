"""PowerDNS serves primary and secondary zones only (#4570).

A forward zone on a PowerDNS group was accepted (201) and never answered
(REFUSED); a stub was created as a full secondary. Refused on the transition,
so a zone already stored that way stays editable.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSZone
from tests.test_zone_forward_transport import _group, _headers


def _body(zone_type: str) -> dict[str, object]:
    extra: dict[str, object] = (
        {"forwarders": ["9.9.9.9"]} if zone_type == "forward" else {"masters": ["192.0.2.1"]}
    )
    return {"name": f"{zone_type}-{uuid.uuid4().hex[:5]}.example.", "zone_type": zone_type, **extra}


async def test_create_forward_and_stub_refused_on_powerdns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    group = await _group(db_session, "powerdns")
    await db_session.commit()
    for zt in ("forward", "stub"):
        r = await client.post(
            f"/api/v1/dns/groups/{group.id}/zones", json=_body(zt), headers=headers
        )
        assert r.status_code == 422, r.text
        assert "PowerDNS" in r.json()["detail"] and zt in r.json()["detail"]


async def test_create_forward_and_secondary_ok_on_bind9_and_powerdns_secondary(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    bind = await _group(db_session, "bind9")
    pdns = await _group(db_session, "powerdns")
    await db_session.commit()
    for gid, zt in ((bind.id, "forward"), (bind.id, "stub"), (pdns.id, "secondary")):
        r = await client.post(f"/api/v1/dns/groups/{gid}/zones", json=_body(zt), headers=headers)
        assert r.status_code == 201, r.text


async def test_convert_to_forward_refused_but_stored_forward_stays_editable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    group = await _group(db_session, "powerdns")
    prim = DNSZone(group_id=group.id, name="p.example.", zone_type="primary", kind="forward")
    stored = DNSZone(
        group_id=group.id,
        name="f.example.",
        zone_type="forward",
        kind="forward",
        forwarders=["9.9.9.9"],
    )
    db_session.add_all([prim, stored])
    await db_session.commit()
    base = f"/api/v1/dns/groups/{group.id}/zones"
    r = await client.put(
        f"{base}/{prim.id}",
        json={"zone_type": "forward", "forwarders": ["9.9.9.9"]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    r = await client.put(f"{base}/{stored.id}", json={"zone_type": "forward"}, headers=headers)
    assert r.status_code == 200, r.text
