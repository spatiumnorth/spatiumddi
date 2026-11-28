"""PowerDNS serves primary and secondary zones only (#4570).

A forward zone on a PowerDNS group was accepted (201) and never answered
(REFUSED); a stub was created as a full secondary. Refused on the transition,
so a zone already stored that way stays editable.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerGroup, DNSZone
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


# ── sibling paths: every route to a forward / stub zone shares one helper ──


async def test_copilot_create_dns_zone_refuses_forward_and_stub_on_powerdns(
    db_session: AsyncSession,
) -> None:
    from app.core.security import hash_password
    from app.models.auth import User
    from app.services.ai.operations import CreateDNSZoneArgs, get_operation

    user = User(
        username=f"cp-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="cp",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    pdns = await _group(db_session, "powerdns")
    bind = await _group(db_session, "bind9")
    await db_session.commit()
    op = get_operation("create_dns_zone")
    assert op is not None
    for zt in ("forward", "stub"):
        args = CreateDNSZoneArgs(name=f"cp-{zt}.example.com", group_id=str(pdns.id), zone_type=zt)
        preview = await op.preview(db_session, user, args)
        assert preview.ok is False and "PowerDNS" in preview.detail
        try:
            await op.apply(db_session, user, args)
        except ValueError as exc:
            assert "PowerDNS" in str(exc)
        else:
            raise AssertionError("apply must refuse a forward/stub zone on PowerDNS")
        ok = await op.preview(
            db_session,
            user,
            CreateDNSZoneArgs(name=f"cp-{zt}.example.net", group_id=str(bind.id), zone_type=zt),
        )
        assert ok.ok is True, ok.detail


async def test_importer_refuses_forward_and_stub_zone_for_powerdns_group(
    db_session: AsyncSession,
) -> None:
    from app.models.auth import User
    from app.services.dns_import.canonical import ImportedZone, ImportPreview
    from app.services.dns_import.commit import commit_import

    user = User(
        username=f"im-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="im",
        hashed_password="x",
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    group = await _group(db_session, "powerdns")
    zones = [
        ImportedZone(
            name="imp-fwd.example.",
            zone_type="forward",
            kind="forward",
            soa=None,
            records=[],
            forwarders=["9.9.9.9"],
        ),
        ImportedZone(
            name="imp-stub.example.",
            zone_type="stub",
            kind="forward",
            soa=None,
            records=[],
            masters=["192.0.2.1"],
        ),
    ]
    preview = ImportPreview(
        source="bind9",
        zones=zones,
        conflicts=[],
        warnings=[],
        total_records=0,
        record_type_histogram={},
    )
    res = await commit_import(
        db_session,
        preview=preview,
        target_group_id=group.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
    )
    assert all(z.action_taken != "created" for z in res.zones), res
    assert all("PowerDNS" in str(z.error) for z in res.zones), res
    stored = (
        (await db_session.execute(select(DNSZone).where(DNSZone.group_id == group.id)))
        .scalars()
        .all()
    )
    assert stored == []


async def test_powerdns_server_cannot_join_a_group_holding_a_forward_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    db_session.add(
        DNSZone(
            group_id=group.id,
            name="held.example.",
            zone_type="forward",
            kind="forward",
            forwarders=["9.9.9.9"],
        )
    )
    await db_session.commit()
    body = {"name": "pdns1", "driver": "powerdns", "host": "pdns1.example.test"}
    r = await client.post(f"/api/v1/dns/groups/{group.id}/servers", json=body, headers=headers)
    assert r.status_code == 422, r.text
    assert "forward" in r.text and "PowerDNS" in r.text
    body["driver"] = "bind9"
    ok = await client.post(f"/api/v1/dns/groups/{group.id}/servers", json=body, headers=headers)
    assert ok.status_code == 201, ok.text


async def test_zone_move_preview_and_commit_refuse_forward_into_powerdns_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    src = await _group(db_session, "bind9")
    dst = await _group(db_session, "powerdns")
    zone = DNSZone(
        group_id=src.id,
        name="mv.example.",
        zone_type="forward",
        kind="forward",
        forwarders=["9.9.9.9"],
    )
    db_session.add(zone)
    await db_session.commit()
    base = f"/api/v1/dns/groups/{src.id}/zones/{zone.id}/move"
    p = await client.post(f"{base}/preview", json={"target_group_id": str(dst.id)}, headers=headers)
    assert p.status_code == 200, p.text
    assert "PowerDNS" in (p.json()["powerdns_refusal"] or "")
    c = await client.post(
        f"{base}/commit",
        json={
            "target_group_id": str(dst.id),
            "confirmation_zone_name": "mv.example.",
            "acknowledgements": [],
        },
        headers=headers,
    )
    assert c.status_code == 422, c.text
    assert "PowerDNS" in c.text
