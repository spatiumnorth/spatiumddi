"""#4565 — views on a group whose servers cannot serve them.

Only BIND9 answers by client address (``capabilities()["views"]``). A view on
a PowerDNS group used to be accepted, and the agent merged every view's copy
of a zone into the one zone PowerDNS holds, so a record of one view was
answered to every client. The API now refuses the view, anything newly scoped
to one, and a server that would bring such a driver into a group with views.
A group that already holds views keeps working: its views can be edited and
removed, an untouched save passes, and the group carries a warning.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns import _DRIVERS
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns.zone_move import assemble_move_plan
from app.services.dns_import.canonical import ImportedSOA, ImportedZone, ImportPreview
from app.services.dns_import.commit import commit_import

VIEW = {"name": "internal", "match_clients": ["10.0.0.0/8"]}


async def _setup(
    db: AsyncSession, driver: str | None = "powerdns"
) -> tuple[User, dict[str, str], DNSServerGroup]:
    user = User(
        username=f"vw-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Views",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([user, grp])
    await db.flush()
    if driver is not None:
        await _server(db, grp, driver)
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, grp


async def _server(db: AsyncSession, grp: DNSServerGroup, driver: str) -> DNSServer:
    srv = DNSServer(
        group_id=grp.id,
        driver=driver,
        host=f"dns-{uuid.uuid4().hex[:6]}",
        name=f"dns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(srv)
    await db.flush()
    return srv


async def _stored_view(db: AsyncSession, grp: DNSServerGroup, name: str = "internal") -> DNSView:
    """A view stored before the refusal existed."""
    view = DNSView(group_id=grp.id, name=name, match_clients=["10.0.0.0/8"])
    db.add(view)
    await db.flush()
    return view


def test_only_bind9_offers_views() -> None:
    """The gate reads the capability, so this names what it refuses today."""
    from app.services.dns.server_move import views_unsupported_drivers

    assert views_unsupported_drivers(_DRIVERS) == sorted(set(_DRIVERS) - {"bind9"})


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["powerdns", "technitium", "windows_dns", "route53"])
async def test_view_create_refused_without_views_support(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    _, headers, grp = await _setup(db_session, driver)
    resp = await client.post(f"/api/v1/dns/groups/{grp.id}/views", json=VIEW, headers=headers)
    assert resp.status_code == 422, resp.text
    assert "Views are not supported" in resp.text and driver in resp.text
    listed = await client.get(f"/api/v1/dns/groups/{grp.id}/views", headers=headers)
    assert listed.json() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["bind9", None])
async def test_view_create_allowed_on_bind9_and_on_an_empty_group(
    client: AsyncClient, db_session: AsyncSession, driver: str | None
) -> None:
    _, headers, grp = await _setup(db_session, driver)
    resp = await client.post(f"/api/v1/dns/groups/{grp.id}/views", json=VIEW, headers=headers)
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_zone_and_record_cannot_be_newly_scoped_to_a_stored_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers, grp = await _setup(db_session, "powerdns")
    view = await _stored_view(db_session, grp)
    base = f"/api/v1/dns/groups/{grp.id}/zones"

    scoped = await client.post(
        base, json={"name": "split.example", "view_id": str(view.id)}, headers=headers
    )
    assert scoped.status_code == 422, scoped.text
    assert "Views are not supported" in scoped.text

    plain = await client.post(base, json={"name": "split.example"}, headers=headers)
    assert plain.status_code == 201, plain.text
    zone_url = f"{base}/{plain.json()['id']}"

    pin = await client.put(zone_url, json={"view_id": str(view.id)}, headers=headers)
    assert pin.status_code == 422, pin.text

    record: dict[str, Any] = {"name": "www", "record_type": "A", "value": "10.1.1.1"}
    rec = await client.post(
        f"{zone_url}/records", json={**record, "view_id": str(view.id)}, headers=headers
    )
    assert rec.status_code == 422, rec.text
    assert "Views are not supported" in rec.text
    shared = await client.post(f"{zone_url}/records", json=record, headers=headers)
    assert shared.status_code == 201, shared.text


@pytest.mark.asyncio
async def test_a_group_that_already_holds_views_keeps_working(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Stored state is not refused: an untouched save of a pinned zone passes,
    the view can be edited and removed, and the group says what is wrong."""
    _, headers, grp = await _setup(db_session, "powerdns")
    view = await _stored_view(db_session, grp)
    zone = DNSZone(group_id=grp.id, view_id=view.id, name="old.example.", zone_type="primary")
    db_session.add(zone)
    await db_session.flush()

    saved = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        json={"view_id": str(view.id), "ttl": 600},
        headers=headers,
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["view_id"] == str(view.id)

    group = await client.get(f"/api/v1/dns/groups/{grp.id}", headers=headers)
    (warning,) = group.json()["scope_warnings"]
    assert "internal" in warning and "powerdns" in warning

    view_url = f"/api/v1/dns/groups/{grp.id}/views/{view.id}"
    edited = await client.put(view_url, json={"description": "to remove"}, headers=headers)
    assert edited.status_code == 200, edited.text
    unpin = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}", json={"view_id": None}, headers=headers
    )
    assert unpin.status_code == 200, unpin.text
    gone = await client.delete(view_url, headers=headers)
    assert gone.status_code == 204, gone.text
    group = await client.get(f"/api/v1/dns/groups/{grp.id}", headers=headers)
    assert group.json()["scope_warnings"] == []


@pytest.mark.asyncio
async def test_bind9_group_with_views_carries_no_warning(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers, grp = await _setup(db_session, "bind9")
    await _stored_view(db_session, grp)
    group = await client.get(f"/api/v1/dns/groups/{grp.id}", headers=headers)
    assert group.json()["scope_warnings"] == []


@pytest.mark.asyncio
async def test_server_cannot_be_created_in_a_group_with_views(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers, grp = await _setup(db_session, None)
    await _stored_view(db_session, grp)
    body: dict[str, Any] = {"name": "pdns1", "driver": "powerdns", "host": "pdns1.example.test"}
    resp = await client.post(f"/api/v1/dns/groups/{grp.id}/servers", json=body, headers=headers)
    assert resp.status_code == 422, resp.text
    assert "has views (internal)" in resp.text
    body["driver"] = "bind9"
    ok = await client.post(f"/api/v1/dns/groups/{grp.id}/servers", json=body, headers=headers)
    assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_server_cannot_be_moved_into_a_group_with_views(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers, source = await _setup(db_session, None)
    srv = await _server(db_session, source, "powerdns")
    target = DNSServerGroup(name=f"t-{uuid.uuid4().hex[:6]}")
    db_session.add(target)
    await db_session.flush()
    await _stored_view(db_session, target)

    resp = await client.put(
        f"/api/v1/dns/groups/{source.id}/servers/{srv.id}",
        json={"group_id": str(target.id)},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert "has views (internal)" in resp.text
    await db_session.refresh(srv)
    assert srv.group_id == source.id


@pytest.mark.asyncio
async def test_importer_refuses_a_target_view_on_a_powerdns_group(
    db_session: AsyncSession,
) -> None:
    user, _, grp = await _setup(db_session, "powerdns")
    view = await _stored_view(db_session, grp)
    preview = ImportPreview(
        source="bind9",
        zones=[
            ImportedZone(
                name="imported.example.",
                zone_type="primary",
                kind="forward",
                soa=ImportedSOA(
                    "ns1.example.net.", "admin.example.net.", 1, 3600, 600, 86400, 300, 3600
                ),
                records=[],
            )
        ],
        conflicts=[],
        warnings=[],
        total_records=0,
        record_type_histogram={},
    )
    kwargs: dict[str, Any] = {
        "preview": preview,
        "target_group_id": grp.id,
        "conflict_actions": {},
        "current_user": user,
    }
    with pytest.raises(ValueError, match="Views are not supported"):
        await commit_import(db_session, target_view_id=view.id, **kwargs)
    res = await commit_import(db_session, target_view_id=None, **kwargs)
    assert res.zones[0].action_taken == "created", res


@pytest.mark.asyncio
async def test_zone_move_refuses_keeping_a_view_in_a_group_that_cannot_serve_it(
    db_session: AsyncSession,
) -> None:
    """A pinned zone moving into a group with a same-name view would stay
    scoped there; into a group with no views its pin is simply dropped."""
    _, _, source = await _setup(db_session, "bind9")
    view = await _stored_view(db_session, source)
    zone = DNSZone(group_id=source.id, view_id=view.id, name="mv.example.", zone_type="primary")
    db_session.add(zone)
    _, _, legacy = await _setup(db_session, "powerdns")
    await _stored_view(db_session, legacy)
    _, _, clean = await _setup(db_session, "powerdns")
    await db_session.flush()

    plan = await assemble_move_plan(db_session, zone, legacy)
    assert plan.views_refusal and "Views are not supported" in plan.views_refusal
    assert (await assemble_move_plan(db_session, zone, clean)).views_refusal is None
