"""#1153 — a zone's primary_ns / admin_email reach the agent, and an edit to
either moves the zone's serial.

Both fields were stored, returned and editable, but the per-zone payload of
the agent bundle never carried them, so the BIND9 agent rendered every zone
with the placeholder apex ``SOA ns1.<zone> admin.<zone>`` / ``NS ns1.<zone>``
(glued to 127.0.0.1) whatever was set: a PUT of primary_ns changed nothing on
the wire, and not even the etag moved. They now ship in every zone copy, so an
edit shifts the structural etag and the agent re-renders the apex; and the edit
bumps ``last_serial``, without which a secondary would never transfer the new
apex (it transfers only when the serial moves).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns.agent_config import build_config_bundle


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"apex-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Zone Apex Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group_with_server(db: AsyncSession) -> tuple[DNSServerGroup, DNSServer]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host=f"dns-{uuid.uuid4().hex[:6]}",
        name=f"dns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    return grp, server


def _zone(grp: DNSServerGroup, name: str, **extra: object) -> DNSZone:
    return DNSZone(group_id=grp.id, name=name, zone_type="primary", kind="forward", **extra)


# ── The bundle carries both fields ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_every_zone_copy_carries_its_primary_ns_and_admin_email(
    db_session: AsyncSession,
) -> None:
    grp, server = await _group_with_server(db_session)
    db_session.add(
        _zone(
            grp,
            "lab.example.test.",
            primary_ns="ns1.corp.example.test",
            admin_email="hostmaster.corp.example.test",
        )
    )
    db_session.add(_zone(grp, "23.77.10.in-addr.arpa."))
    await db_session.commit()

    bundle = await build_config_bundle(db_session, server)

    by_name = {z["name"]: z for z in bundle["zones"]}
    assert by_name["lab.example.test."]["primary_ns"] == "ns1.corp.example.test"
    assert by_name["lab.example.test."]["admin_email"] == "hostmaster.corp.example.test"
    # Unset is "", never None: the agent treats both as unset, but the etag
    # must not flip between the two spellings of nothing.
    assert by_name["23.77.10.in-addr.arpa."]["primary_ns"] == ""
    assert by_name["23.77.10.in-addr.arpa."]["admin_email"] == ""


@pytest.mark.asyncio
async def test_every_view_copy_carries_them_too(db_session: AsyncSession) -> None:
    grp, server = await _group_with_server(db_session)
    db_session.add(DNSView(group_id=grp.id, name="internal", match_clients=["10.0.0.0/8"]))
    db_session.add(DNSView(group_id=grp.id, name="external", match_clients=["any"], order=10))
    db_session.add(_zone(grp, "corp.example.test.", primary_ns="ns1.corp.example.test."))
    await db_session.commit()

    bundle = await build_config_bundle(db_session, server)

    copies = [z for z in bundle["zones"] if z["name"] == "corp.example.test."]
    assert sorted(z["view_name"] for z in copies) == ["external", "internal"]
    assert {z["primary_ns"] for z in copies} == {"ns1.corp.example.test."}


@pytest.mark.asyncio
async def test_an_apex_edit_moves_the_structural_etag(db_session: AsyncSession) -> None:
    """The agent re-renders only when the structural etag moves. Before #1153
    a primary_ns edit left it where it was, so nothing re-rendered at all."""
    grp, server = await _group_with_server(db_session)
    zone = _zone(grp, "corp.example.test.")
    db_session.add(zone)
    await db_session.commit()
    before = (await build_config_bundle(db_session, server))["structural_etag"]

    zone.primary_ns = "ns1.example.net."
    await db_session.commit()
    after_ns = (await build_config_bundle(db_session, server))["structural_etag"]

    zone.admin_email = "hostmaster.example.net."
    await db_session.commit()
    after_admin = (await build_config_bundle(db_session, server))["structural_etag"]

    assert len({before, after_ns, after_admin}) == 3


# ── An apex edit moves the serial ───────────────────────────────────────────


async def _zone_via_api(
    client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup
) -> dict[str, object]:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": f"z{uuid.uuid4().hex[:6]}.example.test", "zone_type": "primary"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    body: dict[str, object] = resp.json()
    return body


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [{"primary_ns": "dns1.example.net."}, {"admin_email": "hostmaster.example.net."}],
)
async def test_an_apex_edit_bumps_the_serial_the_agent_renders(
    client: AsyncClient, db_session: AsyncSession, change: dict[str, str]
) -> None:
    """The issue's own repro: PUT primary_ns → 200, and the serial the agent
    renders from must move with it."""
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)
    zone = await _zone_via_api(client, headers, grp)
    serial_before = int(zone["last_serial"])  # type: ignore[call-overload]

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone['id']}", json=change, headers=headers
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()[next(iter(change))] == next(iter(change.values()))
    assert resp.json()["last_serial"] > serial_before
    bundle = await build_config_bundle(db_session, server)
    (shipped,) = [z for z in bundle["zones"] if z["id"] == zone["id"]]
    assert shipped["serial"] == resp.json()["last_serial"]
    assert shipped[next(iter(change))] == next(iter(change.values()))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [{"primary_ns": ""}, {"color": "blue"}, {"primary_ns": "", "admin_email": ""}],
)
async def test_an_edit_that_leaves_the_apex_alone_keeps_the_serial(
    client: AsyncClient, db_session: AsyncSession, change: dict[str, str]
) -> None:
    """Re-saving the zone form sends every field back unchanged; that is not
    an apex change and must not look like one to a secondary."""
    headers = await _headers(db_session)
    grp, _server = await _group_with_server(db_session)
    zone = await _zone_via_api(client, headers, grp)

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone['id']}", json=change, headers=headers
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["last_serial"] == zone["last_serial"]
