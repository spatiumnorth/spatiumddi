"""#2263 — client access controls that were stored and enforced nothing.

* A zone's own ``allow_query`` on a Technitium group: the agent now applies
  it, so the API refuses a list it cannot translate rather than store a
  restriction the daemon leaves open.
* The group ``blackhole``: now shipped in the bundle (BIND9 renders it) and
  refused on a group with a Technitium or PowerDNS server, neither of which
  can drop a client by address.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import ServerOptions
from app.drivers.dns.bind9 import BIND9Driver
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions, DNSZone
from app.services.dns.agent_config import build_config_bundle


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession, driver: str) -> tuple[DNSServerGroup, DNSServer]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host=f"h-{uuid.uuid4().hex[:6]}",
        port=53,
        is_primary=True,
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    return group, server


# ── zone allow_query on Technitium ───────────────────────────────────────


@pytest.mark.asyncio
async def test_technitium_zone_allow_query_it_cannot_apply_is_a_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "technitium")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones"

    r = await client.post(
        url,
        json={"name": "bad.test.", "zone_type": "primary", "allow_query": ["localnets"]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert "allow_query" in str(r.json()["detail"])

    r = await client.post(
        url,
        json={
            "name": "ok.test.",
            "zone_type": "primary",
            "allow_query": ["10.0.0.0/8", "!10.9.0.0/16"],
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    zone_id = r.json()["id"]

    r = await client.put(f"{url}/{zone_id}", json={"allow_query": ["localnets"]}, headers=headers)
    assert r.status_code == 422, r.text
    assert "allow_query" in str(r.json()["detail"])


@pytest.mark.asyncio
async def test_bind9_zone_allow_query_keeps_localnets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json={"name": "z.test.", "zone_type": "primary", "allow_query": ["localnets"]},
        headers=headers,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_stored_zone_allow_query_technitium_cannot_apply_is_warned(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "technitium")
    db_session.add(DNSServerOptions(group_id=group.id))
    db_session.add(
        DNSZone(
            group_id=group.id,
            name="old.test.",
            zone_type="primary",
            kind="forward",
            allow_query=["localnets"],
        )
    )
    await db_session.commit()
    r = await client.get(f"/api/v1/dns/groups/{group.id}/options", headers=headers)
    assert r.status_code == 200, r.text
    warnings = r.json()["technitium_warnings"]
    assert any("old.test." in w and "allow_query" in w for w in warnings), warnings


# ── group blackhole ──────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["technitium", "powerdns"])
async def test_blackhole_is_refused_where_the_daemon_cannot_apply_it(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, driver)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(url, json={"blackhole": ["198.51.100.0/24"]}, headers=headers)
    assert r.status_code == 422, r.text
    assert "blackhole" in str(r.json()["detail"])
    # Leaving it empty, as the form posts it, is fine.
    r = await client.put(url, json={"blackhole": [], "allow_query": ["any"]}, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_bind9_blackhole_is_stored_and_shipped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, server = await _group(db_session, "bind9")
    await db_session.commit()

    bundle = await build_config_bundle(db_session, server)
    # Unset: absent from the bundle, so the etag of a group that does not
    # use it does not move on upgrade.
    assert "blackhole" not in bundle["options"]

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"blackhole": ["198.51.100.0/24", "!192.0.2.7"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    db_session.expire_all()
    await db_session.refresh(server)
    bundle = await build_config_bundle(db_session, server)
    assert bundle["options"]["blackhole"] == ["198.51.100.0/24", "!192.0.2.7"]


def test_control_plane_template_renders_blackhole_like_the_agent() -> None:
    """The preview renderer and the agent emit the same statement, and
    nothing at all when the list is empty."""
    driver = BIND9Driver()
    out = driver.render_server_config(
        None, ServerOptions(blackhole=("198.51.100.0/24", "!192.0.2.7"))
    )
    assert "    blackhole { 198.51.100.0/24; !192.0.2.7; };" in out
    assert "blackhole" not in driver.render_server_config(None, ServerOptions())


# ── zone move into a Technitium group ────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ztype", "field", "value"),
    [
        ("primary", "allow_query", ["localnets"]),
        ("secondary", "allow_query", ["localnets"]),
        ("primary", "allow_transfer", ["localnets"]),
    ],
)
async def test_move_into_technitium_refuses_a_zone_list_it_cannot_apply(
    client: AsyncClient, db_session: AsyncSession, ztype: str, field: str, value: list[str]
) -> None:
    """A move is another way into the group, and on a zone Technitium
    creates fresh an unapplied list means open. Same refusal as create."""
    headers = await _superadmin(db_session)
    src, _ = await _group(db_session, "bind9")
    dst, _ = await _group(db_session, "technitium")
    zone = DNSZone(
        group_id=src.id,
        name=f"m-{uuid.uuid4().hex[:6]}.test.",
        zone_type=ztype,
        kind="forward",
        **{field: value},
    )
    db_session.add(zone)
    await db_session.commit()
    base = f"/api/v1/dns/groups/{src.id}/zones/{zone.id}/move"
    r = await client.post(f"{base}/preview", json={"target_group_id": str(dst.id)}, headers=headers)
    assert r.status_code == 200, r.text
    refusal = r.json()["technitium_acl_refusal"]
    assert refusal and field in refusal, refusal
    r = await client.post(
        f"{base}/commit",
        json={
            "target_group_id": str(dst.id),
            "confirmation_zone_name": zone.name,
            "acknowledgements": [],
        },
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert field in str(r.json()["detail"])


@pytest.mark.asyncio
async def test_move_into_technitium_allows_an_expressible_zone_list(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    src, _ = await _group(db_session, "bind9")
    dst, _ = await _group(db_session, "technitium")
    zone = DNSZone(
        group_id=src.id,
        name=f"m-{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        allow_query=["10.0.0.0/8", "!10.9.0.0/16"],
    )
    db_session.add(zone)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{src.id}/zones/{zone.id}/move/preview",
        json={"target_group_id": str(dst.id)},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["technitium_acl_refusal"] is None
