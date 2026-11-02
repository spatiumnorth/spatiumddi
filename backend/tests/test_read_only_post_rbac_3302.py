"""A route marked ``@read_only_post`` is gated on ``read``, not ``write`` (#3302).

The scope gate learned the marker in #3223 (a ``read`` token reaches the route);
RBAC kept reading every POST as ``write``, so a Viewer was still refused on a
find-free / plan-allocation / allocation-preview route that only reads. These
tests pin both halves: the marked routes now admit a read-only account, and the
previews that must stay write-gated (resize, import) still refuse it.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.token_binding import route_honours_token_binding  # noqa: F401
from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, Group, Role, User
from app.models.dns import DNSServerGroup, DNSServerOptions, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet

pytestmark = pytest.mark.asyncio


async def _user(db: AsyncSession, perms: list[dict] | None, *, superadmin: bool = False) -> User:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.flush()
    if perms is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:8]}", description="", permissions=perms)
        db.add(role)
        await db.flush()
        g = Group(name=f"g-{uuid.uuid4().hex[:8]}", description="")
        g.roles = [role]
        g.users = [u]
        db.add(g)
        await db.flush()
    return u


async def _viewer(db: AsyncSession) -> dict[str, str]:
    u = await _user(db, [{"action": "read", "resource_type": "*"}])
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _token(
    db: AsyncSession, owner: User, scopes: list[str], grants: list[dict] | None = None
) -> dict[str, str]:
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=scopes,
            resource_grants=grants,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.commit()
    return {"Authorization": f"Bearer {raw}"}


async def _ipam(db: AsyncSession) -> tuple[IPSpace, IPBlock, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.77.1.0/24", name="s")
    db.add(subnet)
    await db.commit()
    return space, block, subnet


# ── S2-c: a read-only account reaches the marked routes ──────────────────


async def test_viewer_reaches_find_free_plan_allocation_and_av_preview(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space, block, _ = await _ipam(db_session)
    h = await _viewer(db_session)
    r = await client.post(
        f"/api/v1/ipam/spaces/{space.id}/find-free", json={"prefix_length": 24}, headers=h
    )
    assert r.status_code == 200, r.text
    r = await client.post(
        f"/api/v1/ipam/blocks/{block.id}/plan-allocation",
        json={"items": [{"count": 1, "prefix_len": 24}]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    r = await client.post(
        "/api/v1/av/allocation-preview",
        json={"space_id": str(space.id), "address_or_cidr": "239.1.1.1", "av_protocol": "dante"},
        headers=h,
    )
    assert r.status_code == 200, r.text


async def test_viewer_is_still_refused_on_write_gated_previews(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Resize (and import / bulk) previews stay write-gated: the marker relaxes
    the router gate only, and these handlers check ``write`` themselves."""
    space, block, subnet = await _ipam(db_session)
    h = await _viewer(db_session)
    r = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/resize/preview",
        json={"new_cidr": "10.77.0.0/23"},
        headers=h,
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        f"/api/v1/ipam/blocks/{block.id}/resize/preview",
        json={"new_cidr": "10.77.0.0/15"},
        headers=h,
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/ipam/import/preview-json", json={"payload": {"subnets": []}}, headers=h
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/multicast/groups/bulk-allocate/preview",
        json={
            "space_id": str(space.id),
            "start_address": "239.2.0.1",
            "count": 2,
            "name_template": "g{n}",
        },
        headers=h,
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/dicom/aes/import/preview",
        json={"csv_text": "ae\nA\n", "column_map": {"ae_title": "ae"}},
        headers=h,
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/ot/devices/import/preview",
        json={"csv_text": "ip\n1.1.1.1\n", "column_map": {"address": "ip"}},
        headers=h,
    )
    assert r.status_code == 403, r.text


async def test_viewer_is_refused_on_the_dns_zone_import_preview(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = DNSZone(group_id=grp.id, name="example.test.", zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.commit()
    h = await _viewer(db_session)
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/import/preview",
        json={"zone_file": "a 60 IN A 192.0.2.1\n"},
        headers=h,
    )
    assert r.status_code == 403, r.text


async def test_a_viewer_cannot_use_a_plain_write_post(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space, _, _ = await _ipam(db_session)
    h = await _viewer(db_session)
    r = await client.post(
        "/api/v1/ipam/blocks",
        json={"space_id": str(space.id), "network": "10.88.0.0/16"},
        headers=h,
    )
    assert r.status_code == 403, r.text


# ── S2-a: the four DB-only previews admit a read token ───────────────────


async def test_read_token_reaches_the_db_only_previews(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner = await _user(db_session, None, superadmin=True)
    h = await _token(db_session, owner, ["read"])
    r = await client.post(
        "/api/v1/appliance/acme/preview", json={"domains": ["www.example.com"]}, headers=h
    )
    assert r.status_code == 200, r.text
    r = await client.post(
        "/api/v1/wake-scheduler/preview-targets",
        json={"target_selector": {"mode": "subnet_tags", "tags": ["x"]}},
        headers=h,
    )
    assert r.status_code == 200, r.text
    r = await client.post(
        f"/api/v1/wake-scheduler/schedules/{uuid.uuid4()}/preview-targets", headers=h
    )
    assert r.status_code == 404, r.text  # reached the handler, not the scope gate
    r = await client.post(
        "/api/v1/appliance/firewall/preview", json={"appliance_id": str(uuid.uuid4())}, headers=h
    )
    assert r.status_code == 404, r.text


# ── S2-b: HELD ───────────────────────────────────────────────────────────

_HELD_BODY = (
    '<locationRequest xmlns="urn:ietf:params:xml:ns:geopriv:held">'
    "<locationType>civic</locationType><device><ip>10.20.3.44</ip></device></locationRequest>"
)


async def test_held_admits_a_read_token_and_a_read_only_account(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = {"Content-Type": "application/held+xml"}
    owner = await _user(db_session, [{"action": "read", "resource_type": "e911_location"}])
    await db_session.commit()
    token = await _token(db_session, owner, ["read"])
    r = await client.post("/held", content=_HELD_BODY, headers={**hdr, **token})
    assert r.status_code != 403, r.text
    # Not located (404 locationUnknown) is a HELD answer; 403 is the refusal.
    assert r.status_code == 404, r.text
    session = {"Authorization": f"Bearer {create_access_token(str(owner.id))}"}
    r = await client.post("/held", content=_HELD_BODY, headers={**hdr, **session})
    assert r.status_code == 404, r.text


async def test_held_still_needs_e911_read(client: AsyncClient, db_session: AsyncSession) -> None:
    u = await _user(db_session, [{"action": "read", "resource_type": "ip_space"}])
    await db_session.commit()
    h = {
        "Authorization": f"Bearer {create_access_token(str(u.id))}",
        "Content-Type": "application/held+xml",
    }
    r = await client.post("/held", content=_HELD_BODY, headers=h)
    assert r.status_code == 403, r.text


# ── S2-d: analytics honours a bound token like its siblings ──────────────


async def test_dns_analytics_treats_a_bound_token_like_its_siblings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The analytics route narrows through the same ``resolve_dns_log_servers``
    as ``dns-queries``, so it declares the binding too. Without the declaration
    the auth layer refuses a bound token with "cannot be limited to them" before
    the route's own permission check is reached."""
    owner = await _user(db_session, None, superadmin=True)
    h = await _token(
        db_session,
        owner,
        ["read"],
        [{"action": "read", "resource_type": "dns_zone", "resource_id": str(uuid.uuid4())}],
    )
    answers = {}
    for path in ("/api/v1/logs/dns-queries", "/api/v1/logs/dns-queries/analytics"):
        r = await client.post(path, json={}, headers=h)
        answers[path] = (r.status_code, r.json().get("detail"))
        assert "cannot be limited to them" not in str(r.json()), (path, r.text)
    assert len(set(answers.values())) == 1, answers


# ── S3-d: GET options does not write ─────────────────────────────────────


async def test_get_options_returns_defaults_without_persisting(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.commit()
    h = await _viewer(db_session)

    async def _rows() -> int:
        return (
            await db_session.execute(
                select(func.count())
                .select_from(DNSServerOptions)
                .where(DNSServerOptions.group_id == grp.id)
            )
        ).scalar_one()

    assert await _rows() == 0
    r = await client.get(f"/api/v1/dns/groups/{grp.id}/options", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["group_id"] == str(grp.id)
    assert body["recursion_enabled"] is True or body["recursion_enabled"] is False
    assert await _rows() == 0

    # PUT still creates it.
    su = await _user(db_session, None, superadmin=True)
    await db_session.commit()
    sh = {"Authorization": f"Bearer {create_access_token(str(su.id))}"}
    r = await client.put(f"/api/v1/dns/groups/{grp.id}/options", json={}, headers=sh)
    assert r.status_code == 200, r.text
    assert await _rows() == 1
