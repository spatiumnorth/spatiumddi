"""spatiumddi#4797 — an address's PTR goes into the reverse zone of its
forward zone's view.

A group may hold the same reverse zone once per view (split horizon), and
``pick_reverse_zone`` never read the view, so the PTR landed in whichever of
the two the database listed first: possibly the view the forward zone is not
in. The PTR now stays in the forward zone's view (or a zone pinned to none);
when that view has no reverse zone, no PTR is written rather than one into
another view's zone.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.models.ipam import IPBlock, IPSpace

REV = "5.52.10.in-addr.arpa."


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u1419-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _setup(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone, IPSpace, IPBlock]:
    """A group served by one BIND9 primary, its primary forward zone, and a
    space with the 10.98.0.0/16 block the subnets are carved from."""
    grp = DNSServerGroup(name=f"g1419-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    fwd = DNSZone(
        group_id=grp.id,
        name=f"z1419-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    space = IPSpace(name=f"sp1419-{uuid.uuid4().hex[:8]}", description="")
    db.add_all([fwd, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.98.0.0/16", name="b")
    db.add(block)
    await db.flush()
    return grp, fwd, space, block


async def _subnet(
    client: AsyncClient,
    headers: dict[str, str],
    space: IPSpace,
    block: IPBlock,
    grp: DNSServerGroup,
    fwd: DNSZone,
    network: str = "10.98.95.0/24",
) -> str:
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": network,
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(fwd.id),
        },
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _allocate(
    client: AsyncClient, headers: dict[str, str], sid: str, address: str, hostname: str
) -> str:
    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": address, "hostname": hostname},
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _ptrs(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type, DNSRecord.value)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted((str(n), str(t), str(v)) for n, t, v in rows)


async def _views_setup(
    db: AsyncSession, fwd_in: str = "b"
) -> tuple[DNSServerGroup, dict[str, DNSView], DNSZone, IPSpace, IPBlock]:
    grp = DNSServerGroup(name=f"g4797-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    views = {n: DNSView(group_id=grp.id, name=n) for n in ("a", "b")}
    db.add_all(views.values())
    await db.flush()
    fwd = DNSZone(
        group_id=grp.id,
        view_id=views[fwd_in].id,
        name=f"f4797-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    space = IPSpace(name=f"sp4797-{uuid.uuid4().hex[:8]}", description="")
    db.add_all([fwd, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.52.0.0/16", name="b")
    db.add(block)
    await db.flush()
    return grp, views, fwd, space, block


async def _reverse(db: AsyncSession, grp: DNSServerGroup, view: DNSView) -> DNSZone:
    z = DNSZone(
        group_id=grp.id,
        view_id=view.id,
        name=REV,
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(z)
    await db.flush()  # sequential flushes: row order is creation order
    return z


async def _allocate_ptr_zones(
    client: AsyncClient, db: AsyncSession, grp: DNSServerGroup, fwd: DNSZone, space, block, zs
) -> dict[str, list[tuple[str, str]]]:
    await db.commit()
    headers = await _headers(db)
    sid = await _subnet(client, headers, space, block, grp, fwd, "10.52.5.0/24")
    await _allocate(client, headers, sid, "10.52.5.10", "h1")
    out: dict[str, list[tuple[str, str]]] = {}
    for key, z in zs.items():
        rows = await _ptrs(db, z.id)
        out[key] = [(n, v) for n, t, v in rows if t == "PTR"]
    return out


@pytest.mark.asyncio
@pytest.mark.parametrize("first", ["a", "b"])
async def test_ptr_lands_in_the_forward_zones_view(
    client: AsyncClient, db_session: AsyncSession, first: str
) -> None:
    """Forward zone in view b; both views hold the reverse zone, created in
    either order. The PTR is in b's, never a's."""
    grp, views, fwd, space, block = await _views_setup(db_session, "b")
    order = [first, "b" if first == "a" else "a"]
    zs = {}
    for k in order:
        zs[k] = await _reverse(db_session, grp, views[k])
    got = await _allocate_ptr_zones(client, db_session, grp, fwd, space, block, zs)
    assert got["a"] == [], got
    assert ("10", f"h1.{fwd.name}") in got["b"], got


@pytest.mark.asyncio
async def test_no_ptr_when_only_another_view_holds_the_reverse_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Forward zone in view b, reverse zone only in view a: no PTR is written
    (wrong-view data would answer a's clients with a name a does not serve)."""
    grp, views, fwd, space, block = await _views_setup(db_session, "b")
    zs = {"a": await _reverse(db_session, grp, views["a"])}
    got = await _allocate_ptr_zones(client, db_session, grp, fwd, space, block, zs)
    assert got["a"] == [], got


@pytest.mark.asyncio
@pytest.mark.parametrize("unpinned_first", [True, False])
async def test_view_pinned_reverse_zone_beats_unpinned_of_same_name(
    client: AsyncClient, db_session: AsyncSession, unpinned_first: bool
) -> None:
    """An unpinned reverse zone beside one pinned to the forward zone's view:
    the pinned one takes the PTR whichever row the database lists first."""
    grp, views, fwd, space, block = await _views_setup(db_session, "b")
    unpinned = DNSZone(
        group_id=grp.id,
        view_id=None,
        name=REV,
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    zs: dict[str, DNSZone] = {}
    if unpinned_first:
        db_session.add(unpinned)
        await db_session.flush()
        zs["none"] = unpinned
        zs["b"] = await _reverse(db_session, grp, views["b"])
    else:
        zs["b"] = await _reverse(db_session, grp, views["b"])
        db_session.add(unpinned)
        await db_session.flush()
        zs["none"] = unpinned
    got = await _allocate_ptr_zones(client, db_session, grp, fwd, space, block, zs)
    assert got["none"] == [], got
    assert ("10", f"h1.{fwd.name}") in got["b"], got


def _cand(zone: DNSZone):  # type: ignore[no-untyped-def]
    from app.services.dns.sync_check import ReverseCandidate

    return ReverseCandidate(zone, None, None, True)


@pytest.mark.parametrize("reverse_order", [False, True])
def test_pick_prefers_own_view_then_unpinned_whatever_the_list_order(reverse_order: bool) -> None:
    """The tie between same-named reverse zones is decided by the view, not
    by where the zone sits in the candidate list."""
    import ipaddress
    from types import SimpleNamespace

    va, vb = uuid.uuid4(), uuid.uuid4()

    def z(view: uuid.UUID | None) -> DNSZone:
        return DNSZone(
            id=uuid.uuid4(),
            group_id=uuid.uuid4(),
            view_id=view,
            name=REV,
            zone_type="primary",
            kind="reverse",
        )

    za, zb, zn = z(va), z(vb), z(None)
    cands = [_cand(x) for x in (za, zn, zb)]
    if reverse_order:
        cands.reverse()
    from app.services.dns.sync_check import pick_reverse_zone

    subnet = SimpleNamespace(id=uuid.uuid4(), space_id=None, network="10.52.5.0/24")
    ip = ipaddress.ip_address("10.52.5.10")
    assert pick_reverse_zone(subnet, ip, cands, vb) is zb  # type: ignore[arg-type]
    assert pick_reverse_zone(subnet, ip, cands, va) is za  # type: ignore[arg-type]
    assert pick_reverse_zone(subnet, ip, cands, None) is zn  # type: ignore[arg-type]
