"""Moving a DNS zone between server groups (issue #935).

The sibling of the #934 server move and a much sharper tool. A server
carries state ABOUT a group; a zone carries references INTO one, and the
sharpest of those is the view.

**Clearing a view widens exposure.** Under split-horizon a record with
``view_id IS NOT NULL`` renders in exactly that view; one with
``view_id IS NULL`` is shared and renders in EVERY view. So dropping a
reference the target cannot resolve does not remove the zone from a view —
it adds it to all of them. Most of this file exists to pin that, and to
pin that it cannot happen without the operator saying so.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSKey,
    DNSPool,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSServerZoneState,
    DNSTSIGKey,
    DNSView,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.services.dns.tsig import group_tsig_secret


async def _superadmin(db: AsyncSession, username: str = "root935") -> str:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _group(db: AsyncSession, name: str) -> DNSServerGroup:
    g = DNSServerGroup(name=name, description="")
    db.add(g)
    await db.flush()
    return g


async def _view(db: AsyncSession, group: DNSServerGroup, name: str) -> DNSView:
    v = DNSView(group_id=group.id, name=name, match_clients=["any"])
    db.add(v)
    await db.flush()
    return v


async def _zone(
    db: AsyncSession,
    group: DNSServerGroup,
    name: str = "example.com.",
    *,
    view: DNSView | None = None,
    zone_type: str = "primary",
    **kw: object,
) -> DNSZone:
    z = DNSZone(
        group_id=group.id,
        name=name,
        zone_type=zone_type,
        view_id=view.id if view else None,
        **kw,
    )
    db.add(z)
    await db.flush()
    return z


async def _record(
    db: AsyncSession, zone: DNSZone, name: str, *, view: DNSView | None = None
) -> DNSRecord:
    r = DNSRecord(
        zone_id=zone.id,
        name=name,
        record_type="A",
        value="10.0.0.1",
        ttl=300,
        view_id=view.id if view else None,
    )
    db.add(r)
    await db.flush()
    return r


async def _server(db: AsyncSession, group: DNSServerGroup, name: str) -> DNSServer:
    s = DNSServer(
        group_id=group.id,
        name=name,
        driver="bind9",
        host=name,
        port=53,
        roles=["authoritative"],
        status="active",
        is_primary=True,
    )
    db.add(s)
    await db.flush()
    return s


def _preview_url(z: DNSZone) -> str:
    return f"/api/v1/dns/groups/{z.group_id}/zones/{z.id}/move/preview"


def _commit_url(z: DNSZone) -> str:
    return f"/api/v1/dns/groups/{z.group_id}/zones/{z.id}/move/commit"


async def _preview(client: AsyncClient, token: str, zone: DNSZone, target: DNSServerGroup):
    return await client.post(
        _preview_url(zone),
        json={"target_group_id": str(target.id)},
        headers=_auth(token),
    )


async def _commit(
    client: AsyncClient,
    token: str,
    zone: DNSZone,
    target: DNSServerGroup,
    *,
    acks: list[str] | None = None,
    name: str | None = None,
):
    return await client.post(
        _commit_url(zone),
        json={
            "target_group_id": str(target.id),
            "confirmation_zone_name": name if name is not None else zone.name,
            "acknowledgements": acks or [],
        },
        headers=_auth(token),
    )


# ── The plain case ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_move_a_plain_zone(client: AsyncClient, db_session: AsyncSession) -> None:
    """No views, no DNSSEC, no grants — the discussion's actual ask."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)
    await _record(db_session, zone, "www")

    prev = await _preview(client, token, zone, dst)
    assert prev.status_code == 200, prev.text
    assert prev.json()["required_acknowledgements"] == []
    assert prev.json()["records_total"] == 1

    resp = await _commit(client, token, zone, dst)
    assert resp.status_code == 200, resp.text

    await db_session.refresh(zone)
    assert zone.group_id == dst.id


@pytest.mark.asyncio
async def test_preview_writes_nothing(client: AsyncClient, db_session: AsyncSession) -> None:
    """It is called repeatedly while the operator reads the warnings."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)

    for _ in range(3):
        assert (await _preview(client, token, zone, dst)).status_code == 200

    await db_session.refresh(zone)
    assert zone.group_id == src.id


@pytest.mark.asyncio
async def test_commit_requires_the_zone_name(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)

    bad = await _commit(client, token, zone, dst, name="wrong.example.")
    assert bad.status_code == 422
    await db_session.refresh(zone)
    assert zone.group_id == src.id

    # A trailing dot is a formatting detail, not a different zone.
    ok = await _commit(client, token, zone, dst, name="example.com")
    assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
async def test_move_to_the_same_group_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Unlike the server move's silent no-op: this endpoint exists to be
    given a DIFFERENT group, so the same one is a mistake worth naming."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    zone = await _zone(db_session, src)

    assert (await _preview(client, token, zone, src)).status_code == 422
    assert (await _commit(client, token, zone, src)).status_code == 422


@pytest.mark.asyncio
async def test_move_requires_superadmin(client: AsyncClient, db_session: AsyncSession) -> None:
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)
    user = User(
        username="plain935",
        email="plain935@example.com",
        display_name="plain",
        hashed_password=hash_password("password123"),
        is_superadmin=False,
    )
    db_session.add(user)
    await db_session.flush()
    token = create_access_token(str(user.id))

    assert (await _preview(client, token, zone, dst)).status_code == 403
    assert (await _commit(client, token, zone, dst)).status_code == 403


# ── Views: the widening property ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_view_remaps_by_name(client: AsyncClient, db_session: AsyncSession) -> None:
    """Name is the only identity a view has across groups — two views
    called ``internal`` are the operator saying they mean the same thing."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    src_internal = await _view(db_session, src, "internal")
    dst_internal = await _view(db_session, dst, "internal")
    zone = await _zone(db_session, src, view=src_internal)
    rec = await _record(db_session, zone, "www", view=src_internal)

    prev = await _preview(client, token, zone, dst)
    body = prev.json()
    assert body["zone_view_action"] == "remapped"
    assert body["records_remapped"] == 1
    assert body["records_widened"] == 0
    # A remap preserves intent, so it needs no acknowledgement.
    assert body["required_acknowledgements"] == []

    assert (await _commit(client, token, zone, dst)).status_code == 200

    await db_session.refresh(zone)
    await db_session.refresh(rec)
    assert zone.view_id == dst_internal.id
    assert rec.view_id == dst_internal.id


@pytest.mark.asyncio
async def test_unresolvable_view_is_reported_as_widening(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """THE property. The target renders views but has no ``internal``, so
    clearing the pin does not remove the zone from a view — it puts the
    zone into every view the target has."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    src_internal = await _view(db_session, src, "internal")
    await _view(db_session, dst, "external")  # target renders views, but not "internal"
    zone = await _zone(db_session, src, view=src_internal)
    await _record(db_session, zone, "secret", view=src_internal)

    prev = await _preview(client, token, zone, dst)
    body = prev.json()
    assert body["zone_view_action"] == "cleared_widening"
    assert body["records_widened"] == 1
    assert body["records_widened_by_view"] == {"internal": 1}
    assert "view_widening" in body["required_acknowledgements"]
    assert any("EVERY view" in w for w in body["warnings"])


@pytest.mark.asyncio
async def test_widening_move_is_refused_without_acknowledgement(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """It is a data-exposure change with no operator-visible symptom, so
    it does not happen by default."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    src_internal = await _view(db_session, src, "internal")
    await _view(db_session, dst, "external")
    zone = await _zone(db_session, src, view=src_internal)

    refused = await _commit(client, token, zone, dst)
    assert refused.status_code == 422
    assert "view_widening" in refused.json()["detail"]
    await db_session.refresh(zone)
    assert zone.group_id == src.id, "refused move must not have applied"

    allowed = await _commit(client, token, zone, dst, acks=["view_widening"])
    assert allowed.status_code == 200, allowed.text
    await db_session.refresh(zone)
    assert zone.group_id == dst.id
    assert zone.view_id is None


@pytest.mark.asyncio
async def test_clearing_a_view_into_a_viewless_group_is_inert(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Same row change, different consequence: with no views in the target
    the reference was going to be ignored anyway, so it is reported but
    needs no acknowledgement."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")  # no views at all
    src_internal = await _view(db_session, src, "internal")
    zone = await _zone(db_session, src, view=src_internal)
    await _record(db_session, zone, "www", view=src_internal)

    prev = await _preview(client, token, zone, dst)
    body = prev.json()
    assert body["zone_view_action"] == "cleared_inert"
    assert body["records_cleared_inert"] == 1
    assert body["records_widened"] == 0
    assert body["required_acknowledgements"] == []

    assert (await _commit(client, token, zone, dst)).status_code == 200


@pytest.mark.asyncio
async def test_unscoped_records_are_left_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A record with no view is already shared. Nothing to remap, and it
    must not be counted as widened — it was never narrow."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    await _view(db_session, dst, "external")
    zone = await _zone(db_session, src)
    await _record(db_session, zone, "www")
    await _record(db_session, zone, "mail")

    body = (await _preview(client, token, zone, dst)).json()
    assert body["records_total"] == 2
    assert body["records_widened"] == 0
    assert body["records_remapped"] == 0
    assert body["required_acknowledgements"] == []


# ── Name collision, against the RESOLVED view ───────────────────────────────


@pytest.mark.asyncio
async def test_collision_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)
    await _zone(db_session, dst)  # same name, same (NULL) view

    assert (await _preview(client, token, zone, dst)).json()["name_collision"] is True
    resp = await _commit(client, token, zone, dst)
    assert resp.status_code == 409
    await db_session.refresh(zone)
    assert zone.group_id == src.id


@pytest.mark.asyncio
async def test_same_name_in_a_different_view_is_not_a_collision(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The constraint is ``(group_id, view_id, name)``. A naive
    ``(group, name)`` check would refuse this legitimate split-horizon
    move — the whole point of views is the same zone name twice."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    await _view(db_session, src, "internal")
    dst_internal = await _view(db_session, dst, "internal")
    dst_external = await _view(db_session, dst, "external")
    # The incoming zone resolves into dst/internal; the sitting one is in
    # dst/external. Different rows under the constraint.
    await _zone(db_session, dst, view=dst_external)
    src_internal = (
        await db_session.execute(
            select(DNSView).where(DNSView.group_id == src.id, DNSView.name == "internal")
        )
    ).scalar_one()
    zone = await _zone(db_session, src, view=src_internal)

    body = (await _preview(client, token, zone, dst)).json()
    assert body["zone_view_action"] == "remapped"
    assert body["name_collision"] is False

    assert (await _commit(client, token, zone, dst)).status_code == 200, "legitimate move"
    await db_session.refresh(zone)
    assert zone.view_id == dst_internal.id


@pytest.mark.asyncio
async def test_collision_is_checked_against_the_cleared_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The subtle one. The zone's view does not exist in the target, so it
    lands at ``(target, NULL, name)`` — which collides with an unviewed
    zone that a check against the ORIGINAL view id would have missed."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    src_internal = await _view(db_session, src, "internal")
    await _view(db_session, dst, "external")
    await _zone(db_session, dst)  # unviewed, same name
    zone = await _zone(db_session, src, view=src_internal)

    body = (await _preview(client, token, zone, dst)).json()
    assert body["zone_view_action"] == "cleared_widening"
    assert body["name_collision"] is True

    resp = await _commit(client, token, zone, dst, acks=["view_widening"])
    assert resp.status_code == 409
    await db_session.refresh(zone)
    assert zone.group_id == src.id


# ── DNSSEC ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_signed_zone_requires_rollover_acknowledgement(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The private keys live on the old group's servers and do not travel.
    Moving a delegated signed zone takes it off the internet until the DS
    is republished, so it cannot happen silently."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src, dnssec_enabled=True)
    db_session.add(DNSKey(zone_id=zone.id, key_tag=12345, key_type="ksk", algorithm=13))
    await db_session.flush()

    body = (await _preview(client, token, zone, dst)).json()
    assert body["dnssec_signed"] is True
    assert body["dnssec_key_count"] == 1
    assert "dnssec_rollover" in body["required_acknowledgements"]
    assert any("DS record" in w for w in body["warnings"])

    assert (await _commit(client, token, zone, dst)).status_code == 422

    ok = await _commit(client, token, zone, dst, acks=["dnssec_rollover"])
    assert ok.status_code == 200, ok.text

    # The key mirror describes keys no server in the new group holds.
    remaining = (
        (await db_session.execute(select(DNSKey).where(DNSKey.zone_id == zone.id))).scalars().all()
    )
    assert remaining == []


# ── Dynamic-update grants ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_grant_remaps_by_key_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    src_key = DNSTSIGKey(
        group_id=src.id, name="dhcp-ddns", algorithm="hmac-sha256", secret_encrypted=b"x"
    )
    dst_key = DNSTSIGKey(
        group_id=dst.id, name="dhcp-ddns", algorithm="hmac-sha256", secret_encrypted=b"y"
    )
    db_session.add_all([src_key, dst_key])
    await db_session.flush()
    zone = await _zone(db_session, src)
    acl = DNSZoneUpdateAcl(
        zone_id=zone.id, seq=0, action="grant", match_kind="tsig_key", tsig_key_id=src_key.id
    )
    db_session.add(acl)
    await db_session.flush()

    body = (await _preview(client, token, zone, dst)).json()
    assert body["acl_rows_remapped"] == 1
    assert body["acl_keys_lost"] == []
    assert body["required_acknowledgements"] == []

    assert (await _commit(client, token, zone, dst)).status_code == 200
    await db_session.refresh(acl)
    assert acl.tsig_key_id == dst_key.id


@pytest.mark.asyncio
async def test_unmappable_update_grant_is_deleted_with_acknowledgement(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``num_nonnulls(tsig_key_id, ip_cidr) = 1`` forbids clearing the key,
    so the row has to go. Deleting an authorisation rule fails CLOSED,
    which is the safe direction — but losing a grant silently is not, so
    it takes an acknowledgement."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    src_key = DNSTSIGKey(
        group_id=src.id, name="dhcp-ddns", algorithm="hmac-sha256", secret_encrypted=b"x"
    )
    db_session.add(src_key)
    await db_session.flush()
    zone = await _zone(db_session, src)
    db_session.add(
        DNSZoneUpdateAcl(
            zone_id=zone.id, seq=0, action="grant", match_kind="tsig_key", tsig_key_id=src_key.id
        )
    )
    await db_session.flush()

    body = (await _preview(client, token, zone, dst)).json()
    assert body["acl_keys_lost"] == ["dhcp-ddns"]
    assert "lost_update_grants" in body["required_acknowledgements"]

    assert (await _commit(client, token, zone, dst)).status_code == 422

    ok = await _commit(client, token, zone, dst, acks=["lost_update_grants"])
    assert ok.status_code == 200, ok.text
    rows = (
        (
            await db_session.execute(
                select(DNSZoneUpdateAcl).where(DNSZoneUpdateAcl.zone_id == zone.id)
            )
        )
        .scalars()
        .all()
    )
    assert rows == []


@pytest.mark.asyncio
async def test_ip_based_grants_are_untouched(client: AsyncClient, db_session: AsyncSession) -> None:
    """An IP grant references nothing group-scoped, so it survives."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)
    acl = DNSZoneUpdateAcl(
        zone_id=zone.id, seq=0, action="grant", match_kind="ip", ip_cidr="10.0.0.0/24"
    )
    db_session.add(acl)
    await db_session.flush()

    body = (await _preview(client, token, zone, dst)).json()
    assert body["acl_keys_lost"] == []

    assert (await _commit(client, token, zone, dst)).status_code == 200
    await db_session.refresh(acl)
    assert acl.ip_cidr == "10.0.0.0/24"


# ── Everything else that points at the zone ─────────────────────────────────


@pytest.mark.asyncio
async def test_pools_follow_the_zone(client: AsyncClient, db_session: AsyncSession) -> None:
    """A pool is attached by ``zone_id`` and its health checks run from the
    control plane, not the group's agents — so it follows rather than
    being detached, which is the point of a move over export/import."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)
    pool = DNSPool(group_id=src.id, zone_id=zone.id, name="web", record_name="www")
    db_session.add(pool)
    await db_session.flush()

    assert (await _preview(client, token, zone, dst)).json()["pools_repointed"] == 1
    assert (await _commit(client, token, zone, dst)).status_code == 200

    await db_session.refresh(pool)
    assert pool.group_id == dst.id


@pytest.mark.asyncio
async def test_zone_state_and_queued_ops_are_purged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Both describe the OLD group's servers."""
    from app.models.dns import DNSRecordOp

    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    srv = await _server(db_session, src, "ns1")
    await _server(db_session, dst, "ns2")
    zone = await _zone(db_session, src)
    db_session.add(DNSServerZoneState(server_id=srv.id, zone_id=zone.id, current_serial=7))
    for state in ("pending", "in_flight"):
        db_session.add(
            DNSRecordOp(
                server_id=srv.id,
                zone_name=zone.name,
                op="create",
                record={"name": "www", "type": "A", "value": "10.0.0.1"},
                state=state,
            )
        )
    # History, not queued work.
    db_session.add(
        DNSRecordOp(
            server_id=srv.id,
            zone_name=zone.name,
            op="create",
            record={"name": "old", "type": "A", "value": "10.0.0.2"},
            state="applied",
        )
    )
    await db_session.flush()

    body = (await _preview(client, token, zone, dst)).json()
    assert body["zone_state_rows"] == 1
    assert body["pending_ops"] == 2

    assert (await _commit(client, token, zone, dst)).status_code == 200

    states = (
        (
            await db_session.execute(
                select(DNSServerZoneState).where(DNSServerZoneState.zone_id == zone.id)
            )
        )
        .scalars()
        .all()
    )
    assert states == []
    ops = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == srv.id)))
        .scalars()
        .all()
    )
    assert [o.state for o in ops] == ["applied"]


@pytest.mark.asyncio
async def test_records_move_with_the_zone(client: AsyncClient, db_session: AsyncSession) -> None:
    """Records hang off ``zone_id``, so they need no rewrite — but the
    move is worthless if they don't actually come along."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)
    for n in ("www", "mail", "ftp"):
        await _record(db_session, zone, n)

    assert (await _commit(client, token, zone, dst)).status_code == 200

    await db_session.refresh(zone)
    recs = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id)))
        .scalars()
        .all()
    )
    assert len(recs) == 3
    assert zone.group_id == dst.id


@pytest.mark.asyncio
async def test_target_group_gets_a_tsig_key(client: AsyncClient, db_session: AsyncSession) -> None:
    """Same reasoning as the #934 server move: a group created in the UI
    has never been through agent registration."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    assert group_tsig_secret(dst) is None
    zone = await _zone(db_session, src)

    resp = await _commit(client, token, zone, dst)
    assert resp.status_code == 200, resp.text
    assert resp.json()["target_tsig_key_generated"] is True

    await db_session.refresh(dst)
    assert group_tsig_secret(dst)


@pytest.mark.asyncio
async def test_driver_change_and_empty_target_are_warned_not_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Unlike the #934 server move, a zone is not itself driver-bound —
    it is data. Moving it to a group of another driver is a legitimate
    migration, so it warns rather than refuses."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    await _server(db_session, src, "ns1")
    pdns = DNSServer(
        group_id=dst.id,
        name="pdns1",
        driver="powerdns",
        host="pdns1",
        port=53,
        roles=["authoritative"],
        status="active",
    )
    db_session.add(pdns)
    await db_session.flush()
    zone = await _zone(db_session, src)

    body = (await _preview(client, token, zone, dst)).json()
    assert body["source_drivers"] == ["bind9"]
    assert body["target_drivers"] == ["powerdns"]
    assert any("Driver change" in w for w in body["warnings"])
    assert body["required_acknowledgements"] == []
    assert (await _commit(client, token, zone, dst)).status_code == 200


@pytest.mark.asyncio
async def test_empty_target_group_is_warned(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    await _server(db_session, src, "ns1")
    zone = await _zone(db_session, src)

    body = (await _preview(client, token, zone, dst)).json()
    assert any("no servers" in w for w in body["warnings"])


@pytest.mark.asyncio
async def test_unknown_target_group_404s(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    zone = await _zone(db_session, src)

    resp = await client.post(
        _preview_url(zone),
        json={"target_group_id": str(uuid.uuid4())},
        headers=_auth(token),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_zone_addressed_under_the_wrong_group_404s(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(db_session, src)

    resp = await client.post(
        f"/api/v1/dns/groups/{dst.id}/zones/{zone.id}/move/preview",
        json={"target_group_id": str(dst.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 404


# ── Code-review follow-ups ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_integration_owned_zone_cannot_be_moved(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A reconciler-owned zone is not the operator's to re-home — the next
    sync recreates it in the group the integration is bound to. Refused on
    the PREVIEW too, so it is learned before the modal is filled in."""
    from app.models.ipam import IPSpace
    from app.models.tailscale import TailscaleTenant

    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    space = IPSpace(name="ts-space")
    db_session.add(space)
    await db_session.flush()
    tenant = TailscaleTenant(name="tailnet", ipam_space_id=space.id)
    db_session.add(tenant)
    await db_session.flush()
    zone = await _zone(db_session, src, "ts.net.", tailscale_tenant_id=tenant.id)

    prev = await _preview(client, token, zone, dst)
    assert prev.status_code == 422
    assert "Tailscale" in prev.json()["detail"]

    resp = await _commit(client, token, zone, dst, name="ts.net.")
    assert resp.status_code == 422
    await db_session.refresh(zone)
    assert zone.group_id == src.id


@pytest.mark.asyncio
async def test_signed_zone_refused_on_a_group_that_cannot_sign(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Not waivable by acknowledgement: the row would keep saying
    ``dnssec_enabled`` while the zone is served unsigned, indefinitely,
    with nothing to notice it. Every other path into a signed zone goes
    through the same driver gate."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    await _server(db_session, src, "ns1")
    win = DNSServer(
        group_id=dst.id,
        name="win1",
        driver="windows_dns",
        host="win1",
        port=53,
        roles=["authoritative"],
        status="active",
    )
    db_session.add(win)
    await db_session.flush()
    zone = await _zone(db_session, src, dnssec_enabled=True)

    body = (await _preview(client, token, zone, dst)).json()
    assert body["dnssec_unsupported_drivers"] == ["windows_dns"]

    # Even WITH the rollover acknowledgement — this one is a hard refusal.
    resp = await _commit(client, token, zone, dst, acks=["dnssec_rollover"])
    assert resp.status_code == 422
    assert "cannot sign" in resp.json()["detail"]
    await db_session.refresh(zone)
    assert zone.group_id == src.id


@pytest.mark.asyncio
async def test_signed_zone_moves_to_a_signing_capable_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The gate must not block the legitimate case."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    await _server(db_session, src, "ns1")
    await _server(db_session, dst, "ns2")
    zone = await _zone(db_session, src, dnssec_enabled=True)

    body = (await _preview(client, token, zone, dst)).json()
    assert body["dnssec_unsupported_drivers"] == []
    assert (await _commit(client, token, zone, dst, acks=["dnssec_rollover"])).status_code == 200


@pytest.mark.asyncio
async def test_move_clears_the_cached_ds_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Deleting the DNSKey rows alone left ``dnssec_ds_records`` at the old
    group's values — so the UI would tell the operator to publish a DS for
    keys that no server in the new group holds."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(
        db_session,
        src,
        dnssec_enabled=True,
        dnssec_ds_records=[{"key_tag": 12345, "digest": "abc"}],
    )

    assert (await _commit(client, token, zone, dst, acks=["dnssec_rollover"])).status_code == 200
    await db_session.refresh(zone)
    assert zone.dnssec_ds_records is None


@pytest.mark.asyncio
async def test_forward_zone_without_forwarders_refused_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The #743 guard every create/update runs, applied to the group the
    zone lands in. Technitium has no global-forwarder fallback, so the zone
    would be accepted and then silently never created on the daemon."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    tech = DNSServer(
        group_id=dst.id,
        name="tech1",
        driver="technitium",
        host="tech1",
        port=53,
        roles=["authoritative"],
        status="active",
    )
    db_session.add(tech)
    await db_session.flush()
    zone = await _zone(db_session, src, "fwd.example.", zone_type="forward", forwarders=[])

    resp = await _commit(client, token, zone, dst, name="fwd.example.")
    assert resp.status_code == 422
    assert "forwarder" in resp.json()["detail"]
    await db_session.refresh(zone)
    assert zone.group_id == src.id


@pytest.mark.asyncio
async def test_named_acl_reference_the_target_lacks_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``DNSAcl`` is per-group (#899). A name the target does not define is
    an undefined symbol in its named.conf — and BIND rejects the file
    WHOLE, so the entire target group stops converging, not just this
    zone. Refused rather than warned for that reason."""
    from app.models.dns import DNSAcl

    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    db_session.add(DNSAcl(group_id=src.id, name="trusted"))
    await db_session.flush()
    zone = await _zone(db_session, src, allow_transfer=["trusted"])

    body = (await _preview(client, token, zone, dst)).json()
    assert body["acl_names_lost"] == ["trusted"]

    resp = await _commit(client, token, zone, dst)
    assert resp.status_code == 422
    assert "trusted" in resp.json()["detail"]
    await db_session.refresh(zone)
    assert zone.group_id == src.id


@pytest.mark.asyncio
async def test_named_acl_present_in_the_target_is_fine(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Same name in both groups is the operator saying they mean the same
    thing — the view / TSIG rule applied to ACLs."""
    from app.models.dns import DNSAcl

    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    db_session.add(DNSAcl(group_id=src.id, name="trusted"))
    db_session.add(DNSAcl(group_id=dst.id, name="trusted"))
    await db_session.flush()
    zone = await _zone(db_session, src, allow_transfer=["trusted"])

    body = (await _preview(client, token, zone, dst)).json()
    assert body["acl_names_remapped"] == ["trusted"]
    assert body["acl_names_lost"] == []
    assert (await _commit(client, token, zone, dst)).status_code == 200


@pytest.mark.asyncio
async def test_builtin_match_list_values_are_not_acl_references(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``any`` / ``none`` / a CIDR / an address are not names, so they must
    not be reported as ACLs the target is missing — that would refuse
    almost every zone."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    zone = await _zone(
        db_session,
        src,
        allow_query=["any"],
        allow_transfer=["none", "10.0.0.0/8", "192.168.1.1"],
    )

    body = (await _preview(client, token, zone, dst)).json()
    assert body["acl_names_lost"] == []
    assert body["acl_names_remapped"] == []
    assert (await _commit(client, token, zone, dst)).status_code == 200


@pytest.mark.asyncio
async def test_soft_deleted_records_have_their_view_remapped_too(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """DNSRecord is soft-deleted, so the default query filter hides deleted
    rows. Left behind, a restored record points at a view in a group the
    zone has left — and under split-horizon that renders it into no
    operator view at all."""
    from sqlalchemy import update as sa_update

    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    src_internal = await _view(db_session, src, "internal")
    dst_internal = await _view(db_session, dst, "internal")
    zone = await _zone(db_session, src)
    gone = await _record(db_session, zone, "old", view=src_internal)
    await db_session.execute(
        sa_update(DNSRecord)
        .where(DNSRecord.id == gone.id)
        .values(deleted_at=datetime.now(UTC))
        .execution_options(include_deleted=True)
    )
    await db_session.flush()

    # It is not part of "records moving" — that count is live rows.
    body = (await _preview(client, token, zone, dst)).json()
    assert body["records_total"] == 0
    assert body["records_remapped"] == 1

    assert (await _commit(client, token, zone, dst)).status_code == 200

    row = (
        await db_session.execute(
            select(DNSRecord).where(DNSRecord.id == gone.id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert row.view_id == dst_internal.id, "a soft-deleted row must not keep a stale view"


@pytest.mark.asyncio
async def test_tsig_key_reference_the_target_lacks_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A ``key <name>`` element is the same undefined-symbol failure as an
    ACL name when the target defines no such key (#1316) — and so is the
    ``key`` in an ``also-notify`` entry."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    for name in ("xfer", "notif"):
        db_session.add(
            DNSTSIGKey(group_id=src.id, name=name, algorithm="hmac-sha256", secret_encrypted=b"x")
        )
    await db_session.flush()
    zone = await _zone(
        db_session,
        src,
        allow_transfer=["key xfer"],
        also_notify=["192.0.2.1 key notif"],
    )

    body = (await _preview(client, token, zone, dst)).json()
    assert body["key_names_lost"] == ["notif", "xfer"]

    resp = await _commit(client, token, zone, dst)
    assert resp.status_code == 422
    assert "xfer" in resp.json()["detail"]
    await db_session.refresh(zone)
    assert zone.group_id == src.id


@pytest.mark.asyncio
async def test_tsig_key_present_in_the_target_is_fine(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    for g in (src, dst):
        db_session.add(
            DNSTSIGKey(group_id=g.id, name="xfer", algorithm="hmac-sha256", secret_encrypted=b"x")
        )
    await db_session.flush()
    zone = await _zone(db_session, src, allow_transfer=["!key xfer"])

    body = (await _preview(client, token, zone, dst)).json()
    assert body["key_names_lost"] == []
    assert (await _commit(client, token, zone, dst)).status_code == 200
