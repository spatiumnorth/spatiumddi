"""Fixes for the low-severity advisories filed from the 2026-10-06 walks.

* GHSA-c4v7-2235-v88h — a DNS server's recent-events and rndc-status are not
  any token grant's resource, so a resource-scoped token is refused them.
* GHSA-875w-8f2h-9mw6 — an IPAM write may name only a DNS zone the token may
  write: the subnet's own zones, the row's current zone, or a granted one.
* GHSA-hxpx-gjqf-6p4f — deleting an address removes its DHCP reservations
  only for a caller with ``delete`` on ``dhcp_static``, and audits them.
* GHSA-rc6p-vq45-64v3 — ``redact()`` matches a secret in any mixture of
  ``%HH`` (either hex case) and JSON ``\\u00HH`` encodings.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import APIToken, Group, Role, User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.forward_secrets import REDACTED, redact

# ── shared fixtures ──────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Admin",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _user_with_perms(
    db: AsyncSession, permissions: list[dict]
) -> tuple[User, dict[str, str]]:
    tag = uuid.uuid4().hex[:8]
    role = Role(name=f"r-{tag}", permissions=permissions)
    group = Group(name=f"g-{tag}")
    group.roles = [role]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="Scoped User",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=False,
    )
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _token(db: AsyncSession, owner: User, grants: list[dict]) -> dict[str, str]:
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=grants,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.flush()
    return {"Authorization": f"Bearer {raw}"}


async def _dns(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone, DNSZone]:
    tag = uuid.uuid4().hex[:6]
    group = DNSServerGroup(name=f"g-{tag}", description="")
    db.add(group)
    await db.flush()
    zone_a = DNSZone(group_id=group.id, name=f"a-{tag}.test.", kind="forward")
    zone_b = DNSZone(group_id=group.id, name=f"b-{tag}.test.", kind="forward")
    db.add_all([zone_a, zone_b])
    await db.flush()
    return group, zone_a, zone_b


async def _subnet(db: AsyncSession, network: str = "10.81.0.0/24") -> Subnet:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=network, name="lan")
    db.add(subnet)
    await db.flush()
    return subnet


# ── GHSA-c4v7: server-level reads refuse a resource-scoped token ──────────────


@pytest.mark.asyncio
async def test_server_level_reads_refuse_a_zone_scoped_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, admin_headers = await _superadmin(db_session)
    # A separate token owner: the test client shares one session, so the
    # owner's User instance would carry the token's grants into the
    # session request below.
    owner, _ = await _superadmin(db_session)
    group, zone_a, _ = await _dns(db_session)
    server = DNSServer(
        group_id=group.id, name=f"s-{uuid.uuid4().hex[:6]}", driver="bind9", host="192.0.2.1"
    )
    db_session.add(server)
    tok = await _token(
        db_session,
        owner,
        [{"action": "read", "resource_type": "dns_zone", "resource_id": str(zone_a.id)}],
    )
    await db_session.commit()

    for path in ("recent-events", "rndc-status"):
        url = f"/api/v1/dns/servers/{server.id}/{path}"
        refused = await client.get(url, headers=tok)
        assert refused.status_code == 403, (path, refused.text)
        # A session is unaffected.
        assert (await client.get(url, headers=admin_headers)).status_code == 200, path


# ── GHSA-875w: an IPAM write names only a zone the token may write ────────────


async def _subnet_token_setup(
    db: AsyncSession, *, zone_grant: bool = False
) -> tuple[Subnet, DNSZone, DNSZone, dict[str, str]]:
    admin, _ = await _superadmin(db)
    _, zone_a, zone_b = await _dns(db)
    subnet = await _subnet(db)
    subnet.dns_zone_id = str(zone_a.id)
    subnet.dns_inherit_settings = False
    grants = [{"action": "*", "resource_type": "subnet", "resource_id": str(subnet.id)}]
    if zone_grant:
        grants.append({"action": "*", "resource_type": "dns_zone", "resource_id": str(zone_b.id)})
    tok = await _token(db, admin, grants)
    await db.commit()
    return subnet, zone_a, zone_b, tok


@pytest.mark.asyncio
async def test_address_create_refuses_a_zone_the_token_holds_no_grant_on(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, zone_a, zone_b, tok = await _subnet_token_setup(db_session)
    url = f"/api/v1/ipam/subnets/{subnet.id}/addresses"

    foreign = await client.post(
        url,
        headers=tok,
        json={"address": "10.81.0.10", "hostname": "h10", "dns_zone_id": str(zone_b.id)},
    )
    assert foreign.status_code == 403, foreign.text

    foreign_extra = await client.post(
        url,
        headers=tok,
        json={"address": "10.81.0.11", "hostname": "h11", "extra_zone_ids": [str(zone_b.id)]},
    )
    assert foreign_extra.status_code == 403, foreign_extra.text

    # The subnet's own zone is what it publishes into anyway.
    own = await client.post(
        url,
        headers=tok,
        json={"address": "10.81.0.12", "hostname": "h12", "dns_zone_id": str(zone_a.id)},
    )
    assert own.status_code == 201, own.text


@pytest.mark.asyncio
async def test_address_create_accepts_a_granted_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, _, zone_b, tok = await _subnet_token_setup(db_session, zone_grant=True)
    r = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses",
        headers=tok,
        json={"address": "10.81.0.20", "hostname": "h20", "dns_zone_id": str(zone_b.id)},
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_address_update_and_subnet_rebind_refuse_a_foreign_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, _, zone_b, tok = await _subnet_token_setup(db_session)
    created = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses",
        headers=tok,
        json={"address": "10.81.0.30", "hostname": "h30"},
    )
    assert created.status_code == 201, created.text
    row_id = created.json()["id"]

    moved = await client.put(
        f"/api/v1/ipam/addresses/{row_id}", headers=tok, json={"dns_zone_id": str(zone_b.id)}
    )
    assert moved.status_code == 403, moved.text

    # An edit that names no zone is unaffected.
    renamed = await client.put(
        f"/api/v1/ipam/addresses/{row_id}", headers=tok, json={"description": "kept"}
    )
    assert renamed.status_code == 200, renamed.text

    rebound = await client.put(
        f"/api/v1/ipam/subnets/{subnet.id}", headers=tok, json={"dns_zone_id": str(zone_b.id)}
    )
    assert rebound.status_code == 403, rebound.text


@pytest.mark.asyncio
async def test_a_session_may_name_any_zone(client: AsyncClient, db_session: AsyncSession) -> None:
    _, admin_headers = await _superadmin(db_session)
    _, _, zone_b = await _dns(db_session)
    subnet = await _subnet(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses",
        headers=admin_headers,
        json={"address": "10.81.0.40", "hostname": "h40", "dns_zone_id": str(zone_b.id)},
    )
    assert r.status_code == 201, r.text


# ── GHSA-hxpx: deleting an address gates its reservation cascade ──────────────


_IPAM_WRITE = [
    {"action": "admin", "resource_type": "subnet"},
    {"action": "admin", "resource_type": "ip_address"},
]


async def _linked_row(db: AsyncSession) -> tuple[uuid.UUID, uuid.UUID]:
    subnet = await _subnet(db, network="10.82.0.0/24")
    group = DHCPServerGroup(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(
        DHCPServer(
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=group.id,
        )
    )
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="scope", address_family="ipv4")
    db.add(scope)
    await db.flush()
    row = IPAddress(
        subnet_id=subnet.id,
        address="10.82.0.50",
        status="static_dhcp",
        hostname="printer",
        mac_address="aa:bb:cc:dd:ee:50",
    )
    db.add(row)
    await db.flush()
    from app.services.dhcp.static_ipam import sync_static_for_ipam_row

    sync = await sync_static_for_ipam_row(db, row)
    assert sync.action == "create", sync
    await db.commit()
    return row.id, subnet.id


async def _statics(db: AsyncSession) -> list[DHCPStaticAssignment]:
    db.expire_all()
    return list((await db.execute(select(DHCPStaticAssignment))).scalars().all())


@pytest.mark.asyncio
async def test_ipam_only_user_cannot_delete_an_address_with_a_reservation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, ipam_headers = await _user_with_perms(db_session, _IPAM_WRITE)
    row_id, _ = await _linked_row(db_session)

    for permanent in ("false", "true"):
        r = await client.delete(
            f"/api/v1/ipam/addresses/{row_id}?permanent={permanent}", headers=ipam_headers
        )
        assert r.status_code == 403, (permanent, r.text)
        assert "dhcp_static" in r.text
    assert len(await _statics(db_session)) == 1


@pytest.mark.asyncio
async def test_dhcp_static_deleter_removes_the_reservation_with_an_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _user_with_perms(
        db_session, [*_IPAM_WRITE, {"action": "delete", "resource_type": "dhcp_static"}]
    )
    row_id, _ = await _linked_row(db_session)
    static_id = (await _statics(db_session))[0].id

    r = await client.delete(f"/api/v1/ipam/addresses/{row_id}?permanent=true", headers=headers)
    assert r.status_code == 204, r.text
    assert await _statics(db_session) == []
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dhcp_static_assignment",
                    AuditLog.resource_id == str(static_id),
                    AuditLog.action == "delete",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1


# ── GHSA-rc6p: redact() in any encoding of the secret ────────────────────────


def test_redact_matches_lower_case_percent_encoding() -> None:
    header = "Bearer QA1636+E7/TOK=v2"
    body = "rejected token=QA1636%2bE7%2fTOK%3dv2"
    out = redact(body, header)
    assert "QA1636" not in out
    assert REDACTED in out


def test_redact_matches_json_unicode_escapes() -> None:
    header = "Bearer QA1636+E8/TOK=v2"
    body = '{"error":"invalid token","token":"QA1636\\u002BE8/TOK=v2"}'
    out = redact(body, header)
    assert "QA1636" not in out
    assert "E8/TOK" not in out


def test_redact_matches_a_mixture_of_encodings() -> None:
    header = "Bearer QA1636+E9/TOK=v2"
    body = "token: QA1636\\u002bE9%2FTOK%3Dv2"
    assert "QA1636" not in redact(body, header)


def test_redact_leaves_unrelated_text_alone() -> None:
    assert redact("all good here", "Bearer QA1636+E7/TOK=v2") == "all good here"


# ── #1714: bulk delete applies the single delete's reservation rule ──────────


@pytest.mark.asyncio
async def test_bulk_delete_refuses_a_reservation_linked_row_for_an_ipam_only_user(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _user_with_perms(db_session, _IPAM_WRITE)
    row_id, subnet_id = await _linked_row(db_session)
    plain = IPAddress(subnet_id=subnet_id, address="10.82.0.60", status="allocated")
    db_session.add(plain)
    await db_session.flush()
    plain_id = plain.id
    await db_session.commit()

    for permanent in (False, True):
        r = await client.post(
            "/api/v1/ipam/addresses/bulk-delete",
            headers=headers,
            json={"ip_ids": [str(row_id)], "permanent": permanent},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["deleted_count"] == 0
        assert body["skipped"] == [str(row_id)]
        assert "dhcp_static" in body["skipped_reasons"][str(row_id)]
    db_session.expire_all()
    assert len(await _statics(db_session)) == 1
    row = await db_session.get(IPAddress, row_id)
    assert row is not None and row.status == "static_dhcp"

    # Mixed selection: the plain row is still deleted, the linked one skipped.
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        headers=headers,
        json={"ip_ids": [str(row_id), str(plain_id)], "permanent": True},
    )
    body = r.json()
    assert body["deleted_count"] == 1
    assert body["skipped"] == [str(row_id)]
    assert len(await _statics(db_session)) == 1


@pytest.mark.asyncio
async def test_bulk_delete_removes_the_reservation_for_a_dhcp_static_deleter(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _user_with_perms(
        db_session, [*_IPAM_WRITE, {"action": "delete", "resource_type": "dhcp_static"}]
    )
    row_id, _ = await _linked_row(db_session)
    static_id = (await _statics(db_session))[0].id

    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        headers=headers,
        json={"ip_ids": [str(row_id)], "permanent": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["deleted_count"] == 1
    assert r.json()["skipped_reasons"] == {}
    assert await _statics(db_session) == []
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dhcp_static_assignment",
                    AuditLog.resource_id == str(static_id),
                    AuditLog.action == "delete",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1


# ── #1714 validation: single and bulk delete agree, row for row ──────────────


async def _single_delete(
    client: AsyncClient, headers: dict[str, str], row_id: uuid.UUID, permanent: bool
) -> tuple[int, str]:
    r = await client.delete(
        f"/api/v1/ipam/addresses/{row_id}?permanent={str(permanent).lower()}", headers=headers
    )
    return r.status_code, (r.json().get("detail", "") if r.content else "")


async def _bulk_delete(
    client: AsyncClient, headers: dict[str, str], row_id: uuid.UUID, permanent: bool
) -> tuple[int, str]:
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        headers=headers,
        json={"ip_ids": [str(row_id)], "permanent": permanent},
    )
    assert r.status_code in (200, 502), r.text
    if r.status_code == 502:
        return 502, r.json()["detail"]
    return r.json()["deleted_count"], r.json()["skipped_reasons"].get(str(row_id), "")


@pytest.mark.asyncio
@pytest.mark.parametrize("permanent", [False, True])
async def test_single_and_bulk_refuse_with_the_same_text(
    client: AsyncClient, db_session: AsyncSession, permanent: bool
) -> None:
    _, headers = await _user_with_perms(db_session, _IPAM_WRITE)
    row_id, _ = await _linked_row(db_session)

    code, single_text = await _single_delete(client, headers, row_id, permanent)
    assert code == 403
    deleted, bulk_text = await _bulk_delete(client, headers, row_id, permanent)
    assert deleted == 0
    assert bulk_text == single_text and "dhcp_static" in bulk_text
    assert len(await _statics(db_session)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["single", "bulk"])
@pytest.mark.parametrize("permanent", [False, True])
async def test_single_and_bulk_leave_the_same_state_for_a_dhcp_static_deleter(
    client: AsyncClient, db_session: AsyncSession, path: str, permanent: bool
) -> None:
    """Soft delete removes the reservation too, on both paths — the single
    delete has always done so, and restoring an orphan does not re-create it."""
    _, headers = await _user_with_perms(
        db_session, [*_IPAM_WRITE, {"action": "delete", "resource_type": "dhcp_static"}]
    )
    row_id, _ = await _linked_row(db_session)
    static_id = (await _statics(db_session))[0].id

    if path == "single":
        code, _ = await _single_delete(client, headers, row_id, permanent)
        assert code == 204
    else:
        deleted, _ = await _bulk_delete(client, headers, row_id, permanent)
        assert deleted == 1

    assert await _statics(db_session) == []
    row = await db_session.get(IPAddress, row_id)
    if permanent:
        assert row is None
    else:
        assert row is not None and row.status == "orphan"
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dhcp_static_assignment",
                    AuditLog.resource_id == str(static_id),
                    AuditLog.action == "delete",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1


@pytest.mark.asyncio
async def test_bulk_delete_finds_a_reservation_linked_only_from_the_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#1628 back-link: the reservation's ``ip_address_id`` was never stamped,
    only the row's ``static_assignment_id``. Both paths must still see it."""
    _, headers = await _user_with_perms(db_session, _IPAM_WRITE)
    row_id, _ = await _linked_row(db_session)
    static = (await _statics(db_session))[0]
    row = await db_session.get(IPAddress, row_id)
    assert row is not None
    row.static_assignment_id = str(static.id)
    static.ip_address_id = None
    await db_session.commit()

    code, _ = await _single_delete(client, headers, row_id, True)
    assert code == 403
    deleted, reason = await _bulk_delete(client, headers, row_id, True)
    assert deleted == 0 and "dhcp_static" in reason
    assert len(await _statics(db_session)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["single", "bulk"])
async def test_a_failed_reservation_push_aborts_before_any_change(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    """A server refusing the reservation removal aborts the whole request
    with 502 on both paths, before DNS teardown, leaving row and
    reservation untouched."""
    from app.api.v1.ipam import router as ipam_router
    from app.services.dhcp.windows_writethrough import WindowsPushError

    async def _refuse(db: AsyncSession, statics: object) -> None:
        raise WindowsPushError("server said no")

    dns_calls: list[str] = []

    async def _record_dns(db: AsyncSession, ip: IPAddress, subnet: Subnet, **kw: object) -> None:
        dns_calls.append(str(ip.address))

    _, headers = await _user_with_perms(
        db_session, [*_IPAM_WRITE, {"action": "delete", "resource_type": "dhcp_static"}]
    )
    row_id, _ = await _linked_row(db_session)
    # Patched only after setup: creating the linked row syncs its DNS too.
    monkeypatch.setattr(ipam_router, "push_statics_bulk_delete", _refuse)
    monkeypatch.setattr(ipam_router, "_sync_dns_record", _record_dns)

    if path == "single":
        code, detail = await _single_delete(client, headers, row_id, True)
    else:
        code, detail = await _bulk_delete(client, headers, row_id, True)
    assert code == 502 and "server said no" in detail
    assert dns_calls == []
    assert len(await _statics(db_session)) == 1
    row = await db_session.get(IPAddress, row_id)
    assert row is not None and row.status == "static_dhcp"
