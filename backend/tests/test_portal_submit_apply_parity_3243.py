"""The portal's submit and apply run the checks the normal creates run (#3243-#3250)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ChangeRequest
from app.models.dhcp import DHCPPool, DHCPScope
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import CustomFieldDefinition, IPAddress, Subnet
from tests.test_portal_dhcp_static_ipam_mirror_2901 import _estate
from tests.test_portal_submit_refusals_2903 import _requester, _submit
from tests.test_self_service_requests import _user


async def _rows(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(ChangeRequest)) or 0)


async def _zone_subnet(db: AsyncSession, subnet: Subnet, *, public: bool = False) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", is_public_facing=public)
    db.add(grp)
    await db.flush()
    zone = DNSZone(group_id=grp.id, name="example.test.")
    db.add(zone)
    await db.flush()
    subnet.dns_inherit_settings = False
    subnet.dns_group_ids = [str(grp.id)]
    subnet.dns_zone_id = str(zone.id)
    await db.flush()
    return zone


# ── #3243 ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_name_collision_refused_at_submit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    zone = await _zone_subnet(db_session, subnet)
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.60.0.10",
            status="allocated",
            hostname="host-a",
            forward_zone_id=zone.id,
        )
    )
    await db_session.flush()
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {"subnet_id": str(subnet.id), "address": "10.60.0.20", "hostname": "host-a"},
    )
    assert resp.status_code == 409, resp.text
    assert "host-a.example.test" in resp.text
    ok = await _submit(
        client,
        tok,
        "ip_address",
        {"subnet_id": str(subnet.id), "address": "10.60.0.21", "hostname": "host-b"},
    )
    assert ok.status_code == 201, ok.text
    assert await _rows(db_session) == 1


@pytest.mark.asyncio
async def test_mac_collision_refused_at_submit_without_naming_the_other_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.60.0.10",
            status="allocated",
            mac_address="02:00:5e:20:11:01",
        )
    )
    await db_session.flush()
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {
            "subnet_id": str(subnet.id),
            "address": "10.60.0.21",
            "hostname": "host-b",
            "mac_address": "02:00:5e:20:11:01",
        },
    )
    assert resp.status_code == 409, resp.text
    assert "10.60.0.10" not in resp.text
    assert await _rows(db_session) == 0


@pytest.mark.asyncio
async def test_dynamic_pool_refused_at_submit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    scope, subnet, _ = await _estate(db_session)
    db_session.add(
        DHCPPool(
            scope_id=scope.id, start_ip="10.60.0.100", end_ip="10.60.0.150", pool_type="dynamic"
        )
    )
    await db_session.flush()
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {"subnet_id": str(subnet.id), "address": "10.60.0.120", "hostname": "host-c"},
    )
    assert resp.status_code == 409, resp.text
    assert "dynamic pool" in resp.text
    assert await _rows(db_session) == 0


@pytest.mark.asyncio
async def test_private_address_in_public_facing_zone_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    await _zone_subnet(db_session, subnet, public=True)
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {"subnet_id": str(subnet.id), "address": "10.60.0.20", "hostname": "host-d"},
    )
    assert resp.status_code == 409, resp.text
    assert "public-facing" in resp.text
    assert await _rows(db_session) == 0


@pytest.mark.asyncio
async def test_overlong_hostname_refused_at_submit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    await _zone_subnet(db_session, subnet)
    host = ".".join(["a" * 60] * 4)
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {"subnet_id": str(subnet.id), "address": "10.60.0.23", "hostname": host},
    )
    assert resp.status_code == 422, resp.text
    assert await _rows(db_session) == 0


# ── #3244 ───────────────────────────────────────────────────────────────


async def _block_id(db: AsyncSession) -> str:
    _, _, block = await _estate(db)
    return str(block.id)


@pytest.mark.asyncio
async def test_subnet_request_with_bad_template_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    block = await _block_id(db_session)
    base = {"block_id": block, "prefix_len": 28, "name": "x"}
    bad = await _submit(client, tok, "subnet", {**base, "template_id": "not-a-uuid"})
    assert bad.status_code == 422, bad.text
    gone = await _submit(client, tok, "subnet", {**base, "template_id": str(uuid.uuid4())})
    assert gone.status_code == 404, gone.text
    assert await _rows(db_session) == 0
    ok = await _submit(client, tok, "subnet", base)
    assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_subnet_request_missing_required_custom_field_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    block = await _block_id(db_session)
    db_session.add(
        CustomFieldDefinition(
            resource_type="subnet", name="owner", label="Owner", field_type="text", is_required=True
        )
    )
    await db_session.flush()
    resp = await _submit(client, tok, "subnet", {"block_id": block, "prefix_len": 28, "name": "x"})
    assert resp.status_code == 422, resp.text
    assert "Owner" in resp.text
    assert await _rows(db_session) == 0


# ── #3245 ───────────────────────────────────────────────────────────────


async def _zone(db: AsyncSession) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(group_id=grp.id, name="example.test.")
    db.add(zone)
    await db.flush()
    return zone


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rtype,value,extra,words",
    [
        ("A", "10.199.5.90", {"priority": 10}, "A records do not take priority"),
        (
            "MX",
            "mx.example.test.",
            {"priority": 10, "weight": 5, "port": 25},
            "MX records take only a priority",
        ),
        ("TXT", "hello", {"priority": 1}, "TXT records do not take priority"),
    ],
)
async def test_dns_record_fields_its_type_does_not_take_refused(
    client: AsyncClient,
    db_session: AsyncSession,
    rtype: str,
    value: str,
    extra: dict,
    words: str,
) -> None:
    tok = await _requester(db_session)
    zone = await _zone(db_session)
    resp = await _submit(
        client,
        tok,
        "dns_record",
        {"zone_id": str(zone.id), "name": "n", "record_type": rtype, "value": value, **extra},
    )
    assert resp.status_code == 400, resp.text  # the preview refusal's status
    assert words in resp.text
    assert await _rows(db_session) == 0


@pytest.mark.asyncio
async def test_apply_stores_only_the_fields_its_type_takes(db_session: AsyncSession) -> None:
    from app.services.ai import operations

    zone = await _zone(db_session)
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_dns_record")
    # A request queued before submit learned the rule: apply refuses it too.
    args = op.args_model(
        zone_id=str(zone.id), name="h", record_type="A", value="10.0.0.5", priority=10
    )
    with pytest.raises(ValueError, match="do not take priority"):
        await op.apply(db_session, admin, args)
    assert await db_session.scalar(select(func.count()).select_from(DNSRecord)) == 0


# ── #3248 ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hostless_apply_refuses_pool_and_mac_collision(db_session: AsyncSession) -> None:
    from app.services.ai import operations

    scope, subnet, _ = await _estate(db_session)
    db_session.add_all(
        [
            DHCPPool(
                scope_id=scope.id,
                start_ip="10.60.0.100",
                end_ip="10.60.0.150",
                pool_type="dynamic",
            ),
            IPAddress(
                subnet_id=subnet.id,
                address="10.60.0.10",
                status="allocated",
                mac_address="02:00:5e:20:11:01",
            ),
        ]
    )
    await db_session.flush()
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_ip_address")
    pooled = op.args_model(subnet_id=str(subnet.id), address="10.60.0.110", status="reserved")
    with pytest.raises(ValueError, match="dynamic pool"):
        await op.apply(db_session, admin, pooled)
    dup = op.args_model(
        subnet_id=str(subnet.id), address="10.60.0.24", mac_address="02:00:5e:20:11:01"
    )
    with pytest.raises(ValueError, match="MAC"):
        await op.apply(db_session, admin, dup)
    clean = op.args_model(subnet_id=str(subnet.id), address="10.60.0.25")
    assert (await op.apply(db_session, admin, clean))["address"] == "10.60.0.25"


# ── #3249 ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_available_row_is_not_called_a_failure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    db_session.add(IPAddress(subnet_id=subnet.id, address="10.60.0.40", status="available"))
    await db_session.flush()
    resp = await _submit(
        client, tok, "ip_address", {"subnet_id": str(subnet.id), "address": "10.60.0.40"}
    )
    assert resp.status_code == 201, resp.text
    assert "apply will fail" not in resp.json()["preview_text"]


# ── #3250 ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_static_dhcp_without_a_scope_refused_at_submit_and_apply(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.ai import operations

    tok = await _requester(db_session)
    scope, subnet, _ = await _estate(db_session)
    await db_session.delete(scope)
    await db_session.flush()
    args = {
        "subnet_id": str(subnet.id),
        "address": "10.60.0.30",
        "status": "static_dhcp",
        "mac_address": "02:00:5e:20:11:04",
    }
    resp = await _submit(client, tok, "ip_address", args)
    assert resp.status_code == 422, resp.text
    assert "No DHCP scope" in resp.text
    assert await _rows(db_session) == 0
    # Queued before submit learned it: the approval fails and creates nothing.
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_ip_address")
    with pytest.raises(ValueError, match="No DHCP scope"):
        await op.apply(db_session, admin, op.args_model(**args))
    assert await db_session.scalar(select(func.count()).select_from(DHCPScope)) == 0
    assert (
        await db_session.scalar(
            select(func.count()).select_from(IPAddress).where(IPAddress.subnet_id == subnet.id)
        )
        == 0
    )


# ── #3250, the rest of the sync's refusals ─────────────────────────────


@pytest.mark.asyncio
async def test_static_dhcp_with_a_clashing_mac_refused_at_submit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A MAC the scope's group already reserves: the sync would make no
    reservation, so submit says so and names no other address."""
    from app.models.dhcp import DHCPStaticAssignment

    tok = await _requester(db_session)
    scope, subnet, _ = await _estate(db_session)
    db_session.add(
        DHCPStaticAssignment(
            scope_id=scope.id, ip_address="10.60.0.77", mac_address="02:00:5e:20:11:05"
        )
    )
    await db_session.flush()
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {
            "subnet_id": str(subnet.id),
            "address": "10.60.0.31",
            "status": "static_dhcp",
            "mac_address": "02:00:5e:20:11:05",
        },
    )
    assert resp.status_code == 422, resp.text
    assert "already" in resp.text
    assert "10.60.0.77" not in resp.text
    assert await _rows(db_session) == 0


@pytest.mark.asyncio
async def test_approver_without_dhcp_static_write_fails_the_request_and_records_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Approved by someone who may not write reservations: the request ends
    failed with the reason, and no address is left behind (atomic), instead of
    "executed" with only ``result.dhcp_static_warning``."""
    from app.models.dhcp import DHCPStaticAssignment
    from tests.test_self_service_requests import _auth

    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    subnet_id = subnet.id  # the approval's commit / rollback expires ``subnet``
    _, appr = await _user(
        db_session,
        name="appr",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
            {"action": "write", "resource_type": "subnet"},
            {"action": "read", "resource_type": "subnet"},
            {"action": "write", "resource_type": "ip_address"},
            {"action": "read", "resource_type": "ip_address"},
        ],
    )
    for host in (None, "host-s"):
        last = "32" if host is None else "33"
        args = {
            "subnet_id": str(subnet_id),
            "address": f"10.60.0.{last}",
            "status": "static_dhcp",
            "mac_address": f"02:00:5e:20:11:{last}",
        }
        if host:
            args["hostname"] = host
        sub = await _submit(client, tok, "ip_address", args)
        assert sub.status_code == 201, sub.text
        resp = await client.post(
            f"/api/v1/requests/{sub.json()['id']}/approve",
            headers=_auth(appr),
            json={"decision_note": "ok"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["state"] == "failed", body
        assert "dhcp_static" in (body.get("error") or ""), body
    assert (
        await db_session.scalar(
            select(func.count()).select_from(IPAddress).where(IPAddress.subnet_id == subnet_id)
        )
        == 0
    )
    assert await db_session.scalar(select(func.count()).select_from(DHCPStaticAssignment)) == 0


@pytest.mark.asyncio
async def test_hostless_static_dhcp_apply_rolls_back_when_the_sync_declines(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pre-flight passed but the sync made no reservation (a DHCP-side
    change in between): the no-hostname apply raises before it commits."""
    from app.services.ai import operations
    from app.services.dhcp import static_ipam

    _, subnet, _ = await _estate(db_session)
    admin, _ = await _user(db_session, name="adm", superadmin=True)

    async def _declines(db: AsyncSession, row: IPAddress, **_: object) -> object:
        return static_ipam.IPAMStaticSync(warning="raced: no reservation was created")

    monkeypatch.setattr(static_ipam, "sync_static_for_ipam_row", _declines)
    op = operations.get_operation("create_ip_address")
    args = op.args_model(
        subnet_id=str(subnet.id),
        address="10.60.0.34",
        status="static_dhcp",
        mac_address="02:00:5e:20:11:34",
    )
    with pytest.raises(ValueError, match="raced"):
        await op.apply(db_session, admin, args)
