"""What a portal requester reads about a refused request names nothing they
cannot read, while the approver's audit row keeps the full reason.

One test per kind of detail a refusal used to carry: another subnet's address
and network, another DHCP scope's id, a template's name, a DHCP pool's bounds,
an existing DNS record's id and CNAME target.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dhcp import DHCPPool, DHCPScope, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPAMTemplate, Subnet
from tests.test_portal_dhcp_static_ipam_mirror_2901 import _estate
from tests.test_portal_submit_refusals_2903 import _requester, _submit
from tests.test_self_service_requests import _auth, _block, _user


async def _approver(db: AsyncSession) -> str:
    _, token = await _user(db, name="appr", permissions=None, superadmin=True)
    return token


async def _approve_failed(client: AsyncClient, rid: str, token: str) -> dict[str, Any]:
    resp = await client.post(
        f"/api/v1/requests/{rid}/approve", headers=_auth(token), json={"decision_note": "go"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "failed", body
    return body


async def _audit_error(db: AsyncSession, rid: str) -> str:
    rows = (
        await db.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "change_request",
                AuditLog.resource_id == rid,
                AuditLog.action == "failed",
            )
        )
    ).scalars()
    return " ".join(str((r.new_value or {}).get("error")) for r in rows)


@pytest.mark.asyncio
async def test_collision_in_another_subnet_is_not_named_to_the_requester(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    appr = await _approver(db_session)
    _, subnet, _ = await _estate(db_session)
    other = Subnet(space_id=subnet.space_id, block_id=subnet.block_id, network="10.61.0.0/24")
    db_session.add(other)
    await db_session.flush()
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {
            "subnet_id": str(subnet.id),
            "address": "10.60.0.70",
            "mac_address": "02:00:5e:20:12:01",
        },
    )
    assert resp.status_code == 201, resp.text
    # Taken between submit and approve, in a subnet the requester never named.
    db_session.add(
        IPAddress(
            subnet_id=other.id,
            address="10.61.0.10",
            status="allocated",
            mac_address="02:00:5e:20:12:01",
        )
    )
    await db_session.flush()
    body = await _approve_failed(client, resp.json()["id"], appr)
    assert "10.61.0.10" not in body["error"] and "10.61.0.0/24" not in body["error"]
    assert "02:00:5e:20:12:01" in body["error"]


@pytest.mark.asyncio
async def test_other_dhcp_scope_id_is_not_named_to_the_requester(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    appr = await _approver(db_session)
    scope, subnet, _ = await _estate(db_session)
    other_subnet = Subnet(
        space_id=subnet.space_id, block_id=subnet.block_id, network="10.61.0.0/24"
    )
    db_session.add(other_subnet)
    await db_session.flush()
    other = DHCPScope(
        group_id=scope.group_id, subnet_id=other_subnet.id, name="o", address_family="ipv4"
    )
    db_session.add(other)
    await db_session.flush()
    other_id = str(other.id)
    resp = await _submit(
        client,
        tok,
        "dhcp_reservation",
        {"scope_id": str(scope.id), "ip_address": "10.60.0.50", "mac_address": "aa:bb:cc:dd:ee:50"},
    )
    assert resp.status_code == 201, resp.text
    db_session.add(
        DHCPStaticAssignment(
            scope_id=other.id, ip_address="10.61.0.5", mac_address="aa:bb:cc:dd:ee:50"
        )
    )
    await db_session.flush()
    body = await _approve_failed(client, resp.json()["id"], appr)
    assert other_id not in body["error"]
    assert "already reserved in this group" in body["error"]
    assert other_id in await _audit_error(db_session, resp.json()["id"])


async def _subnet_request(
    client: AsyncClient, db: AsyncSession, template: IPAMTemplate
) -> tuple[str, str]:
    tok = await _requester(db)
    block = await _block(db, "10.80.0.0/16")
    resp = await _submit(
        client,
        tok,
        "subnet",
        {
            "block_id": str(block.id),
            "prefix_len": 26,
            "name": "net",
            "template_id": str(template.id),
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"], tok


@pytest.mark.asyncio
async def test_template_name_is_not_in_a_failed_request(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appr = await _approver(db_session)
    tpl = IPAMTemplate(name="Secret branch layout", applies_to="subnet")
    db_session.add(tpl)
    await db_session.flush()
    rid, _ = await _subnet_request(client, db_session, tpl)
    tpl.applies_to = "block"  # edited between submit and approve
    await db_session.flush()
    body = await _approve_failed(client, rid, appr)
    assert "Secret branch layout" not in body["error"]
    assert body["error"] == "No IPAM template has that id."
    assert "Secret branch layout" in await _audit_error(db_session, rid)


@pytest.mark.asyncio
async def test_template_of_the_wrong_kind_reads_like_an_unknown_id_at_submit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    block = await _block(db_session, "10.81.0.0/16")
    wrong = IPAMTemplate(name="Block only layout", applies_to="block")
    db_session.add(wrong)
    await db_session.flush()
    base = {"block_id": str(block.id), "prefix_len": 26, "name": "n"}
    one = await _submit(client, tok, "subnet", {**base, "template_id": str(wrong.id)})
    two = await _submit(client, tok, "subnet", {**base, "template_id": str(uuid.uuid4())})
    assert one.status_code == two.status_code == 404
    assert "Block only layout" not in one.text
    assert one.json()["detail"] == two.json()["detail"]


@pytest.mark.asyncio
async def test_pool_bounds_are_not_named_at_submit_or_approve(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    appr = await _approver(db_session)
    scope, subnet, _ = await _estate(db_session)
    args = {"subnet_id": str(subnet.id), "address": "10.60.0.120", "hostname": "h"}
    ok = await _submit(client, tok, "ip_address", {**args, "address": "10.60.0.20"})
    assert ok.status_code == 201, ok.text
    db_session.add(
        DHCPPool(scope_id=scope.id, start_ip="10.60.0.15", end_ip="10.60.0.25", pool_type="dynamic")
    )
    await db_session.flush()
    # At submit.
    resp = await _submit(client, tok, "ip_address", {**args, "address": "10.60.0.21"})
    assert resp.status_code == 409, resp.text
    assert "dynamic pool" in resp.text
    assert "10.60.0.15" not in resp.text and "10.60.0.25" not in resp.text
    # At approve, for the request queued before the pool existed.
    body = await _approve_failed(client, ok.json()["id"], appr)
    assert "10.60.0.15" not in body["error"] and "10.60.0.25" not in body["error"]


async def _zone(db: AsyncSession) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(group_id=grp.id, name="example.test.")
    db.add(zone)
    await db.flush()
    return zone


@pytest.mark.asyncio
async def test_identical_record_id_is_not_named_to_the_requester(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    appr = await _approver(db_session)
    zone = await _zone(db_session)
    args = {"zone_id": str(zone.id), "name": "www", "record_type": "A", "value": "10.9.9.9"}
    first = await _submit(client, tok, "dns_record", args)
    second_resp = await _submit(client, tok, "dns_record", args)
    assert first.status_code == second_resp.status_code == 201, second_resp.text
    ok = await client.post(
        f"/api/v1/requests/{first.json()['id']}/approve",
        headers=_auth(appr),
        json={"decision_note": "go"},
    )
    assert ok.json()["state"] == "executed", ok.text
    rec_id = str((await db_session.execute(select(DNSRecord.id))).scalars().one())
    body = await _approve_failed(client, second_resp.json()["id"], appr)
    assert rec_id not in body["error"]
    assert "already exists" in body["error"]
    assert rec_id in await _audit_error(db_session, second_resp.json()["id"])


@pytest.mark.asyncio
async def test_cname_target_and_id_are_not_named_to_the_requester(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    appr = await _approver(db_session)
    zone = await _zone(db_session)
    cname = DNSRecord(
        zone_id=zone.id,
        name="alias",
        fqdn="alias.example.test.",
        record_type="CNAME",
        value="hidden-target.example.org.",
    )
    db_session.add(cname)
    await db_session.flush()
    args = {"zone_id": str(zone.id), "name": "alias", "record_type": "A", "value": "10.9.9.8"}
    refused = await _submit(client, tok, "dns_record", args)
    assert refused.status_code == 400, refused.text
    assert "can hold no A record" in refused.text
    assert "hidden-target" not in refused.text and str(cname.id) not in refused.text
    # Added after submit: the apply-time refusal is worded the same way.
    ok = await _submit(client, tok, "dns_record", {**args, "name": "later"})
    assert ok.status_code == 201, ok.text
    late = DNSRecord(
        zone_id=zone.id,
        name="later",
        fqdn="later.example.test.",
        record_type="CNAME",
        value="hidden-target.example.org.",
    )
    db_session.add(late)
    await db_session.flush()
    body = await _approve_failed(client, ok.json()["id"], appr)
    assert "hidden-target" not in body["error"] and str(late.id) not in body["error"]
