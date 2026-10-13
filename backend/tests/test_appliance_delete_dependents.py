"""Appliance delete dependents (#197 — cascade-on-delete).

Covers:

* ``GET /appliances/{id}/dependents`` returns DNS + DHCP server rows
  that share the appliance's hostname (legacy path; appliance_id FK
  is forward-compatible but not populated yet — see issue #197 follow-up).
* Soft-delete (``DELETE /appliances/{id}``) sweeps the dependents in
  the same transaction + records the cascaded names in the audit log.
* An appliance with zero dependents soft-deletes cleanly.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup


async def _make_superadmin(db: AsyncSession, password: str = "test-pw-123") -> tuple[User, str]:
    """Create a superadmin user + return (user, bearer-token). Mirrors
    the pattern used in test_audit_forward.py."""
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password(password),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _seed_appliance(db: AsyncSession, hostname: str = "ddi-test-1") -> Appliance:
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint="ff" * 32,
        cert_serial="0000",
        # `assigned_*` fields default to None; the test doesn't
        # exercise role-assignment shape.
    )
    db.add(appliance)
    await db.flush()
    return appliance


async def _seed_dns_server(db: AsyncSession, group: DNSServerGroup, hostname: str) -> DNSServer:
    server = DNSServer(
        group_id=group.id,
        name=hostname,
        driver="bind9",
        host=hostname,
        port=53,
        roles=["authoritative"],
        status="active",
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    return server


async def _seed_dhcp_server(db: AsyncSession, hostname: str) -> DHCPServer:
    server = DHCPServer(
        name=hostname,
        driver="kea",
        host=hostname,
        port=67,
        status="active",
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    return server


@pytest.fixture
async def dns_group(db_session: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(
        name=f"test-group-{uuid.uuid4().hex[:8]}",
        description="",
    )
    db_session.add(group)
    await db_session.flush()
    return group


@pytest.mark.asyncio
async def test_dependents_endpoint_matches_by_hostname(
    client: AsyncClient,
    db_session: AsyncSession,
    dns_group: DNSServerGroup,
) -> None:
    """The preview endpoint surfaces both DNS + DHCP rows whose
    ``hostname`` matches the appliance — the legacy match path that
    works for every pre-#197 row."""
    _, token = await _make_superadmin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    appliance = await _seed_appliance(db_session, hostname="ddi-prev-1")
    dns_server = await _seed_dns_server(db_session, dns_group, "ddi-prev-1")
    dhcp_server = await _seed_dhcp_server(db_session, "ddi-prev-1")
    # An unrelated DNS server on a different hostname must NOT appear.
    other_dns = await _seed_dns_server(db_session, dns_group, "ddi-other-9")
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/appliance/appliances/{appliance.id}/dependents",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    dns_ids = {d["id"] for d in body["dns"]}
    dhcp_ids = {d["id"] for d in body["dhcp"]}
    assert str(dns_server.id) in dns_ids
    assert str(other_dns.id) not in dns_ids
    assert str(dhcp_server.id) in dhcp_ids


@pytest.mark.asyncio
async def test_soft_delete_sweeps_dependent_servers(
    client: AsyncClient,
    db_session: AsyncSession,
    dns_group: DNSServerGroup,
) -> None:
    """Operator clicks Revoke → the dns_server + dhcp_server rows
    that share the appliance's hostname are dropped in the same
    transaction. Audit log records the cascaded names."""
    password = "test-pw-cascade"
    _, token = await _make_superadmin(db_session, password=password)
    headers = {"Authorization": f"Bearer {token}"}

    appliance = await _seed_appliance(db_session, hostname="ddi-cascade-1")
    dns_server = await _seed_dns_server(db_session, dns_group, "ddi-cascade-1")
    dhcp_server = await _seed_dhcp_server(db_session, "ddi-cascade-1")
    untouched_dns = await _seed_dns_server(db_session, dns_group, "ddi-keep-2")
    await db_session.commit()

    resp = await client.request(
        "DELETE",
        f"/api/v1/appliance/appliances/{appliance.id}",
        headers=headers,
        json={"password": password},
    )
    assert resp.status_code == 200, resp.text

    # Dependents gone.
    surviving_dns = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == dns_server.id))
    ).scalar_one_or_none()
    assert surviving_dns is None
    surviving_dhcp = (
        await db_session.execute(select(DHCPServer).where(DHCPServer.id == dhcp_server.id))
    ).scalar_one_or_none()
    assert surviving_dhcp is None
    # Untouched row stays.
    keep = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == untouched_dns.id))
    ).scalar_one_or_none()
    assert keep is not None

    # Audit captures the cascaded names.
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "appliance.soft_deleted",
                AuditLog.resource_id == str(appliance.id),
            )
        )
    ).scalar_one()
    new_value = audit.new_value or {}
    assert "ddi-cascade-1" in (new_value.get("cascaded_dns_servers") or [])
    assert "ddi-cascade-1" in (new_value.get("cascaded_dhcp_servers") or [])


@pytest.mark.asyncio
async def test_soft_delete_with_no_dependents_is_clean(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Appliance with no DNS / DHCP rows registered — soft-delete
    succeeds and the audit row records empty lists, not nulls or
    missing keys."""
    password = "test-pw-lone"
    _, token = await _make_superadmin(db_session, password=password)
    headers = {"Authorization": f"Bearer {token}"}

    appliance = await _seed_appliance(db_session, hostname="ddi-lone-1")
    await db_session.commit()

    resp = await client.request(
        "DELETE",
        f"/api/v1/appliance/appliances/{appliance.id}",
        headers=headers,
        json={"password": password},
    )
    assert resp.status_code == 200, resp.text

    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "appliance.soft_deleted",
                AuditLog.resource_id == str(appliance.id),
            )
        )
    ).scalar_one()
    nv = audit.new_value or {}
    assert nv.get("cascaded_dns_servers") == []
    assert nv.get("cascaded_dhcp_servers") == []
