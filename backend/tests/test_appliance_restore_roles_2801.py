"""A control-plane node that re-registers after losing its Fleet row gets its
roles back (#2801).

Since #2786 a lone control-plane node whose row goes away re-registers by
itself through the self-bootstrap. The roles lived on the row, so it came back
approved with ``assigned_roles: []`` and its DNS and DHCP stayed down until an
operator assigned them again. The supervisor now sends the roles it last
received (read back from its role env) as ``restore_roles``; the register
endpoint restores them, on a self-bootstrap registration only, and audits it.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_mod
from app.models.appliance import Appliance, PairingCode
from app.models.audit import AuditLog
from app.models.dhcp import DHCPServerGroup
from app.models.dns import DNSServerGroup
from app.models.feature_module import FeatureModule
from app.models.settings import PlatformSettings


@pytest.fixture(autouse=True)
def _no_friction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)


def _pubkey_b64() -> str:
    der = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    )
    return base64.b64encode(der).decode("ascii")


async def _setup(db: AsyncSession, code: str, *, auto_approve: bool) -> None:
    settings = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if settings is None:
        db.add(PlatformSettings(id=1, supervisor_registration_enabled=True))
    else:
        settings.supervisor_registration_enabled = True
    db.add(
        PairingCode(
            id=uuid.uuid4(),
            code_hash=hashlib.sha256(code.encode("ascii")).hexdigest(),
            code_last_two=code[-2:],
            persistent=False,
            enabled=True,
            auto_approve=auto_approve,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
    )
    await db.flush()


async def _groups(db: AsyncSession) -> tuple[DNSServerGroup, DHCPServerGroup]:
    dns = DNSServerGroup(name="dns-main")
    dhcp = DHCPServerGroup(name="dhcp-main")
    db.add_all([dns, dhcp])
    await db.flush()
    return dns, dhcp


async def _register(
    client: AsyncClient,
    code: str,
    *,
    variant: str = "control-plane",
    restore: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "pairing_code": code,
        "hostname": "cp1",
        "public_key_der_b64": _pubkey_b64(),
        "appliance_variant": variant,
    }
    if restore is not None:
        body["restore_roles"] = restore
    resp = await client.post("/api/v1/appliance/supervisor/register", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _row(db: AsyncSession, appliance_id: str) -> Appliance:
    db.expire_all()
    row = await db.get(Appliance, uuid.UUID(appliance_id))
    assert row is not None
    return row


async def _audits(db: AsyncSession, action: str) -> list[AuditLog]:
    return list(
        (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
    )


@pytest.mark.asyncio
async def test_self_bootstrap_reregister_restores_the_roles_it_was_serving(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    dns, dhcp = await _groups(db_session)
    dns_id, dhcp_id = dns.id, dhcp.id
    await _setup(db_session, "11223344", auto_approve=True)
    await db_session.commit()

    body = await _register(
        client,
        "11223344",
        restore={
            "roles": ["dns-bind9", "dhcp"],
            "dns_group_name": "dns-main",
            "dhcp_group_name": "dhcp-main",
            "last_apply_state": "ready",
        },
    )

    row = await _row(db_session, body["appliance_id"])
    assert row.state == "approved"
    assert row.assigned_roles == ["dns-bind9", "dhcp"], (
        "the re-registered control-plane node came back with no roles, so its "
        "DNS and DHCP stay down until an operator assigns them again"
    )
    assert row.assigned_dns_group_id == dns_id
    assert row.assigned_dhcp_group_id == dhcp_id

    restored = await _audits(db_session, "appliance.roles_restored")
    assert len(restored) == 1
    nv = restored[0].new_value
    assert nv["roles"] == ["dns-bind9", "dhcp"]
    assert nv["source"] == "supervisor_last_assigned"
    assert nv["last_apply_state"] == "ready"
    assert restored[0].resource_id == body["appliance_id"]


@pytest.mark.asyncio
async def test_the_heartbeat_ships_the_restored_assignment(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """What the supervisor renders its role env from: the restored roles and
    group names, so the service containers come back with the env they had."""
    await _groups(db_session)
    await _setup(db_session, "11223355", auto_approve=True)
    await db_session.commit()
    body = await _register(
        client,
        "11223355",
        restore={
            "roles": ["dns-bind9", "dhcp"],
            "dns_group_name": "dns-main",
            "dhcp_group_name": "dhcp-main",
        },
    )
    row = await _row(db_session, body["appliance_id"])
    assignment = await supervisor_mod._build_role_assignment(db_session, row)
    assert assignment.roles == ["dns-bind9", "dhcp"]
    assert assignment.dns_group_name == "dns-main"
    assert assignment.dns_engine == "bind9"
    assert assignment.dhcp_group_name == "dhcp-main"


@pytest.mark.asyncio
async def test_a_fresh_never_assigned_node_still_gets_no_roles(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _setup(db_session, "11223366", auto_approve=True)
    await db_session.commit()

    body = await _register(client, "11223366")

    row = await _row(db_session, body["appliance_id"])
    assert row.assigned_roles == []
    assert await _audits(db_session, "appliance.roles_restored") == []


@pytest.mark.asyncio
async def test_an_operator_typed_code_never_restores_roles(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A registration the operator has to approve gets its roles from the
    operator, not from what the node says it ran."""
    await _groups(db_session)
    await _setup(db_session, "11223377", auto_approve=False)
    await db_session.commit()

    body = await _register(
        client,
        "11223377",
        variant="appliance",
        restore={"roles": ["dns-bind9"], "dns_group_name": "dns-main"},
    )

    row = await _row(db_session, body["appliance_id"])
    assert row.state == "pending_approval"
    assert row.assigned_roles == []
    assert row.assigned_dns_group_id is None
    assert await _audits(db_session, "appliance.roles_restored") == []
    pending = await _audits(db_session, "appliance.registration_pending")
    assert pending[0].new_value["roles_not_restored"]["roles"] == ["dns-bind9"]


@pytest.mark.asyncio
async def test_restore_applies_the_checks_a_new_role_gets(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Unknown roles, a second DNS engine and a role whose module is off are
    dropped and named; a group that no longer exists is left unassigned."""
    db_session.add(FeatureModule(id="core.dhcp", enabled=False))
    await _setup(db_session, "11223388", auto_approve=True)
    await db_session.commit()

    body = await _register(
        client,
        "11223388",
        restore={
            "roles": ["dns-bind9", "dns-powerdns", "dhcp", "looking-glass", "observer"],
            "dhcp_group_name": "gone",
        },
    )

    row = await _row(db_session, body["appliance_id"])
    assert row.assigned_roles == ["looking-glass"]
    assert row.assigned_dhcp_group_id is None
    nv = (await _audits(db_session, "appliance.roles_restored"))[0].new_value
    assert set(nv["dropped_roles"]) == {"dns-bind9", "dns-powerdns", "dhcp", "observer"}
    assert "disabled" in nv["dropped_roles"]["dhcp"]


@pytest.mark.asyncio
async def test_a_dns_group_that_went_away_leaves_the_role_without_a_group(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _setup(db_session, "11223399", auto_approve=True)
    await db_session.commit()

    body = await _register(
        client,
        "11223399",
        restore={"roles": ["dns-bind9"], "dns_group_name": "renamed-since"},
    )

    row = await _row(db_session, body["appliance_id"])
    assert row.assigned_roles == ["dns-bind9"]
    assert row.assigned_dns_group_id is None
    nv = (await _audits(db_session, "appliance.roles_restored"))[0].new_value
    assert "renamed-since" in nv["groups_not_restored"]["dns"]
