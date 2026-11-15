"""Operation-applied creates audit under the types the event map keys on (#3936).

The request portal's approve and the copilot's apply run the registered
operations. Their audit rows must carry the bare resource types the REST
creates use, or ``event_publisher`` skips them (no ``dns.record.created`` /
``dhcp.static.created`` / ``ip.created``) and the compliance change alert,
which reads ``ip_address``, never sees the new address.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.services import event_publisher
from app.services.ai import operations
from tests.test_portal_dhcp_static_ipam_mirror_2901 import MAC, _estate
from tests.test_portal_submit_apply_parity_3243 import _zone
from tests.test_self_service_requests import _user


async def _created_types(db: AsyncSession) -> set[str]:
    rows = await db.scalars(select(AuditLog).where(AuditLog.action == "create"))
    return {r.resource_type for r in rows}


def _event(resource_type: str) -> str | None:
    ns = event_publisher._RESOURCE_NAMESPACE.get(resource_type)
    return f"{ns}.created" if ns else None


async def test_dns_record_apply_audits_publishable_type(db_session: AsyncSession) -> None:
    zone = await _zone(db_session)
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_dns_record")
    args = op.args_model(zone_id=str(zone.id), name="h", record_type="A", value="10.0.0.5")
    await op.apply(db_session, admin, args)
    types = await _created_types(db_session)
    assert "dns_record" in types
    assert _event("dns_record") == "dns.record.created"


async def test_dhcp_static_apply_audits_publishable_type(db_session: AsyncSession) -> None:
    scope, _subnet, _block = await _estate(db_session)
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_dhcp_static")
    args = op.args_model(scope_id=str(scope.id), ip_address="10.60.0.50", mac_address=MAC)
    await op.apply(db_session, admin, args)
    assert "dhcp_static_assignment" in await _created_types(db_session)


async def test_hostless_address_apply_audits_publishable_type(db_session: AsyncSession) -> None:
    _scope, subnet, _block = await _estate(db_session)
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_ip_address")
    args = op.args_model(subnet_id=str(subnet.id), address="10.60.0.77")
    await op.apply(db_session, admin, args)
    types = await _created_types(db_session)
    assert "ip_address" in types
    assert "ipam.ip_address" not in types


async def _events(db: AsyncSession, resource_id_type: str) -> list[str | None]:
    rows = await db.scalars(select(AuditLog).where(AuditLog.resource_type == resource_id_type))
    return [event_publisher._audit_to_event_type(r.action, r.resource_type) for r in rows]


async def test_hostless_address_apply_fires_ip_created(db_session: AsyncSession) -> None:
    _scope, subnet, _block = await _estate(db_session)
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_ip_address")
    args = op.args_model(subnet_id=str(subnet.id), address="10.60.0.78")
    await op.apply(db_session, admin, args)
    assert "ip.created" in await _events(db_session, "ip_address")


async def test_hostless_static_dhcp_address_apply_fires_ip_created(
    db_session: AsyncSession,
) -> None:
    _scope, subnet, _block = await _estate(db_session)
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_ip_address")
    args = op.args_model(
        subnet_id=str(subnet.id), address="10.60.0.79", status="static_dhcp", mac_address=MAC
    )
    await op.apply(db_session, admin, args)
    assert "ip.created" in await _events(db_session, "ip_address")


async def test_hostless_takeover_of_available_row_fires_created_like_rest(
    db_session: AsyncSession,
) -> None:
    """The reclaim audits ``ip.updated`` (as the REST create does) and the
    create audit now adds the ``ip.created`` that was missing."""
    from app.models.ipam import IPAddress

    _scope, subnet, _block = await _estate(db_session)
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    db_session.add(IPAddress(subnet_id=subnet.id, address="10.60.0.80", status="available"))
    await db_session.flush()
    op = operations.get_operation("create_ip_address")
    args = op.args_model(subnet_id=str(subnet.id), address="10.60.0.80")
    await op.apply(db_session, admin, args)
    events = await _events(db_session, "ip_address")
    assert "ip.created" in events
    assert "ip.updated" in events
