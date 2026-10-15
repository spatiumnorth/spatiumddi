"""#1932 — a zone SpatiumDDI auto-creates in an agentless group must reach the
provider, and before the record ops that need it.

The reverse-zone auto-create (IPAM auto-sync / DDNS / subnet create) wrote the
zone row only, so every PTR op failed at the provider with "No such zone was
found" and retried. The fake driver is registered through the real registry
(``register_driver``) and refuses a record in a zone it was never asked to
create, as Technitium does.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import _DRIVERS, register_driver
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns.record_ops import apply_pending_agentless_ops
from app.services.dns.reverse_zone import ensure_reverse_zones_for_subnet

FWD = "z1932.example."
REV = "7.55.10.in-addr.arpa."


class _FakeTechnitium:
    log: list[tuple[str, str]] = []
    zones: set[str] = set()
    fail_zone_create = False

    async def apply_zone_change(self, _server: Any, zone: Any, op: str) -> bool:
        cls = type(self)
        cls.log.append((f"zone-{op}", zone.name))
        if cls.fail_zone_create:
            raise RuntimeError("503 provider unavailable")
        if zone.name in cls.zones:
            return False
        cls.zones.add(zone.name)
        return True

    async def apply_record_change(self, _server: Any, change: Any) -> None:
        cls = type(self)
        cls.log.append((f"record-{change.op}", f"{change.record.record_type}:{change.zone_name}"))
        if change.zone_name not in cls.zones:
            raise RuntimeError("No such zone was found.")


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> type[_FakeTechnitium]:
    _FakeTechnitium.log = []
    _FakeTechnitium.zones = {FWD}
    _FakeTechnitium.fail_zone_create = False
    monkeypatch.setitem(_DRIVERS, "technitium_api", _DRIVERS["technitium_api"])
    register_driver("technitium_api", _FakeTechnitium)  # type: ignore[arg-type]
    return _FakeTechnitium


async def _setup(db: AsyncSession, *, agentless: bool) -> tuple[Subnet, DNSServerGroup]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="technitium_api" if agentless else "technitium",
            host="10.0.0.1",
            name="ns1",
            is_primary=True,
            is_enabled=True,
            credentials_encrypted=b"x" if agentless else None,
            agent_id=None if agentless else uuid.uuid4(),
        )
    )
    fwd = DNSZone(
        group_id=grp.id,
        name=FWD,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(fwd)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.55.7.0/24",
        name="s",
        dns_zone_id=str(fwd.id),
        dns_group_ids=[str(grp.id)],
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    return subnet, grp


async def _autosync(db: AsyncSession, subnet: Subnet) -> None:
    from app.api.v1.ipam.router import _sync_dns_record

    await ensure_reverse_zones_for_subnet(db, subnet, None)
    ip = IPAddress(subnet_id=subnet.id, address="10.55.7.5", status="allocated", hostname="h1")
    db.add(ip)
    await db.flush()
    await _sync_dns_record(db, ip, subnet, action="create")
    await db.commit()


async def test_reverse_zone_is_created_at_the_provider_before_its_ptr(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    subnet, _grp = await _setup(db_session, agentless=True)
    await _autosync(db_session, subnet)

    assert REV in provider.zones
    assert provider.log.count(("zone-create", REV)) == 1
    ptr = ("record-create", f"PTR:{REV}")
    assert ptr in provider.log
    assert provider.log.index(("zone-create", REV)) < provider.log.index(ptr)
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert ops and all(o.state == "applied" for o in ops), [(o.zone_name, o.state) for o in ops]


async def test_failed_zone_create_is_recovered_by_the_retry_without_double_create(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    subnet, _grp = await _setup(db_session, agentless=True)
    provider.fail_zone_create = True
    await _autosync(db_session, subnet)
    assert REV not in provider.zones
    ptr_ops = [
        o
        for o in (await db_session.execute(select(DNSRecordOp))).scalars().all()
        if o.zone_name == REV
    ]
    assert ptr_ops and all(o.state == "pending" and o.attempts == 1 for o in ptr_ops)

    provider.fail_zone_create = False
    await apply_pending_agentless_ops(db_session, now=datetime.now(UTC) + timedelta(hours=1))
    assert REV in provider.zones
    await db_session.refresh(ptr_ops[0])
    assert ptr_ops[0].state == "applied"

    # A further sweep has nothing left to retry: no second create.
    creates = provider.log.count(("zone-create", REV))
    await apply_pending_agentless_ops(db_session, now=datetime.now(UTC) + timedelta(hours=2))
    assert provider.log.count(("zone-create", REV)) == creates


async def test_agent_managed_group_is_untouched(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    subnet, _grp = await _setup(db_session, agentless=False)
    await _autosync(db_session, subnet)
    assert [e for e in provider.log if e[0].startswith("zone-")] == []
    zones = (await db_session.execute(select(DNSZone).where(DNSZone.name == REV))).scalars().all()
    assert len(zones) == 1
