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
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.drivers.dns import _DRIVERS, register_driver
from app.models.auth import User
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns import record_ops
from app.services.dns.record_ops import (
    AGENTLESS_INLINE_ZONE_CREATES,
    apply_pending_agentless_ops,
    enqueue_record_op,
)
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
    for name in ("technitium_api", "route53"):
        monkeypatch.setitem(_DRIVERS, name, _DRIVERS[name])
        register_driver(name, _FakeTechnitium)  # type: ignore[arg-type]
    return _FakeTechnitium


async def _setup(
    db: AsyncSession,
    *,
    agentless: bool,
    network: str = "10.55.7.0/24",
    driver: str | None = None,
    opt_in: bool = False,
) -> tuple[Subnet, DNSServerGroup]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", auto_reverse_zones_at_provider=opt_in)
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver=driver or ("technitium_api" if agentless else "technitium"),
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
        network=network,
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
    # Held back with the zone's error, never sent into a zone that is not there.
    assert ("record-create", f"PTR:{REV}") not in provider.log
    assert all("could not be created at the provider" in (o.last_error or "") for o in ptr_ops)
    zone = (await db_session.execute(select(DNSZone).where(DNSZone.name == REV))).scalar_one()
    assert zone.agentless_create_due_at is not None

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


async def _zone(db: AsyncSession, name: str) -> DNSZone:
    zone = (await db.execute(select(DNSZone).where(DNSZone.name == name))).scalar_one()
    await db.refresh(zone)
    return zone


async def test_a_zone_that_reached_the_provider_is_never_recreated(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    """The heal is for a create that never succeeded. A zone that reached the
    provider once and was then deleted there (deliberately, as far as we know)
    is left deleted: its ops fail, as Sync with Servers would report."""
    subnet, _grp = await _setup(db_session, agentless=True)
    await _autosync(db_session, subnet)
    assert (await _zone(db_session, REV)).agentless_create_due_at is None

    provider.zones.discard(REV)  # the operator deletes it at the provider
    creates = provider.log.count(("zone-create", REV))
    ip = IPAddress(subnet_id=subnet.id, address="10.55.7.6", status="allocated", hostname="h2")
    db_session.add(ip)
    await db_session.flush()
    from app.api.v1.ipam.router import _sync_dns_record

    await _sync_dns_record(db_session, ip, subnet, action="create")
    await db_session.commit()
    for hours in (1, 2, 3):
        await apply_pending_agentless_ops(
            db_session, now=datetime.now(UTC) + timedelta(hours=hours)
        )
    assert provider.log.count(("zone-create", REV)) == creates
    assert REV not in provider.zones


async def test_the_sweep_creates_the_zone_before_a_ptr_it_claims_first(
    db_session: AsyncSession, provider: type[_FakeTechnitium], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The process dies between the commit and its dispatch, and the sweep
    claims the PTR op while the zone's own retry is not yet due: the op path
    still creates the zone first."""

    async def _died(_bind: Any, _units: Any) -> None:
        return None

    monkeypatch.setattr(record_ops, "_dispatch_agentless_units", _died)
    subnet, _grp = await _setup(db_session, agentless=True)
    await _autosync(db_session, subnet)
    assert provider.log == []
    zone = await _zone(db_session, REV)
    zone.agentless_create_due_at = datetime.now(UTC) + timedelta(days=1)
    await db_session.commit()

    await apply_pending_agentless_ops(db_session, now=datetime.now(UTC) + timedelta(hours=1))
    ptr = ("record-create", f"PTR:{REV}")
    assert provider.log.index(("zone-create", REV)) < provider.log.index(ptr)
    assert (await _zone(db_session, REV)).agentless_create_due_at is None
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    for o in ops:
        await db_session.refresh(o)
    assert ops and all(o.state == "applied" for o in ops)


async def test_inline_zone_creates_are_bounded_and_the_sweep_finishes(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    """A /19 auto-creates 32 reverse zones: the request's own commit makes at
    most AGENTLESS_INLINE_ZONE_CREATES provider calls, the sweep the rest."""
    subnet, _grp = await _setup(db_session, agentless=True, network="10.55.32.0/19")
    zones = await ensure_reverse_zones_for_subnet(db_session, subnet, None)
    assert len(zones) == 32
    await db_session.commit()
    assert len([e for e in provider.log if e[0] == "zone-create"]) == AGENTLESS_INLINE_ZONE_CREATES

    await apply_pending_agentless_ops(db_session, now=datetime.now(UTC) + timedelta(hours=1))
    assert {z.name for z in zones} <= provider.zones
    assert len([e for e in provider.log if e[0] == "zone-create"]) == 32


async def test_record_ops_in_a_zone_from_the_endpoints_never_create_it(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    """A zone not created by the auto path carries no marker: a failing op in
    it is retried as before and never turns into a zone create."""
    await _setup(db_session, agentless=True)
    fwd = (await db_session.execute(select(DNSZone).where(DNSZone.name == FWD))).scalar_one()
    provider.zones.discard(FWD)
    await enqueue_record_op(
        db_session, fwd, "create", {"name": "x", "type": "A", "value": "10.1.1.1", "ttl": 300}
    )
    await db_session.commit()
    await apply_pending_agentless_ops(db_session, now=datetime.now(UTC) + timedelta(hours=1))
    assert [e for e in provider.log if e[0] == "zone-create"] == []


async def test_copilot_zone_create_pushes_once_before_the_commit(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    """The Copilot create pushes the way the REST create does (#798): once,
    synchronously, and a provider refusal fails the apply."""
    from app.services.ai.operations import CreateDNSZoneArgs, get_operation

    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    _subnet, grp = await _setup(db_session, agentless=True)
    op = get_operation("create_dns_zone")
    assert op is not None
    await op.apply(db_session, user, CreateDNSZoneArgs(name="cp.example.com", group_id=str(grp.id)))
    assert provider.log == [("zone-create", "cp.example.com.")]
    zone = await _zone(db_session, "cp.example.com.")
    assert zone.agentless_create_due_at is None

    provider.fail_zone_create = True
    with pytest.raises(HTTPException) as exc:
        await op.apply(
            db_session, user, CreateDNSZoneArgs(name="cp2.example.com", group_id=str(grp.id))
        )
    assert exc.value.status_code == 502


# ── Cloud groups: reverse zones are opt-in (cost) ────────────────────────────


async def test_cloud_group_not_opted_in_gets_no_reverse_zone_and_says_why(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    """A cloud provider bills per hosted zone: without the group's opt-in the
    reverse zone is not created at all, so no PTR is queued against a zone the
    provider will never have, and the IPAM DNS sync report says why. The
    forward record is unaffected."""
    from app.services.dns.sync_check import compute_subnet_dns_drift

    subnet, grp = await _setup(db_session, agentless=True, driver="route53")
    await _autosync(db_session, subnet)

    assert [e for e in provider.log if e[0] == "zone-create"] == []
    assert ("record-create", f"A:{FWD}") in provider.log
    assert not any(e[1].startswith("PTR:") for e in provider.log)
    zones = (await db_session.execute(select(DNSZone).where(DNSZone.name == REV))).scalars().all()
    assert zones == []
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert ops and all(o.zone_name == FWD for o in ops)

    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert report.reverse_zone_skipped_reason is not None
    assert "route53" in report.reverse_zone_skipped_reason
    assert grp.name in report.reverse_zone_skipped_reason


async def test_cloud_group_opted_in_behaves_like_technitium_api(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    from app.services.dns.sync_check import compute_subnet_dns_drift

    subnet, _grp = await _setup(db_session, agentless=True, driver="route53", opt_in=True)
    await _autosync(db_session, subnet)

    ptr = ("record-create", f"PTR:{REV}")
    assert provider.log.index(("zone-create", REV)) < provider.log.index(ptr)
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert ops and all(o.state == "applied" for o in ops)
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert report.reverse_zone_skipped_reason is None


async def test_technitium_api_ignores_the_cloud_opt_in(
    db_session: AsyncSession, provider: type[_FakeTechnitium]
) -> None:
    """The setting is for cloud drivers only: an opted-out technitium_api group
    still gets its reverse zone."""
    subnet, grp = await _setup(db_session, agentless=True)
    assert grp.auto_reverse_zones_at_provider is False
    await _autosync(db_session, subnet)
    assert REV in provider.zones


async def test_upgrade_backfill_marks_only_non_cloud_agentless_groups(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The migration's backfill marks the reverse zones the bug left behind in
    technitium_api / Windows groups, and never a cloud group's: cloud groups
    start opted out, so the upgrade creates nothing at a cloud provider."""
    import importlib.util
    from pathlib import Path

    from alembic import op as alembic_op

    path = next(Path(__file__).parents[1].glob("alembic/versions/c4f19a2e7d53_*.py"))
    spec = importlib.util.spec_from_file_location("mig_1932", path)
    assert spec is not None and spec.loader is not None
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)
    statements: list[Any] = []
    monkeypatch.setattr(alembic_op, "add_column", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(alembic_op, "execute", statements.append, raising=False)
    mig.upgrade()
    assert len(statements) == 1

    zones: dict[str, DNSZone] = {}
    for driver in ("technitium_api", "windows_dns", "route53", "technitium"):
        grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
        db_session.add(grp)
        await db_session.flush()
        agentless = driver != "technitium"
        db_session.add(
            DNSServer(
                group_id=grp.id,
                driver=driver,
                host="10.0.0.1",
                name=f"s-{driver}",
                is_primary=True,
                credentials_encrypted=b"x" if agentless else None,
                agent_id=None if agentless else uuid.uuid4(),
            )
        )
        zone = DNSZone(
            group_id=grp.id,
            name=f"{len(zones) + 1}.10.in-addr.arpa.",
            kind="reverse",
            is_auto_generated=True,
        )
        db_session.add(zone)
        zones[driver] = zone
    await db_session.flush()
    await db_session.execute(statements[0])
    for zone in zones.values():
        await db_session.refresh(zone)
    marked = {d for d, z in zones.items() if z.agentless_create_due_at is not None}
    assert marked == {"technitium_api", "windows_dns"}
