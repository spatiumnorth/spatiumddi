"""IP discovery — sweep helpers + reconcile + report (issue #23)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.discovery import (
    MAX_SWEEP_HOSTS,
    SweepResult,
    build_reconciliation_report,
    enumerate_hosts,
    read_arp_table,
    reconcile_subnet,
)

# ── Pure-logic helpers ──────────────────────────────────────────────


def test_enumerate_hosts_v4_excludes_network_broadcast() -> None:
    hosts = enumerate_hosts("192.0.2.0/24")
    assert hosts is not None
    assert "192.0.2.0" not in hosts  # network
    assert "192.0.2.255" not in hosts  # broadcast
    assert "192.0.2.1" in hosts and "192.0.2.254" in hosts
    assert len(hosts) == 254


def test_enumerate_hosts_too_big_returns_none() -> None:
    # /8 has 16M addresses — far over MAX_SWEEP_HOSTS.
    assert enumerate_hosts("10.0.0.0/8") is None


def test_enumerate_hosts_ipv6_returns_none() -> None:
    assert enumerate_hosts("2001:db8::/64") is None


def test_enumerate_hosts_cap_boundary() -> None:
    # /20 = 4096 addresses == MAX_SWEEP_HOSTS → allowed; /19 → over.
    assert enumerate_hosts("10.0.0.0/20") is not None
    assert MAX_SWEEP_HOSTS == 4096
    assert enumerate_hosts("10.0.0.0/19") is None


def test_read_arp_table_parses_complete_entries(tmp_path) -> None:
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.0.2.10       0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n"
        "192.0.2.11       0x1         0x0         00:00:00:00:00:00     *        eth0\n"  # incomplete
        "192.0.2.12       0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0\n"
    )
    table = read_arp_table(str(arp))
    assert table == {
        "192.0.2.10": "aa:bb:cc:dd:ee:01",
        "192.0.2.12": "aa:bb:cc:dd:ee:02",
    }


def test_read_arp_table_missing_file_is_empty() -> None:
    assert read_arp_table("/nonexistent/path/arp") == {}


def test_sweep_result_alive_union_and_method() -> None:
    sr = SweepResult(ping_alive={"10.0.0.1"}, arp={"10.0.0.2": "aa:bb:cc:dd:ee:ff"})
    assert sr.alive == {"10.0.0.1", "10.0.0.2"}
    assert sr.method_for("10.0.0.1") == "ping"
    assert sr.method_for("10.0.0.2") == "arp"


# ── DB-backed reconcile / report ────────────────────────────────────


async def _make_subnet(db: AsyncSession, cidr: str = "192.0.2.0/24") -> Subnet:
    space = IPSpace(name=f"disco-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=cidr, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=cidr, name="s")
    db.add(subnet)
    await db.flush()
    return subnet


async def test_reconcile_updates_existing_and_creates_discovered(
    db_session: AsyncSession,
) -> None:
    subnet = await _make_subnet(db_session)
    existing = IPAddress(subnet_id=subnet.id, address="192.0.2.10", status="allocated")
    db_session.add(existing)
    await db_session.flush()

    sweep = SweepResult(
        ping_alive={"192.0.2.10", "192.0.2.20"},
        arp={"192.0.2.10": "aa:bb:cc:dd:ee:10"},
    )
    counts = await reconcile_subnet(db_session, subnet, sweep)
    await db_session.flush()

    assert counts["updated"] == 1
    assert counts["created"] == 1
    assert counts["arp_enriched"] == 1

    await db_session.refresh(existing)
    assert existing.last_seen_at is not None
    assert existing.last_seen_method == "ping"
    assert existing.mac_address == "aa:bb:cc:dd:ee:10"  # filled from ARP
    assert existing.status == "allocated"  # lifecycle untouched

    rows = (await db_session.execute(_addr_q(subnet.id, "192.0.2.20"))).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "discovered"
    assert rows[0].last_seen_method == "ping"


async def test_reconcile_skips_network_and_broadcast(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    sweep = SweepResult(ping_alive={"192.0.2.0", "192.0.2.255", "192.0.2.5"})
    counts = await reconcile_subnet(db_session, subnet, sweep)
    await db_session.flush()
    # Only .5 becomes a discovered row; network + broadcast skipped.
    assert counts["created"] == 1
    rows = (await db_session.execute(_addr_q(subnet.id, "192.0.2.0"))).scalars().all()
    assert rows == []


async def test_reconcile_skips_dynamic_pool(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id)
    db_session.add(scope)
    await db_session.flush()
    db_session.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="192.0.2.100",
            end_ip="192.0.2.200",
            pool_type="dynamic",
        )
    )
    await db_session.flush()

    sweep = SweepResult(ping_alive={"192.0.2.150", "192.0.2.50"})
    counts = await reconcile_subnet(db_session, subnet, sweep)
    await db_session.flush()

    # .150 is inside the dynamic pool → skipped; .50 → discovered.
    assert counts["skipped_pool"] == 1
    assert counts["created"] == 1
    pool_rows = (await db_session.execute(_addr_q(subnet.id, "192.0.2.150"))).scalars().all()
    assert pool_rows == []


async def test_reconcile_creates_discovered_on_slash31(db_session: AsyncSession) -> None:
    # RFC 3021 /31: both addresses are usable hosts, so neither is a
    # skip-able network/broadcast placeholder — both get discovered rows.
    subnet = await _make_subnet(db_session, cidr="192.0.2.0/31")
    sweep = SweepResult(ping_alive={"192.0.2.0", "192.0.2.1"})
    counts = await reconcile_subnet(db_session, subnet, sweep)
    await db_session.flush()
    assert counts["created"] == 2


async def test_reconcile_preserves_operator_locked_row(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    locked = IPAddress(
        subnet_id=subnet.id,
        address="192.0.2.30",
        status="reserved",
        user_modified_at=datetime.now(UTC),
    )
    db_session.add(locked)
    await db_session.flush()

    sweep = SweepResult(ping_alive={"192.0.2.30"})
    await reconcile_subnet(db_session, subnet, sweep)
    await db_session.flush()
    await db_session.refresh(locked)
    # Discovery only refreshes last_seen; the operator's status stays.
    assert locked.status == "reserved"
    assert locked.last_seen_at is not None


async def test_reconciliation_report_buckets(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    now = datetime.now(UTC)
    stale = now - timedelta(days=10)
    db_session.add_all(
        [
            # allocated, never seen → in_ipam_not_seen
            IPAddress(subnet_id=subnet.id, address="192.0.2.10", status="allocated"),
            # allocated, last seen long ago → in_ipam_not_seen
            IPAddress(
                subnet_id=subnet.id, address="192.0.2.11", status="allocated", last_seen_at=stale
            ),
            # discovered → discovered_not_allocated
            IPAddress(
                subnet_id=subnet.id, address="192.0.2.20", status="discovered", last_seen_at=now
            ),
            # available but active → status_mismatch
            IPAddress(
                subnet_id=subnet.id, address="192.0.2.30", status="available", last_seen_at=now
            ),
            # allocated + recently seen → in NONE of the buckets
            IPAddress(
                subnet_id=subnet.id, address="192.0.2.40", status="allocated", last_seen_at=now
            ),
        ]
    )
    await db_session.flush()

    report = await build_reconciliation_report(db_session, subnet, stale_minutes=1440)
    assert report["counts"]["in_ipam_not_seen"] == 2
    assert report["counts"]["discovered_not_allocated"] == 1
    assert report["counts"]["status_mismatch"] == 1
    addrs = {e["address"] for e in report["in_ipam_not_seen"]}
    assert addrs == {"192.0.2.10", "192.0.2.11"}


def _addr_q(subnet_id, address):  # noqa: ANN001 — tiny test helper
    from sqlalchemy import select

    return select(IPAddress).where(IPAddress.subnet_id == subnet_id, IPAddress.address == address)


@pytest.mark.parametrize("cidr", ["192.0.2.0/31", "192.0.2.0/32"])
def test_enumerate_hosts_tiny_subnets(cidr: str) -> None:
    # /31 + /32 have no "host" addresses in the classic sense; the
    # sweep just no-ops (empty list, not None).
    hosts = enumerate_hosts(cidr)
    assert hosts is not None


async def test_reconcile_recounts_subnet_and_block_on_insert(db_session: AsyncSession) -> None:
    """#3320: a ``discovered`` insert counts toward utilization, so the
    subnet's and its block's cached figures follow it in the same pass
    rather than at the hourly recount."""
    subnet = await _make_subnet(db_session, "198.51.100.0/28")
    subnet.total_ips = 14
    await db_session.flush()
    assert subnet.allocated_ips == 0

    sweep = SweepResult(ping_alive={"198.51.100.5", "198.51.100.6"}, arp={})
    counts = await reconcile_subnet(db_session, subnet, sweep)
    assert counts["created"] == 2

    await db_session.refresh(subnet)
    assert subnet.allocated_ips == 2
    assert subnet.utilization_percent == pytest.approx(14.29)
    block = await db_session.get(IPBlock, subnet.block_id)
    await db_session.refresh(block)
    # A block counts its subnets' network + broadcast too (#2982).
    assert block.allocated_ips == 4
