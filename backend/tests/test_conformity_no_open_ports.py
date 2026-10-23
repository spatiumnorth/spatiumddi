"""Conformity check ``no_open_ports`` against real nmap output (#2257).

The check used to read ``summary_json["open_ports"]``, a key
``parse_nmap_xml`` has never written, so every host with a recent scan
PASSED — including one with 22 and 3389 open. Every test here builds the
stored summary by running nmap-shaped XML through the real parser, so
the producer and the consumer cannot drift apart again without a test
failing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.nmap import NmapScan
from app.services.conformity.checks import (
    CHECK_REGISTRY,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_WARN,
    CheckOutcome,
)
from app.services.nmap.runner import parse_nmap_xml

TARGET = "10.0.0.5"
# The seeded PCI 1.4.4 policy's argument shape.
ARGS: dict[str, Any] = {"ports": [22, 23, 3389], "max_age_days": 30}


def _port(port: int, state: str, proto: str = "tcp") -> str:
    return (
        f'<port protocol="{proto}" portid="{port}">'
        f'<state state="{state}" reason="syn-ack"/>'
        f'<service name="svc{port}"/></port>'
    )


def _host(address: str, ports: list[str], state: str = "up") -> str:
    family = "ipv6" if ":" in address else "ipv4"
    return (
        f'<host><status state="{state}" reason="echo-reply"/>'
        f'<address addr="{address}" addrtype="{family}"/>'
        f"<ports>{''.join(ports)}</ports></host>"
    )


# What ``--top-ports 1000`` reports probing, abridged: 22, 23 and 3389
# are all inside it.
SCANNED = "1-1024,3389"


def _xml(*hosts: str, scanned: str | None = SCANNED) -> str:
    info = (
        f'<scaninfo type="syn" protocol="tcp" numservices="1" services="{scanned}"/>'
        if scanned is not None
        else ""
    )
    return f'<?xml version="1.0"?><nmaprun scanner="nmap">{info}{"".join(hosts)}</nmaprun>'


async def _target_ip(db: AsyncSession, address: str = TARGET) -> IPAddress:
    v6 = ":" in address
    space = IPSpace(name=f"nop-{uuid.uuid4().hex[:8]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, name="b", network="2001:db8::/32" if v6 else "10.0.0.0/16")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        name="s",
        network="2001:db8::/64" if v6 else "10.0.0.0/24",
    )
    db.add(subnet)
    await db.flush()
    ip = IPAddress(subnet_id=subnet.id, address=address, status="allocated")
    db.add(ip)
    await db.flush()
    return ip


async def _scan(
    db: AsyncSession,
    ip: IPAddress,
    summary: dict | None,
    *,
    target: str = TARGET,
    preset: str = "quick",
) -> NmapScan:
    now = datetime.now(UTC)
    scan = NmapScan(
        target_ip=target,
        ip_address_id=ip.id,
        preset=preset,
        status="completed",
        started_at=now - timedelta(minutes=2),
        finished_at=now - timedelta(minutes=1),
        summary_json=summary,
    )
    db.add(scan)
    await db.flush()
    return scan


async def _run(db: AsyncSession, ip: IPAddress) -> CheckOutcome:
    return await CHECK_REGISTRY["no_open_ports"](
        db, target=ip, target_kind="ip_address", args=ARGS, now=datetime.now(UTC)
    )


async def test_single_host_with_admin_ports_open_fails(db_session: AsyncSession) -> None:
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(
        _xml(_host(TARGET, [_port(22, "open"), _port(443, "open"), _port(3389, "open")]))
    )
    await _scan(db_session, ip, summary)
    out = await _run(db_session, ip)
    assert out.status == STATUS_FAIL, out.detail
    assert out.diagnostic["open_ports"] == [22, 443, 3389]
    assert "[22, 3389]" in out.detail


async def test_single_host_with_only_allowed_ports_open_passes(
    db_session: AsyncSession,
) -> None:
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(
        _xml(_host(TARGET, [_port(22, "closed"), _port(443, "open"), _port(3389, "filtered")]))
    )
    await _scan(db_session, ip, summary)
    out = await _run(db_session, ip)
    assert out.status == STATUS_PASS, out.detail
    assert out.diagnostic["open_ports"] == [443]


async def test_cidr_scan_reads_the_targets_own_entry(db_session: AsyncSession) -> None:
    ip = await _target_ip(db_session)
    # The target is NOT the first host: the top-level single-host fields
    # describe 10.0.0.1, which is clean.
    summary = parse_nmap_xml(
        _xml(
            _host("10.0.0.1", [_port(443, "open")]),
            _host(TARGET, [_port(3389, "open")]),
        )
    )
    await _scan(db_session, ip, summary, target="10.0.0.0/24")
    out = await _run(db_session, ip)
    assert out.status == STATUS_FAIL, out.detail
    assert out.diagnostic["open_ports"] == [3389]


async def test_cidr_scan_does_not_borrow_another_hosts_ports(
    db_session: AsyncSession,
) -> None:
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(
        _xml(
            _host("10.0.0.1", [_port(22, "open")]),
            _host(TARGET, [_port(443, "open")]),
        )
    )
    await _scan(db_session, ip, summary, target="10.0.0.0/24")
    out = await _run(db_session, ip)
    assert out.status == STATUS_PASS, out.detail
    assert out.diagnostic["open_ports"] == [443]


async def test_cidr_scan_without_the_target_warns(db_session: AsyncSession) -> None:
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host("10.0.0.1", [_port(443, "open")]), _host("10.0.0.2", [])))
    await _scan(db_session, ip, summary, target="10.0.0.0/24")
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail


async def test_cidr_scan_where_one_other_host_answered_warns(
    db_session: AsyncSession,
) -> None:
    # One responding host yields a single-host summary (hosts=None) —
    # for 10.0.0.9, not the target. Its open 22 must not be read as the
    # target's, and neither must its "up".
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host("10.0.0.9", [_port(22, "open")])))
    assert summary["hosts"] is None
    await _scan(db_session, ip, summary, target="10.0.0.0/24")
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail


async def test_host_down_warns(db_session: AsyncSession) -> None:
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host(TARGET, [], state="down")))
    await _scan(db_session, ip, summary)
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail
    assert out.diagnostic["host_state"] == "down"


async def test_unparseable_xml_warns(db_session: AsyncSession) -> None:
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml("<nmaprun><host><status state=")
    await _scan(db_session, ip, summary)
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail


async def test_missing_summary_warns(db_session: AsyncSession) -> None:
    # The runner stores summary_json=None when parsing raised.
    ip = await _target_ip(db_session)
    await _scan(db_session, ip, None)
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail


async def test_open_filtered_forbidden_port_warns(db_session: AsyncSession) -> None:
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host(TARGET, [_port(23, "open|filtered", "udp")])))
    await _scan(db_session, ip, summary)
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail


async def test_legacy_summary_without_address_still_read_for_a_direct_scan(
    db_session: AsyncSession,
) -> None:
    # Rows stored before the parser wrote a top-level ``address``.
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host(TARGET, [_port(22, "open")])))
    summary.pop("address")
    await _scan(db_session, ip, summary)
    out = await _run(db_session, ip)
    assert out.status == STATUS_FAIL, out.detail


async def test_no_recent_scan_warns(db_session: AsyncSession) -> None:
    ip = await _target_ip(db_session)
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail


async def test_ping_sweep_that_probed_no_ports_warns(db_session: AsyncSession) -> None:
    # ``-sn`` emits no <scaninfo>: the host is up and the port list is
    # empty because nothing was probed, not because nothing is open.
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host(TARGET, []), scanned=None))
    assert summary["scanned_ports"] == {}
    await _scan(db_session, ip, summary, preset="subnet_sweep")
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail
    assert out.diagnostic["unprobed_ports"] == [22, 23, 3389]


async def test_port_list_that_leaves_a_forbidden_port_out_warns(
    db_session: AsyncSession,
) -> None:
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host(TARGET, [_port(443, "open")]), scanned="22-23,80,443"))
    await _scan(db_session, ip, summary, preset="custom")
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail
    assert out.diagnostic["unprobed_ports"] == [3389]


async def test_legacy_ping_sweep_summary_warns(db_session: AsyncSession) -> None:
    # Rows stored before ``scanned_ports`` existed: only the preset says
    # nothing was probed.
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host(TARGET, []), scanned=None))
    summary.pop("scanned_ports")
    await _scan(db_session, ip, summary, preset="subnet_sweep")
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail


async def test_ipv6_target_matches_nmaps_address(db_session: AsyncSession) -> None:
    target = "2001:db8::5"
    ip = await _target_ip(db_session, target)
    # nmap may print a non-canonical spelling; comparison is by value.
    summary = parse_nmap_xml(_xml(_host("2001:0db8:0:0::5", [_port(22, "open")])))
    await _scan(db_session, ip, summary, target=target)
    out = await _run(db_session, ip)
    assert out.status == STATUS_FAIL, out.detail


async def test_hostname_target_is_matched_by_the_resolved_address(
    db_session: AsyncSession,
) -> None:
    # nmap resolves a hostname target and reports the address it scanned.
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host(TARGET, [_port(3389, "open")])))
    await _scan(db_session, ip, summary, target="pos-01.example.internal")
    out = await _run(db_session, ip)
    assert out.status == STATUS_FAIL, out.detail


async def test_legacy_summary_for_a_hostname_target_warns(db_session: AsyncSession) -> None:
    # No recorded address and a target that is not an IP: nothing ties
    # the summary to this address.
    ip = await _target_ip(db_session)
    summary = parse_nmap_xml(_xml(_host(TARGET, [_port(22, "open")])))
    summary.pop("address")
    await _scan(db_session, ip, summary, target="pos-01.example.internal")
    out = await _run(db_session, ip)
    assert out.status == STATUS_WARN, out.detail
