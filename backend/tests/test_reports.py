"""Top-N reports API (issue #47).

Covers the operator contract per endpoint:

* ranked + capped at 10 + ordered descending
* top-subnets ordering by utilization
* top-owners IP→subnet→customer join math + the "Unowned" bucket
* most-modified honours the 7-day window
* noisiest-dns-clients group-by
* empty tables → [] (not an error)

Plus the gates: lacking the read permission → 403 per endpoint, and
``require_module`` off → /reports 404s.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.logs import DNSQueryLogEntry
from app.models.ownership import Customer
from app.services.feature_modules import invalidate_cache, set_module_enabled

REPORTS = "/api/v1/reports"


@pytest.fixture(autouse=True)
def _reset_module_cache() -> None:
    invalidate_cache()
    yield
    invalidate_cache()


# ── Fixtures / builders ──────────────────────────────────────────────


async def _admin(db: AsyncSession) -> tuple[User, dict]:
    u = User(
        username=f"adm-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _user_with_perms(
    db: AsyncSession, perms: list[dict[str, Any]], *, name: str
) -> tuple[User, dict]:
    role = Role(name=f"{name}-{uuid.uuid4().hex[:6]}", description="", permissions=perms)
    group = Group(name=f"{name}-grp-{uuid.uuid4().hex[:6]}", description="")
    user = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name=name,
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    group.roles = [role]
    group.users = [user]
    db.add_all([role, group, user])
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _space(db: AsyncSession) -> IPSpace:
    s = IPSpace(name=f"space-{uuid.uuid4().hex[:8]}")
    db.add(s)
    await db.flush()
    return s


async def _block(db: AsyncSession, space: IPSpace, network: str) -> IPBlock:
    b = IPBlock(space_id=space.id, network=network, name="blk")
    db.add(b)
    await db.flush()
    return b


async def _subnet(
    db: AsyncSession,
    space: IPSpace,
    block: IPBlock,
    network: str,
    *,
    name: str = "",
    util: float = 0.0,
    allocated: int = 0,
    total: int = 256,
    customer_id: uuid.UUID | None = None,
) -> Subnet:
    sn = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=network,
        name=name,
        utilization_percent=util,
        allocated_ips=allocated,
        total_ips=total,
        customer_id=customer_id,
    )
    db.add(sn)
    await db.flush()
    return sn


async def _customer(db: AsyncSession, name: str) -> Customer:
    c = Customer(name=f"{name}-{uuid.uuid4().hex[:6]}")
    db.add(c)
    await db.flush()
    return c


async def _ip(db: AsyncSession, subnet: Subnet, addr: str) -> IPAddress:
    ip = IPAddress(subnet_id=subnet.id, address=addr, status="allocated")
    db.add(ip)
    await db.flush()
    return ip


# ── top-subnets-by-utilization ───────────────────────────────────────


@pytest.mark.asyncio
async def test_top_subnets_orders_by_utilization(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _admin(db_session)
    sp = await _space(db_session)
    blk = await _block(db_session, sp, "10.0.0.0/8")
    await _subnet(db_session, sp, blk, "10.0.1.0/24", name="low", util=10.0, allocated=5)
    await _subnet(db_session, sp, blk, "10.0.2.0/24", name="high", util=90.0, allocated=230)
    await _subnet(db_session, sp, blk, "10.0.3.0/24", name="mid", util=50.0, allocated=128)
    await db_session.commit()

    r = await client.get(f"{REPORTS}/top-subnets-by-utilization", headers=h)
    assert r.status_code == 200, r.text
    rows = r.json()["rows"]
    utils = [row["utilization_percent"] for row in rows]
    assert utils == sorted(utils, reverse=True)
    assert rows[0]["name"] == "high"
    assert rows[0]["allocated_ips"] == 230
    assert r.json()["generated_at"]


@pytest.mark.asyncio
async def test_top_subnets_capped_at_ten(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _admin(db_session)
    sp = await _space(db_session)
    blk = await _block(db_session, sp, "172.16.0.0/12")
    for i in range(15):
        await _subnet(
            db_session, sp, blk, f"172.16.{i}.0/24", name=f"s{i}", util=float(i), allocated=i
        )
    await db_session.commit()

    r = await client.get(f"{REPORTS}/top-subnets-by-utilization", headers=h)
    assert r.status_code == 200
    assert len(r.json()["rows"]) == 10
    # The 10 returned should be the highest-util ones.
    assert r.json()["rows"][0]["utilization_percent"] == 14.0


@pytest.mark.asyncio
async def test_top_subnets_empty(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _admin(db_session)
    r = await client.get(f"{REPORTS}/top-subnets-by-utilization", headers=h)
    assert r.status_code == 200
    assert r.json()["rows"] == []


# ── top-owners-by-ip-count ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_top_owners_join_math_and_unowned_bucket(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _admin(db_session)
    sp = await _space(db_session)
    blk = await _block(db_session, sp, "10.0.0.0/8")
    cust_a = await _customer(db_session, "Acme")
    cust_b = await _customer(db_session, "Globex")

    sn_a = await _subnet(db_session, sp, blk, "10.1.0.0/24", customer_id=cust_a.id)
    sn_b = await _subnet(db_session, sp, blk, "10.2.0.0/24", customer_id=cust_b.id)
    sn_none = await _subnet(db_session, sp, blk, "10.3.0.0/24", customer_id=None)

    # Acme: 3 IPs, Globex: 1 IP, Unowned: 2 IPs.
    for i in range(3):
        await _ip(db_session, sn_a, f"10.1.0.{i + 1}")
    await _ip(db_session, sn_b, "10.2.0.1")
    for i in range(2):
        await _ip(db_session, sn_none, f"10.3.0.{i + 1}")
    await db_session.commit()

    r = await client.get(f"{REPORTS}/top-owners-by-ip-count", headers=h)
    assert r.status_code == 200, r.text
    rows = r.json()["rows"]
    by_name = {row["customer_name"]: row for row in rows}
    assert by_name[cust_a.name]["ip_count"] == 3
    assert by_name[cust_b.name]["ip_count"] == 1
    assert "Unowned" in by_name
    assert by_name["Unowned"]["ip_count"] == 2
    assert by_name["Unowned"]["customer_id"] is None
    # Ordered descending — Acme (3) first.
    counts = [row["ip_count"] for row in rows]
    assert counts == sorted(counts, reverse=True)
    assert rows[0]["customer_name"] == cust_a.name


@pytest.mark.asyncio
async def test_top_owners_empty(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _admin(db_session)
    r = await client.get(f"{REPORTS}/top-owners-by-ip-count", headers=h)
    assert r.status_code == 200
    assert r.json()["rows"] == []


# ── top-modified-resources ───────────────────────────────────────────


def _audit(
    resource_type: str,
    resource_id: str,
    *,
    action: str,
    ts: datetime,
    display: str | None = None,
) -> AuditLog:
    return AuditLog(
        user_display_name="tester",
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_display=display if display is not None else f"{resource_type}:{resource_id}",
        result="success",
        timestamp=ts,
    )


@pytest.mark.asyncio
async def test_top_modified_honours_window_and_orders(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _admin(db_session)
    now = datetime.now(UTC)
    recent = now - timedelta(days=1)
    stale = now - timedelta(days=30)

    # subnet:A modified 3x recently, subnet:B once recently.
    db_session.add_all(
        [
            _audit("subnet", "A", action="update", ts=recent),
            _audit("subnet", "A", action="update", ts=recent),
            _audit("subnet", "A", action="update", ts=recent),
            _audit("subnet", "B", action="create", ts=recent),
            # Stale row for C — outside the 7d window, must not count.
            _audit("subnet", "C", action="update", ts=stale),
            _audit("subnet", "C", action="update", ts=stale),
        ]
    )
    await db_session.commit()

    r = await client.get(f"{REPORTS}/top-modified-resources", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["window_days"] == 7
    rows = body["rows"]
    by_id = {row["resource_id"]: row for row in rows}
    assert by_id["A"]["change_count"] == 3
    assert by_id["B"]["change_count"] == 1
    assert "C" not in by_id  # stale rows excluded
    # Ordered descending — A first.
    counts = [row["change_count"] for row in rows]
    assert counts == sorted(counts, reverse=True)
    assert rows[0]["resource_id"] == "A"


@pytest.mark.asyncio
async def test_top_modified_capped_at_ten(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _admin(db_session)
    now = datetime.now(UTC)
    rows = []
    for i in range(15):
        rows.append(_audit("subnet", f"r{i}", action="update", ts=now - timedelta(hours=1)))
    db_session.add_all(rows)
    await db_session.commit()

    r = await client.get(f"{REPORTS}/top-modified-resources", headers=h)
    assert r.status_code == 200
    assert len(r.json()["rows"]) == 10


@pytest.mark.asyncio
async def test_top_modified_empty(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _admin(db_session)
    r = await client.get(f"{REPORTS}/top-modified-resources", headers=h)
    assert r.status_code == 200
    assert r.json()["rows"] == []


@pytest.mark.asyncio
async def test_top_modified_uses_latest_display_after_rename(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """resource_display must reflect the MOST-RECENT audit row's display,
    not the lexicographically-largest. A resource renamed mid-window from
    a 'larger' string to a 'smaller' one would mislead under func.max()
    (FIX 3)."""
    _, h = await _admin(db_session)
    now = datetime.now(UTC)

    # Resource renamed "zzz-old-name" → "aaa-new-name" within the window.
    # The new name sorts BEFORE the old one lexicographically, so
    # func.max() would wrongly return "zzz-old-name". The latest-row
    # logic must return "aaa-new-name".
    db_session.add_all(
        [
            _audit(
                "subnet",
                "R",
                action="update",
                ts=now - timedelta(days=2),
                display="zzz-old-name",
            ),
            _audit(
                "subnet",
                "R",
                action="update",
                ts=now - timedelta(hours=1),
                display="aaa-new-name",
            ),
        ]
    )
    await db_session.commit()

    r = await client.get(f"{REPORTS}/top-modified-resources", headers=h)
    assert r.status_code == 200, r.text
    rows = r.json()["rows"]
    by_id = {row["resource_id"]: row for row in rows}
    assert by_id["R"]["change_count"] == 2
    assert by_id["R"]["resource_display"] == "aaa-new-name"


# ── top-dns-clients ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_top_dns_clients_group_by_and_order(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _admin(db_session)
    # Need a dns_server FK target for the log rows.
    from app.models.dns import DNSServer, DNSServerGroup

    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", group_type="internal")
    db_session.add(grp)
    await db_session.flush()
    srv = DNSServer(group_id=grp.id, name="srv", driver="bind9", host="10.0.0.1")
    db_session.add(srv)
    await db_session.flush()

    now = datetime.now(UTC)

    def _q(client_ip: str) -> DNSQueryLogEntry:
        return DNSQueryLogEntry(
            server_id=srv.id, ts=now, client_ip=client_ip, qname="x.example.com", qtype="A", raw=""
        )

    # 192.0.2.10 → 4 queries, 192.0.2.20 → 1 query.
    db_session.add_all([_q("192.0.2.10") for _ in range(4)] + [_q("192.0.2.20")])
    await db_session.commit()

    r = await client.get(f"{REPORTS}/top-dns-clients", headers=h)
    assert r.status_code == 200, r.text
    rows = r.json()["rows"]
    by_ip = {row["client_ip"]: row["query_count"] for row in rows}
    assert by_ip["192.0.2.10"] == 4
    assert by_ip["192.0.2.20"] == 1
    counts = [row["query_count"] for row in rows]
    assert counts == sorted(counts, reverse=True)
    assert rows[0]["client_ip"] == "192.0.2.10"


@pytest.mark.asyncio
async def test_top_dns_clients_empty(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _admin(db_session)
    r = await client.get(f"{REPORTS}/top-dns-clients", headers=h)
    assert r.status_code == 200
    assert r.json()["rows"] == []


@pytest.mark.asyncio
async def test_top_dns_clients_excludes_rows_older_than_24h(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The query is bounded to the trailing 24 h retention window, so a
    log row older than that must NOT be counted even while it lingers in
    the table between nightly prune sweeps (FIX 2)."""
    _, h = await _admin(db_session)
    from app.models.dns import DNSServer, DNSServerGroup

    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", group_type="internal")
    db_session.add(grp)
    await db_session.flush()
    srv = DNSServer(group_id=grp.id, name="srv", driver="bind9", host="10.0.0.1")
    db_session.add(srv)
    await db_session.flush()

    now = datetime.now(UTC)
    recent = now - timedelta(hours=1)
    stale = now - timedelta(hours=30)  # past the 24h window

    def _q(client_ip: str, ts: datetime) -> DNSQueryLogEntry:
        return DNSQueryLogEntry(
            server_id=srv.id, ts=ts, client_ip=client_ip, qname="x.example.com", qtype="A", raw=""
        )

    db_session.add_all(
        [
            _q("192.0.2.10", recent),
            _q("192.0.2.10", recent),
            # Stale row for a different client — must be excluded.
            _q("192.0.2.99", stale),
            _q("192.0.2.99", stale),
            _q("192.0.2.99", stale),
        ]
    )
    await db_session.commit()

    r = await client.get(f"{REPORTS}/top-dns-clients", headers=h)
    assert r.status_code == 200, r.text
    by_ip = {row["client_ip"]: row["query_count"] for row in r.json()["rows"]}
    assert by_ip.get("192.0.2.10") == 2
    assert "192.0.2.99" not in by_ip  # stale rows beyond 24h excluded


# ── Permission gates ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_top_subnets_requires_subnet_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # Has dns_group read but NOT subnet read → 403.
    _, h = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "dns_group"}], name="nosub"
    )
    r = await client.get(f"{REPORTS}/top-subnets-by-utilization", headers=h)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_top_owners_requires_customer_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # The payload IS the customer roster, so it gates on read:customer —
    # NOT read:ip_address. A user with ip_address read but no customer
    # read must be denied (info-disclosure gap; FIX 1).
    _, h = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "ip_address"}], name="noip"
    )
    r = await client.get(f"{REPORTS}/top-owners-by-ip-count", headers=h)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_top_owners_allows_customer_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "customer"}], name="custok"
    )
    r = await client.get(f"{REPORTS}/top-owners-by-ip-count", headers=h)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_find_top_owners_tool_refuses_without_customer_read(
    db_session: AsyncSession,
) -> None:
    """The MCP tool reuses compute_top_owners (no built-in customer
    check), so it must gate on read:customer itself — a caller with
    only read:ip_address gets an error dict, and a caller with
    read:customer gets the rows (FIX 1)."""
    from app.services.ai.tools.reports import (
        FindTopOwnersArgs,
        find_top_owners_by_ip_count,
    )

    user_noperm, _ = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "ip_address"}], name="tool-noip"
    )
    out = await find_top_owners_by_ip_count(db_session, user_noperm, FindTopOwnersArgs())
    assert isinstance(out, dict)
    assert "error" in out

    user_ok, _ = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "customer"}], name="tool-custok"
    )
    out_ok = await find_top_owners_by_ip_count(db_session, user_ok, FindTopOwnersArgs())
    assert isinstance(out_ok, list)


@pytest.mark.asyncio
async def test_top_modified_requires_audit_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "subnet"}], name="noaudit"
    )
    r = await client.get(f"{REPORTS}/top-modified-resources", headers=h)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_top_dns_clients_requires_server_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The report reads the query log of every server, so it needs the same
    ``read:server`` as ``/logs/dns-queries`` — a ``read:dns_group`` grant (one
    group's zones) is not enough (#3130)."""
    _, h_deny = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "subnet"}], name="nodns"
    )
    r = await client.get(f"{REPORTS}/top-dns-clients", headers=h_deny)
    assert r.status_code == 403

    _, h_grp = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "dns_group"}], name="grponly"
    )
    r = await client.get(f"{REPORTS}/top-dns-clients", headers=h_grp)
    assert r.status_code == 403

    _, h_srv = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "server"}], name="srvok"
    )
    r = await client.get(f"{REPORTS}/top-dns-clients", headers=h_srv)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_find_top_dns_clients_tool_needs_server_read(db_session: AsyncSession) -> None:
    from app.services.ai.tools import REGISTRY
    from app.services.ai.tools.base import tool_permission_allows

    perm = REGISTRY.get("find_top_dns_clients").permission
    grp, _ = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "dns_group"}], name="tool-grp"
    )
    srv, _ = await _user_with_perms(
        db_session, [{"action": "read", "resource_type": "server"}], name="tool-srv"
    )
    assert tool_permission_allows(grp, perm) is False
    assert tool_permission_allows(srv, perm) is True


# ── Feature-module gate ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_module_gate_404(client: AsyncClient, db_session: AsyncSession) -> None:
    u, h = await _admin(db_session)
    await set_module_enabled(db_session, "reports.top_n", False, user_id=u.id)
    await db_session.commit()
    invalidate_cache()
    try:
        r = await client.get(f"{REPORTS}/top-subnets-by-utilization", headers=h)
        assert r.status_code == 404
    finally:
        invalidate_cache()
