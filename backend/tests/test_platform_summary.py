"""``GET /api/v1/summary`` — the one-call snapshot (#2143).

Three things matter and each has its own tests: the **role matrix** (a section
the caller may not read is withheld with a reason, never leaked and never a 403
for the whole call), the **numbers** (they come from the same counters the
console reads), and the **cost** (a constant number of queries however large
the estate).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import event, select, update
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.ai.tools  # noqa: F401 — registers the tools
from app.core.security import create_access_token, generate_api_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import APIToken, Group, Role, User
from app.models.dhcp import (
    DHCPLease,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
)
from app.models.dns import DNSBlockList, DNSServer, DNSServerGroup, dns_blocklist_group_assoc
from app.models.feature_module import FeatureModule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.metrics import DNSMetricSample
from app.services import platform_summary
from app.services.ai.tools.base import REGISTRY


@pytest.fixture(autouse=True)
def _stub_health(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real verdict pings Redis and Celery; it has its own tests."""

    async def _ok() -> str:
        return "ok"

    monkeypatch.setattr(platform_summary, "_health_verdict", _ok)


# ── helpers ─────────────────────────────────────────────────────────────────


async def _user(
    db: AsyncSession, *, role: str | None = None, superadmin: bool = False
) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"sum-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="summary",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
        is_active=True,
    )
    u.groups = []
    if role is not None:
        description, perms = _BUILTIN_ROLES[role]
        r = Role(name=f"{role}-{uuid.uuid4().hex[:6]}", description=description, permissions=perms)
        g = Group(name=f"g-{uuid.uuid4().hex[:6]}")
        g.roles = [r]
        u.groups = [g]
        db.add_all([r, g])
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _token(
    db: AsyncSession,
    owner: User,
    *,
    scopes: list[str] | None = None,
    grants: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=scopes or [],
            resource_grants=grants,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.commit()
    return {"Authorization": f"Bearer {raw}"}


async def _seed_estate(db: AsyncSession, *, groups: int = 1, tag: str = "") -> None:
    """``groups`` DNS + DHCP groups, each with servers, traffic, a pool, a lease."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    db.add(
        Subnet(
            space_id=space.id,
            block_id=block.id,
            network="10.9.0.0/24" if not tag else "10.9.2.0/24",
            name=f"tracked{tag}",
            total_ips=254,
            allocated_ips=127,
            utilization_percent=50.0,
            tags={"ha": "track"},
        )
    )
    db.add(
        Subnet(
            space_id=space.id,
            block_id=block.id,
            network="10.9.1.0/24" if not tag else "10.9.3.0/24",
            name=f"untracked{tag}",
            total_ips=254,
        )
    )
    now = datetime.now(UTC)
    for i in range(groups):
        dg = DNSServerGroup(name=f"dns-{i}-{uuid.uuid4().hex[:4]}")
        hg = DHCPServerGroup(name=f"dhcp-{i}-{uuid.uuid4().hex[:4]}")
        db.add_all([dg, hg])
        await db.flush()
        bl = DNSBlockList(name=f"bl-{i}-{uuid.uuid4().hex[:4]}", enabled=bool(i % 2))
        db.add(bl)
        await db.flush()
        await db.execute(
            dns_blocklist_group_assoc.insert().values(blocklist_id=bl.id, group_id=dg.id)
        )
        up = DNSServer(
            group_id=dg.id, name=f"ns{i}a{tag}", host="10.1.0.1", status="active", is_enabled=True
        )
        down = DNSServer(
            group_id=dg.id,
            name=f"ns{i}b{tag}",
            host="10.1.0.2",
            status="unreachable",
            is_enabled=True,
            config_apply_status="reverted",
        )
        kea = DHCPServer(
            name=f"kea{i}{tag}",
            host="10.2.0.1",
            driver="kea",
            server_group_id=hg.id,
            status="active",
        )
        db.add_all([up, down, kea])
        await db.flush()
        db.add(
            DNSMetricSample(
                server_id=up.id,
                bucket_at=now - timedelta(minutes=1),
                queries_total=300,
                noerror=270,
                nxdomain=20,
                servfail=10,
                recursion=0,
            )
        )
        scope = DHCPScope(group_id=hg.id, subnet_id=(await _subnet_id(db, tag)), name=f"sc{i}{tag}")
        db.add(scope)
        await db.flush()
        db.add(
            DHCPPool(
                scope_id=scope.id,
                name=f"pool{i}{tag}",
                start_ip=f"10.9.0.{10 + i * 20}",
                end_ip=f"10.9.0.{19 + i * 20}",
                pool_type="dynamic",
            )
        )
        db.add(
            DHCPLease(
                server_id=kea.id,
                scope_id=scope.id,
                ip_address=f"10.9.0.{10 + i * 20}",
                mac_address=f"aa:bb:cc:00:00:{i:02x}",
                state="active",
            )
        )
    rule = AlertRule(name="r", rule_type="subnet_utilization", severity="critical")
    db.add(rule)
    await db.flush()
    for sev in ("critical", "warning", "warning"):
        db.add(
            AlertEvent(
                rule_id=rule.id,
                subject_type="subnet",
                subject_id=uuid.uuid4().hex,
                subject_display="x",
                severity=sev,
                message="m",
                fired_at=now,
            )
        )
    await db.commit()


async def _subnet_id(db: AsyncSession, tag: str = "") -> uuid.UUID:
    return (await db.execute(select(Subnet.id).where(Subnet.name == f"tracked{tag}"))).scalar_one()


async def _get(client: AsyncClient, headers: dict[str, str] | None = None) -> Any:
    platform_summary.invalidate_cache()
    return await client.get("/api/v1/summary", headers=headers or {})


SECTIONS = ("ipam", "new_devices", "dns", "dhcp", "alerts")


def _present(body: dict[str, Any]) -> set[str]:
    return {k for k in SECTIONS if body[k] is not None}


# ── role matrix ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unauthenticated_is_401(client: AsyncClient) -> None:
    r = await _get(client)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_superadmin_sees_everything(client: AsyncClient, db_session: AsyncSession) -> None:
    await _seed_estate(db_session)
    _, h = await _user(db_session, superadmin=True)
    r = await _get(client, h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert _present(body) == set(SECTIONS)
    assert body["withheld"] == {}
    assert body["platform"]["health"] == "ok"
    assert body["ipam"]["spaces"] == 1 and body["ipam"]["subnets"] == 2
    assert [s["name"] for s in body["ipam"]["tracked_subnets"]] == ["tracked"]
    assert body["ipam"]["tracked_subnets"][0]["utilization_percent"] == 50.0
    dns = body["dns"]
    assert dns["blocklists"] is not None and dns["rpz_blocked_24h"] == 0
    g = dns["groups"][0]
    assert (g["servers_total"], g["servers_online"], g["servers_config_failing"]) == (2, 1, 1)
    assert g["queries_total"] == 300
    assert g["nxdomain_rate"] == pytest.approx(20 / 300, abs=1e-4)
    assert g["servfail_rate"] == pytest.approx(10 / 300, abs=1e-4)
    dhcp = body["dhcp"]
    assert dhcp["groups"][0]["active_leases"] == 1
    assert dhcp["fullest_pools"][0]["occupancy_percent"] == 10.0
    assert body["alerts"]["open_total"] == 3
    assert body["alerts"]["open_by_severity"] == {"critical": 1, "warning": 2}
    assert len(body["alerts"]["newest"]) == 3


@pytest.mark.asyncio
async def test_viewer_sees_every_section(client: AsyncClient, db_session: AsyncSession) -> None:
    await _seed_estate(db_session)
    _, h = await _user(db_session, role="Viewer")
    body = (await _get(client, h)).json()
    assert _present(body) == set(SECTIONS)
    assert body["withheld"] == {}


@pytest.mark.asyncio
async def test_ipam_editor_gets_ipam_and_alerts_and_nothing_of_dns_or_dhcp(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed_estate(db_session)
    _, h = await _user(db_session, role="IPAM Editor")
    r = await _get(client, h)
    assert r.status_code == 200
    body = r.json()
    assert _present(body) == {"ipam", "new_devices", "alerts"}
    assert body["dns"] is None and body["dhcp"] is None
    assert body["withheld"] == {"dns": "permission", "dhcp": "permission"}
    # No DNS / DHCP figure may appear anywhere in the response.
    text = r.text
    assert "queries_total" not in text and "active_leases" not in text


@pytest.mark.asyncio
async def test_dns_editor_gets_dns_only_and_not_the_rpz_figure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed_estate(db_session)
    _, h = await _user(db_session, role="DNS Editor")
    body = (await _get(client, h)).json()
    assert _present(body) == {"dns", "alerts"}
    assert body["dns"]["blocklists"] is not None  # DNS Editor holds dns_blocklist
    assert body["dns"]["rpz_blocked_24h"] is None  # needs read on "server"
    assert body["withheld"]["dns.rpz"] == "permission"
    assert body["withheld"]["ipam"] == "permission"
    assert body["withheld"]["dhcp"] == "permission"
    assert body["withheld"]["new_devices"] == "permission"


@pytest.mark.asyncio
async def test_dhcp_editor_gets_dhcp_only(client: AsyncClient, db_session: AsyncSession) -> None:
    await _seed_estate(db_session)
    _, h = await _user(db_session, role="DHCP Editor")
    body = (await _get(client, h)).json()
    assert _present(body) == {"dhcp", "alerts"}
    assert body["dhcp"]["fullest_pools"] is not None
    assert body["dns"] is None and body["ipam"] is None
    assert body["withheld"]["dns"] == "permission"


@pytest.mark.asyncio
async def test_dhcp_without_pool_read_hides_the_pools_but_not_the_servers(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed_estate(db_session)
    u, h = await _user(db_session, role="DHCP Editor")
    perms = [p for p in _BUILTIN_ROLES["DHCP Editor"][1] if p["resource_type"] != "dhcp_pool"]
    role = u.groups[0].roles[0]
    role.permissions = perms
    await db_session.commit()
    body = (await _get(client, h)).json()
    assert body["dhcp"] is not None and body["dhcp"]["fullest_pools"] is None
    assert body["withheld"]["dhcp.pools"] == "permission"


@pytest.mark.asyncio
async def test_a_grant_scoped_to_one_group_reads_no_estate_wide_dns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A role scoped to one DNS group is not a type-wide grant: the snapshot
    aggregates every group, so the section is withheld, not narrowed."""
    await _seed_estate(db_session, groups=2)
    u, h = await _user(db_session, role="DNS Editor")
    gid = (await db_session.execute(select(DNSServerGroup.id).limit(1))).scalar_one()
    u.groups[0].roles[0].permissions = [
        {"action": "read", "resource_type": "dns_group", "resource_id": str(gid)}
    ]
    await db_session.commit()
    body = (await _get(client, h)).json()
    assert body["dns"] is None and body["withheld"]["dns"] == "permission"


@pytest.mark.asyncio
async def test_trashed_subnets_and_spaces_are_not_counted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The counts agree with the list routes, which hide the Trash."""
    await _seed_estate(db_session)
    _, h = await _user(db_session, superadmin=True)
    before = (await _get(client, h)).json()["ipam"]
    assert (before["spaces"], before["subnets"]) == (1, 2)
    await db_session.execute(
        update(Subnet).where(Subnet.name == "tracked").values(deleted_at=datetime.now(UTC))
    )
    await db_session.commit()
    after = (await _get(client, h)).json()["ipam"]
    assert after["subnets"] == 1 and after["tracked_subnets"] == []
    await db_session.execute(update(IPSpace).values(deleted_at=datetime.now(UTC)))
    await db_session.commit()
    assert (await _get(client, h)).json()["ipam"]["spaces"] == 0


@pytest.mark.asyncio
async def test_user_with_no_grants_gets_only_the_platform_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed_estate(db_session)
    _, h = await _user(db_session)
    r = await _get(client, h)
    assert r.status_code == 200
    body = r.json()
    assert _present(body) == set()
    assert body["platform"]["version"]
    assert set(body["withheld"]) == set(SECTIONS)
    assert set(body["withheld"].values()) == {"permission"}


@pytest.mark.asyncio
async def test_read_scoped_token_works(client: AsyncClient, db_session: AsyncSession) -> None:
    await _seed_estate(db_session)
    owner, _ = await _user(db_session, superadmin=True)
    h = await _token(db_session, owner, scopes=["read"])
    r = await _get(client, h)
    assert r.status_code == 200, r.text
    assert _present(r.json()) == set(SECTIONS)


@pytest.mark.asyncio
async def test_read_scoped_token_cannot_exceed_its_owner(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed_estate(db_session)
    owner, _ = await _user(db_session, role="DNS Editor")
    h = await _token(db_session, owner, scopes=["read"])
    assert _present((await _get(client, h)).json()) == {"dns", "alerts"}


@pytest.mark.asyncio
async def test_resource_scoped_token_type_wide_grant_reads_only_that_type(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed_estate(db_session)
    owner, _ = await _user(db_session, superadmin=True)
    h = await _token(
        db_session,
        owner,
        grants=[{"action": "read", "resource_type": "dns_group", "resource_id": None}],
    )
    r = await _get(client, h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert _present(body) == {"dns"}
    # The token covers dns_group, not the blocklists or the other families.
    assert body["dns"]["blocklists"] is None
    assert body["withheld"]["dns.blocklists"] == "token_scoped"
    for k in ("ipam", "new_devices", "dhcp", "alerts"):
        assert body["withheld"][k] == "token_scoped"


@pytest.mark.asyncio
async def test_instance_bound_token_gets_no_estate_wide_counts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed_estate(db_session)
    owner, _ = await _user(db_session, superadmin=True)
    sid = await _subnet_id(db_session)
    h = await _token(
        db_session,
        owner,
        grants=[{"action": "read", "resource_type": "subnet", "resource_id": str(sid)}],
    )
    r = await _get(client, h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert _present(body) == set()
    assert body["withheld"]["ipam"] == "token_scoped"
    assert "tracked" not in r.text and "10.9.0.0" not in r.text


@pytest.mark.asyncio
async def test_disabled_module_withholds_with_module_reason(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services import feature_modules

    await _seed_estate(db_session)
    _, h = await _user(db_session, superadmin=True)
    db_session.add(FeatureModule(id="core.dhcp", enabled=False))
    await db_session.commit()
    feature_modules.invalidate_cache()
    body = (await _get(client, h)).json()
    assert body["dhcp"] is None
    assert body["withheld"]["dhcp"] == "module_disabled"
    assert body["dns"] is not None


@pytest.mark.asyncio
async def test_module_state_is_not_revealed_to_a_caller_without_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services import feature_modules

    _, h = await _user(db_session, role="IPAM Editor")
    db_session.add(FeatureModule(id="core.dhcp", enabled=False))
    await db_session.commit()
    feature_modules.invalidate_cache()
    assert (await _get(client, h)).json()["withheld"]["dhcp"] == "permission"


@pytest.mark.asyncio
async def test_cache_is_per_access_shape(client: AsyncClient, db_session: AsyncSession) -> None:
    """A superadmin's cached snapshot must never be served to a narrower role."""
    await _seed_estate(db_session)
    _, admin = await _user(db_session, superadmin=True)
    _, ipam = await _user(db_session, role="IPAM Editor")
    platform_summary.invalidate_cache()
    assert (await client.get("/api/v1/summary", headers=admin)).json()["dns"] is not None
    body = (await client.get("/api/v1/summary", headers=ipam)).json()
    assert body["dns"] is None and body["dhcp"] is None


@pytest.mark.asyncio
async def test_real_health_verdict_is_a_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()
    assert await platform_summary._health_verdict() in {"ok", "degraded", "unknown"}


# ── cost ────────────────────────────────────────────────────────────────────


async def _count_queries(db: AsyncSession, user: User) -> int:
    platform_summary.invalidate_cache()
    engine = db.bind.sync_engine  # type: ignore[union-attr]
    n = 0

    def _tick(*_a: Any, **_k: Any) -> None:
        nonlocal n
        n += 1

    event.listen(engine, "before_cursor_execute", _tick)
    try:
        await platform_summary.build_summary(db, user)
    finally:
        event.remove(engine, "before_cursor_execute", _tick)
    return n


@pytest.mark.asyncio
async def test_query_count_is_constant_in_the_size_of_the_estate(db_session: AsyncSession) -> None:
    admin, _ = await _user(db_session, superadmin=True)
    await db_session.refresh(admin, ["groups"])
    await _seed_estate(db_session, groups=1)
    await _count_queries(db_session, admin)  # warm the module + settings caches
    small = await _count_queries(db_session, admin)
    await _seed_estate(db_session, groups=6, tag="x")
    large = await _count_queries(db_session, admin)
    assert small == large, (small, large)
    assert large <= 25, large


# ── MCP ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_tool_is_the_same_snapshot_and_default_enabled(
    db_session: AsyncSession,
) -> None:
    await _seed_estate(db_session)
    admin, _ = await _user(db_session, superadmin=True)
    await db_session.refresh(admin, ["groups"])
    tool = REGISTRY.get("get_platform_summary")
    assert tool is not None and tool.default_enabled and not tool.writes
    platform_summary.invalidate_cache()
    out = await tool.executor(db_session, admin, tool.args_model())
    assert json.loads(json.dumps(out))["alerts"]["open_total"] == 3


@pytest.mark.asyncio
async def test_mcp_tool_withholds_like_the_route(db_session: AsyncSession) -> None:
    await _seed_estate(db_session)
    u, _ = await _user(db_session, role="IPAM Editor")
    await db_session.refresh(u, ["groups"])
    tool = REGISTRY.get("get_platform_summary")
    assert tool is not None
    platform_summary.invalidate_cache()
    out = await tool.executor(db_session, u, tool.args_model())
    assert out["dns"] is None and out["withheld"]["dns"] == "permission"
