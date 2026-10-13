"""#1835 — a factory-reset section removes only what it names.

``Tools`` ran ``TRUNCATE "nmap_scan" … CASCADE``. Postgres empties every
table with a foreign key into a truncated one whatever the key's ``ON
DELETE`` rule, so ``ip_address.last_profile_scan_id`` (``SET NULL``)
pulled in ``ip_address`` and, through it, every DNS record and DHCP
static. The execute answered ``deleted_rows_total: 0``.

Two halves, because neither sees the other's:

* the **guard** walks the SQLAlchemy foreign-key graph and fails when a
  section's ``ON DELETE CASCADE`` reach differs from the
  ``cascade_dependents`` it declares — so a new CASCADE key cannot
  widen a reset unseen;
* the **behaviour** test seeds an estate linked to tools / DNS / DHCP
  rows and runs the real wipe against Postgres, then asserts the estate
  survives.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import uuid
from pathlib import Path

import asyncpg
import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

import app.models as _models_pkg
from app.models.base import Base
from app.services.factory_reset import runner
from app.services.factory_reset.fk_graph import (
    FK_EDGES_SQL,
    blocking_edges,
    cascade_closure,
    delete_order,
    edges_from_metadata,
    edges_from_rows,
    truncatable,
)
from app.services.factory_reset.sections import (
    AUTH_RBAC_CASCADE_DEPENDENTS,
    AUTH_RBAC_TABLES,
    FACTORY_SECTIONS,
    expand_everything,
)

for _m in pkgutil.iter_modules(_models_pkg.__path__):
    importlib.import_module(f"app.models.{_m.name}")

EDGES = edges_from_metadata(Base.metadata)
TRUNCATE_SECTIONS = [s for s in FACTORY_SECTIONS if s.kind == "truncate"]
ESTATE = {"ip_address", "dns_record", "dhcp_static_assignment"}


# ── guard (pure, FK graph from metadata) ────────────────────────────


@pytest.mark.parametrize("section", TRUNCATE_SECTIONS, ids=lambda s: s.key)
def test_section_cascade_reach_is_exactly_what_it_declares(section) -> None:
    reach = cascade_closure(EDGES, section.tables)
    declared = set(section.cascade_dependents)
    assert reach == declared, (
        f"section {section.key!r}: ON DELETE CASCADE reaches {sorted(reach - declared)} "
        f"beyond its tables and not declared; declared but unreachable: "
        f"{sorted(declared - reach)}. Declare it in cascade_dependents (it is named in "
        "the preview) or null the reference instead."
    )


def test_auth_rbac_cascade_reach_is_declared() -> None:
    assert cascade_closure(EDGES, AUTH_RBAC_TABLES) == set(AUTH_RBAC_CASCADE_DEPENDENTS)


@pytest.mark.parametrize("section", TRUNCATE_SECTIONS, ids=lambda s: s.key)
def test_every_section_table_exists(section) -> None:
    missing = [t for t in section.tables if t not in Base.metadata.tables]
    assert not missing


@pytest.mark.parametrize(
    "key",
    [
        "dns",
        "dhcp",
        "migration",
        "network_modeling",
        "ai",
        "compliance",
        "verticals",
        "tools",
        "observability_logs",
    ],
)
def test_estate_tables_are_unreachable_from_non_ipam_sections(key: str) -> None:
    """The core data named in the issue is neither wiped nor cascaded by
    any section other than IPAM / Integrations (which own it)."""
    section = next(s for s in TRUNCATE_SECTIONS if s.key == key)
    # A section may name its OWN estate table (DNS wipes dns_record, DHCP
    # dhcp_static_assignment); it must not reach the other two.
    reached = cascade_closure(EDGES, section.tables)
    assert not reached & ESTATE
    assert not (ESTATE - {"dns_record"}) & set(section.tables) or key != "dns"
    assert not (ESTATE - {"dhcp_static_assignment"}) & set(section.tables) or key != "dhcp"
    if key not in ("dns", "dhcp"):
        assert not set(section.tables) & ESTATE


def test_everything_has_no_refusing_key() -> None:
    """``Everything`` must not be refused by a RESTRICT key from a table
    outside every section (cloud_endpoint & co. used to be)."""
    tables = [t for s in expand_everything() if s.kind == "truncate" for t in s.tables]
    assert blocking_edges(EDGES, tables) == []


def test_runner_never_issues_truncate_cascade() -> None:
    """Look at executable SQL string literals (``f"TRUNCATE …"``), not at
    the module docstring that explains why CASCADE is gone."""
    src = Path(runner.__file__).read_text()
    statements = re.findall(r"""f?["']\s*TRUNCATE\b[^"'\n]*""", src)
    assert statements, "expected the runner to issue a TRUNCATE"
    assert not [s for s in statements if "CASCADE" in s.upper()]


def test_truncatable_excludes_referenced_tables() -> None:
    # nmap_scan is referenced by ip_address (outside the wipe) → DELETE.
    assert "nmap_scan" not in truncatable(EDGES, ["nmap_scan"])
    # a log table nothing references stays on the fast path.
    assert truncatable(EDGES, ["audit_log"]) == {"audit_log"}


def test_delete_order_puts_restrict_children_first() -> None:
    order = delete_order(EDGES, ["ip_space", "docker_host"])
    assert order.index("docker_host") < order.index("ip_space")


# ── behaviour (real Postgres) ───────────────────────────────────────


def _dsn() -> str:
    from tests.conftest import _TEST_DATABASE_URL  # noqa: PLC0415

    return str(_TEST_DATABASE_URL).replace("postgresql+asyncpg://", "postgresql://", 1)


async def _seed_estate(db: AsyncSession) -> None:
    from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment  # noqa: PLC0415
    from app.models.dns import DNSRecord, DNSServerGroup, DNSZone  # noqa: PLC0415
    from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet  # noqa: PLC0415
    from app.models.nmap import NmapScan  # noqa: PLC0415

    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.77.1.0/24", name="s")
    dns_grp = DNSServerGroup(name=f"d-{uuid.uuid4().hex[:6]}")
    dhcp_grp = DHCPServerGroup(name=f"h-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, dns_grp, dhcp_grp])
    await db.flush()
    scan = NmapScan(target_ip="10.77.1.5")
    db.add(scan)
    await db.flush()
    ip = IPAddress(
        subnet_id=subnet.id,
        address="10.77.1.5",
        status="allocated",
        last_profile_scan_id=scan.id,
    )
    db.add(ip)
    zone = DNSZone(
        group_id=dns_grp.id,
        name="corp.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.corp.example.",
        admin_email="admin.corp.example.",
    )
    scope = DHCPScope(group_id=dhcp_grp.id, subnet_id=subnet.id, name="scope-a")
    db.add_all([zone, scope])
    await db.flush()
    db.add_all(
        [
            DNSRecord(
                zone_id=zone.id,
                name="host",
                fqdn="host.corp.example",
                record_type="A",
                value="10.77.1.5",
                ip_address_id=ip.id,
            ),
            DHCPStaticAssignment(
                scope_id=scope.id,
                ip_address="10.77.1.5",
                mac_address="02:00:00:00:0a:05",
                ip_address_id=ip.id,
            ),
        ]
    )
    await db.commit()


async def _counts(db: AsyncSession) -> dict[str, int]:
    out = {}
    for t in (
        "ip_address",
        "dns_record",
        "dhcp_static_assignment",
        "nmap_scan",
        "dhcp_scope",
        "dns_zone",
        "subnet",
    ):
        out[t] = int((await db.execute(text(f'SELECT COUNT(*) FROM "{t}"'))).scalar() or 0)
    return out


async def _wipe(*keys: str) -> None:
    from app.services.factory_reset.runner import _resolve_targets  # noqa: PLC0415

    conn = await asyncpg.connect(_dsn())
    try:
        async with conn.transaction():
            await runner._execute_sections(
                conn, _resolve_targets(list(keys)), calling_user_id=uuid.uuid4()
            )
    finally:
        await conn.close()


async def test_tools_reset_keeps_the_estate(db_session: AsyncSession) -> None:
    """The reported case, verbatim."""
    await _seed_estate(db_session)
    await _wipe("tools")
    db_session.expire_all()
    c = await _counts(db_session)
    assert c["nmap_scan"] == 0
    assert (c["ip_address"], c["dns_record"], c["dhcp_static_assignment"]) == (1, 1, 1)
    link = (await db_session.execute(text("SELECT last_profile_scan_id FROM ip_address"))).scalar()
    assert link is None  # the column's own ON DELETE SET NULL


@pytest.mark.parametrize(
    "key",
    [
        "dns",
        "dhcp",
        "migration",
        "network_modeling",
        "ai",
        "compliance",
        "verticals",
        "observability_logs",
        "tools",
    ],
)
async def test_other_sections_keep_the_estate(db_session: AsyncSession, key: str) -> None:
    await _seed_estate(db_session)
    await _wipe(key)
    db_session.expire_all()
    c = await _counts(db_session)
    assert c["ip_address"] == 1 and c["subnet"] == 1
    if key != "dns":
        assert c["dns_record"] == 1 and c["dns_zone"] == 1
    if key != "dhcp":
        assert c["dhcp_static_assignment"] == 1 and c["dhcp_scope"] == 1


async def test_dns_reset_keeps_addresses_and_statics_and_clears_the_link(
    db_session: AsyncSession,
) -> None:
    await _seed_estate(db_session)
    await _wipe("dns")
    db_session.expire_all()
    c = await _counts(db_session)
    assert (c["dns_record"], c["dns_zone"]) == (0, 0)
    assert (c["ip_address"], c["dhcp_static_assignment"]) == (1, 1)


async def test_dhcp_reset_keeps_addresses_and_records(db_session: AsyncSession) -> None:
    await _seed_estate(db_session)
    await _wipe("dhcp")
    db_session.expire_all()
    c = await _counts(db_session)
    assert (c["dhcp_scope"], c["dhcp_static_assignment"]) == (0, 0)
    assert (c["ip_address"], c["dns_record"]) == (1, 1)


async def test_ipam_reset_keeps_dns_records_but_scopes_go_with_their_subnet(
    db_session: AsyncSession,
) -> None:
    """A scope cannot exist without its subnet (NOT NULL CASCADE), so
    those are declared + previewed; DNS records are NOT swept."""
    await _seed_estate(db_session)
    await _wipe("ipam")
    db_session.expire_all()
    c = await _counts(db_session)
    assert (c["ip_address"], c["subnet"]) == (0, 0)
    assert c["dns_record"] == 1 and c["dns_zone"] == 1
    linked = await db_session.execute(
        text("SELECT COUNT(*) FROM dns_record WHERE ip_address_id IS NOT NULL")
    )
    assert linked.scalar() == 0  # the link was nulled, the record kept


async def test_everything_runs_in_foreign_key_order_with_an_integration_present(
    db_session: AsyncSession,
) -> None:
    """IPAM precedes Integrations in the list, but an integration's
    ``ip_space`` key is RESTRICT — the order must come from the keys."""
    from app.models.docker import DockerHost  # noqa: PLC0415
    from app.models.ipam import IPSpace  # noqa: PLC0415

    await _seed_estate(db_session)
    space = (await db_session.execute(select(IPSpace))).scalars().first()
    assert space is not None
    db_session.add(
        DockerHost(
            name="d1",
            connection_type="tcp",
            endpoint="docker.example.test:2376",
            ipam_space_id=space.id,
            client_key_encrypted=b"",
        )
    )
    await db_session.commit()
    await _wipe("all")
    db_session.expire_all()
    c = await _counts(db_session)
    assert all(v == 0 for v in c.values())
    assert (await db_session.execute(text('SELECT COUNT(*) FROM "docker_host"'))).scalar() == 0


async def test_a_lone_ipam_reset_is_refused_while_an_integration_points_at_a_space(
    db_session: AsyncSession,
) -> None:
    from app.models.docker import DockerHost  # noqa: PLC0415
    from app.models.ipam import IPSpace  # noqa: PLC0415

    await _seed_estate(db_session)
    space = (await db_session.execute(select(IPSpace))).scalars().first()
    assert space is not None
    db_session.add(
        DockerHost(
            name="d1",
            connection_type="tcp",
            endpoint="docker.example.test:2376",
            ipam_space_id=space.id,
            client_key_encrypted=b"",
        )
    )
    await db_session.commit()
    blockers = await runner._preview_blockers(db_session, runner._resolve_targets(["ipam"]))
    assert any("docker_host" in b for b in blockers)
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await _wipe("ipam")
    # the transaction rolled back: nothing was deleted
    db_session.expire_all()
    c = await _counts(db_session)
    assert c["ip_address"] == 1 and c["subnet"] == 1


async def test_preview_names_cascade_dependents(db_session: AsyncSession) -> None:
    await _seed_estate(db_session)
    previews = await runner.preview_factory_reset(
        db_session, section_keys=["ipam"], calling_user_id=uuid.uuid4()
    )
    counts = previews[0].table_counts
    assert counts.get("dhcp_scope (cascade)") == 1
    assert counts.get("dhcp_static_assignment (cascade)") == 1
    assert "dns_record (cascade)" not in counts
    tools = await runner.preview_factory_reset(
        db_session, section_keys=["tools"], calling_user_id=uuid.uuid4()
    )
    assert not any("(cascade)" in k for k in tools[0].table_counts)


async def test_live_fk_edges_match_metadata(db_session: AsyncSession) -> None:
    """The runner reads pg_constraint; the guard reads metadata. They
    must describe the same graph or the guard proves nothing."""
    live = edges_from_rows((await db_session.execute(text(FK_EDGES_SQL))).mappings().all())

    def norm(es):
        return {(e.child, e.parent, e.ondelete, tuple(sorted(e.columns))) for e in es}

    assert norm(live) == norm(EDGES)
