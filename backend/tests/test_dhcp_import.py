"""Tests for the DHCP configuration importer (issue #129).

Two layers:

* **Parser layer** — ``parse_kea_config`` / ``parse_isc_config``
  against synthetic configs. Pure-Python; no DB dependency.
* **Commit layer** — preview + commit endpoints exercised through the
  FastAPI test client with a real Postgres-backed session so the IPAM
  link/create resolution, per-scope savepoints, provenance stamping,
  and audit-log rows are covered end-to-end.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import (
    DHCPClientClass,
    DHCPPool,
    DHCPScope,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp_import import (
    IscImportError,
    KeaImportError,
    parse_isc_config,
    parse_kea_config,
)

# ── fixtures / helpers ───────────────────────────────────────────────


_KEA_CONF = b"""
{
  // top of the file
  "Dhcp4": {
    "valid-lifetime": 4000,
    "option-data": [ { "name": "domain-name", "data": "example.org" } ],
    "subnet4": [
      {
        "subnet": "192.0.2.0/24",
        "pools": [ { "pool": "192.0.2.10 - 192.0.2.100" } ],
        "option-data": [
          { "name": "routers", "data": "192.0.2.1" },
          { "name": "domain-name-servers", "data": "1.1.1.1, 8.8.8.8" }
        ],
        "reservations": [
          { "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "192.0.2.5", "hostname": "printer" }
        ]
      }
    ],
    "client-classes": [ { "name": "voip", "test": "substring(option[60].hex,0,6) == 'Aastra'" } ]
  }
}
"""

_ISC_CONF = b"""
# global config
option domain-name "isc.example";
default-lease-time 600;

subnet 10.5.5.0 netmask 255.255.255.0 {
  range 10.5.5.10 10.5.5.100;
  option routers 10.5.5.1;
  option domain-name-servers 10.5.5.1, 8.8.8.8;
  max-lease-time 7200;
}

host laptop {
  hardware ethernet 01:02:03:04:05:06;
  fixed-address 10.5.5.50;
}

class "pxe" {
  match if substring(option vendor-class-identifier,0,9) = "PXEClient";
}

failover peer "dhcp-failover" { primary; }
"""


async def _make_admin(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username="dhcpimport-admin",
        email="dhcpimport-admin@example.com",
        display_name="dhcpimport-admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_group(db: AsyncSession, name: str = "dhcp-import-grp") -> DHCPServerGroup:
    g = DHCPServerGroup(name=name)
    db.add(g)
    await db.flush()
    return g


async def _make_space(db: AsyncSession, name: str = "import-space") -> IPSpace:
    sp = IPSpace(name=name, description="")
    db.add(sp)
    await db.flush()
    return sp


async def _make_block(db: AsyncSession, space: IPSpace, network: str = "192.0.2.0/24") -> IPBlock:
    b = IPBlock(space_id=space.id, network=network, name="b")
    db.add(b)
    await db.flush()
    return b


async def _make_subnet(db: AsyncSession, space: IPSpace, block: IPBlock, network: str) -> Subnet:
    s = Subnet(space_id=space.id, block_id=block.id, network=network)
    db.add(s)
    await db.flush()
    return s


# ── Parser layer — Kea ───────────────────────────────────────────────


def test_kea_basic_scope() -> None:
    p = parse_kea_config(_KEA_CONF)
    assert p.source == "kea"
    assert len(p.scopes) == 1
    sc = p.scopes[0]
    assert sc.subnet_cidr == "192.0.2.0/24"
    assert sc.address_family == "ipv4"
    assert sc.lease_time == 4000
    # global domain-name merged + scope routers/dns-servers
    assert sc.options["domain-name"] == "example.org"
    assert sc.options["routers"] == "192.0.2.1"
    assert sc.options["dns-servers"] == ["1.1.1.1", "8.8.8.8"]
    assert len(sc.pools) == 1
    assert sc.pools[0].start_ip == "192.0.2.10"
    assert sc.pools[0].end_ip == "192.0.2.100"
    assert len(sc.reservations) == 1
    assert sc.reservations[0].mac_address == "aa:bb:cc:dd:ee:ff"
    assert sc.reservations[0].ip_address == "192.0.2.5"
    assert len(p.client_classes) == 1
    assert p.client_classes[0].name == "voip"
    assert p.client_classes[0].supported is True


def test_kea_bare_dhcp4_body() -> None:
    """A config that is the bare Dhcp4 body (no wrapper) parses too."""
    p = parse_kea_config(b'{"subnet4": [{"subnet": "10.0.0.0/8"}]}')
    assert len(p.scopes) == 1
    assert p.scopes[0].subnet_cidr == "10.0.0.0/8"


def test_kea_v6_subnet() -> None:
    p = parse_kea_config(
        b'{"Dhcp6": {"subnet6": [{"subnet": "2001:db8::/64", '
        b'"pools": [{"pool": "2001:db8::10 - 2001:db8::ff"}]}]}}'
    )
    assert len(p.scopes) == 1
    assert p.scopes[0].address_family == "ipv6"
    assert p.scopes[0].v6_address_mode == "stateful"
    assert p.address_family_histogram == {"ipv6": 1}


def test_kea_pool_cidr_form() -> None:
    p = parse_kea_config(
        b'{"subnet4": [{"subnet": "10.0.0.0/24", "pools": [{"pool": "10.0.0.0/25"}]}]}'
    )
    pool = p.scopes[0].pools[0]
    assert pool.start_ip == "10.0.0.0"
    assert pool.end_ip == "10.0.0.127"


def test_kea_invalid_json_raises() -> None:
    with pytest.raises(KeaImportError):
        parse_kea_config(b"this is not json {")


def test_kea_no_subnets_raises() -> None:
    with pytest.raises(KeaImportError):
        parse_kea_config(b'{"Dhcp4": {"valid-lifetime": 3600}}')


# ── Parser layer — ISC ───────────────────────────────────────────────


def test_isc_basic_subnet() -> None:
    p = parse_isc_config(_ISC_CONF)
    assert p.source == "isc_dhcp"
    sc = next(s for s in p.scopes if s.subnet_cidr == "10.5.5.0/24")
    assert sc.lease_time == 600  # inherited global default
    assert sc.max_lease_time == 7200
    assert sc.options["domain-name"] == "isc.example"  # inherited global
    assert sc.options["routers"] == "10.5.5.1"
    assert sc.options["dns-servers"] == ["10.5.5.1", "8.8.8.8"]
    assert len(sc.pools) == 1
    # global host attaches to the containing subnet
    assert any(r.ip_address == "10.5.5.50" for r in sc.reservations)
    assert sc.reservations[0].mac_address == "01:02:03:04:05:06"


def test_isc_class_unsupported_and_failover_listed() -> None:
    p = parse_isc_config(_ISC_CONF)
    assert len(p.client_classes) == 1
    assert p.client_classes[0].name == "pxe"
    assert p.client_classes[0].supported is False
    assert any("failover" in u.lower() for u in p.unsupported)


def test_isc_shared_network_flattened() -> None:
    conf = b"""
shared-network office {
  subnet 10.6.6.0 netmask 255.255.255.0 { range 10.6.6.20 10.6.6.40; }
  subnet 10.7.7.0 netmask 255.255.255.0 { range 10.7.7.20 10.7.7.40; }
}
"""
    p = parse_isc_config(conf)
    cidrs = {s.subnet_cidr for s in p.scopes}
    assert cidrs == {"10.6.6.0/24", "10.7.7.0/24"}
    assert any("shared-network" in w.lower() for w in p.warnings)


def test_isc_empty_raises() -> None:
    with pytest.raises(IscImportError):
        parse_isc_config(b"authoritative;\n")


# ── Commit layer — endpoints ─────────────────────────────────────────


async def _kea_preview(client: AsyncClient, token: str, group_id: str, space_id: str | None = None):
    data = {"target_group_id": group_id}
    if space_id:
        data["ipam_space_id"] = space_id
    resp = await client.post(
        "/api/v1/dhcp/import/kea/preview",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("kea.conf", _KEA_CONF, "application/json")},
        data=data,
    )
    return resp


@pytest.mark.asyncio
async def test_kea_preview_endpoint(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    await db_session.commit()

    resp = await _kea_preview(client, token, str(group.id))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source"] == "kea"
    assert len(body["scopes"]) == 1
    assert body["scopes"][0]["subnet_cidr"] == "192.0.2.0/24"
    assert body["total_pools"] == 1
    assert body["total_reservations"] == 1
    assert body["conflicts"] == []  # no IPAM subnet matches yet


@pytest.mark.asyncio
async def test_kea_commit_autocreates_subnet_with_provenance(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "192.0.2.0/24")
    await db_session.commit()

    preview = (await _kea_preview(client, token, str(group.id), str(space.id))).json()
    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": preview,
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_scopes_created"] == 1
    assert body["total_subnets_created"] == 1
    assert body["total_pools_created"] == 1
    assert body["total_reservations_created"] == 1
    assert body["client_classes_created"] == 1
    assert body["scopes"][0]["action_taken"] == "created"

    # subnet auto-created + linked to the group
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "192.0.2.0/24"))
    ).scalar_one()
    assert str(subnet.dhcp_server_group_id) == str(group.id)
    # Usable size, as every other create path stores it (#3093, #2411):
    # network + broadcast are left out of a v4 subnet's total.
    assert subnet.total_ips == 254

    # scope + provenance
    scope = (
        (await db_session.execute(select(DHCPScope).where(DHCPScope.subnet_id == subnet.id)))
        .unique()
        .scalar_one()
    )
    assert scope.import_source == "kea"
    assert scope.imported_at is not None
    pool = (
        await db_session.execute(select(DHCPPool).where(DHCPPool.scope_id == scope.id))
    ).scalar_one()
    assert pool.import_source == "kea"
    static = (
        await db_session.execute(
            select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope.id)
        )
    ).scalar_one()
    assert static.mac_address == "aa:bb:cc:dd:ee:ff"
    cc = (
        await db_session.execute(
            select(DHCPClientClass).where(DHCPClientClass.group_id == group.id)
        )
    ).scalar_one()
    assert cc.name == "voip"
    assert cc.import_source == "kea"

    # audit row
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dhcp_scope", AuditLog.resource_id == str(scope.id)
            )
        )
    ).scalar_one()
    assert audit.action == "create"


@pytest.mark.asyncio
async def test_kea_commit_links_existing_subnet(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A scope whose CIDR already matches an IPAM subnet links to it
    (no auto-create) even in link-only mode (no space/block in body)."""
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "192.0.2.0/24")
    await _make_subnet(db_session, space, block, "192.0.2.0/24")
    await db_session.commit()

    preview = (await _kea_preview(client, token, str(group.id))).json()
    # preview should flag the existing subnet (link, not conflict)
    assert preview["conflicts"][0]["existing_subnet_id"] is not None
    assert preview["conflicts"][0]["existing_scope_id"] is None

    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "plan": preview,
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_scopes_created"] == 1
    assert body["total_subnets_created"] == 0  # linked, not created


@pytest.mark.asyncio
async def test_kea_commit_link_only_fails_without_subnet(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Link-only mode (no space/block) + no matching subnet → the scope
    fails with an actionable error, not a 500."""
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    await db_session.commit()

    preview = (await _kea_preview(client, token, str(group.id))).json()
    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_group_id": str(group.id), "plan": preview, "conflict_actions": {}},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_scopes_failed"] == 1
    assert "No IPAM subnet matches" in body["scopes"][0]["error"]


@pytest.mark.asyncio
async def test_kea_commit_skip_then_overwrite(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "192.0.2.0/24")
    subnet = await _make_subnet(db_session, space, block, "192.0.2.0/24")
    # an existing scope already serves this subnet in the group
    existing = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="old")
    db_session.add(existing)
    await db_session.commit()

    preview = (await _kea_preview(client, token, str(group.id))).json()
    assert preview["conflicts"][0]["existing_scope_id"] is not None

    # default skip
    skip_resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_group_id": str(group.id), "plan": preview, "conflict_actions": {}},
    )
    assert skip_resp.status_code == 200
    assert skip_resp.json()["total_scopes_skipped"] == 1

    # explicit overwrite
    ow_resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "plan": preview,
            "conflict_actions": {"192.0.2.0/24": {"action": "overwrite"}},
        },
    )
    assert ow_resp.status_code == 200, ow_resp.text
    assert ow_resp.json()["total_scopes_overwrote"] == 1
    # the new scope replaced the old; only one scope on the subnet
    scopes = (
        (
            await db_session.execute(
                select(DHCPScope).where(
                    DHCPScope.subnet_id == subnet.id, DHCPScope.deleted_at.is_(None)
                )
            )
        )
        .unique()
        .scalars()
        .all()
    )
    assert len(scopes) == 1
    assert scopes[0].import_source == "kea"


@pytest.mark.asyncio
async def test_kea_commit_soft_deleted_scope_overwrite(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A soft-deleted scope still holds the (group, subnet) unique slot.
    The importer must flag it as a conflict (in Trash) and let overwrite
    hard-delete + recreate — not blow up on an IntegrityError."""
    from datetime import UTC, datetime

    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "192.0.2.0/24")
    subnet = await _make_subnet(db_session, space, block, "192.0.2.0/24")
    trashed = DHCPScope(
        group_id=group.id,
        subnet_id=subnet.id,
        name="trashed",
        deleted_at=datetime.now(UTC),
    )
    db_session.add(trashed)
    await db_session.commit()

    preview = (await _kea_preview(client, token, str(group.id))).json()
    conflict = preview["conflicts"][0]
    assert conflict["existing_scope_id"] is not None
    assert conflict["soft_deleted"] is True

    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "plan": preview,
            "conflict_actions": {"192.0.2.0/24": {"action": "overwrite"}},
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["total_scopes_overwrote"] == 1
    # exactly one live scope on the subnet, and the trashed one is purged
    live = (
        (
            await db_session.execute(
                select(DHCPScope).where(
                    DHCPScope.subnet_id == subnet.id, DHCPScope.deleted_at.is_(None)
                )
            )
        )
        .unique()
        .scalars()
        .all()
    )
    assert len(live) == 1
    assert live[0].import_source == "kea"


@pytest.mark.asyncio
async def test_isc_preview_and_commit(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "10.5.5.0/24")
    await db_session.commit()

    preview_resp = await client.post(
        "/api/v1/dhcp/import/isc/preview",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("dhcpd.conf", _ISC_CONF, "text/plain")},
        data={"target_group_id": str(group.id), "ipam_space_id": str(space.id)},
    )
    assert preview_resp.status_code == 200, preview_resp.text
    preview = preview_resp.json()
    assert any(s["subnet_cidr"] == "10.5.5.0/24" for s in preview["scopes"])

    commit_resp = await client.post(
        "/api/v1/dhcp/import/isc/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": preview,
            "conflict_actions": {},
        },
    )
    assert commit_resp.status_code == 200, commit_resp.text
    body = commit_resp.json()
    assert body["total_scopes_created"] == 1
    # ISC classes are unsupported → never created
    assert body["client_classes_created"] == 0


@pytest.mark.asyncio
async def test_windows_servers_endpoint_empty(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_admin(db_session)
    await db_session.commit()
    resp = await client.get(
        "/api/v1/dhcp/import/windows/servers",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_commit_source_mismatch_400(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    await db_session.commit()
    preview = (await _kea_preview(client, token, str(group.id))).json()
    resp = await client.post(
        "/api/v1/dhcp/import/isc/commit",  # wrong endpoint for a kea plan
        headers={"Authorization": f"Bearer {token}"},
        json={"target_group_id": str(group.id), "plan": preview, "conflict_actions": {}},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_kea_commit_failed_scope_does_not_poison_the_next_2816(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A scope that fails rolls back only itself (#2816): the scope after it
    is created and audited, and the route answers 200, not 500."""
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "10.9.0.0/16")
    await _make_subnet(db_session, space, block, "10.9.9.0/24")
    await _make_subnet(db_session, space, block, "10.9.10.0/24")
    await db_session.commit()

    # Link-only (no space). The first scope carries a reservation whose MAC
    # the MACADDR column rejects, so its write RAISES (not a returned
    # failure); the second must still land.
    plan = (await _kea_preview(client, token, str(group.id))).json()
    good = {**plan["scopes"][0], "subnet_cidr": "10.9.10.0/24"}
    bad_res = {**plan["scopes"][0]["reservations"][0], "mac_address": "not-a-mac"}
    bad = {**plan["scopes"][0], "subnet_cidr": "10.9.9.0/24", "reservations": [bad_res]}
    plan["scopes"] = [bad, good]
    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_group_id": str(group.id), "plan": plan, "conflict_actions": {}},
    )
    assert resp.status_code == 200, resp.text
    scopes = resp.json()["scopes"]
    assert [x["action_taken"] for x in scopes] == ["failed", "created"], scopes
    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_type == "dhcp_scope")))
        .scalars()
        .all()
    )
    assert len(audits) == 1


# ── Pool syntax (#3037) ──────────────────────────────────────────────


def _kea_pools(subnet: str, *pools: str):
    import json

    body = {
        "subnet4" if ":" not in subnet else "subnet6": [
            {"subnet": subnet, "pools": [{"pool": p} for p in pools]}
        ]
    }
    return parse_kea_config(json.dumps(body).encode()).scopes[0]


@pytest.mark.parametrize(
    "pool",
    [
        "10.0.0.100-10.0.0.150",
        "10.0.0.100 - 10.0.0.150",
        "10.0.0.100 -10.0.0.150",
        " 10.0.0.100- 10.0.0.150 ",
    ],
)
def test_kea_pool_dash_with_any_spacing_3037(pool: str) -> None:
    sc = _kea_pools("10.0.0.0/24", pool)
    assert [(p.start_ip, p.end_ip) for p in sc.pools] == [("10.0.0.100", "10.0.0.150")]
    assert sc.parse_warnings == []


def test_kea_pool_v6_no_spaces_3037() -> None:
    sc = _kea_pools("2001:db8::/64", "2001:db8::10-2001:db8::20")
    assert [(p.start_ip, p.end_ip) for p in sc.pools] == [("2001:db8::10", "2001:db8::20")]


def test_kea_pool_v6_prefix_form_3037() -> None:
    sc = _kea_pools("2001:db8::/64", "2001:db8::/120")
    assert (sc.pools[0].start_ip, sc.pools[0].end_ip) == ("2001:db8::", "2001:db8::ff")


@pytest.mark.parametrize(
    "pool",
    ["not-an-ip", "10.0.0.150-10.0.0.100", "10.1.0.1-10.1.0.9", "10.0.0.1-", "banana"],
)
def test_kea_bad_pool_is_a_preview_warning_3037(pool: str) -> None:
    sc = _kea_pools("10.0.0.0/24", pool)
    assert sc.pools == []
    assert len(sc.parse_warnings) == 1
    assert repr(pool) in sc.parse_warnings[0]


def test_isc_range_outside_subnet_is_a_preview_warning_3037() -> None:
    p = parse_isc_config(
        b"subnet 10.0.0.0 netmask 255.255.255.0 {\n"
        b"  range 10.0.0.10 10.0.0.20;\n  range 10.5.0.10 10.5.0.20;\n}\n"
    )
    sc = p.scopes[0]
    assert [(x.start_ip, x.end_ip) for x in sc.pools] == [("10.0.0.10", "10.0.0.20")]
    assert any("10.5.0.10" in w for w in sc.parse_warnings)


@pytest.mark.asyncio
async def test_kea_commit_bad_pool_error_has_no_sql_3037(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "192.0.2.0/24")
    await db_session.commit()

    plan = (await _kea_preview(client, token, str(group.id))).json()
    # A value the column refuses at the database (the MACADDR cast), so the
    # failure is the driver's own error, which carries the SQL.
    plan["scopes"][0]["reservations"][0]["mac_address"] = "not-a-mac"
    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": plan,
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    scope = resp.json()["scopes"][0]
    assert scope["action_taken"] == "failed"
    assert "SQL" not in scope["error"] and "INSERT" not in scope["error"]
    assert "asyncpg" not in scope["error"]


@pytest.mark.parametrize("pool", ["10.0.0.1-10.0.0.2-10.0.0.3", "", "   "])
def test_kea_pool_kea_rejects_is_a_preview_warning_3037(pool: str) -> None:
    sc = _kea_pools("10.0.0.0/24", pool)
    assert sc.pools == []
    assert len(sc.parse_warnings) == 1


def test_isc_range_written_high_to_low_is_kept_3037() -> None:
    """dhcpd reads ``range high low`` as the same range, so the import must
    not drop it as invalid."""
    p = parse_isc_config(
        b"subnet 10.0.0.0 netmask 255.255.255.0 {\n  range 10.0.0.50 10.0.0.10;\n}\n"
    )
    sc = p.scopes[0]
    assert [(x.start_ip, x.end_ip) for x in sc.pools] == [("10.0.0.10", "10.0.0.50")]
    assert sc.parse_warnings == []


def test_isc_range6_prefix_and_temporary_3037() -> None:
    p = parse_isc_config(
        b"subnet6 2001:db8::/64 {\n  range6 2001:db8::/120 temporary;\n"
        b"  range6 2001:db8::1:0 2001:db8::1:ff;\n}\n"
    )
    sc = p.scopes[0]
    assert [(x.start_ip, x.end_ip) for x in sc.pools] == [
        ("2001:db8::", "2001:db8::ff"),
        ("2001:db8::1:0", "2001:db8::1:ff"),
    ]
    assert sc.parse_warnings == []


@pytest.mark.asyncio
async def test_kea_commit_rechecks_pools_in_the_plan_3037(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The commit takes the plan the client sends back, so a pool the parser
    would have refused (here, valid addresses outside the subnet, which an
    INET column accepts) is dropped and named there too, not stored."""
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "192.0.2.0/24")
    await db_session.commit()

    plan = (await _kea_preview(client, token, str(group.id))).json()
    plan["scopes"][0]["pools"].append(
        {**plan["scopes"][0]["pools"][0], "start_ip": "10.1.1.1", "end_ip": "10.1.1.9"}
    )
    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": plan,
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scopes"][0]["action_taken"] == "created"
    assert body["scopes"][0]["pools_created"] == 1
    assert any("10.1.1.1" in w for w in body["warnings"]), body["warnings"]
    starts = (await db_session.execute(select(DHCPPool.start_ip))).scalars().all()
    assert [str(x) for x in starts] == ["192.0.2.10"]


# ── #3097: every dropped pool gets a note ────────────────────────────


def test_kea_pool_that_is_not_an_object_is_a_preview_warning_3097() -> None:
    import json

    body = {
        "subnet4": [
            {
                "subnet": "10.0.0.0/24",
                "pools": [{"pool": "10.0.0.10-10.0.0.20"}, "10.0.0.30-10.0.0.40"],
            }
        ]
    }
    sc = parse_kea_config(json.dumps(body).encode()).scopes[0]
    assert [(p.start_ip, p.end_ip) for p in sc.pools] == [("10.0.0.10", "10.0.0.20")]
    assert len(sc.parse_warnings) == 1
    assert "10.0.0.30-10.0.0.40" in sc.parse_warnings[0]


def test_isc_range_with_no_address_is_a_preview_warning_3097() -> None:
    p = parse_isc_config(
        b"subnet 10.0.0.0 netmask 255.255.255.0 {\n"
        b"  range 10.0.0.10 10.0.0.20;\n  range dynamic-bootp;\n"
        b"  pool { range; }\n}\n"
    )
    sc = p.scopes[0]
    assert [(x.start_ip, x.end_ip) for x in sc.pools] == [("10.0.0.10", "10.0.0.20")]
    notes = [w for w in sc.parse_warnings if "no address" in w]
    assert len(notes) == 2
    assert any("dynamic-bootp" in w for w in notes)


def test_windows_pool_with_no_end_is_a_preview_warning_3097() -> None:
    from app.services.dhcp_import.windows_dhcp_pull import _scope_from_dict

    sc = _scope_from_dict(
        {
            "subnet_cidr": "10.0.0.0/24",
            "pools": [
                {"start_ip": "10.0.0.10", "end_ip": "10.0.0.20"},
                {"start_ip": "10.0.0.30", "end_ip": None},
            ],
        }
    )
    assert sc is not None
    assert len(sc.pools) == 1
    assert len(sc.parse_warnings) == 1
    assert "10.0.0.30" in sc.parse_warnings[0]


_V6_64_IMPORTS_3093 = [
    pytest.param(
        "kea",
        "kea.conf",
        '{"Dhcp6": {"subnet6": [{"id": 64, "subnet": "2001:db8:6::/64", "pools": []}]}}',
        [],
        id="kea-no-pool",
    ),
    pytest.param(
        "kea",
        "kea.conf",
        '{"Dhcp6": {"subnet6": [{"id": 64, "subnet": "2001:db8:6::/64", '
        '"pools": [{"pool": "2001:db8:6::100 - 2001:db8:6::1ff"}]}]}}',
        [("2001:db8:6::100", "2001:db8:6::1ff")],
        id="kea-range-pool",
    ),
    pytest.param(
        "isc",
        "dhcpd6.conf",
        "subnet6 2001:db8:6::/64 {\n  range6 2001:db8:6::100 2001:db8:6::1ff;\n}\n",
        [("2001:db8:6::100", "2001:db8:6::1ff")],
        id="isc-range6",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("source", "filename", "conf", "pools"), _V6_64_IMPORTS_3093)
async def test_commit_autocreates_v6_64_subnet_3093(
    db_session: AsyncSession,
    client: AsyncClient,
    source: str,
    filename: str,
    conf: str,
    pools: list[tuple[str, str]],
) -> None:
    """A /64 has 2**64 addresses, one past BIGINT: the auto-created Subnet's
    ``total_ips`` must be clamped like every other creation path, so a v6
    scope whose /64 is not yet in IPAM imports — with or without pools, from
    any source (they share one commit path)."""
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "2001:db8::/32")
    await db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    preview_resp = await client.post(
        f"/api/v1/dhcp/import/{source}/preview",
        headers=headers,
        files={"file": (filename, conf, "application/octet-stream")},
        data={"target_group_id": str(group.id), "ipam_space_id": str(space.id)},
    )
    assert preview_resp.status_code == 200, preview_resp.text
    resp = await client.post(
        f"/api/v1/dhcp/import/{source}/commit",
        headers=headers,
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": preview_resp.json(),
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scopes"][0]["action_taken"] == "created", body
    assert body["total_subnets_created"] == 1
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "2001:db8:6::/64"))
    ).scalar_one()
    assert subnet.total_ips == 2**63 - 1
    scope = (
        await db_session.execute(select(DHCPScope).where(DHCPScope.subnet_id == subnet.id))
    ).scalar_one()
    assert scope.address_family == "ipv6"
    got = (
        await db_session.execute(
            select(DHCPPool.start_ip, DHCPPool.end_ip).where(DHCPPool.scope_id == scope.id)
        )
    ).all()
    assert sorted((str(a), str(b)) for a, b in got) == pools
