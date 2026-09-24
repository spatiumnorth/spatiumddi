"""New-device (arpwatch) detection — issue #459.

Covers the classification core (``classify_mac`` / ``is_locally_administered`` /
``record_mac_observation``), the operator service actions (baseline / allowlist /
acknowledge), the ``new_mac_seen`` alert matcher, and the end-to-end DHCP
lease-events → new-sighting + ``device.first_seen`` audit path.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _auth_agent
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.alerts import AlertRule
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPMACBlock, DHCPServer, DHCPServerGroup
from app.models.feature_module import FeatureModule
from app.models.ipam import IPAddress, IPBlock, IpMacHistory, IPSpace, MACAllowlist, Subnet
from app.services import feature_modules
from app.services.alerts import RULE_TYPE_NEW_MAC_SEEN, _matching_new_mac_seen_subjects
from app.services.ipam.discovery import record_mac_observation
from app.services.ipam.new_device import (
    CLASSIFICATION_ACKNOWLEDGED,
    CLASSIFICATION_KNOWN,
    CLASSIFICATION_NEW,
    acknowledge_sighting,
    add_allowlist_entry,
    baseline_import,
    classify_mac,
    is_locally_administered,
    normalize_oui_prefix,
)

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_module_cache():
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


async def _enable_watch(db: AsyncSession) -> None:
    db.add(FeatureModule(id="security.new_device_watch", enabled=True))
    await db.flush()
    feature_modules.invalidate_cache()


async def _disable_watch(db: AsyncSession) -> None:
    """Turn the module OFF with a row, not by leaning on the shipped default.

    The suite patches every catalog default to enabled (see the
    ``_all_feature_modules_enabled`` fixture in conftest), because which
    modules ship on is a product decision #1069 revised and the tests must
    not encode it. A row still beats the default, so this is how a test
    says "off" and keeps saying it through the next revision.
    """
    db.add(FeatureModule(id="security.new_device_watch", enabled=False))
    await db.flush()
    feature_modules.invalidate_cache()


async def _make_subnet(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"nd-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.40.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.40.1.0/24",
        name="sn",
        total_ips=254,
    )
    db.add(subnet)
    await db.flush()
    return subnet


async def _ip(
    db: AsyncSession, subnet: Subnet, addr: str, *, status: str, mac: str | None = None
) -> IPAddress:
    row = IPAddress(subnet_id=subnet.id, address=addr, status=status, mac_address=mac)
    db.add(row)
    await db.flush()
    return row


async def _superadmin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── MAC helpers ──────────────────────────────────────────────────────────


async def test_is_locally_administered() -> None:
    # 0x02 bit set in the first octet → randomised (0x02, 0x0a, 0xaa, 0xde).
    assert is_locally_administered("02:11:22:33:44:55") is True
    assert is_locally_administered("0a:11:22:33:44:55") is True
    assert is_locally_administered("aa:bb:cc:dd:ee:ff") is True  # 0xAA & 0x02 == 2
    assert is_locally_administered("DE:AD:BE:EF:00:01") is True  # 0xDE & 0x02 == 2
    # Globally-unique (vendor) MACs (bit clear) → not randomised.
    assert is_locally_administered("00:50:56:11:22:33") is False  # 0x00
    assert is_locally_administered("3c:5a:b4:11:22:33") is False  # 0x3c
    assert is_locally_administered("08:00:27:11:22:33") is False  # 0x08
    assert is_locally_administered(None) is False
    assert is_locally_administered("not-a-mac") is False


async def test_normalize_oui_prefix() -> None:
    assert normalize_oui_prefix("00:50:56") == "005056"
    assert normalize_oui_prefix("005056") == "005056"
    assert normalize_oui_prefix("00-50-56-ab-cd-ef") == "005056"
    assert normalize_oui_prefix("0050.56ab.cdef") == "005056"
    assert normalize_oui_prefix("0050") is None
    assert normalize_oui_prefix(None) is None


# ── classify_mac ─────────────────────────────────────────────────────────


async def test_classify_unknown_is_new(db_session: AsyncSession) -> None:
    assert await classify_mac(db_session, "aa:bb:cc:00:00:01") == CLASSIFICATION_NEW


async def test_classify_known_fleet(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    await _ip(db_session, subnet, "10.40.1.10", status="allocated", mac="aa:bb:cc:00:00:02")
    await db_session.flush()
    assert await classify_mac(db_session, "aa:bb:cc:00:00:02") == CLASSIFICATION_KNOWN
    # A MAC only on a 'dhcp' (integration-owned) row is NOT the known fleet.
    subnet2 = await _make_subnet(db_session)
    await _ip(db_session, subnet2, "10.40.1.11", status="dhcp", mac="aa:bb:cc:00:00:03")
    await db_session.flush()
    assert await classify_mac(db_session, "aa:bb:cc:00:00:03") == CLASSIFICATION_NEW


async def test_classify_allowlisted(db_session: AsyncSession) -> None:
    db_session.add(MACAllowlist(mac_address="aa:bb:cc:00:00:04"))
    await db_session.flush()
    assert await classify_mac(db_session, "aa:bb:cc:00:00:04") == CLASSIFICATION_KNOWN


async def test_classify_oui_allowlisted(db_session: AsyncSession) -> None:
    db_session.add(MACAllowlist(oui_prefix="005056"))
    await db_session.flush()
    assert await classify_mac(db_session, "00:50:56:ab:cd:ef") == CLASSIFICATION_KNOWN
    assert await classify_mac(db_session, "00:50:57:ab:cd:ef") == CLASSIFICATION_NEW


# ── record_mac_observation ───────────────────────────────────────────────


async def test_record_observation_first_then_repeat(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    ip = await _ip(db_session, subnet, "10.40.1.20", status="dhcp")
    await db_session.flush()

    first = await record_mac_observation(
        db_session, ip.id, "aa:bb:cc:00:00:10", source="dhcp_lease"
    )
    assert first is not None
    assert first.is_new_row is True
    assert first.is_first_seen_new is True
    assert first.classification == CLASSIFICATION_NEW

    # A second sighting of the same (ip, mac) is not a new row.
    second = await record_mac_observation(db_session, ip.id, "aa:bb:cc:00:00:10", source="snmp")
    assert second is not None
    assert second.is_new_row is False
    assert second.is_first_seen_new is False

    # Acknowledging then re-observing must NOT downgrade back to 'new'.
    row = (
        await db_session.execute(select(IpMacHistory).where(IpMacHistory.ip_address_id == ip.id))
    ).scalar_one()
    row.classification = CLASSIFICATION_ACKNOWLEDGED
    await db_session.flush()
    third = await record_mac_observation(db_session, ip.id, "aa:bb:cc:00:00:10", source="sweep")
    assert third is not None
    assert third.classification == CLASSIFICATION_ACKNOWLEDGED


async def test_record_observation_randomized_flag(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    ip = await _ip(db_session, subnet, "10.40.1.21", status="dhcp")
    await db_session.flush()
    res = await record_mac_observation(db_session, ip.id, "02:aa:bb:cc:dd:ee", source="dhcp_lease")
    assert res is not None and res.is_randomized is True
    stored = (
        await db_session.execute(select(IpMacHistory).where(IpMacHistory.ip_address_id == ip.id))
    ).scalar_one()
    assert stored.is_randomized is True
    assert stored.source == "dhcp_lease"


# ── baseline / allowlist / acknowledge ───────────────────────────────────


async def test_baseline_import(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    for i in range(3):
        ip = await _ip(db_session, subnet, f"10.40.1.{30 + i}", status="dhcp")
        await db_session.flush()
        await record_mac_observation(
            db_session, ip.id, f"aa:bb:cc:00:01:{i:02d}", source="dhcp_lease"
        )
    await db_session.flush()
    count = await baseline_import(db_session)
    assert count == 3
    remaining_new = (
        (
            await db_session.execute(
                select(IpMacHistory).where(IpMacHistory.classification == CLASSIFICATION_NEW)
            )
        )
        .scalars()
        .all()
    )
    assert remaining_new == []


async def test_add_allowlist_reclassifies(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    ip = await _ip(db_session, subnet, "10.40.1.40", status="dhcp")
    await db_session.flush()
    await record_mac_observation(db_session, ip.id, "00:50:56:aa:bb:cc", source="dhcp_lease")
    await db_session.flush()

    row, reclassified = await add_allowlist_entry(db_session, oui_prefix="00:50:56", note="vmware")
    await db_session.flush()
    assert row.oui_prefix == "005056"
    assert reclassified == 1
    stored = (
        await db_session.execute(select(IpMacHistory).where(IpMacHistory.ip_address_id == ip.id))
    ).scalar_one()
    assert stored.classification == CLASSIFICATION_KNOWN


async def test_add_allowlist_requires_a_key(db_session: AsyncSession) -> None:
    with pytest.raises(ValueError):
        await add_allowlist_entry(db_session, note="nothing")


async def test_acknowledge_sighting(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)
    ip = await _ip(db_session, subnet, "10.40.1.50", status="dhcp")
    await db_session.flush()
    await record_mac_observation(db_session, ip.id, "aa:bb:cc:00:02:00", source="dhcp_lease")
    await db_session.flush()
    sighting = (
        await db_session.execute(select(IpMacHistory).where(IpMacHistory.ip_address_id == ip.id))
    ).scalar_one()
    u, _ = await _superadmin(db_session)
    out = await acknowledge_sighting(db_session, sighting.id, u)
    assert out is not None
    assert out.classification == CLASSIFICATION_ACKNOWLEDGED
    assert out.acknowledged_by_user_id == u.id
    assert out.acknowledged_at is not None
    assert await acknowledge_sighting(db_session, uuid.uuid4(), u) is None


# ── new_mac_seen alert matcher ───────────────────────────────────────────


async def test_new_mac_seen_matcher(db_session: AsyncSession) -> None:
    subnet = await _make_subnet(db_session)

    async def _sighting(addr: str, mac: str, classification: str, *, randomized: bool) -> IPAddress:
        ip = await _ip(db_session, subnet, addr, status="dhcp")
        await db_session.flush()
        await record_mac_observation(db_session, ip.id, mac, source="dhcp_lease")
        row = (
            await db_session.execute(
                select(IpMacHistory).where(IpMacHistory.ip_address_id == ip.id)
            )
        ).scalar_one()
        row.classification = classification
        row.is_randomized = randomized
        await db_session.flush()
        return ip

    new_ip = await _sighting("10.40.1.60", "aa:bb:cc:00:03:00", "new", randomized=False)
    rand_ip = await _sighting("10.40.1.61", "02:bb:cc:00:03:01", "new", randomized=True)
    ack_ip = await _sighting("10.40.1.62", "aa:bb:cc:00:03:02", "acknowledged", randomized=False)
    await db_session.commit()

    rule = AlertRule(name="t", rule_type=RULE_TYPE_NEW_MAC_SEEN, severity="info", threshold_days=7)
    subjects = await _matching_new_mac_seen_subjects(db_session, rule)
    ids = {sid for sid, _d, _m in subjects}
    assert f"{new_ip.id}:aa:bb:cc:00:03:00" in ids  # composite subject id
    assert not any(str(rand_ip.id) in sid for sid in ids)  # randomised excluded by default
    assert not any(str(ack_ip.id) in sid for sid in ids)  # acknowledged excluded

    # classification='all' opts randomised back in.
    rule_all = AlertRule(
        name="t",
        rule_type=RULE_TYPE_NEW_MAC_SEEN,
        severity="info",
        threshold_days=7,
        classification="all",
    )
    ids_all = {sid for sid, _d, _m in await _matching_new_mac_seen_subjects(db_session, rule_all)}
    assert any(str(rand_ip.id) in sid for sid in ids_all)


# ── HTTP: lease-events → new sighting + device.first_seen ────────────────


async def _seed_dhcp(db: AsyncSession) -> tuple[DHCPServer, Subnet]:
    space = IPSpace(name=f"le-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.41.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.41.1.0/24", name="sn")
    db.add(subnet)
    server = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}", driver="kea", host="127.0.0.1", port=67, status="active"
    )
    db.add(server)
    await db.flush()
    return server, subnet


def _lease_payload(ip: str, mac: str) -> dict:
    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return {
        "leases": [
            {
                "ip_address": ip,
                "mac_address": mac,
                "hostname": "host1",
                "state": "active",
                "starts_at": datetime.now(UTC).isoformat(),
                "ends_at": end,
                "expires_at": end,
            }
        ]
    }


async def test_lease_event_creates_new_sighting(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _subnet = await _seed_dhcp(db_session)
    await _enable_watch(db_session)
    await db_session.commit()

    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post(
            "/api/v1/dhcp/agents/lease-events",
            json=_lease_payload("10.41.1.50", "aa:bb:cc:de:ad:01"),
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text

    sighting = (
        await db_session.execute(
            select(IpMacHistory).where(IpMacHistory.mac_address == "aa:bb:cc:de:ad:01")
        )
    ).scalar_one()
    assert sighting.classification == "new"
    assert sighting.source == "dhcp_lease"

    # device.first_seen audit row was written (the after-commit publisher turns
    # it into the typed event).
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "first_seen",
                    AuditLog.resource_type == "ip_mac_observation",
                )
            )
        )
        .scalars()
        .all()
    )
    assert any("aa:bb:cc:de:ad:01" in str(a.resource_id) for a in audit)


async def test_lease_event_no_sighting_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _subnet = await _seed_dhcp(db_session)
    await _disable_watch(db_session)
    await db_session.commit()

    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post(
            "/api/v1/dhcp/agents/lease-events",
            json=_lease_payload("10.41.1.51", "aa:bb:cc:de:ad:02"),
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text
    sighting = (
        await db_session.execute(
            select(IpMacHistory).where(IpMacHistory.mac_address == "aa:bb:cc:de:ad:02")
        )
    ).scalar_one_or_none()
    assert sighting is None  # zero-overhead when the feature is off


# ── HTTP: review queue + block ───────────────────────────────────────────


async def test_sightings_and_block_endpoints(client: AsyncClient, db_session: AsyncSession) -> None:
    await _enable_watch(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _ip(db_session, subnet, "10.40.1.70", status="dhcp")
    await db_session.flush()
    await record_mac_observation(db_session, ip.id, "3c:5a:b4:de:ad:10", source="dhcp_lease")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    _u, token = await _superadmin(db_session)
    await db_session.commit()

    # list sightings
    resp = await client.get("/api/v1/new-devices/sightings", headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] >= 1
    assert any(r["mac_address"] == "3c:5a:b4:de:ad:10" for r in body["items"])

    # block the MAC in all groups
    resp = await client.post(
        "/api/v1/new-devices/block",
        headers=_hdr(token),
        json={"mac_address": "3c:5a:b4:de:ad:10", "reason": "other"},
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["blocked_group_ids"]) == 1
    block = (
        await db_session.execute(
            select(DHCPMACBlock).where(DHCPMACBlock.mac_address == "3c:5a:b4:de:ad:10")
        )
    ).scalar_one()
    assert block.group_id == group.id


async def test_mac_sightings_endpoint(client: AsyncClient, db_session: AsyncSession) -> None:
    """The L2-sniffer ingest endpoint creates a discovered IPAM row + new sighting."""
    server, _subnet = await _seed_dhcp(db_session)
    await _enable_watch(db_session)
    await db_session.commit()

    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post(
            "/api/v1/dhcp/agents/mac-sightings",
            json={"sightings": [{"mac_address": "3c:5a:b4:5e:e0:01", "ip_address": "10.41.1.80"}]},
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text
    # #1077 added the shared ``status`` / ``duplicate`` ack fields.
    assert resp.json() == {"status": "ok", "duplicate": False, "recorded": 1, "new": 1}

    # A 'discovered' IPAM row was auto-created and a 'new' sighting logged.
    ip = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.41.1.80"))
    ).scalar_one()
    assert ip.status == "discovered"
    sighting = (
        await db_session.execute(
            select(IpMacHistory).where(IpMacHistory.mac_address == "3c:5a:b4:5e:e0:01")
        )
    ).scalar_one()
    assert sighting.source == "l2_sniff"
    assert sighting.classification == "new"


async def test_mac_sightings_noop_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _subnet = await _seed_dhcp(db_session)
    await _disable_watch(db_session)
    await db_session.commit()
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post(
            "/api/v1/dhcp/agents/mac-sightings",
            json={"sightings": [{"mac_address": "3c:5a:b4:5e:e0:02", "ip_address": "10.41.1.81"}]},
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text
    # #1077 added the shared ``status`` / ``duplicate`` ack fields.
    assert resp.json() == {"status": "ok", "duplicate": False, "recorded": 0, "new": 0}
    assert (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.41.1.81"))
    ).scalar_one_or_none() is None


async def test_sweep_discovered_new_row_records_sighting(db_session: AsyncSession) -> None:
    """A never-tracked host found by the ping/ARP sweep gets a sighting too — not
    just existing rows (regression guard for the new-row branch in #459)."""
    from app.services.ipam.discovery import SweepResult, reconcile_subnet

    subnet = await _make_subnet(db_session)
    await db_session.flush()
    sweep = SweepResult(
        ping_alive={"10.40.1.200"},
        arp={"10.40.1.200": "3c:5a:b4:0d:15:c0"},
    )
    counts = await reconcile_subnet(db_session, subnet, sweep)
    await db_session.flush()
    assert counts["created"] == 1

    new_row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.40.1.200"))
    ).scalar_one()
    assert new_row.status == "discovered"
    sighting = (
        await db_session.execute(
            select(IpMacHistory).where(IpMacHistory.ip_address_id == new_row.id)
        )
    ).scalar_one()
    assert sighting.mac_address == "3c:5a:b4:0d:15:c0"
    assert sighting.source == "sweep"
    assert sighting.classification == "new"


async def test_duplicate_allowlist_returns_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Allowlisting an already-allowlisted MAC is a clean 409, not a 500."""
    await _enable_watch(db_session)
    _u, token = await _superadmin(db_session)
    await db_session.commit()

    first = await client.post(
        "/api/v1/new-devices/allowlist",
        headers=_hdr(token),
        json={"mac_address": "3c:5a:b4:ab:cd:ef", "note": "trusted"},
    )
    assert first.status_code == 201, first.text
    dup = await client.post(
        "/api/v1/new-devices/allowlist",
        headers=_hdr(token),
        json={"mac_address": "3c:5a:b4:ab:cd:ef", "note": "again"},
    )
    assert dup.status_code == 409, dup.text
