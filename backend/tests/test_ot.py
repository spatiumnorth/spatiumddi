"""Industrial / OT registry + Purdue zoning tests — issue #542 (#543).

Covers the device and zone CRUD round-trips, both 1:1 constraints (one
descriptor per address, one zone per subnet), the ``Numeric(2,1)``
Purdue column — level 3.5, the manufacturing/enterprise DMZ, has to
survive a round-trip, which is exactly what an integer column would
have silently broken — the CSV importer's "enrich, never invent"
contract, and the ``network.ot`` feature-module gate.
"""

from __future__ import annotations

import csv
import uuid
from decimal import Decimal

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.ot import OTDevice, OTZone


async def _make_superadmin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


async def _make_user_with_perm(db: AsyncSession, perm: dict | None) -> tuple[User, str]:
    """Create a non-superadmin user; optionally grant ``perm`` via a
    role + group so the permission helper sees it."""
    u = User(
        username=f"user-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="User",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db.add(u)
    await db.flush()
    if perm is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=[perm])
        db.add(role)
        await db.flush()
        group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
        group.roles = [role]
        group.users = [u]
        db.add(group)
        await db.flush()
    return u, create_access_token(str(u.id))


async def _make_subnet(db: AsyncSession, network: str = "10.0.0.0/24") -> Subnet:
    """Minimum IPSpace → IPBlock → Subnet chain for a descriptor anchor."""
    space = IPSpace(name=f"ot-space-{uuid.uuid4().hex[:8]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, name="b", network="10.0.0.0/16")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, name="s", network=network)
    db.add(subnet)
    await db.flush()
    return subnet


async def _make_ip(db: AsyncSession, subnet: Subnet, addr: str) -> IPAddress:
    ip = IPAddress(subnet_id=subnet.id, address=addr, status="allocated")
    db.add(ip)
    await db.flush()
    return ip


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── Device CRUD ───────────────────────────────────────────────────────


async def test_device_crud_round_trip(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.0.0.5")
    headers = _auth(token)

    created = await client.post(
        "/api/v1/ot/devices",
        headers=headers,
        json={
            "ip_address_id": str(ip.id),
            "ot_protocol": "profinet",
            "ot_role": "plc",
            "profinet_device_name": "plc-line3-weld",
            "ot_vendor": "Siemens",
            "ot_product": "S7-1500",
            "purdue_level": "1",
            "cell_area": "Line-3 Weld",
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    device_id = body["id"]
    assert body["address"] == "10.0.0.5"
    assert body["subnet_id"] == str(subnet.id)
    assert body["purdue_level"] == "1"

    listed = await client.get("/api/v1/ot/devices", headers=headers)
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["id"] == device_id

    fetched = await client.get(f"/api/v1/ot/devices/{device_id}", headers=headers)
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["profinet_device_name"] == "plc-line3-weld"

    updated = await client.put(
        f"/api/v1/ot/devices/{device_id}",
        headers=headers,
        json={"firmware_rev": "V2.9.4", "ot_role": "hmi"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["firmware_rev"] == "V2.9.4"
    assert updated.json()["ot_role"] == "hmi"

    deleted = await client.delete(f"/api/v1/ot/devices/{device_id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    assert (await client.get(f"/api/v1/ot/devices/{device_id}", headers=headers)).status_code == 404
    assert (await db_session.scalar(select(func.count()).select_from(OTDevice))) == 0
    # Deleting the descriptor says "no longer an OT device", not "this
    # address is free" — the IPAM row is untouched.
    assert (
        await db_session.scalar(
            select(func.count()).select_from(IPAddress).where(IPAddress.id == ip.id)
        )
    ) == 1


async def test_second_descriptor_for_same_address_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The sidecar is 1:1 by construction (``uq_ot_device_ip_address``)."""
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.0.0.5")
    headers = _auth(token)

    first = await client.post(
        "/api/v1/ot/devices",
        headers=headers,
        json={"ip_address_id": str(ip.id), "ot_protocol": "profinet"},
    )
    assert first.status_code == 201, first.text

    clash = await client.post(
        "/api/v1/ot/devices",
        headers=headers,
        json={"ip_address_id": str(ip.id), "ot_protocol": "modbus_tcp"},
    )
    assert clash.status_code == 409, clash.text
    assert first.json()["id"] in clash.json()["detail"]
    assert (await db_session.scalar(select(func.count()).select_from(OTDevice))) == 1


async def test_by_address_reports_zone_and_mismatch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.0.0.5")
    headers = _auth(token)

    await client.post(
        "/api/v1/ot/devices",
        headers=headers,
        json={
            "ip_address_id": str(ip.id),
            "ot_protocol": "profinet",
            "purdue_level": "1",
        },
    )
    # No zone yet: an unknown is an unknown, never a violation.
    unzoned = await client.get(f"/api/v1/ot/by-address/{ip.id}", headers=headers)
    assert unzoned.status_code == 200, unzoned.text
    assert unzoned.json()["zone_id"] is None
    assert unzoned.json()["purdue_mismatch"] is None

    zoned_resp = await client.post(
        "/api/v1/ot/zones",
        headers=headers,
        json={"subnet_id": str(subnet.id), "purdue_level": "4", "name": "Enterprise"},
    )
    assert zoned_resp.status_code == 201, zoned_resp.text

    zoned = await client.get(f"/api/v1/ot/by-address/{ip.id}", headers=headers)
    assert zoned.status_code == 200, zoned.text
    assert zoned.json()["zone_purdue_level"] == "4"
    assert zoned.json()["purdue_mismatch"] is True


async def test_by_address_404_without_descriptor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.0.0.5")

    resp = await client.get(f"/api/v1/ot/by-address/{ip.id}", headers=_auth(token))
    assert resp.status_code == 404


# ── Zone CRUD ─────────────────────────────────────────────────────────


async def test_zone_crud_round_trip(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    headers = _auth(token)

    created = await client.post(
        "/api/v1/ot/zones",
        headers=headers,
        json={
            "subnet_id": str(subnet.id),
            "purdue_level": "2",
            "cell_area": "Line-3 Weld",
            "name": "Weld supervisory",
        },
    )
    assert created.status_code == 201, created.text
    zone_id = created.json()["id"]
    assert created.json()["purdue_level"] == "2"
    assert created.json()["subnet_network"] == "10.0.0.0/24"
    assert created.json()["device_count"] == 0

    listed = await client.get("/api/v1/ot/zones", headers=headers)
    assert listed.status_code == 200, listed.text
    assert [z["id"] for z in listed.json()] == [zone_id]

    by_subnet = await client.get(f"/api/v1/ot/zones/by-subnet/{subnet.id}", headers=headers)
    assert by_subnet.status_code == 200, by_subnet.text
    assert by_subnet.json()["id"] == zone_id

    fetched = await client.get(f"/api/v1/ot/zones/{zone_id}", headers=headers)
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["cell_area"] == "Line-3 Weld"

    updated = await client.put(
        f"/api/v1/ot/zones/{zone_id}",
        headers=headers,
        json={"purdue_level": "3", "description": "re-zoned after the cell move"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["purdue_level"] == "3"

    deleted = await client.delete(f"/api/v1/ot/zones/{zone_id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    assert (
        await client.get(f"/api/v1/ot/zones/by-subnet/{subnet.id}", headers=headers)
    ).status_code == 404
    assert (await db_session.scalar(select(func.count()).select_from(OTZone))) == 0


async def test_second_zone_for_same_subnet_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Two conflicting classifications would make every boundary report
    ambiguous, so the second declaration is a 409."""
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    headers = _auth(token)

    first = await client.post(
        "/api/v1/ot/zones",
        headers=headers,
        json={"subnet_id": str(subnet.id), "purdue_level": "2"},
    )
    assert first.status_code == 201, first.text

    clash = await client.post(
        "/api/v1/ot/zones",
        headers=headers,
        json={"subnet_id": str(subnet.id), "purdue_level": "3"},
    )
    assert clash.status_code == 409, clash.text
    assert first.json()["id"] in clash.json()["detail"]
    assert (await db_session.scalar(select(func.count()).select_from(OTZone))) == 1


# ── Purdue level 3.5 (Numeric(2,1)) ───────────────────────────────────


async def test_purdue_level_3_5_round_trips(client: AsyncClient, db_session: AsyncSession) -> None:
    """3.5 is the manufacturing/enterprise DMZ — a real level, and the
    reason the column is ``Numeric(2,1)`` rather than an integer."""
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.0.0.5")
    headers = _auth(token)

    device = await client.post(
        "/api/v1/ot/devices",
        headers=headers,
        json={
            "ip_address_id": str(ip.id),
            "ot_protocol": "opc_ua",
            "ot_role": "historian",
            "purdue_level": "3.5",
        },
    )
    assert device.status_code == 201, device.text
    assert device.json()["purdue_level"] == "3.5"
    assert (await client.get(f"/api/v1/ot/devices/{device.json()['id']}", headers=headers)).json()[
        "purdue_level"
    ] == "3.5"

    zone = await client.post(
        "/api/v1/ot/zones",
        headers=headers,
        json={"subnet_id": str(subnet.id), "purdue_level": "3.5", "name": "IDMZ"},
    )
    assert zone.status_code == 201, zone.text
    assert zone.json()["purdue_level"] == "3.5"

    # Stored value, not just the rendered string — an integer column would
    # have truncated this to 3 or 4 without anything downstream noticing.
    assert (
        await db_session.scalar(
            select(OTDevice.purdue_level).where(OTDevice.ip_address_id == ip.id)
        )
    ) == Decimal("3.5")
    assert (
        await db_session.scalar(select(OTZone.purdue_level).where(OTZone.subnet_id == subnet.id))
    ) == Decimal("3.5")

    # Device and zone agree, so the by-address verdict is "no mismatch"
    # rather than the None an unknown level would produce.
    descriptor = await client.get(f"/api/v1/ot/by-address/{ip.id}", headers=headers)
    assert descriptor.json()["purdue_mismatch"] is False

    filtered = await client.get("/api/v1/ot/devices?purdue_level=3.5", headers=headers)
    assert filtered.status_code == 200, filtered.text
    assert filtered.json()["total"] == 1


async def test_purdue_level_6_rejected(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.0.0.5")
    headers = _auth(token)

    device = await client.post(
        "/api/v1/ot/devices",
        headers=headers,
        json={"ip_address_id": str(ip.id), "ot_protocol": "profinet", "purdue_level": "6"},
    )
    assert device.status_code == 422, device.text

    zone = await client.post(
        "/api/v1/ot/zones",
        headers=headers,
        json={"subnet_id": str(subnet.id), "purdue_level": "6"},
    )
    assert zone.status_code == 422, zone.text
    assert (await db_session.scalar(select(func.count()).select_from(OTDevice))) == 0
    assert (await db_session.scalar(select(func.count()).select_from(OTZone))) == 0


# ── CSV import ────────────────────────────────────────────────────────

_IMPORT_CSV = (
    "IP address,Protocol,Role,Device name\n"
    "10.0.0.5,PROFINET,Controller,plc-line3-weld\n"
    "10.9.9.9,PROFINET,Controller,ghost-plc\n"
)

_IMPORT_COLUMN_MAP = {
    "address": "IP address",
    "ot_protocol": "Protocol",
    "ot_role": "Role",
    "profinet_device_name": "Device name",
}


async def test_import_preview_reports_unknown_addresses_without_writing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The importer enriches IPAM, it never invents it: an IP that isn't
    already allocated is a row error, not an auto-created address."""
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    await _make_ip(db_session, subnet, "10.0.0.5")
    headers = _auth(token)

    resp = await client.post(
        "/api/v1/ot/devices/import/preview",
        headers=headers,
        json={"csv_text": _IMPORT_CSV, "column_map": _IMPORT_COLUMN_MAP},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["create_count"] == 1
    assert body["error_count"] == 1
    rows = {row["address"]: row for row in body["rows"]}
    assert rows["10.0.0.5"]["action"] == "create"
    # "Controller" is a Studio 5000 spelling of a PLC.
    assert rows["10.0.0.5"]["fields"]["ot_role"] == "plc"
    assert rows["10.9.9.9"]["action"] == "error"
    assert "no IPAM address matches" in rows["10.9.9.9"]["reason"]

    # Preview is pure planning: no descriptors, and — the point of the
    # contract — no IPAM row conjured for the unknown 10.9.9.9.
    assert (await db_session.scalar(select(func.count()).select_from(OTDevice))) == 0
    assert (await db_session.scalar(select(func.count()).select_from(IPAddress))) == 1


async def test_import_commit_only_touches_existing_addresses(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    known = await _make_ip(db_session, subnet, "10.0.0.5")
    headers = _auth(token)

    resp = await client.post(
        "/api/v1/ot/devices/import/commit",
        headers=headers,
        json={"csv_text": _IMPORT_CSV, "column_map": _IMPORT_COLUMN_MAP},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["created"] == 1
    assert body["errors"] == 1
    assert body["updated"] == 0

    devices = (await db_session.execute(select(OTDevice))).scalars().all()
    assert [d.ip_address_id for d in devices] == [known.id]
    assert devices[0].seen_via == "import"
    assert devices[0].profinet_device_name == "plc-line3-weld"
    # The unknown 10.9.9.9 stayed unknown — commit creates descriptors,
    # never IPAM rows.
    assert (await db_session.scalar(select(func.count()).select_from(IPAddress))) == 1

    # Re-running without overwrite_existing skips rather than duplicating.
    again = await client.post(
        "/api/v1/ot/devices/import/commit",
        headers=headers,
        json={"csv_text": _IMPORT_CSV, "column_map": _IMPORT_COLUMN_MAP},
    )
    assert again.status_code == 201, again.text
    assert again.json()["created"] == 0
    assert again.json()["skipped"] == 1
    assert (await db_session.scalar(select(func.count()).select_from(OTDevice))) == 1


@pytest.mark.parametrize("eol", ["\n", "\r\n", "\r"], ids=["LF", "CRLF", "CR"])
async def test_import_reads_every_line_ending(
    eol: str, client: AsyncClient, db_session: AsyncSession
) -> None:
    """A device table saved with classic Mac line endings (a bare carriage
    return between rows) imports like any other (#1711, #1637). The CR
    reached the csv reader inside an unquoted field, and preview and commit
    answered 500."""
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    await _make_ip(db_session, subnet, "10.0.0.5")
    await _make_ip(db_session, subnet, "10.0.0.6")
    headers = _auth(token)
    body = {
        "csv_text": eol.join(
            [
                "IP address,Protocol,Device name",
                "10.0.0.5,PROFINET,plc-a",
                "10.0.0.6,PROFINET,plc-b",
            ]
        )
        + eol,
        "column_map": {
            "address": "IP address",
            "ot_protocol": "Protocol",
            "profinet_device_name": "Device name",
        },
    }

    preview = await client.post("/api/v1/ot/devices/import/preview", headers=headers, json=body)
    assert preview.status_code == 200, preview.text
    assert [(r["address"], r["action"]) for r in preview.json()["rows"]] == [
        ("10.0.0.5", "create"),
        ("10.0.0.6", "create"),
    ]

    commit = await client.post("/api/v1/ot/devices/import/commit", headers=headers, json=body)
    assert commit.status_code == 201, commit.text
    assert commit.json()["created"] == 2
    assert (await db_session.scalar(select(func.count()).select_from(OTDevice))) == 2


async def test_import_answers_422_when_the_csv_reader_refuses_the_text(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Whatever else the csv reader refuses is a 422 that says why, not a
    500 (#1711): here a cell over the reader's field size limit."""
    _, token = await _make_superadmin(db_session)
    resp = await client.post(
        "/api/v1/ot/devices/import/preview",
        headers=_auth(token),
        json={
            "csv_text": "IP address,Notes\n10.0.0.5," + "x" * (csv.field_size_limit() + 1) + "\n",
            "column_map": {"address": "IP address"},
        },
    )
    assert resp.status_code == 422, resp.text[:300]
    assert resp.json()["detail"].startswith("CSV could not be read"), resp.json()["detail"]


async def test_import_rejects_unmapped_column(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A typo'd mapping must not look like a successful import that
    quietly dropped a column."""
    _, token = await _make_superadmin(db_session)

    resp = await client.post(
        "/api/v1/ot/devices/import/preview",
        headers=_auth(token),
        json={
            "csv_text": _IMPORT_CSV,
            "column_map": dict(_IMPORT_COLUMN_MAP, ot_vendor="Manufacturer"),
        },
    )
    assert resp.status_code == 422, resp.text
    assert "Manufacturer" in resp.json()["detail"]


# ── Permission gate ───────────────────────────────────────────────────


async def test_read_permission_does_not_grant_write(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user_with_perm(
        db_session, {"action": "read", "resource_type": "ot_device"}
    )
    subnet = await _make_subnet(db_session)
    headers = _auth(token)

    assert (await client.get("/api/v1/ot/devices", headers=headers)).status_code == 200
    denied = await client.post(
        "/api/v1/ot/zones",
        headers=headers,
        json={"subnet_id": str(subnet.id), "purdue_level": "2"},
    )
    assert denied.status_code == 403, denied.text


# ── Feature-module gate ───────────────────────────────────────────────


async def test_disabled_module_returns_404(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)

    await db_session.execute(
        text(
            "INSERT INTO feature_module (id, enabled) VALUES (:id, false) "
            "ON CONFLICT (id) DO UPDATE SET enabled = false"
        ).bindparams(id="network.ot")
    )
    await db_session.commit()

    from app.services.feature_modules import invalidate_cache

    invalidate_cache()
    try:
        resp = await client.get("/api/v1/ot/devices", headers=_auth(token))
        assert resp.status_code == 404
    finally:
        await db_session.execute(
            text("UPDATE feature_module SET enabled = true WHERE id = :id").bindparams(
                id="network.ot"
            )
        )
        await db_session.commit()
        invalidate_cache()
