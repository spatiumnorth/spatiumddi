"""#5022 phase 1 — optional built-in icons on IP addresses and DNS records.

Covers the catalog and its validation, the resolution order (explicit, then
device class, then IP role for an address; explicit, then the linked address for
a record), every route that takes or returns an icon (create / update / bulk
edit / list / export / import / defaults / catalog), the audit rows, the
Trash cases, permissions, and the Copilot tools against the REST behaviour.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import IPAddressResponse
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.dns import DNSRecord, DNSRecordOp
from app.models.icon import IconDefault
from app.models.ipam import IPAddress
from app.services import icons as icon_svc
from app.services.ai.operations import get_operation
from app.services.ai.tools import REGISTRY
from app.services.ai.tools.icons import FindIconsArgs, ProposeSetIconArgs
from tests.test_subnet_trash_retracts_dns_1906 import _address, _admin_headers, _setup

# ── Catalog + validation (no database) ───────────────────────────────────


def test_catalog_validates_names_and_excludes_brand_logos() -> None:
    assert icon_svc.is_valid_icon("mdi:printer")
    assert icon_svc.is_valid_icon("mdi:router-wireless")
    assert not icon_svc.is_valid_icon("mdi:printr")  # a typo is not a blank cell
    assert not icon_svc.is_valid_icon("printer")  # the namespace is required
    assert not icon_svc.is_valid_icon("lucide:printer")
    # Brand logos are deprecated in the set's metadata and left out.
    assert not icon_svc.is_valid_icon("mdi:github")
    assert not icon_svc.is_valid_icon("mdi:microsoft-windows")


def test_every_shipped_default_is_a_catalog_icon() -> None:
    for kind, mapping in icon_svc.SHIPPED_DEFAULTS.items():
        for match, icon in mapping.items():
            assert icon_svc.is_valid_icon(icon), (kind, match, icon)
            assert match == icon_svc.normalise_match(match), (kind, match)


def test_validate_icon_shapes() -> None:
    assert icon_svc.validate_icon(None) is None
    assert icon_svc.validate_icon("") is None
    assert icon_svc.validate_icon("  mdi:printer ") == "mdi:printer"
    assert icon_svc.validate_icon(7) == 7  # core validation 422s a non-string
    with pytest.raises(ValueError, match="unknown icon"):
        icon_svc.validate_icon("mdi:nope-nope")
    with pytest.raises(ValueError, match="built-in icon"):
        icon_svc.validate_icon("custom:abc")


def test_search_ranks_name_prefix_first_and_finds_by_tag() -> None:
    hits = [e.name for e in icon_svc.search_catalog("printer")]
    assert hits[0] == "mdi:printer"
    assert "mdi:printer-3d" in hits
    assert icon_svc.search_catalog("zzzzqqqq") == []
    assert len(icon_svc.search_catalog(None)) > 7000


# ── Resolution order (no database) ───────────────────────────────────────


def test_ip_resolution_order() -> None:
    r = icon_svc.resolve_ip_icon
    # explicit wins over everything
    assert r(icon="mdi:lock", device_class="Printer", device_type=None, role="gateway") == (
        "mdi:lock",
        "explicit",
    )
    # device class beats role; case-insensitive and alias-aware
    assert r(icon=None, device_class="PRINTER or Scanner", device_type=None, role="gateway") == (
        "mdi:printer",
        "device_class",
    )
    # device_type is the second device-class candidate
    assert r(icon=None, device_class=None, device_type="Smartphones", role=None) == (
        "mdi:cellphone",
        "device_class",
    )
    # role default when no class matches
    assert r(icon=None, device_class="Mystery Box", device_type=None, role="gateway") == (
        "mdi:router-network",
        "ip_role",
    )
    # nothing: an ordinary host with an unknown class gets no icon, not a placeholder
    assert r(icon=None, device_class="Mystery Box", device_type=None, role="host") == (
        None,
        "none",
    )


def test_record_resolution_order() -> None:
    linked = icon_svc.ResolvedIcon("mdi:printer", "device_class")
    assert icon_svc.resolve_record_icon(icon="mdi:lock", linked=linked) == ("mdi:lock", "explicit")
    assert icon_svc.resolve_record_icon(icon=None, linked=linked) == ("mdi:printer", "linked_ip")
    assert icon_svc.resolve_record_icon(icon=None, linked=None) == (None, "none")
    assert icon_svc.resolve_record_icon(icon=None, linked=icon_svc.NO_ICON) == (None, "none")


def test_overrides_beat_the_shipped_mapping_and_reset() -> None:
    icon_svc.set_overrides([("device_class", "printer", "mdi:fax")])
    try:
        assert icon_svc.default_icon_for("device_class", " Printer ") == "mdi:fax"
        assert icon_svc.default_icon_for("device_class", "scanner") == "mdi:scanner"
    finally:
        icon_svc.reset_overrides()
    assert icon_svc.default_icon_for("device_class", "printer") == "mdi:printer"


def test_response_schema_resolves_without_a_database() -> None:
    from datetime import UTC, datetime

    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "subnet_id": uuid.uuid4(),
        "address": "10.0.0.1",
        "status": "allocated",
        "hostname": None,
        "fqdn": None,
        "mac_address": None,
        "description": "",
        "owner_user_id": None,
        "last_seen_at": None,
        "last_seen_method": None,
        "custom_fields": {},
        "tags": {},
        "created_at": datetime.now(UTC),
        "modified_at": datetime.now(UTC),
    }
    out = IPAddressResponse(**base, role="bmc")
    assert (out.icon, out.effective_icon, out.icon_source) == (None, "mdi:chip", "ip_role")
    out = IPAddressResponse(**base, role="bmc", icon="mdi:lock")
    assert (out.effective_icon, out.icon_source) == ("mdi:lock", "explicit")


# ── Helpers ──────────────────────────────────────────────────────────────


async def _user_headers(
    db: AsyncSession, perms: list[dict[str, str]], *, superadmin: bool = False
) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"ic-{tag}",
        email=f"{tag}@example.test",
        display_name="Icon user",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    role = Role(name=f"r-{tag}", description="", permissions=perms)
    group = Group(name=f"g-{tag}", description="")
    group.roles = [role]
    group.users = [user]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _audit(db: AsyncSession, resource_type: str, rid: str | None = None) -> list[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.resource_type == resource_type)
    if rid is not None:
        stmt = stmt.where(AuditLog.resource_id == rid)
    return list((await db.execute(stmt.order_by(AuditLog.timestamp))).scalars().all())


async def _row(db: AsyncSession, ip_id: str) -> IPAddress:
    return (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.id == uuid.UUID(ip_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


@pytest.fixture
async def world(client: AsyncClient, db_session: AsyncSession) -> dict[str, Any]:
    headers = await _admin_headers(db_session)
    grp, server, zone, sid, _ = await _setup(
        client, db_session, headers, "10.150.1.0/24", None, "10.150.0.0/16"
    )
    return {"h": headers, "grp": grp, "server": server, "zone": zone, "sid": sid}


# ── IP address routes ────────────────────────────────────────────────────


async def test_create_address_with_icon_and_bad_names(
    client: AsyncClient, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": "10.150.1.10", "hostname": "pr1", "icon": "mdi:printer"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert (body["icon"], body["effective_icon"], body["icon_source"]) == (
        "mdi:printer",
        "mdi:printer",
        "explicit",
    )
    # a typo is a 422 naming the problem, never a 500
    bad = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": "10.150.1.11", "hostname": "pr2", "icon": "mdi:printr"},
    )
    assert bad.status_code == 422
    assert "unknown icon" in bad.text
    for junk in ("lucide:printer", ["mdi:printer"], 5):
        r = await client.post(
            f"/api/v1/ipam/subnets/{sid}/addresses",
            headers=h,
            json={"address": "10.150.1.12", "hostname": "pr3", "icon": junk},
        )
        assert r.status_code == 422, (junk, r.text)


async def test_update_sets_and_clears_icon_without_locking_the_row(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    ip_id = await _address(client, h, sid, "10.150.1.20", "cam1")
    assert (await _row(db_session, ip_id)).user_modified_at is None

    r = await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=h, json={"icon": "mdi:cctv"})
    assert r.status_code == 200, r.text
    assert r.json()["effective_icon"] == "mdi:cctv"
    row = await _row(db_session, ip_id)
    assert row.icon == "mdi:cctv"
    # an icon is not a soft field: an integration reconciler may still own the row
    assert row.user_modified_at is None

    audits = [a for a in await _audit(db_session, "ip_address", ip_id) if a.action == "update"]
    assert audits[-1].old_value["icon"] is None
    assert audits[-1].new_value["icon"] == "mdi:cctv"

    # null and "" both clear it back to automatic
    for clear in (None, ""):
        await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=h, json={"icon": "mdi:lock"})
        r = await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=h, json={"icon": clear})
        assert r.status_code == 200, r.text
        assert r.json()["icon"] is None
        assert r.json()["icon_source"] == "none"
    audits = [a for a in await _audit(db_session, "ip_address", ip_id) if a.action == "update"]
    assert audits[-1].old_value["icon"] == "mdi:lock"
    assert audits[-1].new_value["icon"] is None

    bad = await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=h, json={"icon": "mdi:zzz"})
    assert bad.status_code == 422


async def test_default_icons_from_device_class_and_role_in_every_read(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    ip_id = await _address(client, h, sid, "10.150.1.30", "box1", role="gateway")
    got = (await client.get(f"/api/v1/ipam/addresses/{ip_id}", headers=h)).json()
    assert (got["icon"], got["effective_icon"], got["icon_source"]) == (
        None,
        "mdi:router-network",
        "ip_role",
    )
    row = await _row(db_session, ip_id)
    row.device_class = "Printer or Scanner"
    await db_session.commit()
    for url in (
        f"/api/v1/ipam/addresses/{ip_id}",
        f"/api/v1/ipam/subnets/{sid}/addresses",
        "/api/v1/ipam/addresses/search?q=box1",
    ):
        data = (await client.get(url, headers=h)).json()
        item = data["items"][0] if isinstance(data, dict) and "items" in data else data
        if isinstance(item, list):
            item = next(i for i in item if i["id"] == ip_id)
        assert item["effective_icon"] == "mdi:printer", url
        assert item["icon_source"] == "device_class", url
        assert item["icon"] is None, url  # the explicit column stays empty


async def test_bulk_edit_sets_and_clears_with_audit(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    a = await _address(client, h, sid, "10.150.1.40", "b1")
    b = await _address(client, h, sid, "10.150.1.41", "b2")
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=h,
        json={"ip_ids": [a, b], "changes": {"icon": "mdi:nas"}},
    )
    assert r.status_code == 200, r.text
    assert r.json()["updated_count"] == 2
    assert (await _row(db_session, a)).icon == (await _row(db_session, b)).icon == "mdi:nas"
    assert (await _row(db_session, a)).user_modified_at is None
    last = (await _audit(db_session, "ip_address", a))[-1]
    assert last.old_value["icon"] is None
    assert last.new_value["icon"] == "mdi:nas"

    r = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=h,
        json={"ip_ids": [a, b], "changes": {"icon": ""}},
    )
    assert r.status_code == 200, r.text
    assert (await _row(db_session, a)).icon is None
    bad = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=h,
        json={"ip_ids": [a], "changes": {"icon": "mdi:nonsense"}},
    )
    assert bad.status_code == 422


async def test_next_address_accepts_an_icon(client: AsyncClient, world: dict[str, Any]) -> None:
    h, sid = world["h"], world["sid"]
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=h,
        json={"hostname": "auto1", "icon": "mdi:speaker"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["icon"] == "mdi:speaker"


async def test_icon_writes_need_the_existing_write_permission(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    ip_id = await _address(client, world["h"], world["sid"], "10.150.1.50", "perm1")
    reader = await _user_headers(db_session, [{"action": "read", "resource_type": "*"}])
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=reader, json={"icon": "mdi:lock"}
    )
    assert r.status_code == 403
    assert (await _row(db_session, ip_id)).icon is None
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=reader,
        json={"ip_ids": [ip_id], "changes": {"icon": "mdi:lock"}},
    )
    assert r.status_code == 403
    editor = await _user_headers(db_session, [{"action": "admin", "resource_type": "*"}])
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=editor, json={"icon": "mdi:lock"}
    )
    assert r.status_code == 200, r.text
    # unknown id
    r = await client.put(
        f"/api/v1/ipam/addresses/{uuid.uuid4()}", headers=world["h"], json={"icon": "mdi:lock"}
    )
    assert r.status_code == 404


# ── Export / import round trip ───────────────────────────────────────────


async def test_export_carries_only_the_explicit_icon_and_import_restores_it(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    await _address(client, h, sid, "10.150.1.60", "x1", icon="mdi:printer")
    auto = await _address(client, h, sid, "10.150.1.61", "x2", role="gateway")
    assert auto  # automatic icon, must not be pinned by an export

    r = await client.get(
        f"/api/v1/ipam/export?subnet_id={sid}&format=csv&include_addresses=true", headers=h
    )
    assert r.status_code == 200, r.text
    rows = {
        row["address"]: row
        for row in csv.DictReader(io.StringIO(r.text))
        if row.get("address") and row.get("hostname") in ("x1", "x2")
    }
    assert rows["10.150.1.60"]["icon"] == "mdi:printer"
    assert rows["10.150.1.61"]["icon"] == ""
    j = (
        await client.get(
            f"/api/v1/ipam/export?subnet_id={sid}&format=json&include_addresses=true", headers=h
        )
    ).json()
    assert {a["address"]: a["icon"] for a in j["addresses"] if a["hostname"] in ("x1", "x2")} == {
        "10.150.1.60": "mdi:printer",
        "10.150.1.61": None,
    }

    # delete the explicit row, then import the CSV back: the icon returns
    gone = str(
        (
            await db_session.execute(select(IPAddress.id).where(IPAddress.hostname == "x1"))
        ).scalar_one()
    )
    d = await client.delete(f"/api/v1/ipam/addresses/{gone}?permanent=true", headers=h)
    assert d.status_code in (200, 204), d.text
    imp = await client.post(
        "/api/v1/ipam/import/addresses/commit",
        headers=h,
        data={"subnet_id": sid, "strategy": "skip"},
        files={"file": ("a.csv", r.text.encode(), "text/csv")},
    )
    assert imp.status_code == 200, imp.text
    back = (
        await db_session.execute(
            select(IPAddress)
            .where(IPAddress.hostname == "x1")
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert back.icon == "mdi:printer"


async def test_import_refuses_an_unknown_icon_per_row(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    csv_text = "address,hostname,icon\n10.150.1.70,imp1,mdi:printer\n10.150.1.71,imp2,mdi:nope\n"
    imp = await client.post(
        "/api/v1/ipam/import/addresses/commit",
        headers=h,
        data={"subnet_id": sid, "strategy": "skip"},
        files={"file": ("a.csv", csv_text.encode(), "text/csv")},
    )
    assert imp.status_code == 200, imp.text
    got = {
        r.hostname: r.icon
        for r in (
            await db_session.execute(
                select(IPAddress)
                .where(IPAddress.hostname.in_(["imp1", "imp2"]))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    }
    assert got == {"imp1": "mdi:printer"}
    assert any("mdi:nope" in e for e in imp.json()["errors"]), imp.text


# ── DNS records ──────────────────────────────────────────────────────────


def _rec_url(w: dict[str, Any], rid: str | None = None) -> str:
    base = f"/api/v1/dns/groups/{w['grp'].id}/zones/{w['zone'].id}/records"
    return base + (f"/{rid}" if rid else "")


async def _ops(db: AsyncSession) -> int:
    return len((await db.execute(select(DNSRecordOp))).scalars().all())


async def test_record_icon_create_update_clear_is_display_only(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h = world["h"]
    r = await client.post(
        _rec_url(world),
        headers=h,
        json={"name": "web", "record_type": "A", "value": "10.150.9.9", "icon": "mdi:web"},
    )
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert (r.json()["icon"], r.json()["effective_icon"], r.json()["icon_source"]) == (
        "mdi:web",
        "mdi:web",
        "explicit",
    )
    create_audit = (await _audit(db_session, "dns_record", rid))[-1]
    assert create_audit.new_value == {"icon": "mdi:web"}

    zone = world["zone"]
    await db_session.refresh(zone)
    serial, ops = zone.last_serial, await _ops(db_session)

    r = await client.put(_rec_url(world, rid), headers=h, json={"icon": "mdi:server"})
    assert r.status_code == 200, r.text
    assert r.json()["effective_icon"] == "mdi:server"
    await db_session.refresh(zone)
    # an icon is not DNS data: no serial bump, no op for an agent or provider
    assert zone.last_serial == serial
    assert await _ops(db_session) == ops
    last = (await _audit(db_session, "dns_record", rid))[-1]
    assert last.old_value == {"icon": "mdi:web"}
    assert last.new_value == {"icon": "mdi:server"}
    assert last.changed_fields == ["icon"]

    # mixed with a real change it still audits old and new, and still queues the op
    r = await client.put(
        _rec_url(world, rid), headers=h, json={"icon": None, "value": "10.150.9.10"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["icon"] is None
    assert await _ops(db_session) > ops
    last = (await _audit(db_session, "dns_record", rid))[-1]
    assert last.old_value == {"icon": "mdi:server"}
    assert last.new_value == {"icon": None}

    bad = await client.put(_rec_url(world, rid), headers=h, json={"icon": "mdi:nonsense"})
    assert bad.status_code == 422
    bad = await client.post(
        _rec_url(world),
        headers=h,
        json={"name": "w2", "record_type": "A", "value": "10.150.9.11", "icon": "x"},
    )
    assert bad.status_code == 422
    # unknown record
    assert (
        await client.put(_rec_url(world, str(uuid.uuid4())), headers=h, json={"icon": "mdi:web"})
    ).status_code == 404


async def test_record_follows_the_linked_address_until_it_sets_its_own(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    ip_id = await _address(client, h, sid, "10.150.1.80", "linked1", icon="mdi:printer")
    rec = (
        await db_session.execute(
            select(DNSRecord).where(
                DNSRecord.ip_address_id == uuid.UUID(ip_id), DNSRecord.record_type == "A"
            )
        )
    ).scalar_one()

    def page() -> Any:
        return client.get(_rec_url(world), headers=h)

    items = {i["id"]: i for i in (await page()).json()["items"]}
    assert items[str(rec.id)]["icon"] is None
    assert items[str(rec.id)]["effective_icon"] == "mdi:printer"
    assert items[str(rec.id)]["icon_source"] == "linked_ip"

    # the address's own automatic icon is what the record shows when none is explicit
    await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=h, json={"icon": None})
    row = await _row(db_session, ip_id)
    row.role = "gateway"
    await db_session.commit()
    items = {i["id"]: i for i in (await page()).json()["items"]}
    assert items[str(rec.id)]["effective_icon"] == "mdi:router-network"
    assert items[str(rec.id)]["icon_source"] == "linked_ip"

    # explicit beats the link
    r = await client.put(_rec_url(world, str(rec.id)), headers=h, json={"icon": "mdi:lock"})
    assert (r.json()["effective_icon"], r.json()["icon_source"]) == ("mdi:lock", "explicit")
    # and the PUT response of a record with none follows the link too
    await client.put(_rec_url(world, str(rec.id)), headers=h, json={"icon": None})
    r = await client.put(_rec_url(world, str(rec.id)), headers=h, json={"icon": ""})
    assert (r.json()["effective_icon"], r.json()["icon_source"]) == (
        "mdi:router-network",
        "linked_ip",
    )


async def test_trashed_subnet_does_not_feed_a_live_records_icon(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    ip_id = await _address(client, h, sid, "10.150.1.90", "trashlink", icon="mdi:printer")
    rec = (
        await db_session.execute(
            select(DNSRecord).where(
                DNSRecord.ip_address_id == uuid.UUID(ip_id), DNSRecord.record_type == "A"
            )
        )
    ).scalar_one()
    # Hide the subnet the way Trash does, but keep the record live: the address
    # row is still in the table, and must not feed the live record's icon.
    from app.models.ipam import Subnet

    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.id == uuid.UUID(sid)))
    ).scalar_one()
    from datetime import UTC, datetime

    subnet.deleted_at = datetime.now(UTC)
    await db_session.commit()
    items = {i["id"]: i for i in (await client.get(_rec_url(world), headers=h)).json()["items"]}
    if str(rec.id) in items:  # the live record is still listed
        assert items[str(rec.id)]["effective_icon"] is None
        assert items[str(rec.id)]["icon_source"] == "none"


async def test_trashed_record_keeps_its_icon_on_restore_and_is_not_listed(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h = world["h"]
    r = await client.post(
        _rec_url(world),
        headers=h,
        json={"name": "tr", "record_type": "A", "value": "10.150.9.50", "icon": "mdi:cctv"},
    )
    rid = r.json()["id"]
    d = await client.delete(_rec_url(world, rid), headers=h)
    assert d.status_code == 204, d.text
    ids = [i["id"] for i in (await client.get(_rec_url(world), headers=h)).json()["items"]]
    assert rid not in ids
    res = await client.post(f"/api/v1/admin/trash/dns_record/{rid}/restore", headers=h)
    assert res.status_code == 200, res.text
    items = {i["id"]: i for i in (await client.get(_rec_url(world), headers=h)).json()["items"]}
    assert items[rid]["icon"] == "mdi:cctv"
    assert items[rid]["effective_icon"] == "mdi:cctv"


async def test_record_icon_needs_dns_record_write(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    r = await client.post(
        _rec_url(world),
        headers=world["h"],
        json={"name": "pp", "record_type": "A", "value": "10.150.9.60"},
    )
    rid = r.json()["id"]
    reader = await _user_headers(db_session, [{"action": "read", "resource_type": "*"}])
    denied = await client.put(_rec_url(world, rid), headers=reader, json={"icon": "mdi:web"})
    assert denied.status_code == 403
    rec = (
        await db_session.execute(
            select(DNSRecord)
            .where(DNSRecord.id == uuid.UUID(rid))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert rec.icon is None


# ── /icons/catalog and /icons/defaults ───────────────────────────────────


async def test_catalog_route_pages_and_searches(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user_headers(db_session, [])  # any signed-in user, no grants at all
    r = await client.get("/api/v1/icons/catalog?q=printer&page_size=5", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items", "total", "page", "page_size"}
    assert body["items"][0] == {"name": "mdi:printer", "label": "Printer"}
    assert len(body["items"]) == 5
    assert body["total"] > 5
    p2 = (await client.get("/api/v1/icons/catalog?q=printer&page_size=5&page=2", headers=h)).json()
    assert p2["items"][0]["name"] != body["items"][0]["name"]
    empty = (await client.get("/api/v1/icons/catalog?q=zzzzqq", headers=h)).json()
    assert empty["items"] == [] and empty["total"] == 0
    assert (await client.get("/api/v1/icons/catalog?page=0", headers=h)).status_code == 422
    assert (await client.get("/api/v1/icons/catalog")).status_code in (401, 403)


async def test_defaults_routes_permissions_and_audit(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    admin = world["h"]
    reader = await _user_headers(db_session, [])
    r = await client.get("/api/v1/icons/defaults", headers=reader)
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert {i["kind"] for i in items} == {"device_class", "ip_role", "network_device_type"}
    assert not any(i["overridden"] for i in items)
    printer = next(i for i in items if i["match_value"] == "printer")
    assert printer == {
        "kind": "device_class",
        "match_value": "printer",
        "icon": "mdi:printer",
        "default_icon": "mdi:printer",
        "overridden": False,
    }
    assert (await client.get("/api/v1/icons/defaults")).status_code in (401, 403)

    body = {"kind": "device_class", "match_value": "  Printer ", "icon": "mdi:fax"}
    # a plain user (and one holding only icon read) cannot change a mapping
    for who in (
        reader,
        await _user_headers(db_session, [{"action": "read", "resource_type": "icon"}]),
    ):
        assert (
            await client.put("/api/v1/icons/defaults", headers=who, json=body)
        ).status_code == 403
        assert (
            await client.delete(
                "/api/v1/icons/defaults?kind=device_class&match_value=printer", headers=who
            )
        ).status_code == 403
    assert (await db_session.execute(select(IconDefault))).scalars().all() == []

    ok = await client.put("/api/v1/icons/defaults", headers=admin, json=body)
    assert ok.status_code == 200, ok.text
    assert ok.json() == {
        "kind": "device_class",
        "match_value": "printer",
        "icon": "mdi:fax",
        "default_icon": "mdi:printer",
        "overridden": True,
    }
    audit = (await _audit(db_session, "icon_default"))[-1]
    assert audit.old_value == {"icon": "mdi:printer"}
    assert audit.new_value == {"icon": "mdi:fax"}

    # an IP with that device class now resolves to the operator's icon
    ip_id = await _address(client, admin, world["sid"], "10.150.1.100", "ovr1")
    row = await _row(db_session, ip_id)
    row.device_class = "printer"
    await db_session.commit()
    got = (await client.get(f"/api/v1/ipam/addresses/{ip_id}", headers=admin)).json()
    assert (got["effective_icon"], got["icon_source"]) == ("mdi:fax", "device_class")

    # an operator-added mapping for a new match value, listed with no shipped default
    add = await client.put(
        "/api/v1/icons/defaults",
        headers=admin,
        json={"kind": "device_class", "match_value": "Label Maker", "icon": "mdi:label"},
    )
    assert add.status_code == 200, add.text
    assert add.json()["default_icon"] is None

    # PUT back to the shipped icon is not an override: the row goes away
    back = await client.put(
        "/api/v1/icons/defaults",
        headers=admin,
        json={"kind": "device_class", "match_value": "printer", "icon": "mdi:printer"},
    )
    assert back.json()["overridden"] is False
    rows = (await db_session.execute(select(IconDefault))).scalars().all()
    assert [r.match_value for r in rows] == ["label maker"]

    # reset / remove
    assert (
        await client.delete(
            "/api/v1/icons/defaults?kind=device_class&match_value=Label%20Maker", headers=admin
        )
    ).status_code == 204
    assert (await db_session.execute(select(IconDefault))).scalars().all() == []
    assert (await _audit(db_session, "icon_default"))[-1].action == "delete"
    # shipped and untouched: nothing to reset; unknown: 404; bad kind / icon: 422
    assert (
        await client.delete(
            "/api/v1/icons/defaults?kind=ip_role&match_value=gateway", headers=admin
        )
    ).status_code == 409
    assert (
        await client.delete(
            "/api/v1/icons/defaults?kind=ip_role&match_value=nothing-like-it", headers=admin
        )
    ).status_code == 404
    for bad in (
        {"kind": "nope", "match_value": "x", "icon": "mdi:fax"},
        {"kind": "ip_role", "match_value": "x", "icon": "mdi:nope"},
        {"kind": "ip_role", "match_value": "x", "icon": ""},
        {"kind": "ip_role", "match_value": "  ", "icon": "mdi:fax"},
    ):
        assert (
            await client.put("/api/v1/icons/defaults", headers=admin, json=bad)
        ).status_code == 422, bad


def test_openapi_documents_the_icon_surface() -> None:
    from app.main import app

    spec = app.openapi()
    props = spec["components"]["schemas"]["IPAddressResponse"]["properties"]
    assert {"icon", "effective_icon", "icon_source"} <= set(props)
    rec = spec["components"]["schemas"]["RecordResponse"]["properties"]
    assert {"icon", "effective_icon", "icon_source"} <= set(rec)
    for schema in ("IPAddressCreate", "IPAddressUpdate", "RecordCreate", "RecordUpdate"):
        assert "icon" in spec["components"]["schemas"][schema]["properties"], schema
    assert "icon" in spec["components"]["schemas"]["IPAddressBulkChanges"]["properties"]
    paths = spec["paths"]
    assert {"get", "put", "delete"} <= set(paths["/api/v1/icons/defaults"])
    assert "get" in paths["/api/v1/icons/catalog"]
    ok = paths["/api/v1/icons/catalog"]["get"]["responses"]["200"]["content"]["application/json"]
    assert "Page_IconCatalogItem_" in json.dumps(ok)


# ── Copilot tools ────────────────────────────────────────────────────────


def _tool(name: str) -> Any:
    tool = REGISTRY.get(name)
    assert tool is not None, name
    return tool


def test_tools_registered_default_enabled_and_module_less() -> None:
    for name in ("find_icons", "propose_set_icon"):
        tool = REGISTRY.get(name)
        assert tool is not None, name
        assert tool.default_enabled is True
        assert tool.module is None
    assert _tool("find_icons").writes is False
    assert _tool("propose_set_icon").writes is False  # the Apply is the write
    assert get_operation("set_ip_address_icon") is not None
    assert get_operation("set_dns_record_icon") is not None


async def test_find_icons_tool_matches_the_rest_catalog(db_session: AsyncSession) -> None:
    user = await _plain_user(db_session)
    out = await _tool("find_icons").executor(db_session, user, FindIconsArgs(q="printer", limit=3))
    assert out["icons"][0] == {"name": "mdi:printer", "label": "Printer"}
    assert out["returned"] == 3 and out["total"] > 3


async def _plain_user(db: AsyncSession, *, superadmin: bool = True) -> User:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"t-{tag}",
        email=f"{tag}@example.test",
        display_name="tool user",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user


async def test_find_tools_carry_effective_icon_like_rest(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    ip_id = await _address(client, h, sid, "10.150.1.110", "mcp1", role="bmc")
    user = await _plain_user(db_session)
    rest = (await client.get(f"/api/v1/ipam/addresses/{ip_id}", headers=h)).json()
    one = await _tool("find_ip").executor(
        db_session, user, _tool("find_ip").args_model(address="10.150.1.110")
    )
    assert one["matches"][0]["effective_icon"] == rest["effective_icon"] == "mdi:chip"
    many = await _tool("find_ip_addresses").executor(
        db_session, user, _tool("find_ip_addresses").args_model(q="mcp1")
    )
    assert many["matches"][0]["effective_icon"] == "mdi:chip"
    assert many["matches"][0]["icon"] is None

    rec = await client.post(
        _rec_url(world),
        headers=h,
        json={"name": "mcp", "record_type": "A", "value": "10.150.9.70", "icon": "mdi:web"},
    )
    out = await _tool("query_dns_records").executor(
        db_session, user, _tool("query_dns_records").args_model(name="mcp")
    )
    assert [r["effective_icon"] for r in out if r["id"] == rec.json()["id"]] == ["mdi:web"]


async def test_propose_set_icon_stages_then_apply_matches_the_rest_edit(
    client: AsyncClient, db_session: AsyncSession, world: dict[str, Any]
) -> None:
    h, sid = world["h"], world["sid"]
    ip_id = await _address(client, h, sid, "10.150.1.120", "prop1")
    user = await _plain_user(db_session)
    tool = _tool("propose_set_icon")

    # nothing is written by proposing
    out = await tool.executor(
        db_session, user, ProposeSetIconArgs(target="ip_address", id=ip_id, icon="mdi:lock")
    )
    assert out["kind"] == "proposal", out
    assert (await _row(db_session, ip_id)).icon is None

    op = get_operation("set_ip_address_icon")
    assert op is not None
    res = await op.apply(db_session, user, op.args_model(address_id=ip_id, icon="mdi:lock"))
    assert res["changed"] is True
    row = await _row(db_session, ip_id)
    assert row.icon == "mdi:lock" and row.user_modified_at is None
    last = (await _audit(db_session, "ip_address", ip_id))[-1]
    assert last.old_value == {"icon": None}
    assert last.new_value["icon"] == "mdi:lock"
    rest = (await client.get(f"/api/v1/ipam/addresses/{ip_id}", headers=h)).json()
    assert rest["effective_icon"] == "mdi:lock"

    # a bad name or an unknown id is refused at propose time, not staged
    bad = await tool.executor(
        db_session, user, ProposeSetIconArgs(target="ip_address", id=ip_id, icon="mdi:zz")
    )
    assert "error" in bad
    missing = await tool.executor(
        db_session,
        user,
        ProposeSetIconArgs(target="ip_address", id=str(uuid.uuid4()), icon="mdi:lock"),
    )
    assert missing["kind"] == "proposal_rejected"

    # the record flavour, and a user without dns_record write is refused
    r = await client.post(
        _rec_url(world),
        headers=h,
        json={"name": "p2", "record_type": "A", "value": "10.150.9.80"},
    )
    rid = r.json()["id"]
    rop = get_operation("set_dns_record_icon")
    assert rop is not None
    nobody = await _plain_user(db_session, superadmin=False)
    refused = await tool.executor(
        db_session, nobody, ProposeSetIconArgs(target="dns_record", id=rid, icon="mdi:web")
    )
    assert refused["kind"] == "proposal_rejected"
    ok = await rop.apply(db_session, user, rop.args_model(record_id=rid, icon="mdi:web"))
    assert ok["changed"] is True
    shown = (await client.get(_rec_url(world), headers=h)).json()["items"]
    assert [i["effective_icon"] for i in shown if i["id"] == rid] == ["mdi:web"]
    with pytest.raises(ValidationError):
        rop.args_model(record_id=rid, icon="mdi:zz")
