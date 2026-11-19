"""End-to-end tests for DNS zone bulk import/export endpoints."""

from __future__ import annotations

import io
import zipfile

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone

ZONE_TEXT = """\
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. hostmaster.example.com. ( 1 86400 7200 3600000 3600 )
@   IN NS  ns1.example.com.
@   IN A   192.0.2.1
www IN A   192.0.2.10
mail IN AAAA 2001:db8::25
@   IN MX  10 mail.example.com.
_sip._tcp IN SRV 10 60 5060 sipserver.example.com.
txt IN TXT "hello world"
"""


async def _admin_auth(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="dnsadmin",
        email="dns@example.com",
        display_name="DNS Admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _make_zone(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone]:
    group = DNSServerGroup(name="test-group", description="")
    db.add(group)
    await db.flush()
    zone = DNSZone(
        group_id=group.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
        last_serial=1,
    )
    db.add(zone)
    await db.flush()
    return group, zone


@pytest.mark.asyncio
async def test_import_preview_reports_diff(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin_auth(db_session)
    group, zone = await _make_zone(db_session)

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/import/preview",
        json={"zone_file": ZONE_TEXT, "zone_name": "example.com."},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["soa_detected"] is True
    assert body["record_count"] >= 7
    assert len(body["to_create"]) >= 7
    assert body["to_update"] == []
    assert body["to_delete"] == []


@pytest.mark.asyncio
async def test_import_malformed_returns_422(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin_auth(db_session)
    group, zone = await _make_zone(db_session)

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/import/preview",
        json={"zone_file": "{{{ not a zone file", "zone_name": "example.com."},
        headers=headers,
    )
    assert resp.status_code == 422
    assert "parse" in resp.json()["detail"].lower() or "fail" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_import_commit_merge_and_export_round_trip(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_auth(db_session)
    group, zone = await _make_zone(db_session)

    commit = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/import/commit",
        json={
            "zone_file": ZONE_TEXT,
            "zone_name": "example.com.",
            "conflict_strategy": "merge",
        },
        headers=headers,
    )
    assert commit.status_code == 200, commit.text
    body = commit.json()
    assert body["created"] >= 7
    assert body["deleted"] == 0
    assert body["batch_id"]

    export = await client.get(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/export",
        headers=headers,
    )
    assert export.status_code == 200
    text = export.text
    assert "$ORIGIN example.com." in text
    assert "192.0.2.10" in text
    assert "10 60 5060" in text  # SRV

    # Re-importing the exported file at the same zone must result in zero changes.
    preview = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/import/preview",
        json={"zone_file": text, "zone_name": "example.com."},
        headers=headers,
    )
    assert preview.status_code == 200
    pbody = preview.json()
    assert pbody["to_create"] == []
    assert pbody["to_update"] == []
    assert pbody["to_delete"] == []


@pytest.mark.asyncio
async def test_import_commit_replace_deletes_missing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_auth(db_session)
    group, zone = await _make_zone(db_session)

    # Import once with merge
    await client.post(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/import/commit",
        json={
            "zone_file": ZONE_TEXT,
            "zone_name": "example.com.",
            "conflict_strategy": "merge",
        },
        headers=headers,
    )

    # Replace with a smaller zone file — www and mail should be deleted.
    smaller = """\
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. ( 2 86400 7200 3600000 3600 )
@ IN NS ns1.example.com.
@ IN A  192.0.2.1
"""
    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/import/commit",
        json={
            "zone_file": smaller,
            "zone_name": "example.com.",
            "conflict_strategy": "replace",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] >= 4  # www A, mail AAAA, MX, SRV, TXT


@pytest.mark.asyncio
async def test_export_all_zones_returns_zip(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin_auth(db_session)
    group, zone = await _make_zone(db_session)

    # Add a second zone
    zone2 = DNSZone(
        group_id=group.id,
        name="other.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
        last_serial=1,
    )
    db_session.add(zone2)
    await db_session.flush()

    resp = await client.get(
        f"/api/v1/dns/groups/{group.id}/zones/export",
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"

    buf = io.BytesIO(resp.content)
    with zipfile.ZipFile(buf) as zf:
        names = zf.namelist()
    assert "example.com.zone" in names
    assert "other.test.zone" in names


@pytest.mark.asyncio
async def test_reimporting_own_export_keeps_inherited_ttl_inherited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#1727: a record with ttl NULL (inherits the zone) is not an update."""
    from sqlalchemy import select

    from app.models.dns import DNSRecord

    headers = await _admin_auth(db_session)
    group, zone = await _make_zone(db_session)
    zone.ttl = 3600
    db_session.add_all(
        [
            DNSRecord(
                zone_id=zone.id,
                name="ctl1",
                fqdn="ctl1.example.com.",
                record_type="A",
                value="192.0.2.79",
                ttl=None,
            ),
            DNSRecord(
                zone_id=zone.id,
                name="pinned",
                fqdn="pinned.example.com.",
                record_type="A",
                value="192.0.2.80",
                ttl=300,
            ),
        ]
    )
    await db_session.flush()
    base = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"

    export = await client.get(f"{base}/export", headers=headers)
    assert export.status_code == 200
    preview = await client.post(
        f"{base}/import/preview",
        json={
            "zone_file": export.text,
            "zone_name": "example.com.",
            "conflict_strategy": "replace",
        },
        headers=headers,
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["to_update"] == []

    commit = await client.post(
        f"{base}/import/commit",
        json={
            "zone_file": export.text,
            "zone_name": "example.com.",
            "conflict_strategy": "replace",
        },
        headers=headers,
    )
    assert commit.status_code == 200, commit.text
    assert commit.json()["updated"] == 0
    row = (await db_session.execute(select(DNSRecord).where(DNSRecord.name == "ctl1"))).scalar_one()
    await db_session.refresh(row)
    assert row.ttl is None

    # A foreign file whose explicit TTL differs from the zone default still updates.
    foreign = export.text.replace("ctl1\tIN\tA", "ctl1\t120\tIN\tA")
    assert "ctl1\t120" in foreign
    preview = await client.post(
        f"{base}/import/preview",
        json={"zone_file": foreign, "zone_name": "example.com."},
        headers=headers,
    )
    assert [c["name"] for c in preview.json()["to_update"]] == ["ctl1"]
