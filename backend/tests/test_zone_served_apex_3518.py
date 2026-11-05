"""The records list carries the SOA and apex NS a zone serves (#3518)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.ai.tools.dns import ListZonesArgs, list_dns_zones
from app.services.dns.ingest import EXTERNAL_IMPORT_SOURCE

pytestmark = pytest.mark.asyncio


async def _user(db: AsyncSession, permissions: list[dict[str, Any]] | None) -> User:
    tag = uuid.uuid4().hex[:8]
    u = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=permissions is None,
    )
    db.add(u)
    if permissions is not None:
        role = Role(name=f"r-{tag}", description="", permissions=permissions)
        grp = Group(name=f"g-{tag}", description="")
        grp.roles = [role]
        grp.users = [u]
        db.add_all([role, grp])
    await db.flush()
    await db.refresh(u, ["groups"])
    return u


def _h(u: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _zone(
    db: AsyncSession,
    *,
    driver: str | None = "bind9",
    zone_type: str = "primary",
    primary_ns: str = "",
    admin_email: str = "",
    name: str = "apex.example.com.",
) -> DNSZone:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    if driver:
        db.add(
            DNSServer(
                group_id=group.id,
                name="ns",
                driver=driver,
                host="10.0.0.53",
                port=53,
                is_primary=True,
            )
        )
    zone = DNSZone(
        group_id=group.id,
        name=name,
        zone_type=zone_type,
        kind="forward",
        primary_ns=primary_ns,
        admin_email=admin_email,
    )
    db.add(zone)
    await db.flush()
    return zone


def _rec(zone: DNSZone, name: str, rtype: str, value: str, source: str | None = None) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=zone.name.rstrip(".") if name == "@" else f"{name}.{zone.name.rstrip('.')}",
        record_type=rtype,
        value=value,
        import_source=source,
    )


async def _get(client: AsyncClient, zone: DNSZone, h: dict[str, str]) -> Any:
    return await client.get(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records", headers=h
    )


async def test_the_placeholder_case(client: AsyncClient, db_session: AsyncSession) -> None:
    h = _h(await _user(db_session, None))
    zone = await _zone(db_session)
    await db_session.commit()
    body = (await _get(client, zone, h)).json()
    assert body["served_apex"] == {
        "driver_applies": True,
        "soa": {"mname": "ns1.apex.example.com.", "rname": "admin.apex.example.com."},
        "ns": ["ns1.apex.example.com."],
        "source": "placeholder",
        "placeholder_glue_loopback": True,
    }
    # Not records: the list and its counts are untouched.
    assert body["items"] == [] and body["total"] == 0


async def test_the_primary_ns_case(client: AsyncClient, db_session: AsyncSession) -> None:
    h = _h(await _user(db_session, None))
    zone = await _zone(
        db_session, primary_ns="ns.provider.net.", admin_email="hostmaster.example.com."
    )
    db_session.add(_rec(zone, "www", "A", "192.0.2.1"))
    await db_session.commit()
    body = (await _get(client, zone, h)).json()
    assert body["served_apex"]["source"] == "primary_ns"
    assert body["served_apex"]["ns"] == ["ns.provider.net."]
    assert body["served_apex"]["soa"] == {
        "mname": "ns.provider.net.",
        "rname": "hostmaster.example.com.",
    }
    assert body["served_apex"]["placeholder_glue_loopback"] is False
    assert body["total"] == 1


async def test_a_declared_ns_set_is_the_whole_set(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = _h(await _user(db_session, None))
    zone = await _zone(db_session, primary_ns="ns.provider.net.")
    db_session.add(_rec(zone, "@", "NS", "ns-a.other.net."))
    await db_session.commit()
    apex = (await _get(client, zone, h)).json()["served_apex"]
    assert apex["source"] == "declared"
    assert apex["ns"] == ["ns-a.other.net."]
    assert apex["soa"]["mname"] == "ns.provider.net."
    assert apex["placeholder_glue_loopback"] is False


async def test_a_mirrored_or_deleted_ns_is_not_declared(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only rows that reach the agent's bundle decide the NS set."""
    from datetime import UTC, datetime

    h = _h(await _user(db_session, None))
    zone = await _zone(db_session)
    gone = _rec(zone, "@", "NS", "ns-gone.example.net.")
    gone.deleted_at = datetime.now(UTC)
    db_session.add_all([_rec(zone, "@", "NS", "ns-m.example.net.", EXTERNAL_IMPORT_SOURCE), gone])
    await db_session.commit()
    assert (await _get(client, zone, h)).json()["served_apex"]["source"] == "placeholder"


async def test_the_non_host_name_zone_has_no_loopback_glue(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = _h(await _user(db_session, None))
    zone = await _zone(db_session, name="_msdcs.example.com.")
    await db_session.commit()
    apex = (await _get(client, zone, h)).json()["served_apex"]
    assert apex["ns"] == ["invalid."]
    assert apex["soa"] == {"mname": "invalid.", "rname": "invalid."}
    assert apex["source"] == "placeholder"
    assert apex["placeholder_glue_loopback"] is False


@pytest.mark.parametrize("driver", ["powerdns", "technitium", "windows_dns", "route53"])
async def test_another_driver_does_not_apply(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    h = _h(await _user(db_session, None))
    zone = await _zone(db_session, driver=driver)
    await db_session.commit()
    assert (await _get(client, zone, h)).json()["served_apex"]["driver_applies"] is False


async def test_a_mixed_group_does_not_apply(client: AsyncClient, db_session: AsyncSession) -> None:
    h = _h(await _user(db_session, None))
    zone = await _zone(db_session)
    db_session.add(
        DNSServer(group_id=zone.group_id, name="p", driver="powerdns", host="10.0.0.54", port=53)
    )
    await db_session.commit()
    assert (await _get(client, zone, h)).json()["served_apex"]["driver_applies"] is False


async def test_a_zone_that_is_not_primary_has_no_apex(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = _h(await _user(db_session, None))
    zone = await _zone(db_session, zone_type="secondary")
    await db_session.commit()
    assert (await _get(client, zone, h)).json()["served_apex"] is None


async def test_a_reader_sees_it_and_a_refused_role_gets_the_refusal(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    reader = _h(
        await _user(
            db_session,
            [
                {"action": "read", "resource_type": "dns_zone"},
                {"action": "read", "resource_type": "dns_record"},
            ],
        )
    )
    refused = _h(await _user(db_session, [{"action": "read", "resource_type": "subnet"}]))
    zone = await _zone(db_session)
    await db_session.commit()
    ok = await _get(client, zone, reader)
    assert ok.status_code == 200 and ok.json()["served_apex"]["source"] == "placeholder"
    no = await _get(client, zone, refused)
    assert no.status_code == 403
    assert "served_apex" not in no.json()


async def test_nothing_about_it_is_writable(client: AsyncClient, db_session: AsyncSession) -> None:
    """It is a separate field with no id, so no record route can address it, and
    ``items`` holds stored records only."""
    h = _h(await _user(db_session, None))
    zone = await _zone(db_session)
    db_session.add(_rec(zone, "www", "A", "192.0.2.1"))
    await db_session.commit()
    items = (await _get(client, zone, h)).json()["items"]
    assert [i["record_type"] for i in items] == ["A"]


async def test_the_copilot_zone_read_carries_it(db_session: AsyncSession) -> None:
    user = await _user(db_session, None)
    prim = await _zone(db_session, primary_ns="ns.provider.net.", name="a.example.com.")
    sec = await _zone(db_session, zone_type="secondary", name="b.example.com.")
    await db_session.commit()
    rows = {
        r["name"]: r
        for r in await list_dns_zones(db_session, user, ListZonesArgs(group_id=str(prim.group_id)))
    }
    assert rows["a.example.com."]["served_apex"]["source"] == "primary_ns"
    assert rows["a.example.com."]["served_apex"]["ns"] == ["ns.provider.net."]
    rows2 = {
        r["name"]: r
        for r in await list_dns_zones(db_session, user, ListZonesArgs(group_id=str(sec.group_id)))
    }
    assert "served_apex" not in rows2["b.example.com."]
