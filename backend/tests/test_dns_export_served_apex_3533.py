"""#3533 - a zone file export writes the SOA and apex NS the zone is served with.

The writer used to invent its own defaults (MNAME = the zone, RNAME =
``hostmaster.<zone>``) while the BIND9 agent serves ``ns1.<zone>`` /
``admin.<zone>`` for a zone with no Primary NS and Admin Email. The export now
asks ``zone_apex`` for the apex, the rule the agent and the records list use.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns.zone_apex import served_apex_for_zones
from app.services.dns_io import parse_zone_file
from tests.test_dns_import_export import _admin_auth


async def _zone(db: AsyncSession, **kw: object) -> tuple[DNSServerGroup, DNSZone]:
    group = DNSServerGroup(name="g-3533", description="")
    db.add(group)
    await db.flush()
    zone = DNSZone(
        group_id=group.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        last_serial=2026110501,
        **kw,
    )
    db.add(zone)
    await db.flush()
    return group, zone


def _soa_line(text: str) -> str:
    return next(ln for ln in text.splitlines() if "\tSOA\t" in ln)


@pytest.mark.asyncio
async def test_export_of_a_bare_zone_is_the_served_soa(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_auth(db_session)
    group, zone = await _zone(db_session, primary_ns="", admin_email="")
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="192.0.2.1"))
    await db_session.flush()

    served = (await served_apex_for_zones(db_session, [zone]))[zone.id].apex
    assert (served.soa_mname, served.soa_rname) == ("ns1.example.com.", "admin.example.com.")

    base = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"
    r = await client.get(f"{base}/export", headers=headers)
    assert r.status_code == 200, r.text
    assert _soa_line(r.text).split() == [
        "@",
        "IN",
        "SOA",
        served.soa_mname,
        served.soa_rname,
        "(",
        "2026110501",
        str(zone.refresh),
        str(zone.retry),
        str(zone.expire),
        str(zone.minimum),
        ")",
    ]
    assert "hostmaster" not in r.text
    # The served apex NS is noted, and not written as a record that a
    # re-import would create.
    assert "; apex NS served from zone settings: ns1.example.com." in r.text
    assert "\tNS\t" not in r.text

    # The bulk zip export goes through the same writer.
    z = await client.get(f"/api/v1/dns/groups/{group.id}/zones/export", headers=headers)
    with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
        assert _soa_line(zf.read("example.com.zone").decode()) == _soa_line(r.text)


@pytest.mark.asyncio
async def test_export_with_explicit_values_is_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_auth(db_session)
    group, zone = await _zone(
        db_session, primary_ns="ns1.example.net.", admin_email="dns-admin.example.com."
    )
    db_session.add_all(
        [
            DNSRecord(zone_id=zone.id, name="@", record_type="NS", value="ns1.example.net."),
            DNSRecord(zone_id=zone.id, name="www", record_type="A", value="192.0.2.1"),
        ]
    )
    await db_session.flush()
    base = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"
    text = (await client.get(f"{base}/export", headers=headers)).text
    lines = text.splitlines()
    assert lines[0] == "$ORIGIN example.com."
    assert lines[2].split()[3:5] == ["ns1.example.net.", "dns-admin.example.com."]
    assert "2026110501" in lines[2]
    # No synthesised NS beside the declared one.
    assert sum("\tNS\t" in ln for ln in lines) == 1
    assert parse_zone_file(text, "example.com.").soa is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", ["replace", "merge"])
async def test_export_of_a_bare_zone_reimports_as_no_change(
    client: AsyncClient, db_session: AsyncSession, strategy: str
) -> None:
    """#2187 for the zone #3533 is about: the served apex notes are comments,
    so the file re-imports without planning an NS (or loopback glue) record."""
    headers = await _admin_auth(db_session)
    group, zone = await _zone(db_session, primary_ns="", admin_email="")
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="192.0.2.1"))
    await db_session.flush()
    base = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"
    export = await client.get(f"{base}/export", headers=headers)
    assert "glued to 127.0.0.1" in export.text
    preview = await client.post(
        f"{base}/import/preview",
        json={"zone_file": export.text, "zone_name": "example.com.", "conflict_strategy": strategy},
        headers=headers,
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert (body["to_create"], body["to_update"], body["to_delete"]) == ([], [], [])


@pytest.mark.asyncio
async def test_split_horizon_export_notes_each_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Views that serve different apexes are each noted, and the SOA line is the
    worst of them (the placeholder), as the records list summarises it."""
    headers = await _admin_auth(db_session)
    group, zone = await _zone(db_session, primary_ns="", admin_email="")
    internal = DNSView(group_id=group.id, name="internal", match_clients=["10/8"], order=0)
    external = DNSView(group_id=group.id, name="external", match_clients=["any"], order=1)
    db_session.add_all([internal, external])
    await db_session.flush()
    db_session.add_all(
        [
            DNSRecord(
                zone_id=zone.id,
                name="@",
                record_type="NS",
                value="ns-int.example.net.",
                view_id=internal.id,
            ),
            DNSRecord(
                zone_id=zone.id,
                name="www",
                record_type="A",
                value="192.0.2.1",
                view_id=external.id,
            ),
        ]
    )
    await db_session.flush()
    base = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"
    text = (await client.get(f"{base}/export", headers=headers)).text
    assert _soa_line(text).split()[3:5] == ["ns1.example.com.", "admin.example.com."]
    assert (
        "; view internal: SOA ns-int.example.net. admin.example.com.,"
        " apex NS ns-int.example.net." in text
    )
    assert "; view external: SOA ns1.example.com. admin.example.com., apex NS ns1.example.com." in (
        text
    )


@pytest.mark.asyncio
async def test_export_under_another_driver_does_not_claim_the_bind9_apex(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A Technitium group serves its own apex for a zone with no settings, so
    the export does not say the BIND9 placeholder is what is served."""
    headers = await _admin_auth(db_session)
    group, zone = await _zone(db_session, primary_ns="", admin_email="")
    db_session.add(
        DNSServer(group_id=group.id, name="t", driver="technitium", host="192.0.2.53", port=53)
    )
    await db_session.flush()
    base = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"
    text = (await client.get(f"{base}/export", headers=headers)).text
    assert "this group's driver serves its own apex" in text
    assert "served from zone settings" not in text
    assert "glued to 127.0.0.1" not in text
