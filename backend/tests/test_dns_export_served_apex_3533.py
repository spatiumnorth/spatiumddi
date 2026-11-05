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

from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
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
