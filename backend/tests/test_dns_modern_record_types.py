"""Modern DNS record types — SVCB / HTTPS (RFC 9460) + DNAME (RFC 6672), issue #338.

Three layers are exercised:

* the BIND9 zone-file writer renders the new types (SVCB/HTTPS passthrough,
  DNAME written as stored like CNAME: absolute with a dot, relative without,
  #2187),
* the PowerDNS driver's supported-type set accepts them (it rejects unknown
  types at render otherwise),
* the record-create API accepts them on a bind9/powerdns group but gates them
  off a group that also runs a hosted-DNS driver (clear 422, not a late apply
  failure).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.powerdns import _SUPPORTED_RECORD_TYPES
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.services.dns_io import parse_zone_file, write_zone_file


@dataclass
class _Zone:
    name: str = "example.com."
    primary_ns: str = "ns1.example.com."
    admin_email: str = "hostmaster.example.com."
    ttl: int = 3600
    refresh: int = 86400
    retry: int = 7200
    expire: int = 3600000
    minimum: int = 3600
    last_serial: int = 2024010101


@dataclass
class _Rec:
    id: str
    name: str
    record_type: str
    value: str
    ttl: int | None = 3600
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


# ── Renderer ────────────────────────────────────────────────────────────────


def test_writer_renders_svcb_https_dname() -> None:
    records = [
        _Rec(id="1", name="@", record_type="HTTPS", value='1 . alpn="h2,h3"'),
        _Rec(id="2", name="_dns", record_type="SVCB", value="1 dns.example.com."),
        # An absolute DNAME target keeps its trailing dot.
        _Rec(id="3", name="legacy", record_type="DNAME", value="new.example.net."),
        # A bare target is relative to the zone, which is how BIND serves the
        # stored value (#2187); the export writes it as stored, not as root.
        _Rec(id="4", name="old", record_type="DNAME", value="moved"),
    ]
    text = write_zone_file(_Zone(), records)  # type: ignore[arg-type]

    assert '@\t3600\tIN\tHTTPS\t1 . alpn="h2,h3"' in text
    assert "_dns\t3600\tIN\tSVCB\t1 dns.example.com." in text
    assert "legacy\t3600\tIN\tDNAME\tnew.example.net." in text
    assert "old\t3600\tIN\tDNAME\tmoved\n" in text

    # The output round-trips through the parser without losing the types.
    kinds = {r.record_type for r in parse_zone_file(text, "example.com").records}
    assert {"HTTPS", "SVCB", "DNAME"}.issubset(kinds)


def test_powerdns_supports_modern_types() -> None:
    assert {"SVCB", "HTTPS", "DNAME"} <= _SUPPORTED_RECORD_TYPES


# ── API driver-gate ──────────────────────────────────────────────────────────


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group_with_driver(db: AsyncSession, driver: str) -> tuple[DNSServerGroup, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver=driver,
            host=f"{driver}.example.com",
            name=f"srv-{uuid.uuid4().hex[:6]}",
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.flush()
    return grp, zone


async def test_create_modern_record_on_bind9_group_succeeds(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp, zone = await _group_with_driver(db_session, "bind9")
    await db_session.commit()

    for rtype, value in (
        ("HTTPS", '1 . alpn="h2"'),
        ("SVCB", "1 svc.example.com."),
        ("DNAME", "target.example.net."),
    ):
        r = await client.post(
            f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records",
            headers=h,
            json={"name": rtype.lower(), "record_type": rtype, "value": value},
        )
        assert r.status_code == 201, f"{rtype}: {r.text}"
        assert r.json()["record_type"] == rtype


async def test_modern_record_gated_off_cloud_driver_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # A group that also runs an agentless hosted-DNS driver can't serve
    # SVCB/HTTPS/DNAME — the API must 422 up front rather than fail at apply.
    h = await _admin_headers(db_session)
    grp, zone = await _group_with_driver(db_session, "cloudflare")
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records",
        headers=h,
        json={"name": "svc", "record_type": "HTTPS", "value": '1 . alpn="h2"'},
    )
    assert r.status_code == 422, r.text
