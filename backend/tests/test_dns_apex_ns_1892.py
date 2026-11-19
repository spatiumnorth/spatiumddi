"""Imported apex NS (#1892) and Sync's apex NS push (#1893).

The importer tests go through the public preview / commit endpoints with a
real BIND9 archive, and assert on what is stored and what the response says,
so they run unchanged against a build without the fix: there the preview
carries no warning, an ``apex_ns_policy`` the commit model does not know is
ignored, and the source's apex NS is stored as imported.
"""

from __future__ import annotations

import io
import tarfile
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import RecordChangeResult, RecordData
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import pull_from_server as pfs
from app.services.dns.pull_from_server import sync_zone_with_server

_ZONE = "example.com."

_NAMED = """
options { directory "/var/named"; };
zone "example.com" { type master; file "example.com.zone"; };
"""

# The source server's own name as SOA MNAME and first apex NS, the group's
# server as a second apex NS, and a delegation below the apex.
_ZONE_FILE = """\
$TTL 3600
@    IN SOA tech1.old.net. hostmaster.old.net. ( 5 3600 600 86400 300 )
@    IN NS  tech1.old.net.
@    IN NS  ns1.example.com.
sub  IN NS  ns.partner.net.
www  IN A   192.0.2.5
"""


def _archive() -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for path, content in (
            ("etc/named.conf", _NAMED),
            ("var/named/example.com.zone", _ZONE_FILE),
        ):
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return bio.getvalue()


async def _admin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


async def _group(db: AsyncSession, hosts: list[str], driver: str = "bind9") -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    for i, h in enumerate(hosts):
        db.add(
            DNSServer(
                group_id=grp.id,
                name=f"srv{i}",
                driver=driver,
                host=h,
                port=53,
                is_enabled=True,
                is_primary=i == 0,
            )
        )
    await db.flush()
    return grp


async def _preview(client: AsyncClient, token: str, grp: DNSServerGroup) -> dict[str, Any]:
    resp = await client.post(
        "/api/v1/dns/import/bind9/preview",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("bind.tar.gz", _archive(), "application/gzip")},
        data={"target_group_id": str(grp.id)},
    )
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


async def _commit(
    client: AsyncClient, token: str, grp: DNSServerGroup, plan: dict[str, Any], **extra: Any
) -> dict[str, Any]:
    resp = await client.post(
        "/api/v1/dns/import/bind9/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_group_id": str(grp.id), "plan": plan, "conflict_actions": {}, **extra},
    )
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


async def _stored(db: AsyncSession, group_id: uuid.UUID) -> tuple[DNSZone, list[tuple[str, str]]]:
    zone = (await db.execute(select(DNSZone).where(DNSZone.group_id == group_id))).scalar_one()
    rows = (await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))).scalars().all()
    return zone, sorted((r.name, r.value) for r in rows if r.record_type == "NS")


async def test_preview_flags_the_foreign_apex_ns_only(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _admin(db_session)
    grp = await _group(db_session, ["ns1.example.com"])
    await db_session.commit()

    plan = await _preview(client, token, grp)
    (z,) = plan["zones"]
    assert z.get("foreign_apex_ns") == ["tech1.old.net"]
    apex_warnings = [w for w in plan["warnings"] if "apex NS" in w]
    assert len(apex_warnings) == 1
    assert "tech1.old.net" in apex_warnings[0]
    assert "ns1.example.com" not in apex_warnings[0]
    assert "ns.partner.net" not in apex_warnings[0]  # a delegation is not the apex
    # Preview changes nothing: every record is still in the plan.
    assert ("@", "NS", "tech1.old.net.") in {
        (r["name"], r["record_type"], r["value"]) for r in z["records"]
    }


async def test_preview_does_not_flag_for_a_group_with_no_servers(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _admin(db_session)
    grp = await _group(db_session, [])
    await db_session.commit()

    plan = await _preview(client, token, grp)
    assert not plan["zones"][0].get("foreign_apex_ns")
    assert not [w for w in plan["warnings"] if "apex NS" in w]


async def test_commit_keeps_the_source_ns_by_default(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _admin(db_session)
    grp = await _group(db_session, ["ns1.example.com"])
    await db_session.commit()

    await _commit(client, token, grp, await _preview(client, token, grp))
    zone, ns = await _stored(db_session, grp.id)
    assert ("@", "tech1.old.net.") in ns
    assert zone.primary_ns.rstrip(".") == "tech1.old.net"


async def test_commit_replace_serves_the_groups_own_servers(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _admin(db_session)
    # A hostname server, an IP-literal one and a single-label one: only the
    # first can be named by an NS record that resolves.
    grp = await _group(db_session, ["ns1.example.com", "10.0.0.9", "bare"])
    await db_session.commit()

    plan = await _preview(client, token, grp)
    result = await _commit(client, token, grp, plan, apex_ns_policy="replace")

    zone, ns = await _stored(db_session, grp.id)
    # The source's NS is gone, the group's own is kept (not duplicated), the
    # delegation below the apex is untouched, nothing names an IP / bare label.
    assert ns == [("@", "ns1.example.com."), ("sub", "ns.partner.net.")]
    assert zone.primary_ns.rstrip(".") == "ns1.example.com"
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dns_zone", AuditLog.resource_id == str(zone.id)
            )
        )
    ).scalar_one()
    assert audit.new_value["apex_ns_replaced"]["removed"] == ["tech1.old.net."]
    # The preview's "commit with replace" advice is done, so not repeated.
    assert not [w for w in result["warnings"] if "apex NS" in w]


async def test_commit_replace_without_a_usable_host_keeps_the_rows(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _admin(db_session)
    grp = await _group(db_session, ["10.0.0.9", "dns-bind9"])
    await db_session.commit()

    plan = await _preview(client, token, grp)
    result = await _commit(client, token, grp, plan, apex_ns_policy="replace")

    _, ns = await _stored(db_session, grp.id)
    assert ("@", "tech1.old.net.") in ns
    assert any("no enabled server with a hostname" in w for w in result["warnings"])


async def test_copilot_commit_honours_the_policy(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.services.ai.operations_writes  # noqa: F401 — registers the operations
    import app.services.dns_import as dns_import
    from app.services.ai.operations import get_operation

    user, _ = await _admin(db_session)
    grp = await _group(db_session, ["ns1.example.com"])

    async def _fake_pull(**_: Any) -> Any:
        return dns_import.parse_bind9_archive(_archive())

    monkeypatch.setattr(dns_import, "parse_powerdns_server", _fake_pull)
    op = get_operation("commit_dns_import")
    assert op is not None
    args = op.args_model(
        source="powerdns",
        api_url="http://pdns.invalid",
        api_key="k",
        target_group_id=grp.id,
        apex_ns_policy="replace",
    )
    await op.apply(db_session, user, args)

    _, ns = await _stored(db_session, grp.id)
    assert ns == [("@", "ns1.example.com."), ("sub", "ns.partner.net.")]


# ── Sync with Servers (#1893) ────────────────────────────────────────


class _FakeDriver:
    """Returns a fixed read and records what it is asked to push."""

    def __init__(self, wire: list[RecordData]) -> None:
        self.wire = wire
        self.pushed: list[tuple[str, str, str]] = []

    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A", "NS"]}

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        return list(self.wire)

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        for c in changes:
            self.pushed.append((c.record.name, c.record.record_type, c.record.value))
        return [RecordChangeResult(ok=True, change=c) for c in changes]


async def _zone_with_records(db: AsyncSession, grp: DNSServerGroup) -> DNSZone:
    zone = DNSZone(group_id=grp.id, name=_ZONE, zone_type="primary", kind="forward")
    db.add(zone)
    await db.flush()
    for name, rtype, value in (
        ("www", "A", "192.0.2.5"),
        ("@", "NS", "tech1.old.net."),
        ("sub", "NS", "ns.partner.net."),
    ):
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=name,
                fqdn=_ZONE if name == "@" else f"{name}.{_ZONE}",
                record_type=rtype,
                value=value,
                ttl=300,
            )
        )
    await db.flush()
    return zone


async def test_sync_does_not_push_an_apex_ns_the_read_cannot_see(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    grp = await _group(db_session, ["ns1.example.com"])
    zone = await _zone_with_records(db_session, grp)
    # An AXFR read: the apex NS set is dropped by design.
    fake = _FakeDriver([RecordData(name="www", record_type="A", value="192.0.2.5", ttl=300)])
    monkeypatch.setattr(pfs, "get_driver", lambda name: fake)

    for _ in range(2):
        await sync_zone_with_server(db_session, zone, apply=True)
    # bind9 is agent-managed, so Sync queues record ops for the agent instead
    # of pushing through the driver (#2667). Only the delegation, which the
    # read can see is missing, is queued, and the second Sync adds no duplicate.
    assert fake.pushed == []
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    queued = [(o.record["name"], o.record["type"], o.record["value"]) for o in ops]
    assert [q for q in queued if q[0] == "@"] == []
    assert queued.count(("sub", "NS", "ns.partner.net.")) == 1


async def test_sync_still_pushes_a_missing_apex_ns_to_a_read_that_sees_the_apex(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``technitium_api`` reads the apex NS; Sync drops the server's own one
    (``without_server_apex_ns``) when the DB does not hold it. That filtering
    must not be mistaken for a read that cannot see the apex: the stored apex
    NS the server lacks is still pushed."""
    grp = await _group(db_session, ["tech.example.com"], driver="technitium_api")
    zone = await _zone_with_records(db_session, grp)
    fake = _FakeDriver(
        [
            RecordData(name="www", record_type="A", value="192.0.2.5", ttl=300),
            RecordData(name="sub", record_type="NS", value="ns.partner.net.", ttl=300),
            RecordData(name="@", record_type="NS", value="tech.example.com.", ttl=300),
        ]
    )
    monkeypatch.setattr(pfs, "get_driver", lambda name: fake)

    await sync_zone_with_server(db_session, zone, apply=True)
    assert ("@", "NS", "tech1.old.net.") in fake.pushed
