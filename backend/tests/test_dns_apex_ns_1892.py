"""Imported apex NS and Sync's apex NS push (#1892, #1893)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.drivers.dns.base import RecordChangeResult, RecordData
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import pull_from_server as pfs
from app.services.dns.pull_from_server import sync_zone_with_server
from app.services.dns_import import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
    commit_import,
)
from app.services.dns_import.apex_ns import annotate_apex_ns

_ZONE = "example.com."


def _imported_zone(name: str = _ZONE, zone_type: str = "primary") -> ImportedZone:
    return ImportedZone(
        name=name,
        zone_type=zone_type,
        kind="forward",
        soa=ImportedSOA("tech1.old.net.", "h.old.net.", 5, 3600, 600, 86400, 300, 3600),
        records=[
            ImportedRecord("@", "NS", "tech1.old.net.", 300),
            ImportedRecord("@", "NS", "ns1.example.com.", 300),
            ImportedRecord("sub", "NS", "ns.partner.net.", 300),
            ImportedRecord("www", "A", "192.0.2.5", 300),
        ],
    )


def _preview(zone: ImportedZone) -> ImportPreview:
    return ImportPreview(
        source="technitium",
        zones=[zone],
        conflicts=[],
        warnings=[],
        total_records=len(zone.records),
        record_type_histogram={},
    )


async def _group(db: AsyncSession, hosts: list[str]) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    for i, h in enumerate(hosts):
        db.add(
            DNSServer(
                group_id=grp.id,
                name=f"srv{i}",
                driver="bind9",
                host=h,
                port=53,
                is_enabled=True,
                is_primary=i == 0,
            )
        )
    await db.flush()
    return grp


async def _user(db: AsyncSession) -> User:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u


async def _stored_ns(
    db: AsyncSession, group_id: uuid.UUID
) -> tuple[DNSZone, list[tuple[str, str]]]:
    zone = (await db.execute(select(DNSZone).where(DNSZone.group_id == group_id))).scalar_one()
    rows = (await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))).scalars().all()
    return zone, sorted((r.name, r.value) for r in rows if r.record_type == "NS")


async def test_preview_warns_about_foreign_apex_ns_and_changes_nothing(
    db_session: AsyncSession,
) -> None:
    grp = await _group(db_session, ["ns1.example.com"])
    zone = _imported_zone()
    preview = _preview(zone)
    await annotate_apex_ns(db_session, preview, grp.id)
    (warning,) = preview.warnings
    assert "tech1.old.net" in warning and "ns1.example.com" not in warning
    assert "ns.partner.net" not in warning  # a delegation is not the apex
    assert len(zone.records) == 4


async def test_commit_keeps_rows_by_default(db_session: AsyncSession) -> None:
    grp = await _group(db_session, ["ns1.example.com"])
    await commit_import(
        db_session,
        preview=_preview(_imported_zone()),
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=await _user(db_session),
    )
    _, ns = await _stored_ns(db_session, grp.id)
    assert ("@", "tech1.old.net.") in ns


async def test_commit_replace_swaps_foreign_apex_ns_and_audits(db_session: AsyncSession) -> None:
    grp = await _group(db_session, ["ns1.example.com", "10.0.0.9", "bare"])
    await commit_import(
        db_session,
        preview=_preview(_imported_zone()),
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=await _user(db_session),
        apex_ns_policy="replace",
    )
    zone, ns = await _stored_ns(db_session, grp.id)
    # foreign source NS gone; the group's own kept (not duplicated); the
    # delegation below the apex untouched; IP / single-label hosts not minted.
    assert ns == [("@", "ns1.example.com."), ("sub", "ns.partner.net.")]
    assert zone.primary_ns == "ns1.example.com"
    audit = (
        await db_session.execute(select(AuditLog).where(AuditLog.resource_id == str(zone.id)))
    ).scalar_one()
    assert audit.new_value["apex_ns_replaced"]["removed"] == ["tech1.old.net."]


async def test_commit_replace_without_usable_host_keeps_rows(db_session: AsyncSession) -> None:
    grp = await _group(db_session, ["10.0.0.9"])
    result = await commit_import(
        db_session,
        preview=_preview(_imported_zone()),
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=await _user(db_session),
        apex_ns_policy="replace",
    )
    _, ns = await _stored_ns(db_session, grp.id)
    assert ("@", "tech1.old.net.") in ns
    assert any("no enabled server with a hostname" in w for w in result.warnings)


class _AxfrLikeDriver:
    """A read that drops the apex NS, as the AXFR helper does."""

    def __init__(self) -> None:
        self.pushed: list[tuple[str, str, str]] = []

    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A", "NS"]}

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        return [RecordData(name="www", record_type="A", value="192.0.2.5", ttl=300)]

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        for c in changes:
            self.pushed.append((c.record.name, c.record.record_type, c.record.value))
        return [RecordChangeResult(ok=True, change=c) for c in changes]


async def test_sync_does_not_push_apex_ns_a_read_cannot_see(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    grp = await _group(db_session, ["ns1.example.com"])
    zone = DNSZone(group_id=grp.id, name=_ZONE, zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.flush()
    for name, rtype, value in (
        ("www", "A", "192.0.2.5"),
        ("@", "NS", "tech1.old.net."),
        ("sub", "NS", "ns.partner.net."),
    ):
        db_session.add(
            DNSRecord(
                zone_id=zone.id,
                name=name,
                fqdn=_ZONE if name == "@" else f"{name}.{_ZONE}",
                record_type=rtype,
                value=value,
                ttl=300,
            )
        )
    await db_session.flush()
    fake = _AxfrLikeDriver()
    monkeypatch.setattr(pfs, "get_driver", lambda name: fake)

    for _ in range(2):
        await sync_zone_with_server(db_session, zone, apply=True)
    # Only the delegation, which the read can see, is ever pushed; the apex
    # NS is not pushed on either run.
    assert [p for p in fake.pushed if p[0] == "@"] == []
    assert fake.pushed.count(("sub", "NS", "ns.partner.net.")) == 2
