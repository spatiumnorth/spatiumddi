"""#4155 — the DNS configuration importers hold records to BIND's check-names.

The record API 422s an A / AAAA / MX owner (or MX / NS / SRV target) that is
not a host name, because named-checkzone refuses the whole zone that holds
one. The importers stored such rows anyway; the zone then answered SERVFAIL.
The preview now reports each such record and the commit skips it, saying why,
and the zone and its other records still import.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup
from app.services.dns_import import cname_check
from app.services.dns_import.canonical import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
)
from app.services.dns_import.commit import commit_import


def _zone() -> ImportedZone:
    return ImportedZone(
        name="_msdcs.example.com.",
        zone_type="primary",
        kind="forward",
        soa=ImportedSOA("ns1.example.com.", "admin.example.com.", 1, 3600, 600, 86400, 300, 3600),
        records=[
            ImportedRecord("_ldap._tcp.dc", "SRV", "dc1.example.com.", 300, 0, 100, 389),
            ImportedRecord("gc", "A", "192.0.2.1", 300),
            ImportedRecord("bad_host", "A", "192.0.2.9", 300),
            ImportedRecord("txt_ok", "TXT", "hello", 300),
        ],
    )


def _preview(z: ImportedZone) -> ImportPreview:
    return ImportPreview(
        source="bind9",
        zones=[z],
        conflicts=[],
        warnings=[],
        total_records=len(z.records),
        record_type_histogram={},
    )


def test_preview_names_the_refused_record() -> None:
    p = _preview(_zone())
    cname_check.annotate_cname_conflicts(p)
    assert len(p.warnings) == 1
    assert "bad_host A 192.0.2.9" in p.warnings[0]
    assert "not a host name" in p.warnings[0]
    assert cname_check.is_cname_warning(p.warnings[0])
    assert cname_check.count_cname_warnings(p.warnings) == 1


@pytest.mark.asyncio
async def test_commit_skips_it_and_lands_the_rest(db_session: AsyncSession) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, grp])
    await db_session.flush()
    p = _preview(_zone())
    cname_check.annotate_cname_conflicts(p)
    res = await commit_import(
        db_session,
        preview=p,
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
    )
    assert res.zones[0].action_taken == "created"
    assert res.zones[0].records_created == 3
    stored = (await db_session.execute(select(DNSRecord))).scalars().all()
    assert sorted(r.name for r in stored) == ["_ldap._tcp.dc", "gc", "txt_ok"]
    assert len(res.zones[0].skipped_records) == 1
    reasons = [w for w in res.warnings if "record not imported" in w]
    assert len(reasons) == 1 and "bad_host" in reasons[0]
    assert not any(cname_check.is_cname_warning(w) for w in res.warnings)


@pytest.mark.asyncio
async def test_commit_without_the_preview_still_skips(db_session: AsyncSession) -> None:
    """The commit never trusts the preview: the plan round-trips the client."""
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, grp])
    await db_session.flush()
    res = await commit_import(
        db_session,
        preview=_preview(_zone()),
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
    )
    assert res.zones[0].records_created == 3
